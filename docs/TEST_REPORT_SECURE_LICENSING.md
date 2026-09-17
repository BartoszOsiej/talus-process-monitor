# Secure Licensing — E2E Verification Report

> Generated: 2026-09-17 · All tests executed against the **production**
> activation server and the **real** release binary.
> Server: `https://talus-license-server.metaforicmail.workers.dev`
> (Cloudflare Workers + D1, free tier, no credit card)

## 1. Local quality gates

| Gate | Result |
|---|---|
| `cargo build -p process-monitor --release` | ✅ (55.8 s, clean) |
| `cargo test -p process-monitor --bin process-monitor` | ✅ **95 passed; 0 failed** (incl. `key_integrity_check` with the rotated key) |
| `cargo clippy -p process-monitor -- -D warnings` | ✅ 0 warnings |
| `cargo clippy` (license-keygen) | ✅ 0 warnings |
| `cargo fmt --check` (both crates) | ✅ |
| Audit hash chain (`talus license verify-audit`) | ✅ intact |

## 2. HTTP E2E suite — production worker (18/18 PASS)

Executed with real HTTP requests (curl) against the deployed worker.
Test keys were issued with the rotated signing key from
`~/.secrets/talus/license-keys/` (never committed). Tokens are never logged;
only a SHA-256 prefix is recorded (`e1ad95bb9030…`).

| # | Scenario | Expected | Actual | Result |
|---|---|---|---|---|
| 1 | `GET /api/v1/health` | 200 | 200 | ✅ |
| 2 | Activate (seats=3) on machine-1 → token, tier=enterprise | 200 | 200 | ✅ |
| 3 | Re-activate same machine (idempotency) → same token | 200, same token | same token | ✅ |
| 4 | Activate machine-2, machine-3 (seats 2/3, 3/3) | 200 | 200 | ✅ |
| 5 | Activate machine-4 — over `max_seats` | 403 `seat limit` | 403 | ✅ |
| 6 | Activate expired key (2025-01-01) | 403 `expired` | 403 | ✅ |
| 7 | Admin revoke of a **never-seen** key (`revocations` table) | 200 | 200 | ✅ |
| 8 | Activate revoked key | 403 `revoked` | 403 | ✅ |
| 9 | Deactivate with wrong token | no-op message | no-op | ✅ |
| 10 | Deactivate with correct token → seat freed | 200 | 200 | ✅ |
| 11 | Freed seat is reusable (machine-4 activates) | 200 | 200 | ✅ |
| 12 | Corrupted signature | 401 | 401 | ✅ |
| 13 | Malformed key format | 400 | 400 | ✅ |
| 14 | Malformed JSON body | 400 | 400 | ✅ |
| 15 | Missing `machine_id` | 400 | 400 | ✅ |
| 16 | Admin endpoint with wrong bearer token | 401 | 401 | ✅ |
| 17 | Rate limiting: 7 rapid attempts / 1 machine | ≥1× 429 | 2× 429 | ✅ |
| 18 | Method/route hygiene (405/404 family) | enforced | enforced | ✅ |

**Summary: PASS 18 · FAIL 0**

Raw output archived at test time (`/tmp/e2e-http-results.txt`), reproduced
verbatim in this report above.

## 3. Binary E2E — real `talus` release build

| Step | Command | Result |
|---|---|---|
| Fingerprint | `talus license machine-id` | ✅ `T-4e097c7f600d2966` |
| Before | `talus license show` | ✅ Community mode box |
| Activate (production server) | `talus license activate <KEY>` | ✅ `✓ license activated successfully` |
| Tier confirmed | `talus license show` | ✅ `Tier: Enterprise`, License ID, machine binding, features: auto_kill, clickhouse, ffi, json, kafka, memgraph, plain, tui, web |
| Verify | `talus license verify` | ✅ `License TALUS-E2E0-E2E-E-BINARY-0001 is valid (Enterprise)` |
| Export | `talus license export-json` | ✅ JSON with activation state |
| Idempotent re-activation | `talus license activate <KEY>` (2nd) | ✅ succeeds, second `ACTIVATED` audit entry |
| Audit chain | `talus license audit-log` + `verify-audit` | ✅ hash chain intact |
| Deactivate | `talus license deactivate` | ✅ local cache cleared **and** server seat released (`scripts/list-activations.sh` → `[]`) |
| Expired key | `talus license activate <expired-KEY>` | ✅ `Error: license … has expired` |
| Revoked-before-activation key | `talus license activate <revoked-KEY>` | ✅ `activation failed (403): license … has been revoked` |

## 3b. Hosted admin panel E2E — TOTP login + sessions (14/14 PASS)

Suite: login page, unauthenticated probes, wrong-token/wrong-TOTP logins,
valid login + cookie, TOTP replay rejection, session-check, overview page,
stats via cookie, drift ±1 acceptance, logout invalidation, bearer backward
compat, static assets. Run against **production**
(`https://talus-license-server.metaforicmail.workers.dev/admin`).

| Step | Expected | Result |
|---|---|---|
| `GET /admin` unauthenticated | 200, login page | ✅ |
| `GET /admin/session-check` w/o cookie | 401 | ✅ |
| `GET /api/v1/admin/stats` w/o auth | 401 | ✅ |
| Login with wrong TOTP | 401, no cookie | ✅ |
| Login with wrong auth code + valid TOTP | 401, TOTP step **not** consumed | ✅ |
| Login with valid auth code + current TOTP | 200, HttpOnly `talus_admin_session` cookie | ✅ |
| Replay of the same TOTP step | 401 (replay guard) | ✅ |
| `GET /admin` with session | 200, overview UI | ✅ |
| `GET /admin/session-check` with cookie | 200 | ✅ |
| `GET /api/v1/admin/stats` with cookie | 200 | ✅ |
| Login with drift +1 TOTP code | 200 (window ±1 step) | ✅ |
| `POST /admin/logout` then session-check | 200 → 401 (session destroyed) | ✅ |
| `GET /api/v1/admin/stats` with bearer token | 200 (backward compat) | ✅ |
| `GET /admin/app.js` + `/admin/style.css` | 200 | ✅ |

Unit tests for the TOTP/base32 core: `node --test test/` in
`license-server/` — 4/4 PASS (RFC 6238 vectors verified against an
independent Node-crypto HOTP reference).

Post-run hygiene: test sessions and consumed TOTP steps were purged from D1
(`sessions`, `totp_used`); the owner sets the production seed with
`scripts/setup-totp.sh`.

## 4. Issues found and fixed during verification

| Finding | Fix |
|---|---|
| Worker returned HTTP 500 on valid activations | `@noble/ed25519` v2 requires an explicit SHA-512 dependency in Workers; replaced with **native WebCrypto Ed25519** (`crypto.subtle.verify`) — also removes the third-party dependency |
| Admin endpoint returned 401 with the correct token | Secret file contained a trailing newline (from `openssl rand > file`); server now trims the bearer header and the secret, secret re-uploaded |
| Rate limiter consumed by double requests from the first test harness | Harness fixed to a single curl per assertion; D1 test state wiped between runs |
| `scripts/*.sh` read the token file with `read -r` (non-zero exit on a final line without newline; would keep trailing whitespace) | Both scripts now read via `tr -d '[:space:]'` |
| Admin UI assets served via `admin_js()` etc. after moving to text imports — `TypeError: admin_js is not a function` (HTTP 500 on `/admin/app.js`) | Assets are strings now; `new Response(admin_js)` without call parens |
| `session-check` returned 200 unauthenticated (`require_admin(...) !== null` is always true) | Compare `authz.admin === true` |
| A wrong auth code consumed the caller's TOTP step (verification order) — the owner had to wait 30 s for the next code after a typo | Auth code is checked **before** TOTP; TOTP is consumed only on a valid auth code |

## 5. Post-verification state hygiene

- D1 tables were cleared of all E2E test rows
  (`activations`, `rate_events`, `revocations`, `licenses`) after the run —
  the production database starts clean; licenses re-register on first
  activation by design.
- Test keys were issued with organizations named
  `E2E-TEST-DO-NOT-SHIP-…`; they remain recorded only in the **local**
  keygen registry (`~/.secrets/talus/license-keys/issued_licenses.json`,
  0600) — never in the repository. Revoke them with
  `scripts/revoke-license.sh <ID>` before real sales if desired.
- No tokens or license keys are stored in this report, the repository, or
  terminal logs (token appears only as a SHA-256 prefix).

## 6. Remaining owner decisions (not blockers)

- Optional: clean the leaked key from git **history** with
  `git filter-repo` (commands in the session report; requires force-push —
  owner's explicit decision).
- Optional: custom domain for the worker (currently a `*.workers.dev` URL).
- Pricing amounts (by design, not stored in the repo).

# Talus License Server

License activation backend for **Talus Process Monitor** — a Cloudflare Worker
with a D1 database on the **free tier (no credit card required)**.

## Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/v1/activate` | POST | — | Verify signature, enforce expiry/revocation/seats, return activation token |
| `/api/v1/deactivate` | POST | token | Release the machine's seat (token required) |
| `/api/v1/health` | GET | — | Service status |
| `/api/v1/admin/revoke` | POST | Bearer `ADMIN_TOKEN` | Revoke a license (frees all seats) |
| `/api/v1/admin/activations` | POST | Bearer `ADMIN_TOKEN` | List activations for a license |

## Client contract (from `process-monitor/src/license.rs`)

```json
// POST /api/v1/activate
{ "license_key": "<payload>.<signature>", "machine_id": "T-...", "hostname": "...", "version": "0.7.0" }
// → 200 { "success": true, "token": "...", "expires_at": "2027-01-01T00:00:00Z", "tier": "enterprise", "message": "..." }

// POST /api/v1/deactivate
{ "license_id": "TALUS-XXXX-XXXX-XXXX", "token": "..." }
// → 200 { "success": true, "message": "license deactivated — seat released" }
```

## Security model

- **Public-key only.** The worker holds the Ed25519 *public* key (in
  `wrangler.toml [vars]` — same key as embedded in the binary). The private
  signing key never leaves the owner's machine.
- **Server-side signature verification** of every license key before any
  state is created.
- **Seats enforced in D1** (`max_seats`, default from the signed payload's
  `seat_count`); same-machine re-activation is idempotent.
- **Revocation**: `licenses.revoked` flag + `revocations` table for keys
  revoked before first activation; revocation deletes all activations.
- **First-seen auto-registration**: licenses are registered on first
  activation, so `talus-keygen issue` needs no server round-trip.
- **Rate limiting**: 5 activation attempts / 5 min per machine, plus a loose
  global abuse brake (fixed window in D1).
- **No secrets in the repo**: `ADMIN_TOKEN` is a Worker secret
  (`wrangler secret put ADMIN_TOKEN`). Never committed, never logged.

## Deploy (free tier, no credit card)

```bash
cd license-server
npm install

# 1. Create the D1 database and copy its database_id into wrangler.toml
npx wrangler d1 create talus-licenses

# 2. Apply the schema (remote)
npx wrangler d1 execute talus-licenses --remote --file=schema.sql

# 3. Set the admin secret
npx wrangler secret put ADMIN_TOKEN

# 4. Deploy
npx wrangler deploy
```

The worker URL is printed at the end of `wrangler deploy`
(e.g. `https://talus-license-server.<account>.workers.dev`). That URL is the
default activation server baked into the Talus binary
(`activation_server_url()` in `process-monitor/src/license.rs`); users can
override it with `TALUS_LICENSE_SERVER`.

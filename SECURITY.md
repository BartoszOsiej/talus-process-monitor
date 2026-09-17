# Security Policy — Talus Process Monitor

> Enterprise-grade vulnerability disclosure and security response policy.

---

## Supported Versions

| Version | Supported | Notes |
|---|---|---|
| 0.7.x (latest) | ✅ | Active development, security patches |
| 0.6.x | ⚠️ | Security fixes only (EOL: 2027-06-30) |
| < 0.6.0 | ❌ | End of life — upgrade recommended |

## Scope

This policy covers the **talus-process-monitor** repository and all official artifacts:

- Rust source code (`process-monitor/`, `process-monitor-ebpf/`)
- C eBPF programs (`c-ebpf/`)
- Go components (`go-agent/`, `go-web/`)
- Tauri desktop app (`talus-tauri/`)
- Docker images published to `ghcr.io`
- Kubernetes manifests (`k8s/`)
- Published binaries and release artifacts

### Out of Scope

- Third-party dependencies (report upstream, then to us)
- Social engineering attacks
- Physical attacks against infrastructure

---

## Reporting a Vulnerability

### ⚠️ Do NOT open a public issue for security vulnerabilities.

Instead, use one of these **private** channels:

| Channel | Best For | Response Time |
|---|---|---|
| **[GitHub Security Advisories](https://github.com/BartoszOsiej/talus-process-monitor/security/advisories/new)** | All vulnerabilities | Primary channel |
| **Email: thethreadcalls@outlook.com** | Sensitive/critical issues | Backup channel |

### What to Include

When reporting, please provide:

1. **Vulnerability type** (e.g., buffer overflow, privilege escalation, RCE)
2. **Affected component** (eBPF, monitor core, TUI, web server, FFI)
3. **Attack vector** (local, network, adjacent)
4. **Reproduction steps** (POC code, logs, crash output)
5. **Impact assessment** (what an attacker could achieve)
6. **Suggested fix** (if you have one)

---

## Response Timeline

| Phase | SLA | Description |
|---|---|---|
| **Acknowledgment** | 48 hours | Confirm receipt, assign tracking ID |
| **Initial Assessment** | 5 business days | Severity classification, triage |
| **Detailed Analysis** | 15 business days | Root cause analysis, fix development |
| **Patch Release** | 30 business days | Security patch shipped |
| **Disclosure** | 45 business days | Coordinated disclosure after patch |

### Severity Classification

| CVSS Score | Severity | Response SLA | Examples |
|---|---|---|---|
| 9.0–10.0 | **Critical** | 48h acknowledgment, 7d fix | Remote code execution, kernel exploit, privilege escalation |
| 7.0–8.9 | **High** | 48h acknowledgment, 14d fix | Memory corruption, authentication bypass |
| 4.0–6.9 | **Medium** | 1 week acknowledgment, 30d fix | Information disclosure, denial of service |
| 0.1–3.9 | **Low** | 2 weeks acknowledgment, 90d fix | Minor information leak, edge-case DoS |

---

## Security Measures

### Supply Chain Security (Level 1–2 ✅)

| Measure | Status | Description |
|---|---|---|
| License compliance | ✅ Active | `cargo-deny` blocks forbidden licenses |
| Advisory audit | ✅ Active | `cargo-deny` blocks known vulnerabilities |
| SBOM generation | ✅ Active | CycloneDX SBOM attached to every release |
| Dependency pinning | ✅ Active | Cargo.lock committed, Dependabot with cooldown |
| Secret scanning | ✅ Active | gitleaks in CI pipeline |
| Binary signing | ✅ Active | Sigstore cosign keyless OIDC signing |
| SLSA provenance | ✅ Active | SLSA Level 2 provenance for all releases |
| Build attestation | ✅ Active | GitHub artifact attestation |

### Runtime Security

| Measure | Description |
|---|---|
| eBPF verifier safety | All kernel programs pass BPF verifier — no unsafe dereferences |
| Privilege model | Requires `CAP_BPF`/`CAP_SYS_ADMIN` — no ambient capability escalation |
| Process isolation | Each tracked PID has isolated sliding window state |
| Input validation | All userspace pointers read via `bpf_probe_read_user` — no TOCTOU |
| Memory safety | Rust ownership model for userspace; `#![no_std]` for kernel |
| Binary hardening | Full LTO, `panic = "abort"`, stripped symbols |

### Build Reproducibility

| Aspect | Detail |
|---|---|
| Pinned toolchain | CI uses specific commit hashes for all actions |
| Deterministic output | `codegen-units = 1`, `strip = "symbols"` |
| Lock file | `Cargo.lock` committed — identical dependency resolution |
| BPF profile | `lto = false`, `opt-level = 2` — avoids LLVM intrinsics that break determinism |

---

## Security Advisories

Published security advisories are available at:
- [GitHub Security Advisories](https://github.com/BartoszOsiej/talus-process-monitor/security/advisories)

### Advisory Format

Each advisory includes:
- CVE identifier (if applicable)
- Affected versions
- Fixed version
- CVSS score and vector
- Remediation instructions

---

## License & Key Security

Talus ships a commercial licensing system (Ed25519-signed keys + online
activation). This section documents its trust model and the owner-side key
management runbook.

### Trust Model

| Component | Trust anchor |
|---|---|
| Talus binary | Ed25519 **public** key embedded at compile time (`PUBLIC_KEY_BYTES` in `process-monitor/src/license.rs`); compile-time XOR checksum (`KEY_CHECKSUM`) detects binary key tampering |
| License keys | `base64(payload).base64(Ed25519 signature)` — unforgeable without the private key |
| Activation server | Holds the **public** key only; verifies every signature, enforces expiry, revocation and seat limits in D1 (`license-server/`) |
| Seat control | Authoritative server-side: `max_seats` enforced at activation; same-machine re-activation is idempotent; deactivation requires the activation token |
| Local cache | `~/.config/talus/license.dat` — XOR-obfuscated (tamper-resistance, NOT confidentiality) and re-verified against the signed key on every load; any divergence from the signed payload invalidates the cache |
| Trial marker | SHA-256 integrity tag bound to binary + machine (`compute_trial_checksum`) — edited or copied trial files are rejected |
| Downgrade protection | Activating a Community key over a cached Enterprise license is refused until deactivation |
| Offline grace | 30 days; verified licences keep working without network, expiry is still enforced |

**Explicit limits (documented, by design):** an attacker with full control of
the binary can patch out license checks entirely — signed keys protect the
vendor's *distribution* channel, not a modified client. The local trial
marker resists casual tampering, not a determined reverse engineer.

### Key Storage & Backup

- Private signing key lives **outside any repository**:
  `~/.secrets/talus/license-keys/signing_key.json` (0700 dir / 0600 file).
  `talus-keygen` refuses to store keys inside the repo and enforces
  owner-only permissions.
- Backup: one encrypted copy (e.g. `age`/`gpg` to a USB drive or password
  manager attachment). If the private key is lost, no new licenses can be
  signed — recovery means key rotation (below) and re-issuing every key.
- The admin token for the activation server:
  `~/.secrets/talus/admin_token` (0600); deployed as a Workers secret.
- Nothing secret is committed: `.gitignore` blocks `license-keys/`,
  `signing_key*`, `*.pem`, `.dev.vars`, `.env`.

### Key Rotation Runbook

Rotate when: the private key may have leaked, the machine holding keys is
compromised, or as a periodic precaution.

1. `cd license-keygen && cargo build --release`
2. Generate a new keypair **outside the repo**:
   `TALUS_KEYGEN_DIR=~/.secrets/talus/license-keys ./license-keygen/target/release/talus-keygen init`
   (move the old `signing_key.json` aside first; it refuses to overwrite).
3. Update `PUBLIC_KEY_BYTES` in `process-monitor/src/license.rs` with the new
   public key (`talus-keygen export-public` prints it) — `KEY_CHECKSUM` is
   derived automatically.
4. Update `LICENSE_PUBLIC_KEY_HEX` in `license-server/wrangler.toml` and
   `npx wrangler deploy`.
5. Release a new binary build. All old keys verify against the old binary
   only; **all previously issued licenses are void** on new builds.
6. Re-issue keys for paying customers free of charge
   (`docs/issue-first-license.md`).
7. Commit the rotation with a clear message (key material never appears in
   the commit).

### License Leak Response

If a license key is posted publicly or shared beyond its seats:

1. `./scripts/revoke-license.sh <LICENSE_ID> "key leak"` — blocks all future
   activations and frees all seats.
2. Re-issue a fresh key to the legitimate customer.
3. Never publish the revoked key or ID.
4. If leak volume suggests the *signing key* is compromised (validly signed
   keys appearing without an issuance record), run the full rotation runbook.

### Reporting a License/Server Vulnerability

Issues in the activation server, keygen, or license verification logic are in
scope — report via the channels above.

| Role | Contact |
|---|---|
| Security Lead | Bartosz Osiej |
| Email | thethreadcalls@outlook.com |
| GitHub | [@BartoszOsiej](https://github.com/BartoszOsiej) |
| Advisory Portal | [GitHub Security](https://github.com/BartoszOsiej/talus-process-monitor/security) |

---

## Recognition

We value responsible disclosure. Security researchers who report valid vulnerabilities will be:

1. **Acknowledged** in the security advisory (unless anonymity is requested)
2. **Credited** in the CHANGELOG
3. **Listed** in our Security Hall of Fame (below)

### Hall of Fame

| Researcher | Date | Vulnerability | Severity |
|---|---|---|---|
| — | — | *No reported vulnerabilities yet* | — |

---

## Compliance

This security policy aligns with:

- **NIST SP 800-40** — Guide to Enterprise Patch Management
- **CERT Coordination Center** — Vulnerability Reporting Guidelines
- **ISO 27001:2022** — A.8.8 Technical vulnerability management
- **SOC2 Trust Service Criteria** — CC6.1 Logical access controls

---

*Policy version: 2.1 · Effective: 2026-09-17 · Review: 2027-03-17*

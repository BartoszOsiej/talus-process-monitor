-- ── Talus license server — D1 schema ──────────────────────────────────────
-- Applied with: npx wrangler d1 execute talus-licenses --remote --file=schema.sql

-- Issued licenses. Auto-registered on first activation ("first-seen"),
-- so the server becomes the source of truth for revocation from the first
-- activation onwards. Pre-activation revocation is handled by the
-- `revocations` table below.
CREATE TABLE IF NOT EXISTS licenses (
  license_id  TEXT PRIMARY KEY,
  tier        TEXT NOT NULL,
  org         TEXT,
  features    TEXT,
  max_nodes   INTEGER NOT NULL DEFAULT 0,
  max_seats   INTEGER NOT NULL DEFAULT 1,
  expires_at  TEXT,
  revoked     INTEGER NOT NULL DEFAULT 0,
  issued_at   TEXT NOT NULL
);

-- One row per (license, machine) activation. Re-activating the same machine
-- is idempotent: the existing row and token are returned unchanged.
CREATE TABLE IF NOT EXISTS activations (
  license_id   TEXT NOT NULL,
  machine_id   TEXT NOT NULL,
  hostname     TEXT,
  token        TEXT NOT NULL,
  activated_at TEXT NOT NULL,
  seat_index   INTEGER NOT NULL,
  last_seen    TEXT,
  PRIMARY KEY (license_id, machine_id)
);

-- Explicit pre-activation revocations (license IDs killed before they were
-- ever seen by this server — e.g. leaked keys, refunded purchases).
CREATE TABLE IF NOT EXISTS revocations (
  license_id  TEXT PRIMARY KEY,
  reason      TEXT,
  revoked_at  TEXT NOT NULL
);

-- Fixed-window rate limiting (per machine + global). Rows are pruned by the
-- worker on each check, so this stays tiny.
CREATE TABLE IF NOT EXISTS rate_events (
  bucket TEXT NOT NULL,
  ts     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_events_ts ON rate_events (ts);

CREATE INDEX IF NOT EXISTS idx_activations_license ON activations (license_id);

-- ── Admin panel (worker-hosted UI, TOTP login) ─────────────────────────────

-- Web sessions for /admin. Only the SHA-256 hash of the session token is
-- stored, so a D1 snapshot cannot be replayed as a session. Expired rows are
-- pruned on each login.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

-- TOTP replay protection: a time-step counter that was already consumed by a
-- successful login can never be accepted again (within its validity window).
CREATE TABLE IF NOT EXISTS totp_used (
  counter INTEGER PRIMARY KEY,
  used_at TEXT NOT NULL
);

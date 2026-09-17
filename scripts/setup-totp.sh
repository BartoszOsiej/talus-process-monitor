#!/usr/bin/env bash
# ── Talus License Server — TOTP setup (owner-only, one-time) ───────────────
#
# Generates a base32 TOTP secret (Google Authenticator compatible), stores it
# OUTSIDE the repo in ~/.secrets/talus/ and uploads it to the worker as the
# TOTP_SECRET wrangler secret. Then shows the otpauth:// URI and a QR code in
# the terminal — scan it with Google Authenticator. The secret is displayed
# exactly once; rotate with --rotate (invalidates all previous codes).
#
# Usage:
#   ./setup-totp.sh              # first setup
#   ./setup-totp.sh --upload     # re-upload an existing secret to the worker
#   ./setup-totp.sh --rotate     # replace the secret later
#
# Requirements: qrencode (terminal QR), wrangler (CLOUDFLARE_API_TOKEN set —
# the script auto-loads it from ~/.cloudflare_token when present).

set -euo pipefail

# Wrangler needs an API token in non-interactive shells; load the owner's
# token from the standard location unless it is already in the environment.
if [[ -z "${CLOUDFLARE_API_TOKEN:-}" && -s "${CLOUDFLARE_TOKEN_FILE:-$HOME/.cloudflare_token}" ]]; then
  export CLOUDFLARE_API_TOKEN="$(tr -d '[:space:]' < "${CLOUDFLARE_TOKEN_FILE:-$HOME/.cloudflare_token}")"
fi

SECRETS_DIR="${TALUS_SECRETS_DIR:-$HOME/.secrets/talus}"
SECRET_FILE="$SECRETS_DIR/totp_secret"
ADMIN_TOKEN_FILE="$SECRETS_DIR/admin_token"
LABEL="${TALUS_TOTP_LABEL:-Talus License Admin}"
WRANGLER_DIR="$(cd "$(dirname "$0")/../license-server" && pwd)"

MODE="${1:-}"
if [[ "$MODE" == "--rotate" ]]; then
  rm -f "$SECRET_FILE"
fi

# ── Generate the secret if it does not exist ────────────────────────────────
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

need_upload=1
if [[ "$MODE" == "--upload" ]]; then
  # Re-upload the existing secret (e.g. the first run generated it locally
  # but the wrangler upload failed).
  need_upload=1
elif [[ -s "$SECRET_FILE" ]]; then
  echo "TOTP secret already exists at $SECRET_FILE — nothing to generate."
  echo "Use --rotate to replace it (invalidates all previous codes) or"
  echo "--upload to (re-)upload the existing secret to the worker."
  need_upload=0
else
  # 20 random bytes = 160-bit seed, the RFC 6238 recommendation.
  SECRET_BASE32="$(openssl rand -hex 20 | xxd -r -p | base32 | tr -d '=' | tr -d '\n')"
  printf '%s' "$SECRET_BASE32" > "$SECRET_FILE"
  chmod 600 "$SECRET_FILE"
  echo "Generated new TOTP secret → $SECRET_FILE (0600, outside the repo)."
fi

SECRET_BASE32="$(cat "$SECRET_FILE")"

# ── Upload to the worker as a wrangler secret (never printed) ──────────────
if [[ "$need_upload" == "1" ]]; then
  echo "Uploading TOTP_SECRET to the worker…"
  (cd "$WRANGLER_DIR" && npx wrangler secret put TOTP_SECRET < "$SECRET_FILE")
fi

# ── Show the otpauth URI + QR exactly once ─────────────────────────────────
ACCOUNT="${TALUS_TOTP_ACCOUNT:-talus-admin}"
OTPURI="otpauth://totp/${LABEL// /%20}:${ACCOUNT}?secret=${SECRET_BASE32}&issuer=${LABEL// /%20}&algorithm=SHA1&digits=6&period=30"

echo
echo "════════════════════════════════════════════════════════════════"
echo "Scan this QR with Google Authenticator (shown ONCE):"
echo
qrencode -t ANSIUTF8 "$OTPURI"
echo
echo "otpauth URI (if you prefer manual entry):"
echo "  $OTPURI"
echo
echo "Secret (base32, for manual entry): $SECRET_BASE32"
echo "════════════════════════════════════════════════════════════════"
echo
echo "Admin login needs BOTH factors:"
echo "  1. auth_code — the ADMIN_TOKEN value ($( [[ -s "$ADMIN_TOKEN_FILE" ]] && echo "$ADMIN_TOKEN_FILE" || echo 'check your secret store' ))"
echo "  2. totp      — the 6-digit code from Google Authenticator"
echo
echo "Panel: https://talus-license-server.metaforicmail.workers.dev/admin"

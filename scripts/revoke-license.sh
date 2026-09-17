#!/usr/bin/env bash
# ── revoke-license.sh — revoke a license on the activation server ─────────
# Usage: scripts/revoke-license.sh TALUS-XXXX-XXXX-XXXX [reason]
#
# Requires: ADMIN_TOKEN (from ~/.secrets/talus/admin_token by default)
#           TALUS_LICENSE_SERVER_URL (default: production worker)
#
# Revocation blocks all future activations and frees all existing seats.

set -euo pipefail

LICENSE_ID="${1:?usage: revoke-license.sh TALUS-XXXX-XXXX-XXXX [reason]}"
REASON="${2:-revoked by owner}"
SERVER="${TALUS_LICENSE_SERVER_URL:-https://talus-license-server.metaforicmail.workers.dev}"
TOKEN_FILE="${TALUS_ADMIN_TOKEN_FILE:-$HOME/.secrets/talus/admin_token}"

if [[ ! -s "$TOKEN_FILE" ]]; then
  echo "error: admin token not found at $TOKEN_FILE" >&2
  exit 1
fi

ADMIN_TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE")

HTTP_CODE=$(curl -sS -o /tmp/talus-revoke-response.json -w "%{http_code}" \
  -X POST "$SERVER/api/v1/admin/revoke" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d "{\"license_id\":\"$LICENSE_ID\",\"reason\":$(printf '%s' "$REASON" | jq -Rs .)}")

BODY=$(cat /tmp/talus-revoke-response.json)
rm -f /tmp/talus-revoke-response.json

if [[ "$HTTP_CODE" == "200" ]]; then
  echo "✓ License $LICENSE_ID revoked ($SERVER)"
else
  echo "✗ Revocation failed (HTTP $HTTP_CODE): $BODY" >&2
  exit 1
fi

#!/usr/bin/env bash
# ── list-activations.sh — list activations for a license ──────────────────
# Usage: scripts/list-activations.sh TALUS-XXXX-XXXX-XXXX
#
# Requires: ADMIN_TOKEN (from ~/.secrets/talus/admin_token by default)

set -euo pipefail

LICENSE_ID="${1:?usage: list-activations.sh TALUS-XXXX-XXXX-XXXX}"
SERVER="${TALUS_LICENSE_SERVER_URL:-https://talus-license-server.metaforicmail.workers.dev}"
TOKEN_FILE="${TALUS_ADMIN_TOKEN_FILE:-$HOME/.secrets/talus/admin_token}"

if [[ ! -s "$TOKEN_FILE" ]]; then
  echo "error: admin token not found at $TOKEN_FILE" >&2
  exit 1
fi

ADMIN_TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE")

curl -sS -X POST "$SERVER/api/v1/admin/activations" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d "{\"license_id\":\"$LICENSE_ID\"}" | jq .

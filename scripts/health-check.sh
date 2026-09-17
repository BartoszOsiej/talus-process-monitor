#!/usr/bin/env bash
# ── health-check.sh — check the activation server status ──────────────────
# Usage: scripts/health-check.sh [server-url]

set -euo pipefail

SERVER="${1:-${TALUS_LICENSE_SERVER_URL:-https://talus-license-server.metaforicmail.workers.dev}}"

HTTP_CODE=$(curl -sS -o /tmp/talus-health.json -w "%{http_code}" "$SERVER/api/v1/health")
BODY=$(cat /tmp/talus-health.json)
rm -f /tmp/talus-health.json

if [[ "$HTTP_CODE" == "200" ]]; then
  echo "✓ $SERVER is healthy"
  echo "$BODY" | jq .
else
  echo "✗ $SERVER unhealthy (HTTP $HTTP_CODE): $BODY" >&2
  exit 1
fi

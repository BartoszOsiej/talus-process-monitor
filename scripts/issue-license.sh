#!/usr/bin/env bash
# ── issue-license.sh — issue a signed Talus license ───────────────────────
# Usage:
#   scripts/issue-license.sh --org "Acme Corp" [--tier enterprise] \
#       [--expires 2027-12-31] [--seats 5] [--max-nodes 0] [--license-id TALUS-...]
#
# The signing key must exist at ~/.secrets/talus/license-keys/signing_key.json
# (see docs/issue-first-license.md). No secrets are ever printed by this script
# beyond the license key itself, which is delivered to the customer.

set -euo pipefail

KEYGEN="${TALUS_KEYGEN_BIN:-license-keygen/target/release/talus-keygen}"
KEYS_DIR="${TALUS_KEYGEN_DIR:-$HOME/.secrets/talus/license-keys}"

if [[ ! -x "$KEYGEN" ]]; then
  echo "error: keygen binary not found at $KEYGEN" >&2
  echo "build it with: (cd license-keygen && cargo build --release)" >&2
  exit 1
fi
if [[ ! -f "$KEYS_DIR/signing_key.json" ]]; then
  echo "error: no signing key at $KEYS_DIR/signing_key.json" >&2
  echo "create one with: TALUS_KEYGEN_DIR=\"$KEYS_DIR\" $KEYGEN init" >&2
  exit 1
fi

# ── Parse arguments ───────────────────────────────────────────────────────
ORG="" TIER="enterprise" EXPIRES="" SEATS="" MAX_NODES="" LICENSE_ID="" FEATURES=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --org) ORG="$2"; shift 2 ;;
    --tier) TIER="$2"; shift 2 ;;
    --expires) EXPIRES="$2"; shift 2 ;;
    --seats) SEATS="$2"; shift 2 ;;
    --max-nodes) MAX_NODES="$2"; shift 2 ;;
    --license-id) LICENSE_ID="$2"; shift 2 ;;
    --features) FEATURES="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

ARGS=(issue --tier "$TIER")
[[ -n "$ORG" ]] && ARGS+=(--organization "$ORG")
[[ -n "$EXPIRES" ]] && ARGS+=(--expires "$EXPIRES")
[[ -n "$SEATS" ]] && ARGS+=(--seats "$SEATS")
[[ -n "$MAX_NODES" ]] && ARGS+=(--max-nodes "$MAX_NODES")
[[ -n "$LICENSE_ID" ]] && ARGS+=(--license-id "$LICENSE_ID")
[[ -n "$FEATURES" ]] && ARGS+=(--features "$FEATURES")

export TALUS_KEYGEN_DIR="$KEYS_DIR"
exec "$KEYGEN" "${ARGS[@]}"

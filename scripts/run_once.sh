#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load local env (uncommitted)
if [[ -f "$ROOT_DIR/assets/.env" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ROOT_DIR/assets/.env"
  set +a
fi

WORKDIR="${HOMESIGSEC_WORKDIR:-$ROOT_DIR/output}"
mkdir -p "$WORKDIR/state"

# Stub: prove wiring without leaking secrets
python3 "$ROOT_DIR/scripts/poll_kismet_stub.py" \
  --out "$WORKDIR/state/kismet_stub.json"

echo "[homesigsec] wrote: $WORKDIR/state/kismet_stub.json"

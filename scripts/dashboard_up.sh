#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "$ROOT_DIR/assets/.env" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ROOT_DIR/assets/.env"
  set +a
fi

# Resolve workdir. If the env file still has the placeholder path, fall back to repo-local output.
WORKDIR="${HOMESIGSEC_WORKDIR:-$ROOT_DIR/output}"
if [[ "$WORKDIR" == /ABS/* ]]; then
  WORKDIR="$ROOT_DIR/output"
  export HOMESIGSEC_WORKDIR="$WORKDIR"
fi

# Generate current dashboard content first
"$ROOT_DIR/scripts/generate_dashboard.sh" "$(date +%F)"

cd "$ROOT_DIR/assets"

# Use a stable project name to avoid orphan warnings across repos.
# Export env vars so they override any placeholder values in assets/.env
export HOMESIGSEC_WORKDIR="$WORKDIR"
docker compose -p homesigsec-dashboard -f dashboard-compose.yml up -d --build

echo "[homesigsec] dashboard services up (nginx published on $HOMESIGSEC_LAN_BIND and $HOMESIGSEC_TS_BIND)"

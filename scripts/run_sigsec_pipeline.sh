#!/usr/bin/env bash
# HomeSigSec unified pipeline: poll + fingerprint + dashboard
# Sources all env files once, then runs all steps in the same shell.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Source environment files
if [[ -f "$ROOT_DIR/assets/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT_DIR/assets/.env"
  set +a
fi

if [[ -f "$HOME/.openclaw/credentials/adguard.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$HOME/.openclaw/credentials/adguard.env"
  set +a
fi

WORKDIR="${HOMESIGSEC_WORKDIR:-$ROOT_DIR/output}"
# If the env file still has the placeholder path, fall back to repo-local output.
if [[ "$WORKDIR" == /ABS/* ]]; then
  WORKDIR="$ROOT_DIR/output"
fi

export HOMESIGSEC_WORKDIR="$WORKDIR"

# Parse args
POLL_SINCE="${1:--3600}"
MIN_PACKETS="${2:-50}"
DAY="${3:-$(date +%F)}"

echo "=== HomeSigSec Pipeline ==="
echo "WORKDIR: $WORKDIR"
echo "KISMET_URL: ${KISMET_URL:-NOT SET}"
echo "POLL_SINCE: $POLL_SINCE"
echo ""

# Step 1: Poll Kismet
echo "--- Step 1: Poll Kismet ---"
python3 "$ROOT_DIR/scripts/collect_poll.py" \
  --workdir "$WORKDIR" \
  --views "phydot11_accesspoints,phy-IEEE802.11" \
  --since "$POLL_SINCE"
echo ""

# Step 2: Fingerprinting
echo "--- Step 2: Fingerprinting ---"
# Exit code 2 = drift detected (not a failure, just informational)
set +e
python3 "$ROOT_DIR/scripts/fingerprint_devices.py" \
  --workdir "$WORKDIR" \
  --min-packets "$MIN_PACKETS"
FP_EXIT=$?
set -e

if [[ $FP_EXIT -eq 2 ]]; then
  echo "[info] Fingerprint drift detected (will be shown in dashboard)"
elif [[ $FP_EXIT -ne 0 ]]; then
  echo "[error] Fingerprinting failed with exit code $FP_EXIT"
  exit $FP_EXIT
fi
echo ""

# Step 3: Dashboard
echo "--- Step 3: Dashboard ---"
"$ROOT_DIR/scripts/generate_dashboard.sh" "$DAY"
echo ""

echo "=== Pipeline Complete ==="

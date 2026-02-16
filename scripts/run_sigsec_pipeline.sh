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

if [[ -f "$HOME/.openclaw/credentials/kismet-pi.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$HOME/.openclaw/credentials/kismet-pi.env"
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

# --- Kismet Health Check & Auto-Repair ---
check_kismet() {
  local url="${KISMET_URL:-}"
  if [[ -z "$url" ]]; then
    echo "[warn] KISMET_URL not set, skipping health check"
    return 0
  fi
  
  # Try to reach Kismet status endpoint
  if curl -sf --max-time 10 -H "KISMET: ${KISMET_API_TOKEN:-}" "$url/system/status.json" >/dev/null 2>&1; then
    echo "[ok] Kismet responding"
    return 0
  else
    echo "[warn] Kismet not responding at $url"
    return 1
  fi
}

repair_kismet() {
  local host="${KISMET_PI_HOST:-}"
  local user="${KISMET_PI_USER:-}"
  local key="${KISMET_PI_KEY:-}"
  
  if [[ -z "$host" || -z "$user" ]]; then
    echo "[error] KISMET_PI_HOST or KISMET_PI_USER not set, cannot repair"
    return 1
  fi
  
  echo "[info] Attempting to restart Kismet on $host..."
  
  local ssh_opts="-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=yes"
  if [[ -n "$key" && -f "$key" ]]; then
    ssh_opts="$ssh_opts -i $key"
  fi
  
  # Try to restart kismet service
  # shellcheck disable=SC2086
  if ssh $ssh_opts "${user}@${host}" "sudo systemctl restart kismet" 2>/dev/null; then
    echo "[ok] Kismet restart command sent"
    sleep 5  # Give it time to start
    return 0
  else
    echo "[error] Failed to SSH and restart Kismet"
    return 1
  fi
}

# Check Kismet health, attempt repair if down
if ! check_kismet; then
  if repair_kismet; then
    # Verify it came back
    sleep 5
    if check_kismet; then
      echo "[ok] Kismet recovered after restart"
    else
      echo "[error] Kismet still not responding after restart"
      exit 1
    fi
  else
    echo "[error] Could not repair Kismet"
    exit 1
  fi
fi
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

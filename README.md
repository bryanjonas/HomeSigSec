# HomeSigSec

HomeSigSec is a home **signal-security / RF-environment monitoring** pipeline built around **Kismet**.

It is designed to:
- Pull Kismet telemetry from a dedicated sensor host (Wi‑Fi / Bluetooth / SDR)
- Store short-term raw snapshots for forensics
- Store long-term derived data for alerting + dashboards
- Surface simple, actionable panels (rogue SSIDs/BSSIDs, device SSID monitoring, unknown devices)
- Cross-validate detections against UniFi and AdGuard to eliminate false positives

This repository intentionally contains **no secrets** and must not contain identifying network details.

---

## Privacy & Security Model

**Do not commit** any:
- SSIDs, MAC addresses, BSSIDs, Bluetooth addresses
- IP addresses, hostnames, private URLs
- Usernames, passwords, API keys/tokens
- GPS coordinates or location info
- Raw Kismet logs or JSON payloads

Configuration is provided via **uncommitted** `.env` files and local-only state under `output/`.

See `references/security-policy.md` for the full policy.

---

## Repository Layout

```
assets/
├── .env.example              # Safe placeholders (copy to .env)
├── dashboard-compose.yml     # Dashboard container stack
├── dashboard-nginx.conf      # Nginx config
├── dashboard-api/            # Feedback API server
├── collector/                # Eventbus collector container
└── data/
    └── oui.json              # IEEE OUI database (38,899 entries)

scripts/
├── run_sigsec_pipeline.sh    # Unified pipeline (poll + fingerprint + dashboard)
├── collect_poll.py           # Poll Kismet views → sqlite
├── fingerprint_devices.py    # Generate device fingerprints
├── generate_dashboard.sh     # Generate HTML dashboard
├── unifi_client.py           # UniFi Controller API client
├── kismet_client.py          # Kismet API client
├── db.py                     # Database schema and helpers
├── dashboard_up.sh           # Start dashboard containers
└── run_poll_once.sh          # Single poll run

references/                   # Design docs and API notes
output/                       # Runtime state (gitignored)
```

---

## Setup

### 1. Create Environment File

```bash
cp assets/.env.example assets/.env
```

Edit `assets/.env`:
```bash
KISMET_URL="http://kismet-host:2501"
KISMET_API_TOKEN="your-api-token"  # or KISMET_USER/KISMET_PASS
HOMESIGSEC_WORKDIR="/absolute/path/to/output"
HOMESIGSEC_BIND="192.168.1.x:8090"  # LAN/Tailscale only
```

### 2. Configure Credentials

**UniFi Controller** (`~/.openclaw/credentials/unifi.env`):
```
UNIFI_HOST="unifi.lan:8443"
UNIFI_USER="username"
UNIFI_PASS="password"
```

**AdGuard Home** (`~/.openclaw/credentials/adguard.env`):
```bash
ADGUARD_URL="http://adguard-host:port"
ADGUARD_USER="admin"
ADGUARD_PASS="password"
```

### 3. Create Watchlists

Create these under `$HOMESIGSEC_WORKDIR/state/`:

**ssid_approved_bssids.local.json** (Rogue AP monitoring):
```json
{
  "My Network": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
}
```

**device_allowed_ssids.local.json** (Device SSID monitoring):
```json
{
  "aa:bb:cc:dd:ee:ff": {"label": "My Phone", "allowed_ssids": ["My Network"]}
}
```

See `references/watchlists-format.md` for full format.

---

## Running

### Unified Pipeline (Recommended)

Run poll + fingerprint + dashboard generation:

```bash
./scripts/run_sigsec_pipeline.sh
```

This is designed for cron (e.g., every 15 minutes).

### Individual Components

**Poll Kismet once:**
```bash
./scripts/run_poll_once.sh
```

**Generate fingerprints:**
```bash
python3 scripts/fingerprint_devices.py --workdir "$HOMESIGSEC_WORKDIR" --min-packets 50
```

**Regenerate dashboard:**
```bash
./scripts/generate_dashboard.sh
```

### Start Dashboard

```bash
./scripts/dashboard_up.sh
```

Access at `http://<HOMESIGSEC_BIND>/`

---

## Dashboard Panels

### Rogue AP Monitoring
- Watches configured SSIDs for unknown BSSIDs
- Alerts when unapproved access points appear

### Select Device SSID Monitoring
- Tracks specific device MACs
- Alerts when devices connect to unauthorized SSIDs
- Shows fingerprint verification status

### Unknown Connected Devices
- Shows devices on your network not in known devices list
- **Cross-validated**: Must be in UniFi runtime OR AdGuard to confirm real connection
- Eliminates Kismet false positives from neighbor network misattribution

Dashboard metrics:
- **UniFi Connected**: Currently connected clients
- **UniFi Historical**: All-time known clients
- **AdGuard Clients**: DHCP/DNS active clients
- **Unknown**: Confirmed real + not in known devices

---

## Unknown Device Detection Logic

Devices are only flagged as "unknown" when ALL of:

1. **Kismet sees real traffic**
   - `packets_data > 0` (actual 802.11 data frames)
   - `datasize > 5000` bytes
   - `bytes/frame > 50` (filters NULL data frames used for power management)

2. **Cross-validated by authoritative source**
   - Device is in UniFi runtime (currently connected), OR
   - Device is in AdGuard (made DHCP/DNS requests)
   - If not in either → false positive from Kismet misattribution

3. **Not already known**
   - Not in UniFi historical clients
   - Not in AdGuard configured clients

This three-step validation eliminates false positives from neighbor devices on the same WiFi channel.

---

## Fingerprinting

Device fingerprinting creates behavioral baselines for watched devices:

```bash
python3 scripts/fingerprint_devices.py --workdir "$HOMESIGSEC_WORKDIR" --min-packets 50
```

Features captured:
- Packet timing patterns
- Signal strength characteristics
- Traffic volume profiles

Status indicators:
- ✓ **Verified**: Fingerprint matches baseline
- ⚠ **Drift**: Behavior changed from baseline
- ✗ **Insufficient**: Not enough data yet

---

## OUI Manufacturer Lookup

The dashboard includes manufacturer identification for MAC addresses using the IEEE OUI database (`assets/data/oui.json`, 38,899 entries).

---

## Alert Triage

Each alert supports:
- **Verdict**: Benign / Needs Review / Suspicious
- **Comments**: Notes explaining the observation
- **Dismiss**: Remove from active alerts

Feedback is stored server-side in `output/state/feedback.json`.

---

## Database

SQLite database at `$HOMESIGSEC_WORKDIR/state/homesigsec.sqlite`.

Key tables:
- `wifi_client_sightings`: Client device observations
- `wifi_ap_sightings`: Access point observations
- `device_fingerprints`: Stored fingerprints
- `fingerprint_device_status`: Per-device fingerprint status
- `alerts`: Generated alerts
- `eventbus_events`: Real-time Kismet events

See `references/database-design.md` for full schema.

---

## Cron Integration

Example cron job (every 15 minutes):

```bash
*/15 * * * * cd /path/to/HomeSigSec && ./scripts/run_sigsec_pipeline.sh >> /var/log/homesigsec.log 2>&1
```

The pipeline is designed to be quiet on success.

---

## Troubleshooting

**Dashboard not reachable:**
- Verify Docker is running: `docker ps`
- Check port binding: `ss -ltnp | grep <port>`
- Confirm `HOMESIGSEC_BIND` matches your access IP

**Kismet API errors:**
- Verify Kismet is running and accessible
- Test: `curl -H "KISMET: $KISMET_API_TOKEN" "$KISMET_URL/system/status.json"`

**No unknown devices showing:**
- This is correct if all Kismet sightings fail cross-validation
- Check UniFi runtime count (should show currently connected devices)
- Verify AdGuard credentials are working

**False positives were showing:**
- Older versions didn't cross-validate against UniFi/AdGuard
- Update to latest and clear the queue: `rm output/state/unknown_devices_queue.json`

---

## Safety Reminders

- Keep all identifiers in `output/` only (gitignored)
- Run `gitleaks detect` before pushing changes
- Use LAN/Tailscale binds; never expose dashboard publicly
- Credentials stay in `~/.openclaw/credentials/` (not in repo)

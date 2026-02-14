# HomeSigSec

HomeSigSec is a home **signal-security / RF-environment monitoring** pipeline built around **Kismet**.

It is designed to:
- pull Kismet telemetry from a dedicated sensor host (Wi‑Fi / Bluetooth / SDR)
- store short-term raw snapshots for forensics
- store long-term derived data for alerting + dashboards
- surface simple, actionable panels (rogue SSIDs/BSSIDs; selected device SSID monitoring)

This repository intentionally contains **no secrets** and must not contain identifying network details.

---

## Privacy & security model (important)

**Do not commit** any:
- SSIDs
- MAC addresses / BSSIDs / Bluetooth addresses
- IP addresses / hostnames / URLs that include private hostnames
- usernames, passwords, API keys/tokens, cookies
- GPS coordinates / precise location info
- raw Kismet logs / JSON payloads

Configuration is provided via **uncommitted** `.env` and local-only state under `output/`.

For the full policy, see:
- `references/security-policy.md`

---

## Repository layout

- `assets/`
  - `dashboard-compose.yml`, `dashboard-nginx.conf`: containerized dashboard
  - `dashboard-api/`: minimal API for feedback persistence
  - `collector/`: containerized Kismet eventbus collector
  - `.env.example`: safe placeholders (copy to `.env`, do not commit)
- `scripts/`
  - `collect_poll.py`: poll Kismet views → store raw + normalize into sqlite
  - `fingerprint_devices.py`: generate best-effort Wi‑Fi fingerprints for selected devices
  - `generate_dashboard.sh`: generate `output/www/index.html` + `status.json`
  - `dashboard_up.sh`: build + start dashboard containers
- `references/`: design notes, formats, research-backed API notes
- `output/` (**gitignored**): all runtime state

---

## Local-only files (not committed)

HomeSigSec expects certain runtime files under `$HOMESIGSEC_WORKDIR/state/`.
These contain private identifiers and must remain local:

- `ssid_approved_bssids.local.json`
  - watched SSIDs and approved BSSIDs (used by Rogue AP Monitoring)
- `device_allowed_ssids.local.json`
  - device MAC → allowed SSIDs (used by Select Device SSID Monitoring)
- `homesigsec.sqlite`
  - local sqlite database (derived, retained indefinitely)

Formats are documented here:
- `references/watchlists-format.md`

---

## Setup

### 1) Create your local env file

Copy the example:

```bash
cp assets/.env.example assets/.env
```

Edit `assets/.env` and set:
- `KISMET_URL` (sensor host URL)
- one of:
  - `KISMET_API_TOKEN` (preferred), or
  - `KISMET_USER` / `KISMET_PASS`
- `HOMESIGSEC_WORKDIR` (absolute path on this host)
- `HOMESIGSEC_BIND` (dashboard bind socket `IP:PORT`, LAN or Tailscale)

Important:
- `.env` must remain **uncommitted**.
- Use LAN/Tailscale binds; avoid public exposure.

### 2) Ensure watchlists exist (local-only)

Create these under `$HOMESIGSEC_WORKDIR/state/` (see formats in `references/watchlists-format.md`):
- `ssid_approved_bssids.local.json`
- `device_allowed_ssids.local.json`

---

## Run the collectors

### A) Poll-based collector (periodic snapshots)

This pulls Kismet views and stores:
- raw gz snapshots under `output/raw/YYYY-MM-DD/…`
- normalized rows into sqlite

Run once:

```bash
./scripts/run_poll_once.sh
```

This currently polls:
- `phydot11_accesspoints`
- `phy-IEEE802.11`

### B) Eventbus collector (recommended for real-time signals)

The eventbus collector subscribes to Kismet websocket topics and stores:
- raw gz event records under `output/raw-eventbus/YYYY-MM-DD/…`
- normalized rows into sqlite table `eventbus_events`

It runs continuously as part of the dashboard docker compose stack.

---

## Fingerprinting

Generate/update fingerprints for devices allowed on a specific SSID (currently used as a baseline for later matching):

```bash
python3 scripts/fingerprint_devices.py --workdir "$HOMESIGSEC_WORKDIR" --min-packets 50
```

Outputs:
- stored in sqlite table `device_fingerprints`
- per-device status in `fingerprint_device_status`
- run history in `fingerprint_runs`

Dashboard shows fingerprint status inside the **Select Device SSID Monitoring** panel.

---

## Dashboard

### Start (build + run containers)

```bash
./scripts/dashboard_up.sh
```

The dashboard is served by nginx from:
- `http://<HOMESIGSEC_BIND>/`

Panels:
- **Rogue AP Monitoring**: watched SSID → seen BSSIDs, alerts only when unapproved BSSIDs appear
- **Select Device SSID Monitoring**: watched device MACs and SSID violations (plus fingerprint status)

### Regenerate dashboard content

The HTML is generated (server-side) into `output/www/`. Re-run:

```bash
./scripts/generate_dashboard.sh
```

---

## Roadmap (next)

- Wire stronger “attempt to connect” signals via eventbus topics (association/authentication, WPA handshakes, real data frames)
- Use MyHomeNetwork traffic as supervised anchors to continuously refine matching weights
- Add BT/TPMS/RF panels and retention controls

Design notes:
- `references/management_frame_fingerprinting_system.md`
- `references/database-design.md`

---

## Troubleshooting

- Dashboard not reachable:
  - confirm docker published port matches `HOMESIGSEC_BIND`
  - verify `ss -ltnp | grep <port>` on the host
- Kismet API errors:
  - verify credentials and that Kismet is running
  - test: `curl <KISMET_URL>/system/user_status.json` (auth required depending on version)

---

## Safety reminders

- Keep all identifiers in `output/` only.
- Run `gitleaks detect` before pushing changes that touch docs/examples.

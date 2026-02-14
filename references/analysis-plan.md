# HomeSigSec analysis plan (initial)

This plan is intended to guide implementation of a HomeSigSec pipeline which pulls from a remote Kismet instance and produces a local dashboard + alerting.

This document intentionally avoids hardcoding any identifying details. All watch lists are local-only.

## High-level architecture

### Components

1) **Collector (this host)**
- Periodically polls Kismet REST endpoints (or subscribes via websocket later)
- Writes raw snapshots + normalized records to a **local database under `output/`**

2) **Analyzer (container, on-demand)**
- Runs periodic analysis jobs against the local DB
- Produces:
  - `output/state/<day>.digest.json`
  - dashboard content under `output/www/`

3) **Dashboard (container, long-running)**
- Serves static HTML + a small API for feedback/state (pattern borrowed from HomeNetSec)
- Binds only to LAN/Tailscale (config via uncommitted env)

### Why polling first
Kismet provides websocket monitoring (`/devices/views/{VIEWID}/monitor.ws`), but polling is simpler and more robust for a first version. We can move to websocket streaming once the schema and storage are stable.

## Data ingestion strategy

### Preferred Kismet API usage
- Use **device views** and incremental queries:
  - `/devices/views/{VIEWID}/last-time/{TIMESTAMP}/devices.json`
- Maintain a local high-watermark `last_ts` per view.
- Use Kismet’s **field simplification** (`fields`) to minimize returned data.

(See `references/kismet-api-notes.md` for sources.)

### Local database
Store in a local sqlite DB under `output/state/` (gitignored), or store line-delimited JSON under `output/raw/` with a lightweight index.

Recommended initial tables (all local-only):
- `events_wifi_ap` (ssid, bssid, channel, frequency, seen_first, seen_last, signal stats)
- `events_wifi_client` (client_mac, associated_bssid, ssid_guess, seen_first/last)
- `events_bt` (btaddr, type, seen_first/last, rssi stats)
- `events_tpms` (sensor_id, seen_first/last, rssi stats)  
  (exact schema TBD once we know what Kismet exposes for TPMS)

## Analyses you requested

### (A) SSID integrity: detect rogue BSSID advertising your SSIDs

Inputs (local-only config):
- `watched_ssids`: list of SSIDs you care about
- `approved_bssids_by_ssid`: mapping of SSID -> set of allowed BSSIDs

Method:
1) Pull Wi-Fi AP devices view (likely a PHY 802.11 AP view).
2) For each observed AP record with `ssid` in watched list:
   - If its BSSID is not in the approved set, emit an alert:
     - `kind=ssid_rogue_bssid`
     - evidence includes ssid, observed bssid, channel/frequency, signal strength, first/last seen
3) Optional: track signal trends; a persistent strong rogue signal nearby is more urgent.

### (B) Device MAC monitoring: ensure devices only connect to allowed SSIDs

Inputs (local-only config):
- `watched_device_macs`: list/set of device MACs
- `allowed_ssids_for_devices`: allowed SSIDs (global) or per-device allow list

Method:
1) Pull Wi-Fi client view (stations / clients).
2) For each watched MAC, find association history:
   - associated BSSID
   - SSID (if present directly in Kismet record, or inferred via associated BSSID -> SSID)
3) If a watched device is associated with a BSSID whose SSID is not allowed, alert:
   - `kind=device_on_unapproved_ssid`

Notes:
- Some records may not include SSID; we should infer using AP table.
- Locally administered MAC randomization can complicate this; we’ll treat the provided MACs as canonical and only monitor those.

### (C) TPMS sensors passing by

Goal:
- Keep a rolling ledger of TPMS sensor identifiers observed, with timestamps + signal.

Plan:
- Identify which Kismet PHY/plugin emits TPMS (may appear as a device type or custom PHY).
- Store sightings (sensor id + time + rssi + datasource).
- Later: implement your desired behavior (alerting, correlation, frequency).

### (D) Bluetooth devices passing by

Two approaches:
1) If Kismet is already capturing BT/BLE locally, poll the BT device view.
2) If you have a separate BLE scanner, use Kismet’s scanning-mode endpoint to submit scan reports.

(See `references/kismet-api-notes.md` for the scanning-mode endpoint.)

## Dashboard plan

Initial dashboard pages (single page is fine first):
- **Active alerts** (persistent queue until dismissed)
- **Recent sightings** (last N minutes/hours): rogue SSID events, device SSID violations, BT/TPMS sightings
- **Search** (local-only): look up a MAC/BSSID/btaddr in the local DB (but do not expose publicly)

## Polling schedule

- Poll interval: start with 30–60s for incremental device views, then tune.
- Implement backoff on API failure.
- Persist last successful poll timestamp per view.

## What connection details we will need from you

Please be ready to provide these via uncommitted `assets/.env`:
- `KISMET_URL` (scheme+host+port)
- One of:
  - `KISMET_USER` + `KISMET_PASS` (basic auth), OR
  - `KISMET_API_TOKEN` (preferred long-term)
- Which device views to use for:
  - Wi-Fi AP view id
  - Wi-Fi client view id
  - Bluetooth view id (if applicable)
  - TPMS view id / plugin info (if applicable)

Also (local-only state files under `output/state`):
- watched SSIDs
- approved BSSIDs per SSID
- watched device MACs
- allowed SSIDs list

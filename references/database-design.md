# HomeSigSec database design (initial)

Goal: store Kismet-derived telemetry locally for analysis, alerting, and dashboarding.

Constraints:
- Do not commit identifying values (SSIDs, MACs/BSSIDs, IPs, GPS, etc.).
- Raw storage: keep ~7 days (configurable) and assess size.
- Derived/vital storage: keep indefinitely (alerts, audit trail, baselines, feedback).

## Storage model: two-tier

### Tier 1: Raw snapshots (7-day retention)

Purpose:
- Forensics / debugging
- Backfilling derived tables if parsing evolves
- Reproducing “what did Kismet say at the time?”

Format recommendation:
- **Compressed NDJSON** (or JSON) files partitioned by day + view.
- Stored under: `$HOMESIGSEC_WORKDIR/raw/YYYY-MM-DD/<view>.json.gz`
- Each poll writes a record like:

```json
{
  "fetched_at": "<iso8601>",
  "view": "<viewid>",
  "since": "<timestamp param>",
  "payload": <raw response JSON>
}
```

Why files, not DB blobs:
- Easy to rotate by day
- Compresses extremely well
- Doesn’t bloat sqlite with large JSON blobs

Initial size estimate (from your live Kismet, last 1 hour, **simplified fields**, gzipped):
- 802.11 AP view: ~3.6 KB / poll
- 802.11 devices view: ~21.8 KB / poll
- BTLE seen-by hci1 view: ~2.3 KB / poll

Rule of thumb sizing (example):
- If we poll these 3 views every 60s:
  - ~27.7 KB/min gz → ~1.66 MB/hour → ~40 MB/day → ~280 MB/week

This is just the simplified view payload. If you decide to store *full* device records (many more fields), multiply by a large factor (often 5–30×). So we should keep the raw tier configurable and start with simplified.

### Tier 2: Derived / normalized DB (retained forever)

Purpose:
- Alert generation
- Long-term baselines (what’s normal?)
- Dashboard queries without scanning large raw files

Recommended engine:
- **sqlite** (WAL mode), stored under `$HOMESIGSEC_WORKDIR/state/homesigsec.sqlite`

Guiding principle:
- Store **events** (sightings/associations) and small **dimensions** (device identity labels), not entire Kismet records.

## Proposed sqlite schema (v1)

### 1) `meta_kv` (forever)

Key/value metadata:
- schema version
- last successful poll timestamp per view
- retention settings

Columns:
- `k TEXT PRIMARY KEY`
- `v TEXT NOT NULL`
- `updated_at TEXT NOT NULL`

### 2) `poll_runs` (forever)

Audit trail for ingestion:
- `id INTEGER PRIMARY KEY`
- `started_at TEXT NOT NULL`
- `finished_at TEXT`
- `view TEXT NOT NULL`
- `since_param TEXT NOT NULL` (e.g. `-60`, or epoch)
- `status TEXT NOT NULL` (`ok`/`error`)
- `items_count INTEGER`
- `raw_bytes INTEGER`
- `gzip_bytes INTEGER`
- `error TEXT`

### 3) `wifi_ap_sightings` (forever)

A row per “AP observed at time T”.

- `ts INTEGER NOT NULL` (epoch seconds)
- `ssid TEXT` (runtime value; stored locally only in DB)
- `bssid TEXT`
- `channel INTEGER`
- `frequency INTEGER`
- `signal_dbm INTEGER`
- `first_seen INTEGER`
- `last_seen INTEGER`
- `source TEXT` (datasource/view)

Index:
- `(ssid, bssid, ts)`
- `(bssid, ts)`

### 4) `wifi_client_sightings` (forever)

Client device presence and (if available) association info.

- `ts INTEGER NOT NULL`
- `client_mac TEXT NOT NULL`
- `associated_bssid TEXT` (nullable)
- `ssid TEXT` (nullable; inferred via associated_bssid→ssid)
- `signal_dbm INTEGER`
- `first_seen INTEGER`
- `last_seen INTEGER`
- `source TEXT`

Indexes:
- `(client_mac, ts)`
- `(ssid, ts)`

### 5) `bt_sightings` (forever)

- `ts INTEGER NOT NULL`
- `btaddr TEXT NOT NULL`
- `bt_type TEXT` (BT/BTLE)
- `rssi INTEGER`
- `first_seen INTEGER`
- `last_seen INTEGER`
- `source TEXT` (e.g. datasource uuid or view)

Indexes:
- `(btaddr, ts)`

### 6) `tpms_sightings` (forever, schema TBD)

We’ll finalize once we inspect what Kismet exposes for TPMS (likely via `phy-RFSENSOR` or a plugin-specific type).

### 7) `alerts` (forever)

Canonical alert ledger; used to drive the persistent dashboard queue.

- `alert_id TEXT PRIMARY KEY` (stable, deterministic)
- `kind TEXT NOT NULL` (e.g. `ssid_rogue_bssid`, `unknown_mac_on_watched_ssid`, ...)
- `first_seen INTEGER NOT NULL`
- `last_seen INTEGER NOT NULL`
- `severity TEXT NOT NULL` (`low`/`med`/`high`)
- `title TEXT NOT NULL`
- `evidence_json TEXT NOT NULL` (small JSON; redact in exported reports)
- `status TEXT NOT NULL` (`active`/`dismissed`/`resolved`)

### 8) `alert_events` (forever)

Append-only history of state changes:
- `id INTEGER PRIMARY KEY`
- `alert_id TEXT NOT NULL`
- `ts INTEGER NOT NULL`
- `event TEXT NOT NULL` (created/updated/dismissed/verdict/comment)
- `data_json TEXT`

## Retention strategy

- Raw tier: delete raw files older than N days (default 7).
- Derived DB: keep forever, but periodically vacuum/compact (optional).
- Optionally, keep “high-resolution” sightings for 30 days and downsample older data (future enhancement).

## Next implementation steps

1) Implement a collector script that:
   - polls the chosen views via `last-time/-N`
   - writes compressed raw snapshots
   - upserts normalized sightings into sqlite
   - records `poll_runs`

2) Implement analyzers that read sqlite + watchlists and emit alerts:
   - rogue BSSID advertising watched SSIDs
   - unknown MAC attempts on watched SSIDs
   - watched MAC on unapproved SSID
   - BT/TPMS sightings tracking

3) Wire into dashboard persistent queue (like HomeNetSec), with highlighting for unknown MAC attempts.

# HomeSigSec local watchlists format (uncommitted)

All watchlists live under:

- `$HOMESIGSEC_WORKDIR/state/`

They must **never** be committed. They contain SSIDs, MACs, BSSIDs, etc.

## 1) SSID → approved BSSIDs mapping

File (recommended):
- `$HOMESIGSEC_WORKDIR/state/ssid_approved_bssids.local.json`

Schema:
```json
{
  "version": 1,
  "updated_at": "2026-02-13T00:00:00-0500",
  "watched_ssids": ["<SSID_1>", "<SSID_2>"],
  "approved_bssids_by_ssid": {
    "<SSID_1>": ["<BSSID_1>", "<BSSID_2>"],
    "<SSID_2>": ["<BSSID_3>"]
  }
}
```

Notes:
- `watched_ssids` is the canonical list.
- `approved_bssids_by_ssid[ssid]` may be empty to mean “alert on any BSSID advertising this SSID.”

## 2) Device MAC → allowed SSIDs mapping

File (recommended):
- `$HOMESIGSEC_WORKDIR/state/device_allowed_ssids.local.json`

Schema:
```json
{
  "version": 1,
  "updated_at": "2026-02-13T00:00:00-0500",
  "default_allowed_ssids": ["<SSID_1>", "<SSID_2>"],
  "devices": {
    "<DEVICE_MAC_1>": {
      "label": "<friendly label>",
      "allowed_ssids": ["<SSID_1>"]
    },
    "<DEVICE_MAC_2>": {
      "label": "<friendly label>",
      "allowed_ssids": []
    }
  }
}
```

Interpretation rules:
- If a device has `allowed_ssids` non-empty: use it.
- If empty/missing: fall back to `default_allowed_ssids`.
- If both are empty: treat as “no SSIDs allowed” (always alert if we can infer SSID).

## 3) Optional: approved device inventory (MAC ↔ friendly name)

If you want a single canonical device inventory:
- `$HOMESIGSEC_WORKDIR/state/device_inventory.local.json`

Use it to map MACs to friendly names for dashboard display.

## 4) Unknown MACs attempting to connect to watched SSIDs

No separate list needed; “unknown” means:
- A MAC that is *not* in `device_allowed_ssids.local.json` **and**
- is seen in a connection attempt/association/probe pattern relevant to your watched SSIDs.

Depending on what Kismet exposes reliably (association vs probe requests), we’ll implement one of:
- "attempted association to BSSID advertising watched SSID" (best)
- "probe request for watched SSID" (good for detecting nearby device interest, but can false-positive)

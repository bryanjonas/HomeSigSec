# HomeSigSec fingerprinting (current implementation)

This document describes the **currently implemented** fingerprinting approach in HomeSigSec.

It is intentionally conservative and uses only fields we can reliably obtain via the Kismet REST API.
It is **not** an industry-standard fingerprint like JA3/JA4; it is a best-effort mechanism to help
attribute randomized MAC activity over time.

## Goal

Build a baseline “fingerprint profile” for selected devices when they are active on **MyHomeNetwork**,
so we can later compare higher-signal events (association/authentication/handshake/data) against those
profiles.

## Inputs

1) Local-only policy file (not committed):
- `$HOMESIGSEC_WORKDIR/state/device_allowed_ssids.local.json`
  - selects which devices we care about and their allowed SSIDs

2) Kismet device view:
- `POST /devices/views/phy-IEEE802.11/devices.json`

## What we extract (v1 feature set)

For each target device MAC present in the Kismet 802.11 device view, we extract:

- `kismet_type`: `kismet.device.base.type`
- `probe_fp`: `dot11.device.probe_fingerprint`
- `response_fp`: `dot11.device.response_fingerprint`
- `beacon_fp`: `dot11.device.beacon_fingerprint` (often 0 for clients)
- `typeset`: `dot11.device.typeset`

And we also record supporting context:
- `packets_total`: `kismet.device.base.packets.total`
- `data_bytes`: `kismet.device.base.datasize`
- `first_seen`: `kismet.device.base.first_time`
- `last_seen`: `kismet.device.base.last_time`

### Fingerprint hash

We compute a stable identifier:

- `fingerprint_hash = sha256(canonical_json(features))[:16]`

This is used for:
- quick equality comparisons
- dashboard display

## “Enough traffic” threshold

We currently require at least:
- `packets_total >= --min-packets` (default used so far: 50)

If `packets_total` is below threshold and the fingerprint fields are not informative, we mark the device
as **insufficient**.

## Storage

All fingerprint data is stored locally in sqlite under (gitignored):
- `$HOMESIGSEC_WORKDIR/state/homesigsec.sqlite`

Tables:

### `device_fingerprints`
Latest stored fingerprint per device:
- `device_mac` (primary key)
- `label`
- `fingerprint_hash`
- `features_json`
- `packets_total`, `data_bytes`, `first_seen`, `last_seen`, `updated_at`

### `fingerprint_device_status`
Per-device status for the last run:
- `status`: `ok` | `insufficient`
- `reason`: e.g. `not in current Kismet view`, `low packets_total=39`
- `packets_total`, `fingerprint_hash`, `updated_at`

### `fingerprint_runs`
Run history:
- counts of `stored` vs `insufficient`
- `min_packets`
- timestamp

## How to run

From the repo root:

```bash
python3 scripts/fingerprint_devices.py --workdir "$HOMESIGSEC_WORKDIR" --min-packets 50
```

## How it appears on the dashboard

Fingerprint status is displayed inside the **Select Device SSID Monitoring** panel:
- summary pills: `fingerprints_ok`, `fingerprints_insufficient`
- dropdown: per-device fingerprint status

## Limitations (important)

- **Not unique:** different devices can share the same fingerprint values.
- **MAC randomization:** this does not “defeat” randomization; it provides a probabilistic signature.
- **Depends on frames captured:** channel hopping and limited capture windows can reduce fingerprint fidelity.
- **v1 features are coarse:** the strongest approach would parse management frame IEs (order/capabilities) from KismetDB/pcaps;
  that is not implemented yet.

## Next improvements (planned)

- Use eventbus (`DOT11_WPA_HANDSHAKE` + assoc/auth events if available) as the primary triggers for "attempt to connect".
- Expand the feature set beyond Kismet’s fingerprint integers:
  - capability bits / supported rates / extended capabilities
  - more dot11 fields if exposed
- Add probabilistic clustering + adaptive weighting (logistic regression) once we have sufficient labeled “known traffic” examples.

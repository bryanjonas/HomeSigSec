# HomeSigSec

**Kismet-based RF/signal environment monitoring for home networks.**

HomeSigSec monitors your WiFi environment using Kismet and provides:
- **Rogue AP detection**: Alert when unknown BSSIDs appear on watched SSIDs
- **Device SSID monitoring**: Track specific devices and alert on unauthorized network associations
- **Unknown device detection**: Cross-validated against UniFi + AdGuard to eliminate false positives
- **Device fingerprinting**: Baseline behavioral fingerprints for watched devices

## Quick Start

```bash
# 1. Configure environment
cp assets/.env.example assets/.env
# Edit assets/.env with your Kismet URL, credentials, and paths

# 2. Create watchlists (see references/watchlists-format.md)
# - output/state/ssid_approved_bssids.local.json
# - output/state/device_allowed_ssids.local.json

# 3. Run the pipeline
./scripts/run_sigsec_pipeline.sh

# 4. Start the dashboard
./scripts/dashboard_up.sh
```

## Requirements

- Kismet sensor accessible via REST API
- UniFi Controller (for unknown device validation)
- AdGuard Home (for DNS/DHCP client tracking)
- Docker (for dashboard)

Credentials should be stored in:
- `~/.openclaw/credentials/unifi.env`
- `~/.openclaw/credentials/adguard.env`

## Key Features

### Unknown Device Detection
Devices are only flagged as "unknown" when:
1. Kismet sees real traffic (>5KB, >50 bytes/frame to filter NULL data frames)
2. Device is confirmed by UniFi runtime OR AdGuard (cross-validation)
3. Device is not in historical known devices list

This eliminates Kismet misattribution from neighbor networks.

### Device Fingerprinting
Generates behavioral fingerprints based on packet patterns, timing, and signal characteristics. Used to detect device impersonation or unusual behavior.

## Documentation

- `README.md` - Full setup and usage guide
- `references/security-policy.md` - Privacy and security model
- `references/watchlists-format.md` - Watchlist configuration format
- `references/database-design.md` - SQLite schema documentation

## Privacy

**Never commit** SSIDs, MACs, IPs, or credentials. All identifying data stays in `output/` (gitignored) and local credential files.

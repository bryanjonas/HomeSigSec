# HomeSigSec (repo scaffold)

This repository is intended to become an OpenClaw skill repo similar to HomeNetSec, but focused on **Kismet**-based monitoring of the RF/signal environment.

- All host-specific configuration must be supplied via `.env` files and secrets.
- Never commit identifying network details (IPs, MACs, usernames, passwords, SSIDs).

Planned components (to be implemented):
- Poll Kismet REST API from a separate sensor host
- Produce periodic digests (device sightings, channel utilization, anomalies)
- Generate a LAN-only dashboard

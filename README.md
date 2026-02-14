# HomeSigSec

Home signal-security / RF-environment monitoring pipeline (Kismet-based).

## Security / privacy rules

This repo must not contain any:
- IP addresses
- MAC addresses
- usernames
- passwords
- tokens / API keys
- precise location data

Configuration is provided via **uncommitted** `.env` files (see `assets/.env.example`) and local state under `output/`.

## Quick start (local)

1) Copy the example env file and fill in values locally:

```bash
cp assets/.env.example assets/.env
```

2) Run the pipeline (stub for now):

```bash
./scripts/run_once.sh
```

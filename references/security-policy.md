# HomeSigSec security + privacy policy (for the agent)

This document defines **non-negotiable** rules for what may appear in the **git repo** (committed) vs what must stay **local-only**.

## Never commit

Do not commit any of the following (in code, docs, examples, tests, screenshots, or logs):

- IP addresses (LAN/WAN), hostnames, URLs that include private hostnames
- MAC addresses / BSSIDs / Bluetooth addresses
- SSIDs
- usernames, passwords, API keys/tokens, cookies, session ids
- GPS coordinates / precise location info
- device names that uniquely identify people/places
- any raw Kismet JSON/PCAP/log output that contains the above

## Allowed in repo

- Placeholders like `KISMET_HOST`, `KISMET_PORT`, `YOUR_USER`, `YOUR_PASS`
- Abstract field names like `ssid`, `bssid`, `mac`, `btaddr` when describing schemas
- Logic which *processes* MACs/SSIDs/etc **as runtime data** (stored under `output/` which is gitignored)

## Configuration + secrets handling

- All runtime configuration must come from **uncommitted** `.env` files (for example `assets/.env`) or environment variables.
- Watch lists (approved BSSIDs, watched SSIDs, watched device MACs, allowed SSIDs) must live in **local-only** state files under:
  - `$HOMESIGSEC_WORKDIR/state/*.json`

## Operational hygiene

- Keep `output/` entirely untracked.
- Run `gitleaks detect` before pushing commits that touch docs/config examples.
- When writing analysis output for human consumption (reports/dashboard), redact identifiers unless Bryan explicitly wants them shown.
  - Default: show friendly labels (e.g., `watched_device_1`) and store the mapping locally only.

## When uncertain

If a value might be identifying (even if it’s "probably fine"), treat it as **private** and keep it out of git.

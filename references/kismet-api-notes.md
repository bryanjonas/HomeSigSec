# Kismet API notes (research-backed)

This is a working reference for how HomeSigSec should consume Kismet.

## Auth / sessions

Kismet supports:
- HTTP Basic Auth (user/pass)
- Session cookie token (KISMET cookie)
- URI params for endpoints where headers aren’t practical (ex: websockets)

Kismet docs note that as of 2019+ most interactions require login, and a session cookie is created automatically after authenticating to a protected endpoint.

Sources:
- https://www.kismetwireless.net/docs/api/login/

## Device views (recommended primary query interface)

Kismet strongly encourages clients to use **device views**.

Key endpoints:
- List views:
  - `GET /devices/views/all_views.json`
- Pull devices for a given view:
  - `POST /devices/views/{VIEWID}/devices.json` (supports pagination + field simplification)
- Pull devices active since a timestamp:
  - `GET|POST /devices/views/{VIEWID}/last-time/{TIMESTAMP}/devices.json`
  - TIMESTAMP can be absolute epoch, or a relative negative number (“seconds before now”)
- Real-time monitoring:
  - websocket: `/devices/views/{VIEWID}/monitor.ws`

Field simplification and regex filtering exist to reduce payload size.

Sources:
- https://www.kismetwireless.net/docs/api/device_views/

## Bluetooth scanning-mode reports (if you later want to submit scan data)

Kismet has a scanning-mode API for Bluetooth which lets a client submit scan reports.
This is useful if your sensor is not running full Kismet capture but does active BLE scans and reports results.

Endpoint:
- `POST /phy/phybluetooth/scan/scan_report.cmd`

Source:
- https://www.kismetwireless.net/docs/api/bluetooth_scanningmode/

## Practical implications for HomeSigSec

- Prefer polling `last-time/-N` endpoints on a schedule (incremental) rather than dumping the full DB.
- Use `fields` to request only the columns needed for each analysis task.
- Store raw responses locally under `output/` only (never in git).

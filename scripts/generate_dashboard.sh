#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "$ROOT_DIR/assets/.env" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ROOT_DIR/assets/.env"
  set +a
fi

WORKDIR="${HOMESIGSEC_WORKDIR:-$ROOT_DIR/output}"
# If the env file still has the placeholder path, fall back to repo-local output.
if [[ "$WORKDIR" == /ABS/* ]]; then
  WORKDIR="$ROOT_DIR/output"
fi
DAY="${1:-$(date +%F)}"

WWW_DIR="$WORKDIR/www"
STATE_DIR="$WORKDIR/state"
DB_PATH="$STATE_DIR/homesigsec.sqlite"
WATCHLIST="$STATE_DIR/ssid_approved_bssids.local.json"

mkdir -p "$WWW_DIR" "$STATE_DIR"

python3 - "$DAY" "$DB_PATH" "$WATCHLIST" "$WWW_DIR/index.html" "$WWW_DIR/status.json" <<'PY'
import json, os, sys, time, sqlite3, html

DAY, DB_PATH, WATCHLIST, OUT_HTML, OUT_STATUS = sys.argv[1:6]

# Load watchlist (local-only). If missing, show empty state.
wl = {}
try:
    with open(WATCHLIST, 'r', encoding='utf-8') as f:
        wl = json.load(f)
except FileNotFoundError:
    wl = {}
except Exception:
    wl = {}

watched = wl.get('watched_ssids') if isinstance(wl.get('watched_ssids'), list) else []
approved = wl.get('approved_bssids_by_ssid') if isinstance(wl.get('approved_bssids_by_ssid'), dict) else {}

# Query sqlite for current AP->SSID sightings for watched SSIDs.
rows = []
if os.path.exists(DB_PATH) and watched:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    # last 2 hours window (tune later)
    since = int(time.time()) - 2*3600
    q = """
    SELECT ssid, bssid, max(ts) as ts_max
    FROM wifi_ap_sightings
    WHERE ssid IN ({}) AND ts >= ?
    GROUP BY ssid, bssid
    ORDER BY ssid, ts_max DESC
    """.format(",".join(["?"]*len(watched)))
    cur = con.execute(q, [*watched, since])
    rows = [dict(r) for r in cur.fetchall()]
    con.close()

seen_by_ssid = {s: [] for s in watched}
for r in rows:
    seen_by_ssid.setdefault(r['ssid'], []).append(r)

# Compute rogue bssids
panel = []
rogues_total = 0
for ssid in watched:
    seen = [str(x['bssid']).lower() for x in seen_by_ssid.get(ssid, []) if x.get('bssid')]
    seen_set = sorted(set(seen))
    appr_set = sorted(set([str(x).lower() for x in (approved.get(ssid) or [])]))
    rogue = [b for b in seen_set if b not in set(appr_set)]
    rogues_total += len(rogue)
    panel.append({
        'ssid': ssid,
        'approved_bssids': appr_set,
        'seen_bssids': seen_set,
        'rogue_bssids': rogue,
    })

# Load device MAC -> allowed SSIDs mapping (local-only)
mac_cfg_path = os.path.join(os.path.dirname(WATCHLIST), 'device_allowed_ssids.local.json')
mac_cfg = {}
try:
    with open(mac_cfg_path, 'r', encoding='utf-8') as f:
        mac_cfg = json.load(f)
except FileNotFoundError:
    mac_cfg = {}
except Exception:
    mac_cfg = {}

status = {
    'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime()),
    'day': DAY,
    'ssid_bssid_panel': {
        'watched_ssids': len(watched),
        'rogue_bssids': rogues_total,
    },
    'device_ssid_panel': {
        'watched_macs': len((mac_cfg.get('devices') or {}) if isinstance(mac_cfg.get('devices'), dict) else {}),
        'violations': 0,
    }
}

os.makedirs(os.path.dirname(OUT_STATUS), exist_ok=True)
with open(OUT_STATUS, 'w', encoding='utf-8') as f:
    json.dump(status, f, indent=2, sort_keys=True)
    f.write('\n')

style = """
body{font-family:system-ui,Arial,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px}
.card{border:1px solid #ddd;border-radius:10px;padding:16px;margin:16px 0}
.row{display:flex;gap:12px;flex-wrap:wrap}
.pill{display:inline-block;border:1px solid #ccc;border-radius:999px;padding:2px 8px;font-size:12px;color:#333;background:#fafafa}
.bad{border-color:#b42318;color:#b42318;background:#fff5f5}
.muted{color:#555}
code{background:#f6f6f6;padding:1px 4px;border-radius:4px}
pre{background:#0b1020;color:#e8eefc;padding:14px;border-radius:10px;overflow:auto;white-space:pre-wrap}
"""

body = []
body.append('<!doctype html><html><head><meta charset="utf-8">')
body.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
body.append('<title>HomeSigSec Dashboard</title>')
body.append(f'<style>{style}</style></head><body>')
body.append('<h1>HomeSigSec</h1>')
body.append(f"<div class='muted'>Generated: {html.escape(status['generated_at'])} · Day: <code>{html.escape(DAY)}</code></div>")

# Fingerprint health panel
fp_summary = None
fp_rows = []
try:
    if os.path.exists(DB_PATH):
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        fp_summary = con.execute('select stored, insufficient, min_packets, updated_at from fingerprint_runs order by id desc limit 1').fetchone()
        fp_rows = con.execute('select device_mac,label,status,reason,packets_total,fingerprint_hash,updated_at from fingerprint_device_status order by status desc, label asc').fetchall()
        con.close()
except Exception:
    fp_summary = None
    fp_rows = []

body.append('<div class="card">')
body.append('<h2>Fingerprint status</h2>')
if not fp_summary:
    body.append('<div class="muted">No fingerprint runs recorded yet. Run <code>python3 scripts/fingerprint_devices.py</code>.</div>')
else:
    body.append(f"<div class='row'><div class='pill'>stored={int(fp_summary['stored'])}</div><div class='pill {'bad' if int(fp_summary['insufficient']) else ''}'>insufficient={int(fp_summary['insufficient'])}</div><div class='pill'>min_packets={int(fp_summary['min_packets'])}</div></div>")
    body.append(f"<div class='muted small' style='margin-top:8px'>last_run: <code>{html.escape(str(fp_summary['updated_at']))}</code></div>")

    # dropdown with per-device status
    lines = []
    for r in fp_rows:
        mac = r['device_mac']
        label = r['label'] or ''
        st = r['status']
        reason = r['reason'] or ''
        pkt = r['packets_total']
        fph = r['fingerprint_hash'] or ''
        who = f"{label} ({mac})" if label else mac
        extra = f" packets={pkt}" if pkt is not None else ''
        if st != 'ok':
            lines.append(f"{st}: {who} - {reason}{extra}")
        else:
            lines.append(f"ok: {who} fp={fph}{extra}")

    body.append('<details style="margin:10px 0"><summary>Show per-device fingerprint status</summary>')
    body.append('<pre>' + html.escape('\n'.join(lines) or '(none)') + '</pre></details>')

body.append('</div>')

body.append('<div class="card">')
body.append('<h2>SSID → BSSID monitoring</h2>')

# Config dropdown
try:
    cfg_text = json.dumps(wl, indent=2, sort_keys=True)
except Exception:
    cfg_text = ''
body.append('<details style="margin:10px 0"><summary>Show current watchlist config (from disk)</summary>')
body.append('<pre>' + html.escape(cfg_text or '(missing)') + '</pre></details>')

if not watched:
    body.append('<div class="muted">No watched SSIDs configured yet. Create local watchlist under <code>$HOMESIGSEC_WORKDIR/state/ssid_approved_bssids.local.json</code>.</div>')
else:
    body.append(f"<div class='row'><div class='pill'>watched_ssids={len(watched)}</div><div class='pill {'bad' if rogues_total else ''}'>rogue_bssids={rogues_total}</div></div>")

    # Only render SSIDs which currently have rogue BSSIDs.
    rogues = [ent for ent in panel if (ent.get('rogue_bssids') or [])]
    if not rogues:
        body.append('<div class="muted" style="margin-top:10px">No rogue APs detected in the recent window.</div>')
    else:
        for ent in rogues:
            ssid = ent['ssid']
            rogue = ent['rogue_bssids']
            body.append('<hr>')
            body.append(f"<h3>{html.escape(ssid)}</h3>")
            body.append(f"<div class='row'><div class='pill'>approved={len(ent['approved_bssids'])}</div><div class='pill'>seen_recent={len(ent['seen_bssids'])}</div><div class='pill bad'>rogue={len(rogue)}</div></div>")

            body.append('<div class="muted">Unapproved BSSIDs observed recently:</div>')
            body.append('<pre>' + html.escape('\n'.join(rogue)) + '</pre>')

body.append('</div>')

# Device MAC → allowed SSIDs monitoring
body.append('<div class="card">')
body.append('<h2>Device → allowed SSIDs</h2>')

try:
    mac_cfg_text = json.dumps(mac_cfg, indent=2, sort_keys=True)
except Exception:
    mac_cfg_text = ''
body.append('<details style="margin:10px 0"><summary>Show current device/SSID config (from disk)</summary>')
body.append('<pre>' + html.escape(mac_cfg_text or '(missing)') + '</pre></details>')

devices = mac_cfg.get('devices') if isinstance(mac_cfg.get('devices'), dict) else {}
default_allowed = mac_cfg.get('default_allowed_ssids') if isinstance(mac_cfg.get('default_allowed_ssids'), list) else []

def allowed_for(mac: str):
    rec = devices.get(mac) if isinstance(devices, dict) else None
    if isinstance(rec, dict) and isinstance(rec.get('allowed_ssids'), list) and rec.get('allowed_ssids'):
        return [str(x) for x in rec.get('allowed_ssids')]
    return [str(x) for x in default_allowed]

violations = []
if os.path.exists(DB_PATH) and devices:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    since = int(time.time()) - 2*3600
    macs = [str(m).lower() for m in list(devices.keys())]
    q = """
    SELECT lower(client_mac) as client_mac, ssid, max(ts) as ts_max
    FROM wifi_client_sightings
    WHERE lower(client_mac) IN ({}) AND ts >= ? AND ssid IS NOT NULL AND ssid != ''
    GROUP BY lower(client_mac), ssid
    ORDER BY ts_max DESC
    """.format(",".join(["?"]*len(macs)))
    cur = con.execute(q, [*macs, since])
    for r in cur.fetchall():
        mac = r['client_mac']
        ssid = r['ssid']
        allowed = set(allowed_for(mac))
        if allowed and ssid not in allowed:
            label = ''
            rec = devices.get(mac) if isinstance(devices, dict) else None
            if isinstance(rec, dict):
                label = str(rec.get('label') or '')
            violations.append({"mac": mac, "label": label, "ssid": ssid, "ts": int(r['ts_max'] or 0)})
    con.close()

status['device_ssid_panel']['violations'] = len(violations)
# Rewrite status.json after computing violations (overwrite previous).
with open(OUT_STATUS, 'w', encoding='utf-8') as f:
    json.dump(status, f, indent=2, sort_keys=True)
    f.write('\n')

body.append(f"<div class='row'><div class='pill'>watched_macs={len(devices)}</div><div class='pill {'bad' if violations else ''}'>violations={len(violations)}</div></div>")

if not devices:
    body.append('<div class="muted" style="margin-top:10px">No watched device MACs configured yet.</div>')
elif not violations:
    body.append('<div class="muted" style="margin-top:10px">No device SSID violations detected in the recent window.</div>')
    body.append('<div class="muted small">(Note: this requires wifi client ingestion into <code>wifi_client_sightings</code>; it may be empty until we add that collector.)</div>')
else:
    for v in violations:
        who = f"{v['label']} ({v['mac']})" if v.get('label') else v['mac']
        body.append('<hr>')
        body.append(f"<h3>{html.escape(who)}</h3>")
        body.append(f"<div class='row'><div class='pill bad'>ssid={html.escape(str(v['ssid']))}</div></div>")

body.append('</div>')

body.append('</body></html>')

with open(OUT_HTML, 'w', encoding='utf-8') as f:
    f.write('\n'.join(body))
    f.write('\n')

print(f"[homesigsec] dashboard wrote {OUT_HTML} and {OUT_STATUS}")
PY

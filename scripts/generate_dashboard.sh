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
    seen = [x['bssid'] for x in seen_by_ssid.get(ssid, []) if x.get('bssid')]
    seen_set = sorted(set(seen))
    appr_set = sorted(set([str(x) for x in (approved.get(ssid) or [])]))
    rogue = [b for b in seen_set if b not in set(appr_set)]
    rogues_total += len(rogue)
    panel.append({
        'ssid': ssid,
        'approved_bssids': appr_set,
        'seen_bssids': seen_set,
        'rogue_bssids': rogue,
    })

status = {
    'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime()),
    'day': DAY,
    'ssid_bssid_panel': {
        'watched_ssids': len(watched),
        'rogue_bssids': rogues_total,
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

body.append('<div class="card">')
body.append('<h2>SSID → BSSID monitoring (rogue AP alerts)</h2>')

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
body.append('</body></html>')

with open(OUT_HTML, 'w', encoding='utf-8') as f:
    f.write('\n'.join(body))
    f.write('\n')

print(f"[homesigsec] dashboard wrote {OUT_HTML} and {OUT_STATUS}")
PY

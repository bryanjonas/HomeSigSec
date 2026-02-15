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

# Fetch known devices from AdGuard Home (authoritative source)
def fetch_adguard_known_macs() -> set:
    """Fetch known device MACs from AdGuard Home /control/clients."""
    import urllib.request
    import urllib.parse
    
    url = (os.environ.get('ADGUARD_URL') or '').rstrip('/')
    user = os.environ.get('ADGUARD_USER') or ''
    pw = os.environ.get('ADGUARD_PASS') or ''
    if not (url and user and pw):
        return set()
    
    try:
        # Login
        login_body = json.dumps({"name": user, "password": pw}).encode('utf-8')
        login_req = urllib.request.Request(
            f"{url}/control/login",
            data=login_body,
            method='POST',
            headers={'Content-Type': 'application/json'}
        )
        login_resp = urllib.request.urlopen(login_req, timeout=15)
        cookies = login_resp.headers.get_all('Set-Cookie') or []
        login_resp.read()
        cookie = '; '.join([c.split(';', 1)[0] for c in cookies if c])
        
        # Get clients
        clients_req = urllib.request.Request(f"{url}/control/clients", headers={'Cookie': cookie})
        raw = urllib.request.urlopen(clients_req, timeout=15).read()
        data = json.loads(raw.decode('utf-8', errors='replace'))
        
        macs = set()
        for c in (data.get('clients') or []):
            if not isinstance(c, dict):
                continue
            for cid in (c.get('ids') or []):
                cid_s = str(cid).strip().lower()
                # Check if it looks like a MAC (17 chars with colons)
                if ':' in cid_s and len(cid_s) == 17:
                    macs.add(cid_s)
        return macs
    except Exception as e:
        print(f"[homesigsec] WARN: could not fetch AdGuard clients: {e}")
        return set()

adguard_known_macs = fetch_adguard_known_macs()

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

# Compute rogue bssids (excluding dismissed)
panel = []
rogues_total = 0
for ssid in watched:
    seen = [str(x['bssid']).lower() for x in seen_by_ssid.get(ssid, []) if x.get('bssid')]
    seen_set = sorted(set(seen))
    appr_set = sorted(set([str(x).lower() for x in (approved.get(ssid) or [])]))
    rogue_all = [b for b in seen_set if b not in set(appr_set)]
    # Filter out dismissed rogues from count
    rogue = [b for b in rogue_all if not is_dismissed(make_alert_id('rogue_ap', ssid, b))]
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
    },
    'unknown_devices_panel': {
        'known_macs': len(adguard_known_macs),
        'unknown_count': 0,  # Updated later after computing
    }
}

os.makedirs(os.path.dirname(OUT_STATUS), exist_ok=True)
with open(OUT_STATUS, 'w', encoding='utf-8') as f:
    json.dump(status, f, indent=2, sort_keys=True)
    f.write('\n')

# Load persisted feedback for drafting and hiding dismissed.
FEEDBACK_PATH = os.path.join(os.path.dirname(WATCHLIST), 'feedback.json')
feedback_days = {}
try:
    with open(FEEDBACK_PATH, 'r', encoding='utf-8') as f:
        fb = json.load(f)
        if isinstance(fb, dict):
            feedback_days = fb.get('days') if isinstance(fb.get('days'), dict) else {}
except Exception:
    feedback_days = {}

def latest_feedback(alert_id: str):
    """Return (day, rec) for latest feedback for this alert across all days."""
    best_day, best_rec, best_ts = None, None, None
    for d, mp in (feedback_days or {}).items():
        if not isinstance(mp, dict):
            continue
        rec = mp.get(alert_id)
        if not isinstance(rec, dict):
            continue
        ts = rec.get('updated_at') or ''
        if best_ts is None or str(ts) > str(best_ts):
            best_ts = ts
            best_day = d
            best_rec = rec
    return best_day, best_rec

def is_dismissed(alert_id: str) -> bool:
    _, rec = latest_feedback(alert_id)
    return bool((rec or {}).get('dismissed'))

def find_similar_feedback(kind: str, key_parts: list) -> str:
    """Find dismissed feedback for similar alerts and draft a note.
    
    Returns the note from a closely matching dismissed alert, or empty string.
    We do NOT fabricate comments - only return real prior feedback.
    """
    kind_prefix = kind
    for d, mp in (feedback_days or {}).items():
        if not isinstance(mp, dict):
            continue
        for aid, rec in mp.items():
            if not isinstance(rec, dict):
                continue
            if not rec.get('dismissed'):
                continue
            note = str(rec.get('note') or '').strip()
            # Skip useless notes
            if not note or len(note) < 10 or note.lower() in ('test', 'testing', 'tbd', 'unable to generate comments.'):
                continue
            # Check if aid matches similar pattern
            aid_s = str(aid)
            if not aid_s.startswith(kind_prefix):
                continue
            # Require at least 2 key parts to match for a "similar" alert
            matches = sum(1 for p in key_parts if p and str(p).lower() in aid_s.lower())
            if matches >= 2:
                return note  # Return first good match
    return ""

import hashlib

def make_alert_id(kind: str, *parts) -> str:
    """Generate a stable alert ID."""
    key = kind + '|' + '|'.join(str(p) for p in parts)
    return kind + '_' + hashlib.sha256(key.encode()).hexdigest()[:12]

style = """
:root {
  --bg: #f8fafc;
  --card-bg: #ffffff;
  --border: #e2e8f0;
  --text: #1e293b;
  --text-muted: #64748b;
  --accent: #3b82f6;
  --success: #10b981;
  --success-bg: #ecfdf5;
  --warning: #f59e0b;
  --warning-bg: #fffbeb;
  --danger: #ef4444;
  --danger-bg: #fef2f2;
  --code-bg: #f1f5f9;
  --pre-bg: #0f172a;
  --pre-text: #e2e8f0;
  --shadow: 0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.06);
  --shadow-lg: 0 4px 6px rgba(0,0,0,0.07), 0 2px 4px rgba(0,0,0,0.06);
}
*, *::before, *::after { box-sizing: border-box; }
body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  background: var(--bg);
  color: var(--text);
  margin: 0;
  padding: 0;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}
.container { max-width: 960px; margin: 0 auto; padding: 24px 20px 48px; }
header {
  background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
  color: #fff;
  padding: 32px 20px;
  margin-bottom: 24px;
}
header .inner { max-width: 960px; margin: 0 auto; }
header h1 { margin: 0 0 4px; font-size: 28px; font-weight: 700; letter-spacing: -0.5px; }
header .subtitle { color: #94a3b8; font-size: 14px; margin: 0; }
.card {
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px 24px;
  margin-bottom: 20px;
  box-shadow: var(--shadow);
}
.card h2 {
  margin: 0 0 16px;
  font-size: 18px;
  font-weight: 600;
  color: var(--text);
  display: flex;
  align-items: center;
  gap: 10px;
}
.card h2 .icon { font-size: 20px; }
.metrics { display: flex; flex-wrap: wrap; gap: 10px; margin: 12px 0; }
.metric {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--code-bg);
  border-radius: 6px;
  padding: 6px 12px;
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
}
.metric.success { background: var(--success-bg); color: #047857; }
.metric.warning { background: var(--warning-bg); color: #b45309; }
.metric.danger { background: var(--danger-bg); color: #b91c1c; }
.metric .label { color: var(--text-muted); font-weight: 400; }
.muted { color: var(--text-muted); font-size: 14px; }
.small { font-size: 13px; }
code {
  background: var(--code-bg);
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 13px;
}
pre {
  background: var(--pre-bg);
  color: var(--pre-text);
  padding: 16px;
  border-radius: 8px;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 12px;
  line-height: 1.5;
  margin: 12px 0;
}
details {
  margin: 12px 0;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg);
}
details summary {
  padding: 10px 14px;
  cursor: pointer;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-muted);
  list-style: none;
}
details summary::-webkit-details-marker { display: none; }
details summary::before { content: '▸ '; color: var(--text-muted); }
details[open] summary::before { content: '▾ '; }
details > pre { margin: 0; border-radius: 0 0 8px 8px; }
hr { border: none; border-top: 1px solid var(--border); margin: 20px 0; }
.alert-item {
  background: var(--danger-bg);
  border: 1px solid #fecaca;
  border-radius: 8px;
  padding: 14px 16px;
  margin: 12px 0;
}
.alert-item h3 {
  margin: 0 0 8px;
  font-size: 15px;
  font-weight: 600;
  color: #b91c1c;
}
.alert-item .badge {
  display: inline-block;
  background: #fecaca;
  color: #991b1b;
  padding: 3px 10px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
}
.status-ok { color: var(--success); }
.status-warn { color: var(--warning); }
.status-bad { color: var(--danger); }
.empty-state {
  text-align: center;
  padding: 24px;
  color: var(--text-muted);
}
.empty-state .icon { font-size: 32px; margin-bottom: 8px; opacity: 0.5; }
footer {
  text-align: center;
  padding: 20px;
  color: var(--text-muted);
  font-size: 12px;
}
.triage-box {
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px;
  margin-top: 10px;
}
.triage-box .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-top: 8px; }
.triage-box textarea {
  width: 100%;
  min-height: 60px;
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 12px;
  padding: 8px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg);
  color: var(--text);
  resize: vertical;
}
.triage-box select {
  padding: 6px 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--card-bg);
  font-size: 13px;
}
.triage-box button {
  padding: 6px 14px;
  background: var(--accent);
  color: #fff;
  border: none;
  border-radius: 6px;
  font-weight: 500;
  font-size: 13px;
  cursor: pointer;
}
.triage-box button:hover { background: #2563eb; }
.triage-box label { font-size: 13px; display: inline-flex; align-items: center; gap: 4px; }
.triage-box input[type="checkbox"] { width: 14px; height: 14px; accent-color: var(--accent); }
.triage-box .status { font-size: 12px; color: var(--text-muted); }
details.triage-toggle { margin-top: 8px; border: none; background: transparent; }
details.triage-toggle summary { padding: 4px 0; font-size: 12px; }
details.triage-toggle summary::before { content: ''; }
.hidden { display: none !important; }
"""

js_code = """
const DAY = document.body.dataset.day || new Date().toISOString().slice(0,10);

async function loadFeedback(alertId) {
  try {
    const r = await fetch(`/api/feedback?day=${encodeURIComponent(DAY)}`, { cache: 'no-store' });
    if (!r.ok) return null;
    const j = await r.json();
    return (j.feedback || {})[alertId] || null;
  } catch(e) { return null; }
}

async function saveFeedback(alertId) {
  const box = document.querySelector(`[data-alert-id="${CSS.escape(alertId)}"]`);
  if (!box) return;
  const noteEl = box.querySelector('.triage-note');
  const verdictEl = box.querySelector('.triage-verdict');
  const dismissEl = box.querySelector('.triage-dismiss');
  const statusEl = box.querySelector('.status');

  const rec = {
    day: DAY,
    alert_id: alertId,
    updated_at: new Date().toISOString(),
    verdict: verdictEl ? verdictEl.value : 'unsure',
    note: noteEl ? noteEl.value : '',
    dismissed: dismissEl ? dismissEl.checked : false
  };

  if (statusEl) statusEl.textContent = 'saving…';
  try {
    const r = await fetch('/api/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rec)
    });
    if (statusEl) statusEl.textContent = r.ok ? 'saved ✓' : 'error';
    if (rec.dismissed && box.closest('.alert-item')) {
      box.closest('.alert-item').classList.add('hidden');
    }
  } catch(e) {
    if (statusEl) statusEl.textContent = 'error';
  }
}

async function hydrateAll() {
  const boxes = document.querySelectorAll('[data-alert-id]');
  for (const box of boxes) {
    const alertId = box.dataset.alertId;
    const fb = await loadFeedback(alertId);
    if (!fb) continue;
    const noteEl = box.querySelector('.triage-note');
    const verdictEl = box.querySelector('.triage-verdict');
    const dismissEl = box.querySelector('.triage-dismiss');
    if (noteEl && fb.note) noteEl.value = fb.note;
    if (verdictEl && fb.verdict) verdictEl.value = fb.verdict;
    if (dismissEl) dismissEl.checked = !!fb.dismissed;
    if (fb.dismissed && box.closest('.alert-item')) {
      box.closest('.alert-item').classList.add('hidden');
    }
  }
}

window.addEventListener('DOMContentLoaded', hydrateAll);
window.saveFeedback = saveFeedback;
"""

body = []
body.append('<!doctype html><html lang="en"><head><meta charset="utf-8">')
body.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
body.append('<title>HomeSigSec Dashboard</title>')
body.append('<link rel="preconnect" href="https://fonts.googleapis.com">')
body.append('<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>')
body.append('<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">')
body.append(f'<style>{style}</style></head><body data-day="{html.escape(DAY)}">')
body.append('<header><div class="inner">')
body.append('<h1>🛡️ HomeSigSec</h1>')
body.append(f"<p class='subtitle'>RF Environment Monitor · Generated {html.escape(status['generated_at'])}</p>")
body.append('</div></header>')
body.append('<div class="container">')

# Load latest fingerprint run summary (to be shown inside the device SSID panel)
fp_summary = None
try:
    if os.path.exists(DB_PATH):
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        fp_summary = con.execute('select stored, insufficient, min_packets, updated_at from fingerprint_runs order by id desc limit 1').fetchone()
        con.close()
except Exception:
    fp_summary = None

body.append('<div class="card">')
body.append('<h2><span class="icon">📡</span> Rogue AP Monitoring</h2>')

if not watched:
    body.append('<div class="empty-state"><div class="icon">📡</div><p>No watched SSIDs configured yet.<br>Create local watchlist under <code>$HOMESIGSEC_WORKDIR/state/ssid_approved_bssids.local.json</code></p></div>')
else:
    rogue_class = 'danger' if rogues_total else 'success'
    body.append('<div class="metrics">')
    body.append(f"<div class='metric'><span class='label'>Watched SSIDs</span> {len(watched)}</div>")
    body.append(f"<div class='metric {rogue_class}'><span class='label'>Rogue BSSIDs</span> {rogues_total}</div>")
    body.append('</div>')

    # Only render SSIDs which currently have rogue BSSIDs.
    rogues = [ent for ent in panel if (ent.get('rogue_bssids') or [])]
    if not rogues:
        body.append('<div class="empty-state"><div class="icon">✅</div><p>No rogue APs detected in the recent window.</p></div>')
    else:
        for ent in rogues:
            ssid = ent['ssid']
            rogue = ent['rogue_bssids']
            # Generate stable alert ID for each rogue BSSID
            for rbssid in rogue:
                alert_id = make_alert_id('rogue_ap', ssid, rbssid)
                if is_dismissed(alert_id):
                    continue  # Skip dismissed alerts
                
                draft_note = find_similar_feedback('rogue_ap', [ssid, rbssid])
                if not draft_note:
                    draft_note = "Unable to generate comments."
                _, prev_fb = latest_feedback(alert_id)
                prev_verdict = (prev_fb or {}).get('verdict', 'unsure')
                
                body.append(f'<div class="alert-item" id="alert-{html.escape(alert_id)}">')
                body.append(f"<h3>⚠️ Rogue AP on {html.escape(ssid)}</h3>")
                body.append('<div class="metrics">')
                body.append(f"<div class='metric danger'><span class='label'>BSSID</span> {html.escape(rbssid)}</div>")
                body.append('</div>')
                
                # Triage dropdown
                body.append(f'<details class="triage-toggle"><summary>💬 Triage & Comment</summary>')
                body.append(f'<div class="triage-box" data-alert-id="{html.escape(alert_id)}">')
                body.append(f'<textarea class="triage-note" placeholder="Add notes...">{html.escape(draft_note)}</textarea>')
                body.append('<div class="row">')
                
                def verdict_opt(val, label, selected):
                    sel = ' selected' if selected == val else ''
                    return f'<option value="{val}"{sel}>{label}</option>'
                
                body.append('<select class="triage-verdict">')
                body.append(verdict_opt('unsure', 'Unsure', prev_verdict))
                body.append(verdict_opt('benign', 'Benign', prev_verdict))
                body.append(verdict_opt('review', 'Needs Review', prev_verdict))
                body.append(verdict_opt('suspicious', 'Suspicious', prev_verdict))
                body.append('</select>')
                body.append(f'<label><input type="checkbox" class="triage-dismiss"> Dismiss</label>')
                body.append(f'<button onclick="saveFeedback(\'{html.escape(alert_id)}\')">Save</button>')
                body.append('<span class="status"></span>')
                body.append('</div></div></details>')
                body.append('</div>')

# Config dropdown
try:
    cfg_text = json.dumps(wl, indent=2, sort_keys=True)
except Exception:
    cfg_text = ''
body.append('<details><summary>View watchlist configuration</summary>')
body.append('<pre>' + html.escape(cfg_text or '(missing)') + '</pre></details>')

body.append('</div>')

# Device MAC → allowed SSIDs monitoring
body.append('<div class="card">')
body.append('<h2><span class="icon">📱</span> Select Device SSID Monitoring</h2>')

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

# Filter out dismissed violations from the count
active_violations = []
for v in violations:
    alert_id = make_alert_id('device_violation', v['mac'], v['ssid'])
    if not is_dismissed(alert_id):
        active_violations.append(v)

status['device_ssid_panel']['violations'] = len(active_violations)
# Rewrite status.json after computing violations (overwrite previous).
with open(OUT_STATUS, 'w', encoding='utf-8') as f:
    json.dump(status, f, indent=2, sort_keys=True)
    f.write('\n')

# Use active_violations for rendering
violations = active_violations

# Merge fingerprint status into device panel
fp_map = {}
try:
    if os.path.exists(DB_PATH):
        con2 = sqlite3.connect(DB_PATH)
        con2.row_factory = sqlite3.Row
        for r in con2.execute('select device_mac,status,reason,packets_total,fingerprint_hash,updated_at from fingerprint_device_status'):
            fp_map[str(r['device_mac']).lower()] = dict(r)
        con2.close()
except Exception:
    fp_map = {}

ok_fp = 0
ins_fp = 0
for mac in devices.keys():
    st = (fp_map.get(str(mac).lower()) or {}).get('status')
    if st == 'ok':
        ok_fp += 1
    elif st:
        ins_fp += 1

if not devices:
    body.append('<div class="empty-state"><div class="icon">📱</div><p>No watched device MACs configured yet.</p></div>')
else:
    viol_class = 'danger' if violations else 'success'
    fp_ok_class = 'success' if ok_fp else ''
    fp_ins_class = 'warning' if ins_fp else ''

    body.append('<div class="metrics">')
    body.append(f"<div class='metric'><span class='label'>Watched Devices</span> {len(devices)}</div>")
    body.append(f"<div class='metric {viol_class}'><span class='label'>Violations</span> {len(violations)}</div>")
    body.append(f"<div class='metric {fp_ok_class}'><span class='label'>Fingerprints OK</span> {ok_fp}</div>")
    body.append(f"<div class='metric {fp_ins_class}'><span class='label'>Fingerprints Insufficient</span> {ins_fp}</div>")
    body.append('</div>')

    # Fingerprint run summary
    if fp_summary:
        body.append(f"<p class='muted small'>Last fingerprint run: <code>{html.escape(str(fp_summary['updated_at']))}</code> · min_packets: {int(fp_summary['min_packets'])}</p>")
    else:
        body.append('<p class="muted small">No fingerprint runs recorded yet. Run <code>python3 scripts/fingerprint_devices.py</code></p>')

    if not violations:
        body.append('<div class="empty-state"><div class="icon">✅</div><p>No SSID violations detected in the recent window.</p></div>')
    else:
        for v in violations:
            who = f"{v['label']} ({v['mac']})" if v.get('label') else v['mac']
            alert_id = make_alert_id('device_violation', v['mac'], v['ssid'])
            # Already filtered out dismissed in active_violations
            
            draft_note = find_similar_feedback('device_violation', [v['mac'], v['ssid'], v.get('label', '')])
            if not draft_note:
                draft_note = "Unable to generate comments."
            _, prev_fb = latest_feedback(alert_id)
            prev_verdict = (prev_fb or {}).get('verdict', 'unsure')
            
            body.append(f'<div class="alert-item" id="alert-{html.escape(alert_id)}">')
            body.append(f"<h3>⚠️ {html.escape(who)}</h3>")
            body.append(f"<span class='badge'>Connected to: {html.escape(str(v['ssid']))}</span>")
            
            # Triage dropdown
            body.append(f'<details class="triage-toggle"><summary>💬 Triage & Comment</summary>')
            body.append(f'<div class="triage-box" data-alert-id="{html.escape(alert_id)}">')
            body.append(f'<textarea class="triage-note" placeholder="Add notes...">{html.escape(draft_note)}</textarea>')
            body.append('<div class="row">')
            
            def verdict_opt(val, label, selected):
                sel = ' selected' if selected == val else ''
                return f'<option value="{val}"{sel}>{label}</option>'
            
            body.append('<select class="triage-verdict">')
            body.append(verdict_opt('unsure', 'Unsure', prev_verdict))
            body.append(verdict_opt('benign', 'Benign', prev_verdict))
            body.append(verdict_opt('review', 'Needs Review', prev_verdict))
            body.append(verdict_opt('suspicious', 'Suspicious', prev_verdict))
            body.append('</select>')
            body.append(f'<label><input type="checkbox" class="triage-dismiss"> Dismiss</label>')
            body.append(f'<button onclick="saveFeedback(\'{html.escape(alert_id)}\')">Save</button>')
            body.append('<span class="status"></span>')
            body.append('</div></div></details>')
            body.append('</div>')

# Fingerprint status dropdown
lines = []
for mac, rec in sorted(devices.items(), key=lambda kv: (str(kv[1].get('label') or kv[0]).lower())):
    m = str(mac).lower()
    fp = fp_map.get(m) or {}
    label = str(rec.get('label') or '') if isinstance(rec, dict) else ''
    who = f"{label} ({m})" if label else m
    st = fp.get('status') or 'unknown'
    reason = fp.get('reason') or ''
    packets = fp.get('packets_total')
    fph = fp.get('fingerprint_hash') or ''
    extra = f" · packets={packets}" if packets is not None else ''
    if st == 'ok':
        lines.append(f"✓ {who} · fp={fph}{extra}")
    else:
        tail = (f" · {reason}" if reason else '')
        lines.append(f"✗ {who}{tail}{extra}")

body.append('<details><summary>View fingerprint status for selected devices</summary>')
body.append('<pre>' + html.escape('\n'.join(lines) or '(none)') + '</pre></details>')

# Device config dropdown
try:
    mac_cfg_text = json.dumps(mac_cfg, indent=2, sort_keys=True)
except Exception:
    mac_cfg_text = ''
body.append('<details><summary>View device/SSID configuration</summary>')
body.append('<pre>' + html.escape(mac_cfg_text or '(missing)') + '</pre></details>')

body.append('</div>')

# Unknown Devices Panel - devices seen on watched SSIDs but not in AdGuard
body.append('<div class="card">')
body.append('<h2><span class="icon">👤</span> Unknown Device Detection</h2>')

# Get all client MACs seen on watched SSIDs in recent window
unknown_devices = []

def is_locally_administered_mac(mac: str) -> bool:
    """Check if MAC is locally administered (randomized) vs globally unique (real device)."""
    try:
        # Second hex digit indicates local/global: 2, 6, A, E = local
        second_char = mac.replace(':', '')[1].lower()
        return second_char in ('2', '6', 'a', 'e')
    except:
        return False

if os.path.exists(DB_PATH) and watched and adguard_known_macs:
    con3 = sqlite3.connect(DB_PATH)
    con3.row_factory = sqlite3.Row
    since = int(time.time()) - 2*3600
    
    # Get all clients seen on watched SSIDs
    q = """
    SELECT DISTINCT lower(client_mac) as client_mac, ssid, max(ts) as ts_max, signal_dbm
    FROM wifi_client_sightings
    WHERE ssid IN ({}) AND ts >= ? AND client_mac IS NOT NULL AND client_mac != ''
    GROUP BY lower(client_mac), ssid
    ORDER BY ts_max DESC
    """.format(",".join(["?"]*len(watched)))
    cur = con3.execute(q, [*watched, since])
    
    for r in cur.fetchall():
        mac = str(r['client_mac']).lower()
        # Skip locally administered (randomized) MACs - these are just probing
        if is_locally_administered_mac(mac):
            continue
        if mac not in adguard_known_macs:
            alert_id = make_alert_id('unknown_device', mac, r['ssid'])
            if not is_dismissed(alert_id):
                unknown_devices.append({
                    'mac': mac,
                    'ssid': r['ssid'],
                    'ts': int(r['ts_max'] or 0),
                    'signal': r['signal_dbm'],
                    'alert_id': alert_id,
                })
    con3.close()

if not adguard_known_macs:
    body.append('<div class="empty-state"><div class="icon">⚠️</div><p>Could not fetch AdGuard Home client list.<br>Set ADGUARD_URL, ADGUARD_USER, ADGUARD_PASS in environment.</p></div>')
elif not watched:
    body.append('<div class="empty-state"><div class="icon">📡</div><p>No watched SSIDs configured.</p></div>')
else:
    unknown_class = 'danger' if unknown_devices else 'success'
    body.append('<div class="metrics">')
    body.append(f"<div class='metric'><span class='label'>Known Devices (AdGuard)</span> {len(adguard_known_macs)}</div>")
    body.append(f"<div class='metric {unknown_class}'><span class='label'>Unknown on Watched SSIDs</span> {len(unknown_devices)}</div>")
    body.append('</div>')
    
    if not unknown_devices:
        body.append('<div class="empty-state"><div class="icon">✅</div><p>No unknown devices detected on watched SSIDs.</p></div>')
    else:
        for ud in unknown_devices[:20]:  # Limit to 20 to avoid huge pages
            alert_id = ud['alert_id']
            mac = ud['mac']
            ssid = ud['ssid']
            ts_str = time.strftime('%Y-%m-%d %H:%M', time.localtime(ud['ts'])) if ud['ts'] else '?'
            signal = ud['signal'] or '?'
            
            body.append(f'<div class="alert-item" id="alert-{html.escape(alert_id)}">')
            body.append(f"<h3>👤 Unknown: {html.escape(mac)}</h3>")
            body.append('<div class="metrics">')
            body.append(f"<div class='metric'><span class='label'>SSID</span> {html.escape(ssid)}</div>")
            body.append(f"<div class='metric'><span class='label'>Last Seen</span> {html.escape(ts_str)}</div>")
            body.append(f"<div class='metric'><span class='label'>Signal</span> {html.escape(str(signal))} dBm</div>")
            body.append('</div>')
            
            # OUI lookup hint
            body.append(f"<p class='muted small'>OUI: {html.escape(mac[:8].upper())}</p>")
            
            # Simple dismiss button
            body.append(f'<div class="triage-box" data-alert-id="{html.escape(alert_id)}" style="padding:8px;margin-top:8px">')
            body.append('<div class="row">')
            body.append(f'<label><input type="checkbox" class="triage-dismiss"> Dismiss</label>')
            body.append(f'<button onclick="saveFeedback(\'{html.escape(alert_id)}\')">Save</button>')
            body.append('<span class="status"></span>')
            body.append('</div></div>')
            body.append('</div>')
        
        if len(unknown_devices) > 20:
            body.append(f"<p class='muted'>... and {len(unknown_devices) - 20} more unknown devices (showing first 20)</p>")

body.append('</div>')

body.append('</div>')  # close .container
body.append('<footer>HomeSigSec · RF Environment Monitor</footer>')
body.append(f'<script>{js_code}</script>')
body.append('</body></html>')

with open(OUT_HTML, 'w', encoding='utf-8') as f:
    f.write('\n'.join(body))
    f.write('\n')

print(f"[homesigsec] dashboard wrote {OUT_HTML} and {OUT_STATUS}")
PY

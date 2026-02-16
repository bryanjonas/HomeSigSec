#!/usr/bin/env python3
"""Persistent Wi-Fi client fingerprinting with verification and refinement.

Model:
- First observation with sufficient packets → establish baseline fingerprint
- Subsequent observations → compare against baseline, refine feature weights
- Track match/drift counts and confidence score

Features:
- probe_fp: Kismet probe fingerprint
- response_fp: Kismet response fingerprint  
- beacon_fp: Kismet beacon fingerprint
- typeset: Device type set
- kismet_type: Kismet device classification

Confidence:
- Starts at 0.5 when baseline established
- Increases with matches (up to 1.0)
- Decreases with drifts (down to 0.0)

Feature weights:
- Start at 1.0 for all features
- Stable features (same across observations) increase weight
- Volatile features decrease weight
- Used for weighted similarity scoring
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sqlite3
import sys
import time

# Source env file if KISMET_URL not set (fix for cron persistence)
def ensure_env():
    if os.environ.get("KISMET_URL"):
        return
    script_dir = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(script_dir, "..", "assets", ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    os.environ.setdefault(key.strip(), val.strip())

ensure_env()

import db as dbm
from kismet_client import post_json

TARGET_SSID = os.environ.get("HOMESIGSEC_TARGET_SSID", "MyHomeNetwork")

# Fingerprint feature keys
FEATURE_KEYS = ["kismet_type", "probe_fp", "response_fp", "beacon_fp", "typeset"]

# Confidence adjustment per observation
CONFIDENCE_MATCH_BOOST = 0.05
CONFIDENCE_DRIFT_PENALTY = 0.15
CONFIDENCE_MIN = 0.0
CONFIDENCE_MAX = 1.0
CONFIDENCE_INITIAL = 0.5

# Weight adjustment per observation
WEIGHT_STABLE_BOOST = 0.1
WEIGHT_VOLATILE_PENALTY = 0.2
WEIGHT_MIN = 0.1
WEIGHT_MAX = 2.0
WEIGHT_INITIAL = 1.0


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


def lower_mac(m: str) -> str:
    return str(m).strip().lower()


def compute_hash(features: dict) -> str:
    """Compute stable hash from feature dict."""
    blob = json.dumps(features, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def extract_features(kismet_item: dict) -> dict:
    """Extract fingerprint features from Kismet device record."""
    return {
        "kismet_type": str(kismet_item.get("kismet.device.base.type") or ""),
        "probe_fp": kismet_item.get("dot11.device.probe_fingerprint"),
        "response_fp": kismet_item.get("dot11.device.response_fingerprint"),
        "beacon_fp": kismet_item.get("dot11.device.beacon_fingerprint"),
        "typeset": kismet_item.get("dot11.device.typeset"),
    }


def compare_features(baseline: dict, observed: dict, weights: dict) -> tuple[float, dict]:
    """
    Compare observed features against baseline with weighting.
    Returns (similarity_score, feature_match_details).
    
    Similarity is weighted average of feature matches.
    """
    total_weight = 0.0
    weighted_match = 0.0
    details = {}
    
    for key in FEATURE_KEYS:
        w = weights.get(key, WEIGHT_INITIAL)
        base_val = baseline.get(key)
        obs_val = observed.get(key)
        
        # Normalize None/empty comparisons
        base_empty = base_val is None or base_val == "" or base_val == []
        obs_empty = obs_val is None or obs_val == "" or obs_val == []
        
        if base_empty and obs_empty:
            # Both empty = match
            match = 1.0
        elif base_empty or obs_empty:
            # One empty, one not = partial (could be device just woke up)
            match = 0.5
        elif base_val == obs_val:
            match = 1.0
        else:
            match = 0.0
        
        details[key] = {"match": match, "weight": w, "baseline": base_val, "observed": obs_val}
        total_weight += w
        weighted_match += match * w
    
    similarity = weighted_match / total_weight if total_weight > 0 else 0.0
    return similarity, details


def update_weights(current_weights: dict, match_details: dict) -> dict:
    """Adjust feature weights based on match results."""
    new_weights = dict(current_weights)
    
    for key in FEATURE_KEYS:
        detail = match_details.get(key, {})
        match = detail.get("match", 0.5)
        w = new_weights.get(key, WEIGHT_INITIAL)
        
        if match >= 1.0:
            # Feature is stable, increase weight
            w = min(WEIGHT_MAX, w + WEIGHT_STABLE_BOOST)
        elif match <= 0.0:
            # Feature changed, decrease weight
            w = max(WEIGHT_MIN, w - WEIGHT_VOLATILE_PENALTY)
        # match == 0.5 (partial) - no change
        
        new_weights[key] = round(w, 3)
    
    return new_weights


def migrate_old_fingerprints(con: sqlite3.Connection):
    """Migrate old schema fingerprints to new schema."""
    # Check if old columns exist
    cur = con.execute("PRAGMA table_info(device_fingerprints)")
    cols = {row["name"] for row in cur.fetchall()}
    
    if "baseline_hash" in cols:
        # Already migrated
        return
    
    # Old schema - need to recreate table
    print("[fingerprint] Migrating to new schema...")
    
    # Get old data
    try:
        old_data = con.execute("""
            SELECT device_mac, label, fingerprint_hash, features_json, 
                   packets_total, data_bytes, first_seen, last_seen, updated_at
            FROM device_fingerprints
        """).fetchall()
    except sqlite3.OperationalError:
        old_data = []
    
    # Drop and recreate
    con.execute("DROP TABLE IF EXISTS device_fingerprints")
    con.commit()
    dbm.init_db(con)
    
    # Migrate old fingerprints as established baselines
    for row in old_data:
        mac = row["device_mac"]
        label = row["label"]
        fp_hash = row["fingerprint_hash"]
        features = row["features_json"]
        packets = row["packets_total"]
        updated = row["updated_at"]
        
        con.execute("""
            INSERT INTO device_fingerprints 
            (device_mac, label, baseline_hash, baseline_features_json, baseline_established_at,
             baseline_packets, last_observed_hash, last_observed_features_json, last_observed_at,
             last_packets_total, observations_count, match_count, drift_count, confidence,
             feature_weights_json, data_bytes, first_seen, last_seen, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            mac, label, fp_hash, features, updated, packets,
            fp_hash, features, updated, packets,
            1, 1, 0, CONFIDENCE_INITIAL,
            json.dumps({k: WEIGHT_INITIAL for k in FEATURE_KEYS}),
            row["data_bytes"], row["first_seen"], row["last_seen"], updated
        ))
    
    con.commit()
    print(f"[fingerprint] Migrated {len(old_data)} existing fingerprints")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", default=os.environ.get("HOMESIGSEC_WORKDIR") or os.path.join(os.getcwd(), "output"))
    ap.add_argument("--min-packets", type=int, default=50)
    ap.add_argument("--similarity-threshold", type=float, default=0.7,
                    help="Similarity score below this is considered drift")
    args = ap.parse_args()

    workdir = os.path.abspath(args.workdir)
    state = os.path.join(workdir, "state")
    db_path = os.path.join(state, "homesigsec.sqlite")
    cfg_path = os.path.join(state, "device_allowed_ssids.local.json")

    if not os.path.exists(cfg_path):
        raise SystemExit(f"missing config: {cfg_path}")

    cfg = json.load(open(cfg_path, "r", encoding="utf-8"))
    devices = cfg.get("devices") if isinstance(cfg.get("devices"), dict) else {}

    # Select devices which explicitly allow TARGET_SSID
    targets = {}
    for mac, rec in devices.items():
        if not isinstance(rec, dict):
            continue
        allowed = rec.get("allowed_ssids") if isinstance(rec.get("allowed_ssids"), list) else []
        if TARGET_SSID in [str(x) for x in allowed]:
            targets[lower_mac(mac)] = {
                "label": str(rec.get("label") or ""),
                "allowed_ssids": [str(x) for x in allowed],
            }

    con = dbm.connect(db_path)
    dbm.init_db(con)
    migrate_old_fingerprints(con)

    # Pull the 802.11 view once and filter locally
    fields = [
        "kismet.device.base.macaddr",
        "kismet.device.base.type",
        "kismet.device.base.first_time",
        "kismet.device.base.last_time",
        "kismet.device.base.packets.total",
        "kismet.device.base.datasize",
        "kismet.common.signal.last_signal",
        "dot11.device/dot11.device.probe_fingerprint",
        "dot11.device/dot11.device.response_fingerprint",
        "dot11.device/dot11.device.beacon_fingerprint",
        "dot11.device/dot11.device.typeset",
        "dot11.device/dot11.device.last_bssid",
    ]

    payload = {"start": 0, "length": 5000, "datatable": False, "fields": fields}
    items = post_json("/devices/views/phy-IEEE802.11/devices.json", payload)
    if not isinstance(items, list):
        items = items.get("data") if isinstance(items, dict) else []

    by_mac = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        mac = it.get("kismet.device.base.macaddr")
        if not mac:
            continue
        by_mac[lower_mac(mac)] = it

    # Results tracking
    established = []  # New baselines
    verified = []     # Matched existing baseline
    drifted = []      # Diverged from baseline
    insufficient = []

    # Reset per-device status table each run
    con.execute("DELETE FROM fingerprint_device_status")
    con.commit()

    for mac, meta in targets.items():
        label = meta.get("label") or ""
        it = by_mac.get(mac)
        
        if not it:
            reason = "not in current Kismet view"
            insufficient.append((mac, label, reason))
            con.execute(
                """INSERT OR REPLACE INTO fingerprint_device_status
                   (device_mac, label, status, reason, packets_total, fingerprint_hash, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (mac, label, "insufficient", reason, None, None, now_iso())
            )
            continue

        packets_total = int(it.get("kismet.device.base.packets.total") or 0)
        data_bytes = int(it.get("kismet.device.base.datasize") or 0)
        first_seen = int(it.get("kismet.device.base.first_time") or 0)
        last_seen = int(it.get("kismet.device.base.last_time") or 0)
        
        features = extract_features(it)
        obs_hash = compute_hash(features)
        
        # Check existing fingerprint
        row = con.execute(
            "SELECT * FROM device_fingerprints WHERE device_mac = ?", (mac,)
        ).fetchone()
        
        now = now_iso()
        
        if row is None:
            # No existing record
            if packets_total < args.min_packets and not (features.get("probe_fp") or features.get("response_fp")):
                reason = f"low packets_total={packets_total}"
                insufficient.append((mac, label, reason))
                con.execute(
                    """INSERT OR REPLACE INTO fingerprint_device_status
                       (device_mac, label, status, reason, packets_total, fingerprint_hash, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (mac, label, "insufficient", reason, packets_total, None, now)
                )
                continue
            
            # Establish new baseline
            init_weights = {k: WEIGHT_INITIAL for k in FEATURE_KEYS}
            con.execute("""
                INSERT INTO device_fingerprints
                (device_mac, label, baseline_hash, baseline_features_json, baseline_established_at,
                 baseline_packets, last_observed_hash, last_observed_features_json, last_observed_at,
                 last_packets_total, observations_count, match_count, drift_count, confidence,
                 feature_weights_json, data_bytes, first_seen, last_seen, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                mac, label, obs_hash, json.dumps(features), now, packets_total,
                obs_hash, json.dumps(features), now, packets_total,
                1, 1, 0, CONFIDENCE_INITIAL,
                json.dumps(init_weights),
                data_bytes, first_seen, last_seen, now
            ))
            con.execute(
                """INSERT OR REPLACE INTO fingerprint_device_status
                   (device_mac, label, status, reason, packets_total, fingerprint_hash, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (mac, label, "established", "baseline created", packets_total, obs_hash, now)
            )
            established.append((mac, label, obs_hash, packets_total, CONFIDENCE_INITIAL))
            
        elif row["baseline_hash"] is None:
            # Record exists but no baseline yet (shouldn't happen, but handle it)
            if packets_total < args.min_packets and not (features.get("probe_fp") or features.get("response_fp")):
                reason = f"low packets_total={packets_total}"
                insufficient.append((mac, label, reason))
                con.execute(
                    """INSERT OR REPLACE INTO fingerprint_device_status
                       (device_mac, label, status, reason, packets_total, fingerprint_hash, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (mac, label, "insufficient", reason, packets_total, None, now)
                )
                continue
            
            init_weights = {k: WEIGHT_INITIAL for k in FEATURE_KEYS}
            con.execute("""
                UPDATE device_fingerprints SET
                    baseline_hash = ?, baseline_features_json = ?, baseline_established_at = ?,
                    baseline_packets = ?, last_observed_hash = ?, last_observed_features_json = ?,
                    last_observed_at = ?, last_packets_total = ?, observations_count = 1,
                    match_count = 1, drift_count = 0, confidence = ?,
                    feature_weights_json = ?, updated_at = ?
                WHERE device_mac = ?
            """, (
                obs_hash, json.dumps(features), now, packets_total,
                obs_hash, json.dumps(features), now, packets_total,
                CONFIDENCE_INITIAL, json.dumps(init_weights), now, mac
            ))
            con.execute(
                """INSERT OR REPLACE INTO fingerprint_device_status
                   (device_mac, label, status, reason, packets_total, fingerprint_hash, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (mac, label, "established", "baseline created", packets_total, obs_hash, now)
            )
            established.append((mac, label, obs_hash, packets_total, CONFIDENCE_INITIAL))
            
        else:
            # Baseline exists - compare and refine
            baseline_features = json.loads(row["baseline_features_json"])
            current_weights = json.loads(row["feature_weights_json"] or "{}")
            for k in FEATURE_KEYS:
                current_weights.setdefault(k, WEIGHT_INITIAL)
            
            obs_count = (row["observations_count"] or 0) + 1
            match_count = row["match_count"] or 0
            drift_count = row["drift_count"] or 0
            confidence = row["confidence"] or CONFIDENCE_INITIAL
            
            similarity, match_details = compare_features(baseline_features, features, current_weights)
            new_weights = update_weights(current_weights, match_details)
            
            if similarity >= args.similarity_threshold:
                # Match - boost confidence
                match_count += 1
                confidence = min(CONFIDENCE_MAX, confidence + CONFIDENCE_MATCH_BOOST)
                status = "verified"
                verified.append((mac, label, obs_hash, row["baseline_hash"], similarity, confidence))
            else:
                # Drift - penalize confidence
                drift_count += 1
                confidence = max(CONFIDENCE_MIN, confidence - CONFIDENCE_DRIFT_PENALTY)
                status = "drift"
                drifted.append((mac, label, obs_hash, row["baseline_hash"], similarity, confidence, match_details))
            
            con.execute("""
                UPDATE device_fingerprints SET
                    last_observed_hash = ?, last_observed_features_json = ?, last_observed_at = ?,
                    last_packets_total = ?, observations_count = ?, match_count = ?, drift_count = ?,
                    confidence = ?, feature_weights_json = ?, last_seen = ?, updated_at = ?
                WHERE device_mac = ?
            """, (
                obs_hash, json.dumps(features), now, packets_total,
                obs_count, match_count, drift_count, round(confidence, 3),
                json.dumps(new_weights), last_seen, now, mac
            ))
            con.execute(
                """INSERT OR REPLACE INTO fingerprint_device_status
                   (device_mac, label, status, reason, packets_total, fingerprint_hash, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (mac, label, status, f"sim={similarity:.2f} conf={confidence:.2f}", packets_total, obs_hash, now)
            )
    
    con.commit()

    # Record run summary
    con.execute(
        """INSERT INTO fingerprint_runs(ts, updated_at, stored, insufficient, min_packets)
           VALUES (?, ?, ?, ?, ?)""",
        (int(time.time()), now_iso(), len(established) + len(verified), len(insufficient), args.min_packets)
    )
    con.commit()

    # Output summary
    print(f"=== Fingerprint Summary ===")
    
    if established:
        print(f"\nbaselines_established={len(established)}")
        for mac, label, fph, packets, conf in sorted(established, key=lambda x: x[1] or x[0]):
            who = f"{label} ({mac})" if label else mac
            print(f"  ✓ {who}: hash={fph} packets={packets} conf={conf:.2f}")
    
    if verified:
        print(f"\nverified_matches={len(verified)}")
        for mac, label, obs_h, base_h, sim, conf in sorted(verified, key=lambda x: x[1] or x[0]):
            who = f"{label} ({mac})" if label else mac
            print(f"  ✓ {who}: sim={sim:.2f} conf={conf:.2f}")
    
    if drifted:
        print(f"\n⚠️  fingerprint_drifts={len(drifted)}")
        for mac, label, obs_h, base_h, sim, conf, details in sorted(drifted, key=lambda x: x[1] or x[0]):
            who = f"{label} ({mac})" if label else mac
            print(f"  ⚠ {who}: sim={sim:.2f} conf={conf:.2f} baseline={base_h} observed={obs_h}")
            for k, d in details.items():
                if d["match"] < 1.0:
                    print(f"      {k}: baseline={d['baseline']} → observed={d['observed']}")
    
    if insufficient:
        print(f"\ninsufficient_data={len(insufficient)}")
        for mac, label, reason in sorted(insufficient, key=lambda x: x[1] or x[0]):
            who = f"{label} ({mac})" if label else mac
            print(f"  - {who}: {reason}")
    
    # Exit with error if any drifts detected (for alerting)
    if drifted:
        sys.exit(2)


if __name__ == "__main__":
    main()

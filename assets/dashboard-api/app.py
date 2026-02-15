#!/usr/bin/env python3
"""Minimal HomeSigSec dashboard API.

This mirrors the HomeNetSec pattern: persist small user feedback locally under output/state.
No secrets are embedded.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from flask import Flask, request, jsonify

app = Flask(__name__)


def workdir() -> str:
    return os.environ.get("HOMESIGSEC_WORKDIR", "/work/output")


def db_path() -> str:
    return os.path.join(workdir(), "state", "homesigsec.sqlite")


def get_db() -> sqlite3.Connection:
    con = sqlite3.connect(db_path())
    con.row_factory = sqlite3.Row
    return con


def feedback_path() -> str:
    return os.path.join(workdir(), "state", "feedback.json")


def _load() -> dict:
    try:
        with open(feedback_path(), "r", encoding="utf-8") as f:
            j = json.load(f)
            return j if isinstance(j, dict) else {"days": {}}
    except FileNotFoundError:
        return {"days": {}}
    except Exception:
        return {"days": {}}


def _save(j: dict) -> None:
    os.makedirs(os.path.dirname(feedback_path()), exist_ok=True)
    tmp = feedback_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(j, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, feedback_path())


@app.get("/feedback")
def get_feedback():
    day = request.args.get("day", "")
    db = _load()
    days = db.get("days") if isinstance(db.get("days"), dict) else {}
    return jsonify({"day": day, "feedback": (days.get(day) or {})})


@app.post("/feedback")
def put_feedback():
    body = request.get_json(force=True, silent=True) or {}
    day = str(body.get("day") or "")
    alert_id = str(body.get("alert_id") or "")
    if not day or not alert_id:
        return jsonify({"ok": False, "error": "missing day/alert_id"}), 400

    rec = {
        "updated_at": body.get("updated_at") or time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "verdict": body.get("verdict") or "unsure",
        "note": body.get("note") or "",
        "dismissed": bool(body.get("dismissed")),
    }

    db = _load()
    db.setdefault("days", {})
    if not isinstance(db["days"], dict):
        db["days"] = {}
    db["days"].setdefault(day, {})
    if not isinstance(db["days"][day], dict):
        db["days"][day] = {}
    db["days"][day][alert_id] = rec

    _save(db)
    return jsonify({"ok": True})


@app.get("/fingerprints")
def get_fingerprints():
    """Return fingerprint status for all tracked devices."""
    try:
        con = get_db()
        rows = con.execute("""
            SELECT device_mac, label, baseline_hash, baseline_established_at, baseline_packets,
                   last_observed_hash, last_observed_at, last_packets_total,
                   observations_count, match_count, drift_count, confidence, feature_weights_json
            FROM device_fingerprints
            ORDER BY label, device_mac
        """).fetchall()
        con.close()
        
        devices = []
        for r in rows:
            devices.append({
                "mac": r["device_mac"],
                "label": r["label"],
                "baseline_hash": r["baseline_hash"],
                "baseline_established_at": r["baseline_established_at"],
                "baseline_packets": r["baseline_packets"],
                "last_observed_hash": r["last_observed_hash"],
                "last_observed_at": r["last_observed_at"],
                "last_packets": r["last_packets_total"],
                "observations": r["observations_count"],
                "matches": r["match_count"],
                "drifts": r["drift_count"],
                "confidence": r["confidence"],
                "weights": json.loads(r["feature_weights_json"]) if r["feature_weights_json"] else {},
                "status": "drift" if (r["last_observed_hash"] and r["baseline_hash"] and r["last_observed_hash"] != r["baseline_hash"]) else "ok"
            })
        
        return jsonify({"fingerprints": devices})
    except Exception as e:
        return jsonify({"fingerprints": [], "error": str(e)})


@app.get("/fingerprint_status")
def get_fingerprint_status():
    """Return current run status for fingerprint devices."""
    try:
        con = get_db()
        rows = con.execute("""
            SELECT device_mac, label, status, reason, packets_total, fingerprint_hash, updated_at
            FROM fingerprint_device_status
            ORDER BY label, device_mac
        """).fetchall()
        con.close()
        
        return jsonify({"status": [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({"status": [], "error": str(e)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

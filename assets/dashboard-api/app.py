#!/usr/bin/env python3
"""Minimal HomeSigSec dashboard API.

This mirrors the HomeNetSec pattern: persist small user feedback locally under output/state.
No secrets are embedded.
"""

from __future__ import annotations

import json
import os
import time
from flask import Flask, request, jsonify

app = Flask(__name__)


def workdir() -> str:
    return os.environ.get("HOMESIGSEC_WORKDIR", "/work/output")


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

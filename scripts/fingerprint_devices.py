#!/usr/bin/env python3
"""Generate best-effort Wi-Fi client fingerprints for devices on MyHomeNetwork.

- Loads local device policy from $HOMESIGSEC_WORKDIR/state/device_allowed_ssids.local.json
- For devices allowed only on SSID "MyHomeNetwork", pulls Kismet 802.11 device records
- Computes a stable fingerprint hash from selected Kismet dot11 fields
- Stores to sqlite table device_fingerprints (local-only DB)

This is probabilistic; the goal is to build a baseline fingerprint for later matching.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sqlite3
import time

import db as dbm
from kismet_client import post_json

TARGET_SSID = "MyHomeNetwork"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


def lower_mac(m: str) -> str:
    return str(m).strip().lower()


def compute_hash(features: dict) -> str:
    # Hash a canonical JSON representation.
    blob = json.dumps(features, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", default=os.environ.get("HOMESIGSEC_WORKDIR") or os.path.join(os.getcwd(), "output"))
    ap.add_argument("--min-packets", type=int, default=50)
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

    # Pull the 802.11 view once and filter locally (cheaper than 10 requests).
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
        # Some Kismet versions wrap; be defensive.
        items = items.get("data") if isinstance(items, dict) else []

    by_mac = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        mac = it.get("kismet.device.base.macaddr")
        if not mac:
            continue
        by_mac[lower_mac(mac)] = it

    insufficient = []
    stored = []

    # Reset per-device status table each run (local-only DB)
    con.execute("DELETE FROM fingerprint_device_status")
    con.commit()

    for mac, meta in targets.items():
        it = by_mac.get(mac)
        if not it:
            reason = "not in current Kismet view"
            insufficient.append((mac, meta.get("label"), reason))
            con.execute(
                "INSERT OR REPLACE INTO fingerprint_device_status(device_mac,label,status,reason,packets_total,fingerprint_hash,updated_at) VALUES (?,?,?,?,?,?,?)",
                (mac, meta.get("label") or "", "insufficient", reason, None, None, now_iso()),
            )
            con.commit()
            continue

        typ = str(it.get("kismet.device.base.type") or "")
        pkt = it.get("kismet.device.base.packets.total")
        packets_total = int(pkt) if isinstance(pkt, (int, float)) else 0
        data_bytes = int(it.get("kismet.device.base.datasize") or 0) if str(it.get("kismet.device.base.datasize") or "").isdigit() else it.get("kismet.device.base.datasize")
        first_seen = int(it.get("kismet.device.base.first_time") or 0) if str(it.get("kismet.device.base.first_time") or "").isdigit() else None
        last_seen = int(it.get("kismet.device.base.last_time") or 0) if str(it.get("kismet.device.base.last_time") or "").isdigit() else None

        # Fingerprint ingredients (best-effort)
        feats = {
            "kismet_type": typ,
            "probe_fp": it.get("dot11.device.probe_fingerprint"),
            "response_fp": it.get("dot11.device.response_fingerprint"),
            "beacon_fp": it.get("dot11.device.beacon_fingerprint"),
            "typeset": it.get("dot11.device.typeset"),
        }

        # Determine if we have enough information
        if packets_total < args.min_packets and not (feats.get("probe_fp") or feats.get("response_fp")):
            reason = f"low packets_total={packets_total}"
            insufficient.append((mac, meta.get("label"), reason))
            con.execute(
                "INSERT OR REPLACE INTO fingerprint_device_status(device_mac,label,status,reason,packets_total,fingerprint_hash,updated_at) VALUES (?,?,?,?,?,?,?)",
                (mac, meta.get("label") or "", "insufficient", reason, packets_total, None, now_iso()),
            )
            con.commit()
            continue

        fph = compute_hash(feats)

        con.execute(
            """
            INSERT OR REPLACE INTO device_fingerprints
              (device_mac, label, fingerprint_hash, features_json, packets_total, data_bytes, first_seen, last_seen, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                mac,
                meta.get("label") or "",
                fph,
                json.dumps(feats, sort_keys=True),
                packets_total,
                int(data_bytes) if isinstance(data_bytes, (int, float)) else None,
                first_seen,
                last_seen,
                now_iso(),
            ),
        )
        con.execute(
            "INSERT OR REPLACE INTO fingerprint_device_status(device_mac,label,status,reason,packets_total,fingerprint_hash,updated_at) VALUES (?,?,?,?,?,?,?)",
            (mac, meta.get("label") or "", "ok", "", packets_total, fph, now_iso()),
        )
        con.commit()
        stored.append((mac, meta.get("label"), fph, packets_total))

    # record run summary
    con.execute(
        "INSERT INTO fingerprint_runs(ts, updated_at, stored, insufficient, min_packets) VALUES (?,?,?,?,?)",
        (int(time.time()), now_iso(), len(stored), len(insufficient), int(args.min_packets)),
    )
    con.commit()

    print(f"fingerprints_stored={len(stored)}")
    for mac, label, fph, packets in sorted(stored, key=lambda x: (x[1] or x[0])):
        who = f"{label} ({mac})" if label else mac
        print(f"- {who}: fp={fph} packets_total={packets}")

    print(f"\ninsufficient_for_fingerprint={len(insufficient)}")
    for mac, label, why in sorted(insufficient, key=lambda x: (x[1] or x[0])):
        who = f"{label} ({mac})" if label else mac
        print(f"- {who}: {why}")


if __name__ == "__main__":
    main()

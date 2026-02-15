#!/usr/bin/env python3
"""Poll Kismet device views and persist raw + normalized records.

Writes:
- raw gz snapshots (7d retention handled by separate cleanup job)
- sqlite sightings + poll audit

This script intentionally keeps parsing conservative; we'll tighten as we learn Kismet fields.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import os
import time

import db as dbm
from kismet_client import post_json


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


def write_raw(workdir: str, view: str, since: str, payload_obj) -> tuple[str, int, int]:
    day = dt.datetime.now().astimezone().strftime("%Y-%m-%d")
    out_dir = os.path.join(workdir, "raw", day)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{view}.json.gz")

    record = {
        "fetched_at": iso_now(),
        "view": view,
        "since": since,
        "payload": payload_obj,
    }
    raw = (json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    gz = gzip.compress(raw)
    with open(out_path, "ab") as f:
        f.write(gz)
    return out_path, len(raw), len(gz)


def _get_items(resp):
    if isinstance(resp, list):
        return resp
    if isinstance(resp, dict) and isinstance(resp.get("data"), list):
        return resp.get("data")
    if isinstance(resp, dict) and isinstance(resp.get("devices"), list):
        return resp.get("devices")
    return []


def _maybe_int(x):
    try:
        if x is None:
            return None
        if isinstance(x, bool):
            return int(x)
        if isinstance(x, (int, float)):
            return int(x)
        if isinstance(x, str) and x.strip():
            return int(float(x.strip()))
    except Exception:
        return None
    return None


def ingest_ap_view(con, ts_now: int, view: str, items: list[dict]):
    cur = con.cursor()
    for it in items:
        if not isinstance(it, dict):
            continue
        bssid = it.get("kismet.device.base.macaddr")
        bssid = str(bssid).lower() if bssid else bssid
        last_time = _maybe_int(it.get("kismet.device.base.last_time"))
        first_time = _maybe_int(it.get("kismet.device.base.first_time"))
        channel = it.get("kismet.device.base.channel")
        freq = _maybe_int(it.get("kismet.device.base.frequency"))

        # signal may be nested or promoted
        sig = _maybe_int(it.get("kismet.common.signal.last_signal"))
        if sig is None:
            s = it.get("kismet.device.base.signal")
            if isinstance(s, dict):
                sig = _maybe_int(s.get("kismet.common.signal.last_signal"))

        # SSID(s) can appear either nested under it['dot11.device'] (full records)
        # or promoted to a flat key like 'dot11.device.advertised_ssid_map' when using
        # field simplification.
        amap = None
        dot11 = it.get("dot11.device") if isinstance(it.get("dot11.device"), dict) else None
        if isinstance(dot11, dict):
            amap = dot11.get("dot11.device.advertised_ssid_map")
        if amap is None:
            amap = it.get("dot11.device.advertised_ssid_map")
        if not isinstance(amap, list):
            amap = []

        for rec in amap:
            if not isinstance(rec, dict):
                continue
            ssid = rec.get("dot11.advertisedssid.ssid")
            if ssid is None:
                continue
            cur.execute(
                """
                INSERT OR REPLACE INTO wifi_ap_sightings
                  (ts, ssid, bssid, channel, frequency, signal_dbm, first_seen, last_seen, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (ts_now, ssid, bssid, channel, freq, sig, first_time, last_time, view),
            )
    con.commit()


def _infer_ssid_for_bssid(con, bssid: str) -> str:
    # Use most recent AP sighting for this BSSID.
    try:
        row = con.execute(
            """
            SELECT ssid FROM wifi_ap_sightings
            WHERE bssid = ? AND ssid IS NOT NULL AND ssid != ''
            ORDER BY ts DESC
            LIMIT 1
            """,
            (bssid,),
        ).fetchone()
        if row and row[0]:
            return str(row[0])
    except Exception:
        return ""
    return ""


def ingest_client_view(con, ts_now: int, view: str, items: list[dict]):
    cur = con.cursor()
    for it in items:
        if not isinstance(it, dict):
            continue

        typ = (it.get("kismet.device.base.type") or "").strip()
        if typ not in ("Wi-Fi Client", "Wi-Fi Device"):
            # Keep it conservative; AP types would create noise.
            continue

        mac = it.get("kismet.device.base.macaddr")
        if not mac:
            continue
        mac = str(mac).lower()

        last_time = _maybe_int(it.get("kismet.device.base.last_time"))
        first_time = _maybe_int(it.get("kismet.device.base.first_time"))

        sig = _maybe_int(it.get("kismet.common.signal.last_signal"))
        if sig is None:
            s = it.get("kismet.device.base.signal")
            if isinstance(s, dict):
                sig = _maybe_int(s.get("kismet.common.signal.last_signal"))

        # associated bssid
        assoc = None
        dot11 = it.get("dot11.device") if isinstance(it.get("dot11.device"), dict) else None
        if isinstance(dot11, dict):
            assoc = dot11.get("dot11.device.last_bssid")
        if assoc is None:
            assoc = it.get("dot11.device.last_bssid")
        assoc = str(assoc).lower() if assoc else ""

        # typeset - bitmask indicating frame types seen
        typeset = None
        if isinstance(dot11, dict):
            typeset = _maybe_int(dot11.get("dot11.device.typeset"))
        if typeset is None:
            typeset = _maybe_int(it.get("dot11.device.typeset"))

        # Packet counts - key indicators of actual connection
        # packets.total = all frames
        # packets.data = DATA frames only (To-DS/From-DS) - definitive proof of association
        packets = _maybe_int(it.get("kismet.device.base.packets.total"))
        packets_data = None
        pkts_obj = it.get("kismet.device.base.packets")
        if isinstance(pkts_obj, dict):
            packets_data = _maybe_int(pkts_obj.get("kismet.device.base.packets.data"))
        if packets_data is None:
            packets_data = _maybe_int(it.get("kismet.device.base.packets.data"))
        datasize = _maybe_int(it.get("kismet.device.base.datasize"))

        ssid = _infer_ssid_for_bssid(con, assoc) if assoc else ""

        cur.execute(
            """
            INSERT OR REPLACE INTO wifi_client_sightings
              (ts, client_mac, associated_bssid, ssid, signal_dbm, typeset, packets, packets_data, datasize, first_seen, last_seen, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ts_now, mac, assoc, ssid, sig, typeset, packets, packets_data, datasize, first_time, last_time, view),
        )
    con.commit()


def main():
    import sys
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", default=os.environ.get("HOMESIGSEC_WORKDIR") or os.path.join(os.getcwd(), "output"))
    ap.add_argument("--views", default="phydot11_accesspoints")
    ap.add_argument("--since", default="-300", help="Kismet last-time timestamp (e.g. -300 or epoch)")
    ap.add_argument("--full", action="store_true", help="Do not use field simplification")
    args = ap.parse_args()
    
    had_errors = False

    workdir = os.path.abspath(args.workdir)
    os.makedirs(workdir, exist_ok=True)

    db_path = os.path.join(workdir, "state", "homesigsec.sqlite")
    con = dbm.connect(db_path)
    dbm.init_db(con)

    ts_now = int(time.time())

    views = [v.strip() for v in args.views.split(",") if v.strip()]

    for view in views:
        started = iso_now()
        status = "ok"
        err = ""
        raw_bytes = 0
        gz_bytes = 0
        items_count = 0

        try:
            # NOTE: Some Kismet views may not return results for short last-time windows.
            # We'll start with /devices.json (optionally filtered later) and evolve toward
            # eventbus/websocket for high-fidelity event capture.
            path = f"/devices/views/{view}/devices.json"

            payload = {"start": 0, "length": 5000, "datatable": False}
            if not args.full:
                # minimal fields to keep storage manageable (per view)
                if view == "phydot11_accesspoints":
                    payload["fields"] = [
                        "kismet.device.base.macaddr",
                        "kismet.device.base.first_time",
                        "kismet.device.base.last_time",
                        "kismet.device.base.channel",
                        "kismet.device.base.frequency",
                        "kismet.device.base.signal/kismet.common.signal.last_signal",
                        "dot11.device/dot11.device.advertised_ssid_map",
                    ]
                elif view == "phy-IEEE802.11":
                    payload["fields"] = [
                        "kismet.device.base.macaddr",
                        "kismet.device.base.type",
                        "kismet.device.base.first_time",
                        "kismet.device.base.last_time",
                        "kismet.device.base.signal/kismet.common.signal.last_signal",
                        "kismet.device.base.packets.total",
                        "kismet.device.base.packets.data",
                        "kismet.device.base.datasize",
                        "dot11.device/dot11.device.last_bssid",
                        "dot11.device/dot11.device.typeset",
                    ]
                else:
                    payload["fields"] = [
                        "kismet.device.base.macaddr",
                        "kismet.device.base.type",
                        "kismet.device.base.first_time",
                        "kismet.device.base.last_time",
                    ]

            resp = post_json(path, payload)
            items = _get_items(resp)
            items_count = len(items)

            _, rb, gb = write_raw(workdir, view, args.since, resp)
            raw_bytes, gz_bytes = rb, gb

            if view == "phydot11_accesspoints":
                ingest_ap_view(con, ts_now, view, items)
            elif view == "phy-IEEE802.11":
                ingest_client_view(con, ts_now, view, items)

        except Exception as e:
            status = "error"
            err = str(e)
            had_errors = True

        finished = iso_now()
        con.execute(
            """
            INSERT INTO poll_runs
              (started_at, finished_at, view, since_param, status, items_count, raw_bytes, gzip_bytes, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (started, finished, view, args.since, status, items_count, raw_bytes, gz_bytes, err),
        )
        con.commit()

        print(f"[homesigsec] view={view} status={status} items={items_count} raw_bytes={raw_bytes} gzip_bytes={gz_bytes}")
        if err:
            print(f"[homesigsec] error: {err}")

    if had_errors:
        print("[homesigsec] FATAL: one or more views failed to poll")
        sys.exit(1)


if __name__ == "__main__":
    main()

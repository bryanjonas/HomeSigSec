#!/usr/bin/env python3
"""HomeSigSec: Kismet eventbus collector (passive-only).

Connects to Kismet /eventbus/events.ws and subscribes to selected topics.
Persists:
- raw gzipped event records under $HOMESIGSEC_WORKDIR/raw-eventbus/YYYY-MM-DD/events.json.gz
- normalized event rows in sqlite ($HOMESIGSEC_WORKDIR/state/homesigsec.sqlite)

No secrets in repo. Auth comes from env:
- KISMET_API_TOKEN or KISMET_USER/KISMET_PASS
- KISMET_URL
"""

from __future__ import annotations

import asyncio
import datetime as dt
import gzip
import json
import os
import sqlite3
import time
import urllib.parse

import websockets

import db as dbm


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


def day_local() -> str:
    return dt.datetime.now().astimezone().strftime("%Y-%m-%d")


def build_ws_url() -> str:
    kismet_url = (os.environ.get("KISMET_URL") or "").strip().rstrip("/")
    if not kismet_url:
        raise RuntimeError("KISMET_URL missing")

    if kismet_url.startswith("https://"):
        ws_base = "wss://" + kismet_url[len("https://") :]
    elif kismet_url.startswith("http://"):
        ws_base = "ws://" + kismet_url[len("http://") :]
    else:
        ws_base = "ws://" + kismet_url

    params = {}
    token = (os.environ.get("KISMET_API_TOKEN") or "").strip()
    user = (os.environ.get("KISMET_USER") or "").strip()
    pw = (os.environ.get("KISMET_PASS") or "").strip()

    if token:
        params["KISMET"] = token
    elif user and pw:
        params["user"] = user
        params["password"] = pw

    url = ws_base + "/eventbus/events.ws"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    return url


def workdir() -> str:
    w = os.environ.get("HOMESIGSEC_WORKDIR")
    if not w:
        # default to repo-local output if running from workspace
        w = os.path.abspath(os.path.join(os.getcwd(), "output"))
    return os.path.abspath(w)


def db_path() -> str:
    return os.path.join(workdir(), "state", "homesigsec.sqlite")


def raw_path() -> str:
    return os.path.join(workdir(), "raw-eventbus", day_local(), "events.json.gz")


def _lower_mac(x) -> str:
    return str(x).strip().lower()


def detect_topic(msg: dict) -> str:
    # Kismet eventbus often emits dicts keyed by topic names for subscribed topics.
    # For example: {"DOT11_PROBED_SSID": {...}, "DOT11_NEW_SSID_BASEDEV": {...}}
    known = [
        "DOT11_PROBED_SSID",
        "DOT11_ADVERTISED_SSID",
        "DOT11_RESPONSE_SSID",
        "DOT11_WPA_HANDSHAKE",
        "ALERT",
        "MESSAGE",
    ]
    for k in known:
        if k in msg:
            return k
    # fallback: if exactly one key, treat it as topic
    if len(msg.keys()) == 1:
        return list(msg.keys())[0]
    return "unknown"


def extract_mac_bssid(msg: dict) -> tuple[str, str]:
    mac = ""
    bssid = ""

    # DOT11_NEW_SSID_BASEDEV often contains base device record
    base = msg.get("DOT11_NEW_SSID_BASEDEV")
    if isinstance(base, dict):
        mac = base.get("kismet.device.base.macaddr") or mac

    # WPA handshake events embed base + dot11-specific keys (per docs)
    base2 = msg.get("DOT11_WPA_HANDSHAKE_BASEDEV")
    if isinstance(base2, dict):
        mac = base2.get("kismet.device.base.macaddr") or mac

    dot11 = msg.get("DOT11_WPA_HANDSHAKE_DOT11")
    if isinstance(dot11, dict):
        bssid = dot11.get("dot11.device.last_bssid") or bssid

    # As a fallback, look for obvious keys
    for k in ("mac", "macaddr", "client_mac", "kismet.device.base.macaddr"):
        if k in msg and isinstance(msg.get(k), str):
            mac = msg.get(k)

    if mac:
        mac = _lower_mac(mac)
    if bssid:
        bssid = _lower_mac(bssid)
    return mac, bssid


def append_raw(j: dict) -> tuple[int, int]:
    os.makedirs(os.path.dirname(raw_path()), exist_ok=True)
    raw = (json.dumps({"received_at": iso_now(), "event": j}, ensure_ascii=False) + "\n").encode("utf-8")
    gz = gzip.compress(raw)
    with open(raw_path(), "ab") as f:
        f.write(gz)
    return len(raw), len(gz)


def store_event(con: sqlite3.Connection, topic: str, mac: str, bssid: str, raw_bytes: int, gz_bytes: int, payload: dict):
    ts = int(time.time())
    con.execute(
        """
        INSERT INTO eventbus_events
          (ts, topic, mac, bssid, raw_bytes, gzip_bytes, payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (ts, topic, mac or "", bssid or "", raw_bytes, gz_bytes, json.dumps(payload, sort_keys=True)[:200000]),
    )
    con.commit()


def ensure_meta(con: sqlite3.Connection, key: str, val: str):
    con.execute(
        "INSERT OR REPLACE INTO meta_kv(k,v,updated_at) VALUES (?,?,?)",
        (key, val, iso_now()),
    )
    con.commit()


async def main():
    url = build_ws_url()

    con = dbm.connect(db_path())
    dbm.init_db(con)

    subs = [
        "DOT11_PROBED_SSID",
        "DOT11_ADVERTISED_SSID",
        "DOT11_WPA_HANDSHAKE",
        "ALERT",
    ]

    ensure_meta(con, "eventbus_collector.status", "starting")

    while True:
        try:
            async with websockets.connect(url, open_timeout=15, close_timeout=5, ping_interval=20) as ws:
                ensure_meta(con, "eventbus_collector.status", "connected")
                ensure_meta(con, "eventbus_collector.connected_at", iso_now())

                for t in subs:
                    await ws.send(json.dumps({"SUBSCRIBE": t}))

                while True:
                    raw = await ws.recv()
                    try:
                        j = json.loads(raw)
                    except Exception:
                        continue

                    topic = detect_topic(j)
                    mac, bssid = extract_mac_bssid(j)
                    rb, gb = append_raw(j)
                    store_event(con, topic, mac, bssid, rb, gb, j)
                    ensure_meta(con, "eventbus_collector.last_event_at", iso_now())
        except Exception as e:
            ensure_meta(con, "eventbus_collector.status", f"error: {type(e).__name__}: {e}")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""HomeSigSec sqlite helpers.

No secrets in repo. DB lives under $HOMESIGSEC_WORKDIR/state/homesigsec.sqlite (gitignored).
"""

from __future__ import annotations

import os
import sqlite3


SCHEMA_SQL = r"""
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS meta_kv (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS poll_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  view TEXT NOT NULL,
  since_param TEXT NOT NULL,
  status TEXT NOT NULL,
  items_count INTEGER,
  raw_bytes INTEGER,
  gzip_bytes INTEGER,
  error TEXT
);

CREATE TABLE IF NOT EXISTS wifi_ap_sightings (
  ts INTEGER NOT NULL,
  ssid TEXT,
  bssid TEXT,
  channel TEXT,
  frequency INTEGER,
  signal_dbm INTEGER,
  first_seen INTEGER,
  last_seen INTEGER,
  source TEXT,
  PRIMARY KEY (ts, bssid, ssid)
);
CREATE INDEX IF NOT EXISTS idx_wifi_ap_ssid_bssid_ts ON wifi_ap_sightings (ssid, bssid, ts);
CREATE INDEX IF NOT EXISTS idx_wifi_ap_bssid_ts ON wifi_ap_sightings (bssid, ts);

CREATE TABLE IF NOT EXISTS wifi_client_sightings (
  ts INTEGER NOT NULL,
  client_mac TEXT NOT NULL,
  associated_bssid TEXT,
  ssid TEXT,
  signal_dbm INTEGER,
  first_seen INTEGER,
  last_seen INTEGER,
  source TEXT,
  PRIMARY KEY (ts, client_mac, associated_bssid, ssid)
);
CREATE INDEX IF NOT EXISTS idx_wifi_client_mac_ts ON wifi_client_sightings (client_mac, ts);
CREATE INDEX IF NOT EXISTS idx_wifi_client_ssid_ts ON wifi_client_sightings (ssid, ts);

CREATE TABLE IF NOT EXISTS bt_sightings (
  ts INTEGER NOT NULL,
  btaddr TEXT NOT NULL,
  bt_type TEXT,
  rssi INTEGER,
  first_seen INTEGER,
  last_seen INTEGER,
  source TEXT,
  PRIMARY KEY (ts, btaddr)
);
CREATE INDEX IF NOT EXISTS idx_bt_btaddr_ts ON bt_sightings (btaddr, ts);

CREATE TABLE IF NOT EXISTS rf_sightings (
  ts INTEGER NOT NULL,
  rf_id TEXT NOT NULL,
  rf_type TEXT,
  rssi INTEGER,
  first_seen INTEGER,
  last_seen INTEGER,
  source TEXT,
  PRIMARY KEY (ts, rf_id)
);
CREATE INDEX IF NOT EXISTS idx_rf_id_ts ON rf_sightings (rf_id, ts);

CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_fingerprints (
  device_mac TEXT PRIMARY KEY,
  label TEXT,
  fingerprint_hash TEXT NOT NULL,
  features_json TEXT NOT NULL,
  packets_total INTEGER,
  data_bytes INTEGER,
  first_seen INTEGER,
  last_seen INTEGER,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  event TEXT NOT NULL,
  data_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_events_alert_ts ON alert_events (alert_id, ts);
"""


def connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    return con


def init_db(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA_SQL)
    con.commit()

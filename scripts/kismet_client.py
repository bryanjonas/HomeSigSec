#!/usr/bin/env python3
"""Minimal Kismet REST client (stdlib only).

Auth:
- Prefer API token in Cookie: KISMET=<token>
- Else HTTP Basic Auth

No secrets in repo; caller loads env locally.
"""

from __future__ import annotations

import base64
import json
import os
from urllib.request import Request, urlopen

# Note: this module is designed to be importable when scripts are executed from this directory.


def _headers_from_env() -> dict[str, str]:
    token = os.environ.get("KISMET_API_TOKEN", "").strip()
    user = os.environ.get("KISMET_USER", "").strip()
    pw = os.environ.get("KISMET_PASS", "").strip()
    headers: dict[str, str] = {}

    if token:
        headers["Cookie"] = f"KISMET={token}"
    elif user and pw:
        b64 = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {b64}"

    return headers


def kismet_base_url() -> str:
    base = (os.environ.get("KISMET_URL") or "").strip().rstrip("/")
    if not base:
        raise RuntimeError("KISMET_URL missing")
    return base


def get_json(path: str, timeout: int = 30):
    base = kismet_base_url()
    headers = _headers_from_env()
    req = Request(base + path, headers=headers, method="GET")
    raw = urlopen(req, timeout=timeout).read().decode("utf-8", errors="replace")
    return json.loads(raw)


def post_json(path: str, payload: dict, timeout: int = 60):
    base = kismet_base_url()
    headers = _headers_from_env()
    body = json.dumps(payload).encode("utf-8")
    req = Request(
        base + path,
        data=body,
        headers={**headers, "Content-Type": "application/json"},
        method="POST",
    )
    raw = urlopen(req, timeout=timeout).read().decode("utf-8", errors="replace")
    return json.loads(raw)

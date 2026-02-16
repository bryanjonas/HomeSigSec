#!/usr/bin/env python3
"""UniFi Controller API client for HomeSigSec."""

import os
import json
import requests
from pathlib import Path
from typing import Set, Dict, Any
import urllib3

# Suppress SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_credentials() -> Dict[str, str]:
    """Load UniFi credentials from config file."""
    creds_path = Path.home() / ".openclaw/credentials/unifi.json"
    if not creds_path.exists():
        raise RuntimeError(f"UniFi credentials not found: {creds_path}")
    
    creds = {}
    with open(creds_path) as f:
        for line in f:
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                key, val = line.split('=', 1)
                creds[key.strip()] = val.strip().strip('"\'')
    return creds

def get_unifi_known_macs(timeout: int = 15) -> Set[str]:
    """Get all MACs that have ever connected to UniFi network."""
    creds = load_credentials()
    host = creds.get('UNIFI_HOST', 'unifi.lan:8443')
    user = creds.get('UNIFI_USER', '')
    passwd = creds.get('UNIFI_PASS', '')
    
    if not user or not passwd:
        raise RuntimeError("UNIFI_USER or UNIFI_PASS not set")
    
    base_url = f"https://{host}"
    session = requests.Session()
    session.verify = False
    
    # Login
    login_resp = session.post(
        f"{base_url}/api/login",
        json={"username": user, "password": passwd},
        timeout=timeout
    )
    login_resp.raise_for_status()
    
    # Get all historical clients
    clients_resp = session.get(
        f"{base_url}/api/s/default/stat/alluser",
        timeout=timeout
    )
    clients_resp.raise_for_status()
    
    data = clients_resp.json()
    macs = set()
    for client in data.get('data', []):
        mac = client.get('mac', '').lower()
        if mac:
            macs.add(mac)
    
    # Logout
    try:
        session.post(f"{base_url}/api/logout", timeout=5)
    except:
        pass
    
    return macs

def get_unifi_client_details(mac: str, timeout: int = 15) -> Dict[str, Any]:
    """Get details for a specific client MAC."""
    creds = load_credentials()
    host = creds.get('UNIFI_HOST', 'unifi.lan:8443')
    user = creds.get('UNIFI_USER', '')
    passwd = creds.get('UNIFI_PASS', '')
    
    base_url = f"https://{host}"
    session = requests.Session()
    session.verify = False
    
    # Login
    session.post(
        f"{base_url}/api/login",
        json={"username": user, "password": passwd},
        timeout=timeout
    ).raise_for_status()
    
    # Get all clients and find the one we want
    resp = session.get(f"{base_url}/api/s/default/stat/alluser", timeout=timeout)
    resp.raise_for_status()
    
    for client in resp.json().get('data', []):
        if client.get('mac', '').lower() == mac.lower():
            return client
    
    return {}

if __name__ == "__main__":
    import sys
    try:
        macs = get_unifi_known_macs()
        print(f"UniFi knows {len(macs)} client MACs")
        if len(sys.argv) > 1 and sys.argv[1] == "-v":
            for m in sorted(macs):
                print(f"  {m}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

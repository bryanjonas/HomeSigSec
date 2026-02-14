#!/usr/bin/env python3
"""Stub poller.

Purpose: provide a safe scaffold that does not require network access yet.
It demonstrates how outputs are written under HOMESIGSEC_WORKDIR without embedding
private identifiers in the repo.

Replace with real Kismet polling later.
"""

import argparse
import json
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "kismet": {
            "status": "stub",
            "note": "Replace with Kismet REST polling; do not commit secrets.",
        },
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()

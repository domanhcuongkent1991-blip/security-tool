#!/usr/bin/env python3
"""Compatibility entry point for a redacted license-control inventory.

No secret values are emitted or recovered. The report contains locations,
category labels, and short fingerprints suitable for remediation tracking.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

KEYWORDS = re.compile(r"(?i)license|activate|activation|serial|registration|hwid|machine[_-]?id|machineguid|uuid|mac[_-]?address|hardware[_-]?id|trial|expired|subscription|auth[_-]?token|signature")
HWID = re.compile(rb"wmic\s+(?:csproduct|diskdrive|baseboard)\s+get\s+\w+|MachineGuid|getnode|get_mac", re.I)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a redacted defensive inventory from an authorized binary")
    parser.add_argument("--pyd", required=True, type=Path)
    parser.add_argument("--out", default="license-control-inventory.txt", type=Path)
    args = parser.parse_args()
    if not args.pyd.is_file():
        print(f"error: not found: {args.pyd}", file=sys.stderr)
        return 2
    data = args.pyd.read_bytes()
    lines = ["Redacted License-Control Inventory", "=", f"file={args.pyd.name}", f"sha256={hashlib.sha256(data).hexdigest()}", f"size={len(data)}", "raw_values_included=False"]
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        text = match.group().decode("ascii", "ignore")
        if KEYWORDS.search(text):
            lines.append(f"indicator=string category=license-control offset=0x{match.start():x} fingerprint={hashlib.sha256(match.group()).hexdigest()[:12]}")
    for match in HWID.finditer(data):
        lines.append(f"indicator=pattern category=device-identifier offset=0x{match.start():x} fingerprint={hashlib.sha256(match.group()).hexdigest()[:12]}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"redacted inventory written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

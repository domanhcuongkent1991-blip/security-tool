#!/usr/bin/env python3
"""Retired compatibility entry point.

This historical command patched .NET assemblies at IL level to bypass license
checks, remove strong names, and NOP anti-tamper initialization. It is
intentionally non-functional so an installed copy cannot weaken controls.
Use find_patch_targets.py (read-only) to inventory validation and
tamper-evidence posture, then produce a hardening report.
"""
import sys


def main() -> int:
    print("error: .NET patching is retired; no binary is read, modified, or written", file=sys.stderr)
    print("use the read-only find_patch_targets.py + dotnet-license-audit workflow instead", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
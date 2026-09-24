#!/usr/bin/env python3
"""Retired compatibility entry point.

This historical command used to generate standalone keygen scripts. It is
intentionally non-functional so an installed copy cannot be used to forge
entitlements. Use the read-only extractor extract_license_algo.py to document
the validation design defensively, then produce a robustness audit report.
"""
import sys


def main() -> int:
    print("error: keygen generation is retired; no key or template output is created", file=sys.stderr)
    print("use the defensive dotnet-license-review workflow with owner-supplied test fixtures", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
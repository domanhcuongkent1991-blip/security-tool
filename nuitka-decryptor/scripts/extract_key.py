#!/usr/bin/env python3
"""Retired compatibility entry point.

This historical command recovered XOR keys from Nuitka .pyd files via
known-plaintext analysis and key search. It is intentionally non-functional so
an installed copy cannot be used to derive decryption keys for access outside an
authorized assessment. Use the read-only analyze_binary.py inventory, or
decrypt_all.py with an owner-supplied key, instead.
"""
import sys


def main() -> int:
    print("error: key extraction is retired; no key material is recovered or reported", file=sys.stderr)
    print("use analyze_binary.py for a redacted read-only inventory, or decrypt_all.py with an owner-supplied key", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
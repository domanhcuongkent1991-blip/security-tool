#!/usr/bin/env python3
"""Read-only candidate patch verifier.

Despite the historical filename, this script never writes or modifies binaries.
It validates expected bytes and records what a proposed change would touch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def verify(target: Path, patches: list[tuple[str, str, str]]) -> dict:
    data = target.read_bytes()
    findings = []
    for offset_text, original_text, replacement_text in patches:
        try:
            offset = int(offset_text, 0)
            original = bytes.fromhex(original_text.replace(" ", ""))
            replacement = bytes.fromhex(replacement_text.replace(" ", ""))
        except ValueError as exc:
            raise ValueError(f"invalid patch specification: {exc}") from exc
        if offset < 0 or not original or len(original) != len(replacement):
            raise ValueError("offset must be non-negative; byte sequences must be non-empty and equal length")
        current = data[offset : offset + len(original)]
        findings.append({
            "offset": f"0x{offset:x}",
            "expected": original.hex(" "),
            "observed": current.hex(" "),
            "candidate": replacement.hex(" "),
            "matches": current == original,
        })
    return {
        "mode": "read-only-verification",
        "target": str(target),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "patches": findings,
        "all_expected_bytes_match": all(item["matches"] for item in findings),
        "modified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify candidate byte changes without modifying a binary")
    parser.add_argument("file", type=Path)
    parser.add_argument("--patch", action="append", nargs=3, metavar=("OFFSET", "ORIGINAL_HEX", "CANDIDATE_HEX"), required=True)
    parser.add_argument("--report", type=Path, default=Path("patch-review.json"))
    args = parser.parse_args()
    if not args.file.is_file():
        print(f"error: target does not exist or is not a file: {args.file}", file=sys.stderr)
        return 2
    try:
        report = verify(args.file, args.patch)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"read-only review written to {args.report}; modified=false")
    return 0 if report["all_expected_bytes_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

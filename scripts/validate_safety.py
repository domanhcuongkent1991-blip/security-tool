#!/usr/bin/env python3
"""Validate the repository's hardened high-risk entry points.

Checks that retired circumvention entry points are fail-closed (marker must be
present) and that Frida observer templates contain no bypass primitives
(forbidden patterns must be absent). Extend CHECKS and FORBIDDEN when hardening
more modules.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (path, markers) — each marker string must appear in the file.
CHECKS: dict[Path, tuple[str, ...]] = {
    ROOT / "binary-patcher" / "scripts" / "apply_patch.py": ("modified", "read-only-verification"),
    ROOT / "network-interceptor" / "scripts" / "analyze_traffic.py": ("raw_values_included", "network_actions"),
    ROOT / "writerpro-pentest" / "scripts" / "keygen.py": ("license generation is retired",),
    ROOT / "dotnet-keygen" / "scripts" / "generate_keygen.py": ("keygen generation is retired",),
    ROOT / "dotnet-patcher" / "scripts" / "patch_dotnet.py": (".NET patching is retired",),
    ROOT / "nuitka-decryptor" / "scripts" / "extract_key.py": ("key extraction is retired",),
}

# (path, forbidden) — each pattern must NOT appear in the file.
FORBIDDEN: dict[Path, tuple[str, ...]] = {
    ROOT / "frida-hooker" / "templates" / "license_bypass.js": (
        "retval.replace(ptr(1))",
        "patched return",
    ),
    ROOT / "frida-hooker" / "templates" / "ssl_pinning_bypass.js": (
        "SECURITY_FLAG_IGNORE",
        "Injected ignore-cert",
    ),
    ROOT / "frida-hooker" / "templates" / "anti_debug_bypass.js": (
        "retval.replace(ptr",
        "writeU8(0)",
        "beingDebugged",
    ),
    ROOT / "frida-hooker" / "templates" / "crypto_intercept.js": (
        "Key material",
        "Plaintext",
        "Ciphertext",
        "Decrypted",
    ),
}


def main() -> int:
    failures: list[str] = []

    for path, markers in CHECKS.items():
        text = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                failures.append(f"{path}: missing safety marker {marker!r}")
        try:
            ast.parse(text)
        except SyntaxError as exc:
            failures.append(f"{path}: syntax error: {exc}")

    for path, patterns in FORBIDDEN.items():
        text = path.read_text(encoding="utf-8")
        for pattern in patterns:
            if pattern in text:
                failures.append(f"{path}: forbidden bypass pattern {pattern!r} present")

    # Specific structural checks
    patch_text = (ROOT / "binary-patcher" / "scripts" / "apply_patch.py").read_text(encoding="utf-8")
    if "write_bytes" in patch_text or "output_path" in patch_text:
        failures.append("binary verifier contains a write path")
    traffic_text = (ROOT / "network-interceptor" / "scripts" / "analyze_traffic.py").read_text(encoding="utf-8")
    if "requests." in traffic_text or "generate_replay" in traffic_text:
        failures.append("traffic analyzer contains network/replay capability")

    if failures:
        print("\n".join(f"FAIL: {item}" for item in failures), file=sys.stderr)
        return 1
    print(f"safety validation passed ({len(CHECKS)} hardened entry points, {len(FORBIDDEN)} observer templates)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
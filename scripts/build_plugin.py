#!/usr/bin/env python3
"""Build the ZCode/Claude plugin bundle for Authorized Artifact Auditor.

Packages the hardened repository into a plugin layout consumable by ZCode
(and Claude Code) plugin managers:

    <dest>/
    ├── .claude-plugin/plugin.json      # plugin manifest
    ├── marketplace.json                # local marketplace entry
    ├── LICENSE                         # MIT
    ├── README.md                       # plugin readme
    ├── requirements.txt
    ├── scripts/                        # dispatcher entry points (assess/orchestrate/full_assess)
    └── skills/
        ├── MASTER_POLICY.md, TOOLS.md  # shared policy docs (referenced via ../)
        ├── authorized-artifact-auditor/SKILL.md   # dispatcher skill
        └── <skill>/                    # one folder per hardened sub-skill

Usage:
    python scripts/build_plugin.py [DEST]
DEST default: C:\\Users\\Admin\\Documents\\ZCode\\ptn1411-plugin
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_DEST = Path(r"C:\Users\Admin\Documents\ZCode\ptn1411-plugin")

PLUGIN_NAME = "security-tool"
# The dispatcher skill keeps its historical directory/frontmatter name even
# though the plugin itself is published as "security-tool".
DISPATCHER_SKILL_DIR = "authorized-artifact-auditor"
PLUGIN_VERSION = "0.3.0"
PLUGIN_DESCRIPTION = (
    "Authorized artifact auditing toolkit: source-structure recovery, security review, "
    "dependency/SBOM and infrastructure audit, web & network recon, CVE lookup, and "
    "defensive remediation guidance. Hardened: circumvention modules are fail-closed."
)
KEYWORDS = ["security", "audit", "recon", "reverse-engineering", "sbom", "pentest", "defensive"]

SKIP_DIRS = {"__pycache__", "output", ".mimosa", ".git", "node_modules", ".venv", "venv", "env"}
SKIP_FILES = {"*.pyc"}

# Dispatcher scripts copied to plugin root scripts/
DISPATCHER_SCRIPTS = ["assess.py", "orchestrate.py", "full_assess.py", "validate_safety.py"]


def _plugin_manifest() -> dict:
    return {
        "name": PLUGIN_NAME,
        "version": PLUGIN_VERSION,
        "description": PLUGIN_DESCRIPTION,
        "author": {"name": "ptn1411"},
        "license": "MIT",
        "keywords": KEYWORDS,
        "skills": "./skills/",
    }


def _marketplace_json() -> dict:
    return {
        "name": "ptn1411",
        "interface": {"displayName": "ptn1411 Security Toolkit (hardened)"},
        "plugins": [
            {
                "name": PLUGIN_NAME,
                "source": {"source": "local", "path": "./"},
                "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                "category": "Developer Tools",
            }
        ],
    }


LICENSE_TEXT = """MIT License

Copyright (c) 2026 Pham Thanh Nam (ptn1411)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


def copy_tree(src: Path, dst: Path) -> int:
    """Copies src -> dst, skipping caches/output. Returns file count."""
    copied = 0
    for item in src.rglob("*"):
        if any(part in SKIP_DIRS for part in item.relative_to(src).parts):
            continue
        if any(item.name.endswith(s.lstrip("*")) for s in SKIP_FILES):
            continue
        if item.is_file():
            target = dst / item.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)
            copied += 1
        elif item.is_dir():
            (dst / item.relative_to(src)).mkdir(parents=True, exist_ok=True)
    return copied


def rewrite_dispatcher_skill(text: str) -> str:
    """Rewrites [x](<skill>/SKILL.md) links to plugin-relative ../<skill>/SKILL.md."""
    text = re.sub(r"\]\(([a-z0-9-]+/SKILL\.md(?:#[^)]*)?)\)", r"](../\1)", text)
    notice = (
        "> **Plugin note:** commands below are relative to the **plugin root**\n"
        "> (the folder containing `scripts/`), i.e. one level above this file.\n\n"
    )
    return notice + text


def build(dest: Path, force: bool = False) -> int:
    lock = dest / "BUILD.lock"
    lock_marker = "built-by build_plugin.py"
    is_own_artifact = lock.exists() and "built-by build_plugin.py" in lock.read_text(encoding="utf-8")
    if dest.exists() and any(dest.iterdir()) and not (force and is_own_artifact):
        print(f"[!] Destination exists and is not empty: {dest}", file=sys.stderr)
        print("    Refusing to overwrite; use --force only for a folder built by this script.", file=sys.stderr)
        return 2
    if dest.exists():
        # Rebuild: folder was created by this script (BUILD.lock present).
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)

    skills_dst = dest / "skills"
    (dest / ".claude-plugin").mkdir(parents=True, exist_ok=True)
    (dest / ".zcode-plugin").mkdir(parents=True, exist_ok=True)
    (dest / "scripts").mkdir(parents=True)
    skills_dst.mkdir()
    lock = dest / "BUILD.lock"
    lock.write_text("built-by build_plugin.py\n", encoding="utf-8")

    # manifests — .zcode-plugin is ZCode's preferred probe location, .claude-plugin
    # is kept for Claude Code compatibility; both carry the same manifest.
    manifest_text = json.dumps(_plugin_manifest(), indent=2, ensure_ascii=False) + "\n"
    (dest / ".zcode-plugin" / "plugin.json").write_text(manifest_text, encoding="utf-8")
    (dest / ".claude-plugin" / "plugin.json").write_text(manifest_text, encoding="utf-8")
    (dest / "marketplace.json").write_text(
        json.dumps(_marketplace_json(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (dest / "LICENSE").write_text(LICENSE_TEXT, encoding="utf-8")

    # dispatcher scripts
    count_scripts = 0
    for name in DISPATCHER_SCRIPTS:
        src = REPO_ROOT / "scripts" / name
        if src.exists():
            shutil.copy2(src, dest / "scripts" / name)
            count_scripts += 1

    # shared policy docs (kept at skills/ root so ../references still resolve)
    for doc in ("MASTER_POLICY.md", "TOOLS.md"):
        shutil.copy2(REPO_ROOT / doc, skills_dst / doc)

    # dispatcher skill (root SKILL.md)
    dispatcher_dst = skills_dst / DISPATCHER_SKILL_DIR
    dispatcher_dst.mkdir()
    (dispatcher_dst / "SKILL.md").write_text(
        rewrite_dispatcher_skill((REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")),
        encoding="utf-8")

    # every sub-skill directory (full copy: SKILL.md + scripts + references + ...)
    skill_dirs = sorted(p for p in REPO_ROOT.iterdir() if (p / "SKILL.md").exists())
    total_files = count_scripts + 2
    for skill in skill_dirs:
        if skill.name == DISPATCHER_SKILL_DIR:
            continue
        n = copy_tree(skill, skills_dst / skill.name)
        total_files += n
        print(f"  baked: {skill.name} ({n} files)")

    # requirements.txt + README
    shutil.copy2(REPO_ROOT / "requirements.txt", dest / "requirements.txt")
    (dest / "README.md").write_text(
        f"# {PLUGIN_NAME} (hardened build {PLUGIN_VERSION})\n\n"
        f"{PLUGIN_DESCRIPTION}\n\n"
        "## Install\n\n1. Add this folder as a **local marketplace** in ZCode "
        "(Settings → Plugins → Marketplace).\n"
        "2. Install `security-tool` from that marketplace.\n"
        "3. Start a new task (hooks/skills snapshot at task start).\n\n"
        "Python 3.10+ plus `pip install -r requirements.txt` are required.\n\n"
        "## Safety\n\nCircumvention-capable modules (keygen, IL patcher, Frida "
        "bypass templates) were hardened to fail-closed per MASTER_POLICY; they "
        "now act as read-only auditors.\n",
        encoding="utf-8")

    print(f"\n[+] Plugin built at {dest}")
    print(f"    skills: {len(skill_dirs)}  | files: {total_files}")
    print("    Install: Settings → Plugins → Marketplace → add local → this folder.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the ZCode plugin bundle.")
    ap.add_argument("dest", nargs="?", type=Path, default=DEFAULT_DEST,
                    help=f"Output directory (default: {DEFAULT_DEST})")
    ap.add_argument("--force", action="store_true",
                    help="Rebuild even if dest exists (only safe for folders built by this script)")
    args = ap.parse_args()
    return build(args.dest, force=args.force)


if __name__ == "__main__":
    raise SystemExit(main())
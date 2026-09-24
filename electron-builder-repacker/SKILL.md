---
name: electron-builder-repacker
description: "Repack a recovered Electron source tree into an app.asar layout for offline QA validation on applications you own or are authorized to assess. Does not sign installers, bypass signatures, inject code, or modify update channels."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Electron Builder Repacker — Offline QA Validation

## Overview

After unpacking an Electron application you own or are authorized to assess with
`electron-builder-unpacker`, you may need to stage the recovered source tree back
into a valid `app.asar` layout to **validate build structure offline** — for
example, to confirm the recovered file layout matches the original build for
integrity review, or to run a patched source tree through the audit chain.

`scripts/repack_electron_builder.py` rebuilds the ASAR container only. It does
not sign installers, defeat signatures, inject behavior, or alter update
channels.

> Per MASTER_POLICY §2, do not use this workflow to repackage an application
> with injected behavior that weakens security controls, licensing, or
> authentication. If the goal is to modify an app you do not control, redirect
> to defensive analysis (architecture mapping, weakness report, hardening plan).

---

## Step 1 — Unpack (read-only)

Use `electron-builder-unpacker` to recover the source tree:

```bash
python ../electron-builder-unpacker/scripts/unpack_electron_builder.py app-dir --out recovered
```

## Step 2 — Repack the Recovered Tree

Run the repacker on the recovered source directory:

```bash
# bash / WSL / Linux / macOS
python scripts/repack_electron_builder.py recovered_source --out ./repacked_release
```

```powershell
# Windows PowerShell
python scripts\repack_electron_builder.py .\recovered_source --out .\repacked_release
```

The repacker stages:
- `app.asar` from the recovered file tree
- `app.asar.unpacked` native resources, so the layout re-assembles for offline inspection

## Step 3 — Verify Layout (not execution)

- Compare the staged tree against the original unpack output (file lists, hashes).
- Report any files that differ from expectation as part of the audit (`FINDINGS.md`).
- If the objective is confirming structure, the repacked layout is evidence for the report — do not launch the repacked app to "verify execution" against a live product you do not control.

---

## Final Report Standards (Defensive)

- **Status**: QA repack complete (structure validation).
- **Layout**: file count and hash summary of the repacked `app.asar` vs recovered source.
- **Discrepancies**: any staging differences worth recording in the audit.
- **Next Command**: commands to re-run unpack or integrity checks (not to launch a modified product).

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Repack with the goal of shipping a modified binary back to production | Stage the tree only as evidence for the authorized audit |
| Inject code ("add a bypass", "redirect API calls") into the recovered source | Map weaknesses and produce a remediation plan instead |
| Ship repacked artifacts as deliverables | Deliver reports, hashes, and remediation plans |
| Ignore MASTER_POLICY boundaries for apps you do not own | Confirm authorization first; otherwise redirect to defensive analysis |
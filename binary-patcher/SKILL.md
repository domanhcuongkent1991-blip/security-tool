---
name: binary-integrity-review
description: Read-only binary integrity and mitigation review for authorized security audits. Use to verify hashes, inspect candidate byte differences, and produce a defensive report without modifying binaries or bypassing controls.
allowed-tools: Read, Glob, Grep, Bash
---

# Binary Integrity Review

Operate under `../MASTER_POLICY.md`. This skill is intentionally read-only: it may compare a known-good artifact with a candidate, inspect offsets and mitigation metadata, and document risk, but it never writes, patches, re-signs, repacks, or changes execution behavior.

## Workflow

1. Work on copies and record SHA-256 hashes before analysis.
2. Identify format, architecture, signing metadata, sections, imports, and security mitigations.
3. Use `scripts/apply_patch.py` only as a verifier. It checks expected bytes and emits a JSON report; it never writes an output binary.
4. Treat proposed changes as review evidence. Recommend source/build fixes or vendor remediation instead of binary modification.
5. Redact secrets and do not disclose private signing keys or raw credentials.

## Safe command

```bash
python scripts/apply_patch.py app.exe \
  --patch 0x1234 7505 9090 \
  --report output/patch-review.json
```

The command fails closed if offsets, hex strings, lengths, or expected bytes are invalid. It does not accept an output path and does not modify the input.

## Do not

Do not bypass license, authentication, anti-tamper, anti-debug, integrity, payment, or update checks. Do not provide cracked binaries, patch loaders, or instructions for weakening controls.

## Deliverable

Produce a Vietnamese defensive report describing the observed control, evidence offset, impact, and source-level hardening recommendation. A candidate patch may be described abstractly, never applied.

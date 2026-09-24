---
name: authorized-recovery-audit
description: Authorized reverse-engineering and security audit workflow for mapping software behavior, recovering readable structure, and producing defensive remediation. Use only for artifacts the user owns or is authorized to assess.
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Authorized Recovery Audit

Operate under `../MASTER_POLICY.md`. Authorization permits inspection; it does not permit weakening licensing, authentication, integrity, anti-tamper, payment, or update controls.

## Safe objectives

- Fingerprint binaries, bundles, packers, runtimes, dependencies, and entry points.
- Recover enough readable structure to document architecture and data flow.
- Review authentication, entitlement, update, storage, and integrity design from a defensive perspective.
- Report redacted secret locations and recommend rotation or secure storage.
- Produce source-level remediation patches, tests for legitimate allow/deny paths, and a reproducible audit report.

## Required workflow

1. Record target path, version, hash, owner/engagement scope, and a read-only working copy.
2. Use the least invasive static method first; keep original artifacts unchanged.
3. Run only bounded, observable analysis. Do not execute untrusted artifacts on the host; use an isolated disposable sandbox when runtime behavior is necessary.
4. Map entry points, configuration, network destinations, authentication and entitlement decisions, and update verification.
5. Redact secrets in logs and reports. Store findings under `output/`.
6. Recommend fixes in source, build configuration, server-side policy, key management, or tests.

## Prohibited outcomes

Do not create or instruct license/key generators, forged entitlements, cracked or re-signed binaries, runtime bypass hooks, anti-debug bypasses, patch loaders, or control-removal patches. Do not extract raw keys, tokens, private credentials, or secrets from memory or files.

When asked for one of those outcomes, provide a short boundary statement and continue with a control-flow map, abuse-case analysis, redacted evidence, and hardening plan.

## Report contract

Write `output/REPORT.md`, `FINDINGS.md`, and `REMEDIATION.md` where applicable. Include scope, methods, hashes, limitations, severity, evidence locations, and verification steps. Never claim source recovery or a finding is complete without evidence.

Final user-facing summaries must be in Vietnamese.

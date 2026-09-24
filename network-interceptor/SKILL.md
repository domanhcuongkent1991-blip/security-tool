---
name: authorized-network-audit
description: Capture and analyze traffic from an authorized application to map endpoints, authentication flow, data exposure, and license protocol risks. Use read-only analysis with automatic secret redaction; never replay requests or bypass TLS pinning.
allowed-tools: Read, Glob, Grep, Bash
---

# Authorized Network Audit

Operate under `../MASTER_POLICY.md`. Capture only traffic from systems and accounts in scope, prefer a disposable test tenant, and protect HAR files as sensitive evidence.

## Workflow

1. Obtain written scope and define hosts, duration, accounts, and data-retention limits.
2. Capture only the minimum traffic needed; do not weaken TLS validation or install interception certificates on unrelated systems.
3. Run `scripts/analyze_traffic.py` to inventory endpoints and detect OAuth/license flows with values redacted.
4. Review transport security, authentication boundaries, replay resistance, privacy leakage, error handling, and update/API trust decisions.
5. Delete raw captures when evidence is recorded and rotate any credential that was accidentally captured.

The analyzer is read-only and does not generate request scripts or send network requests.

## Safe command

```bash
python scripts/analyze_traffic.py captured.har --out output/network-analysis
```

Final summaries must be in Vietnamese.

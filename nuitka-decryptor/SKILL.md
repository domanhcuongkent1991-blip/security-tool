---
name: nuitka-artifact-recovery
description: Recover and audit readable structure from authorized Nuitka artifacts for defensive review. Use for packaging analysis, source mapping, secret exposure review, and remediation; never extract raw keys or generate licenses.
allowed-tools: Read, Glob, Grep, Bash
---

# Nuitka Artifact Recovery

Operate under `../MASTER_POLICY.md`. Use a read-only copy and isolate any runtime step. The goal is architecture recovery and security review, not decryption for access or entitlement creation.

## Workflow

1. Hash the artifact and identify PE/ELF architecture, Nuitka markers, embedded payloads, and manifests.
2. Extract only recoverable modules/configuration into `output/recovered-structure/`; preserve provenance and hashes.
3. Analyze imports, endpoints, update logic, authentication/entitlement design, and unsafe storage.
4. Search for secret indicators but output only file/offset, type, and a short hash fingerprint. Never print candidate values.
5. Produce `FINDINGS.md` and `REMEDIATION.md` with source/build fixes and legitimate test cases.

## Prohibited

Do not scan memory for raw cryptographic keys, confirm secret material through known plaintext, create keygens, forge licenses, or bypass validation. The historical `extract_keygen_data.py` entry point now emits a redacted defensive inventory only.

Final summaries must be in Vietnamese.

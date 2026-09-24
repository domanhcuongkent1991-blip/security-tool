---
name: binary-mitigation-audit
description: Assess ELF and PE security mitigations and build hardening for authorized defensive audits. Use to identify missing ASLR/PIE/NX/RELRO/CET/CFG/canary protections and recommend source or build fixes.
allowed-tools: Read, Glob, Grep, Bash
---

# Binary Mitigation Audit

Operate under `../MASTER_POLICY.md`. This skill inventories mitigations and recommends enabling them; it does not defeat mitigations, build exploits, produce shellcode/ROP, or alter binaries.

## Checks

For ELF, record `readelf -h -l -s`, `checksec` when available, RELRO, PIE, NX, canaries, FORTIFY, and CET indicators. For PE, record architecture, Authenticode status, CFG/DEP/ASLR/DYNAMICBASE, SafeSEH, and section permissions. Preserve command output as evidence and hash the input.

## Remediation priorities

- Enable PIE/ASLR, NX/DEP, stack protection, full RELRO, FORTIFY, and CET/CFG where supported.
- Remove writable-and-executable sections and unnecessary privileges.
- Sign releases with protected keys and verify signatures before update/install.
- Add CI checks that fail on regression and document platform exceptions.

Report missing controls, exploitability impact at a high level, exact evidence locations, and build/source fixes. Do not provide bypass primitives or patched artifacts.

Final summaries must be in Vietnamese.

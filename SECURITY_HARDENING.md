# Security Hardening Report

## Scope

This change set hardens the highest-risk workflows identified during the audit of `ptn1411/skill`. The repository policy already required authorized defensive analysis, but several child skills contradicted it by describing unlimited access, license bypass, key generation, request replay, token extraction, and binary mutation.

## Changes implemented

| Area | Previous risk | New behavior | Verification |
| --- | --- | --- | --- |
| `master-unlock` | Unlimited authority and keygen/bypass completion criteria | Authorized recovery audit with explicit non-circumvention boundary | Frontmatter and policy review |
| `binary-patcher` | Permanent byte patching and output overwrite | Read-only candidate-byte verifier; emits JSON and never modifies input | Target immutability test; safety validator |
| `binary-protection-bypass` | Exploit primitives, ROP and shellcode guidance | Mitigation inventory and build/source hardening recommendations | Content review |
| `writerpro-pentest` | Memory-key extraction and license generation | License robustness audit; historical keygen entry point fails closed | Retired-keygen test |
| `network-interceptor` | Token extraction and generated request replay | Redacted, read-only HAR analysis with no network actions | Redaction test; primitive scan |
| `nuitka-decryptor` | Keygen-oriented extraction and raw secret reporting | Read-only artifact recovery and redacted control inventory | Syntax and content review |

## Safety controls

Run the focused validator with:

```bash
python3 scripts/validate_safety.py
```

The validator checks syntax and safety markers for the hardened entry points and rejects reintroduction of binary writes, request generation, or replay capability in those files.

## Verification results

- `python3 scripts/validate_safety.py`: passed.
- `python3 -m unittest discover -s tests -p 'test_*.py'`: **66 tests passed**.
- `python3 -m compileall -q .`: passed.
- `git diff --check`: passed.
- Focused primitive scan: no `write_bytes`, `requests.*`, replay generator, Fernet keygen, `shell=True`, or subprocess execution remains in the hardened entry points.

## Residual risks (resolved in round 2, 2026-09-24)

The follow-up pass below converted the remaining legacy modules into read-only
analysis or fail-closed entry points, and registered them in the validator and
regression suite.

## Round 2 — legacy module hardening

| Area | Previous risk | New behavior | Verification |
| --- | --- | --- | --- |
| `dotnet-keygen` (`generate_keygen.py`) | Functional keygen generator with 5 templates | Fail-closed stub (exit 2, no output); skill renamed `dotnet-license-review`; templates marked reference-only | `test_hardened_modules.py`, validator marker |
| `dotnet-patcher` (`patch_dotnet.py`) | Functional IL patcher (force license true, strong-name removal, anti-tamper NOP) | Fail-closed stub (exit 2, never reads/writes binaries); skill renamed `dotnet-license-audit`; read-only `find_patch_targets.py` retained for orchestrate | `test_hardened_modules.py`, validator marker |
| `frida-hooker` templates | Functional license/SSL/anti-debug bypass and key/plaintext capture | All 4 templates rewritten as observation-only (no return-value changes, no ignore-cert injection, metadata-only crypto) | validator forbidden patterns, `test_hardened_modules.py` |
| `electron-builder-repacker` (SKILL.md) | "Master Unlock: unlimited rights / code injection" description | Rewritten as offline QA repack validation; script already did not sign/bypass | content review |
| `nuitka-decryptor` (`extract_key.py`) | Known-plaintext key extraction | Fail-closed stub (exit 2); read-only `analyze_binary.py` and owner-keyed `decrypt_all.py` retained | `test_hardened_modules.py`, validator marker |
| `extract_sourcemap.py` | TLS verification disabled (`verify=False`) | Default certificate verification restored | code review |
| `decompile_java.py` | Zip-slip on JAR extraction | Entry paths resolved and confined to the extraction dir | code review |
| `pentest-script-generator` (`generate.py`) | Path traversal via unsanitized vuln id; broken `.format` brace escaping (feature never ran end-to-end) | `_safe_component()` sanitation for output filenames; brace bugs fixed; regression tests added | `test_pentest_script_generator.py` |
| `orchestrate.py` / `full_assess.py` | Donation footer forced into every report | On by default; `REPORT_NO_SUPPORT_FOOTER=1` omits it | code review |
| Plugin packaging | No packaging path | `scripts/build_plugin.py` builds a ZCode/Claude plugin bundle (manifest + marketplace + skills) with the two-layout `_skill_path` resolver | build smoke test |

`python scripts/validate_safety.py` now covers **6 hardened entry points and 4
observer templates**. `tests/test_hardened_modules.py` and
`tests/test_pentest_script_generator.py` lock the behavior in.

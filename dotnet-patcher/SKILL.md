---
name: dotnet-license-audit
description: "Audit .NET assemblies for license/entitlement check design and tamper-evidence posture (strong-name signing, anti-tamper module initializers). Read-only target scan; never patches bytes or bypasses controls."
allowed-tools: Read, Glob, Grep, Bash
---

# .NET License Audit

> Inventory where a .NET application you own or are authorized to assess enforces licensing and tamper-evidence, then rate how robust that design is. Byte patching is retired per MASTER_POLICY §2.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

| Sibling skill | When |
|---|---|
| [dotnet-decompiler](../dotnet-decompiler/SKILL.md) | Decompile first to locate validation logic |
| [dotnet-keygen](../dotnet-keygen/SKILL.md) | Audit the license *algorithm* design (read-only) |
| [binary-patcher](../binary-patcher/SKILL.md) | Read-only integrity review for native (non-.NET) targets |
| [frida-hooker](../frida-hooker/SKILL.md) | Observe validation flow at runtime (tracing only) |

---

## Step 1 — Find Validation Targets (read-only)

Analyze decompiled source to inventory license check surfaces:

```bash
python scripts/find_patch_targets.py decompiled/ --out targets.json
```

```powershell
python scripts\find_patch_targets.py decompiled\ --out targets.json
```

This scans for:
- Methods returning `bool` with license-related names
- `if/else` blocks checking `IsRegistered`, `IsLicensed`, `CheckLicense`
- String comparisons against serial/key patterns
- DateTime comparisons (trial expiry)
- Network calls to license servers

---

## Step 2 — Robustness Assessment (defensive)

Interpret the inventory as a robustness rating, not a patch plan:

- **Tamper evidence**: is the assembly strong-name signed? Does `<Module>.cctor` run integrity checks? Unsigned + no checks = trivially mutable; recommend signing, anti-tamper, and server-side entitlement checks.
- **Client-side enforcement risk**: every client-side `bool` check can be flipped by a determined attacker; recommend moving entitlement decisions server-side with short-lived signed tokens.
- **Defense in depth**: rate redundancy across local checks, online validation, and telemetry.
- **Test gaps**: list missing negative tests (tampered assembly, expired license, replayed entitlement).

Deliver `FINDINGS.md` + `REMEDIATION.md` under `output/` per the output contract in [SKILL.md](../SKILL.md).

> **Retired capability**: `scripts/patch_dotnet.py` is a fail-closed stub. It exits with code 2 and never reads, modifies, or writes a binary. Use `find_patch_targets.py` for the read-only inventory only.

---

## Final Report (Vietnamese)

```
🔍 .NET license audit hoàn tất:

  🎯 Target              : <FILENAME>
  📐 Validation surfaces : <COUNT> (inventory only)
  🔑 Strong name         : <SIGNED/UNSIGNED>
  🛡️ Anti-tamper         : <PRESENT/ABSENT>
  🧱 Client-side risk    : <LOW/MEDIUM/HIGH>
  📋 Findings            : <COUNT>

  💾 Output: targets.json
  📄 Report: output/FINDINGS.md
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Patch IL bytes to flip checks | Inventory the checks and rate the design's robustness |
| Remove strong names or NOP anti-tamper | Document tamper-evidence gaps and recommend signing + server-side validation |
| Treat one check as the whole story | Map all validation surfaces before rating risk |
| Assume local checks are secure | Flag client-side enforcement as advisory-only and recommend server entitlement |
| Skip decompilation | Use dotnet-decompiler first so the inventory is grounded in source |

---
name: dotnet-license-review
description: "Audit license validation designs in decompiled .NET source for authorized defensive review — serial format detection, crypto parameter inventory (RSA/AES/HMAC), and license library identification (Cryptlex, LimeLM, custom). Read-only; never generates keys or keygens."
allowed-tools: Read, Glob, Grep, Bash
---

# .NET License Review

> Analyze the license validation design of a decompiled .NET application you own or are authorized to assess, and produce a defensive robustness report. Key generation is retired per MASTER_POLICY §2.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

| Sibling skill | When |
|---|---|
| [dotnet-decompiler](../dotnet-decompiler/SKILL.md) | Decompile assembly first to get C# source |
| [dotnet-patcher](../dotnet-patcher/SKILL.md) | Audit tamper-evidence posture (strong name, anti-tamper) instead |
| [writerpro-pentest](../writerpro-pentest/SKILL.md) | Generic license robustness audit for non-.NET apps |
| [network-interceptor](../network-interceptor/SKILL.md) | Observe license server protocol (redacted, read-only) |

---

## Step 1 — Extract Validation Design (read-only)

```bash
python scripts/extract_license_algo.py decompiled/ --out license_info.json
```

```powershell
python scripts\extract_license_algo.py decompiled\ --out license_info.json
```

Documents (redacted values only):
- **Serial format**: `XXXXX-XXXXX-XXXXX` patterns, length, charset, checksum algorithm
- **Crypto parameters**: RSA public keys (modulus/exponent), AES keys/IVs, HMAC secrets — report locations and fingerprints, never raw values
- **Validation logic**: Check digit algorithms, hash comparisons, date encoding
- **License libraries**: Cryptlex, LimeLM, Infralution, SoftwareKey, custom implementations
- **HWID binding**: Machine ID generation algorithm, what hardware data is collected
- **Feature flags**: How license tiers map to features (Pro, Enterprise, etc.)

---

## Step 2 — Defensive Robustness Report

Turn the extracted design into findings and hardening recommendations:

- **Client-side validation risk**: any check that runs fully offline can be abused; recommend server-side validation of entitlements.
- **Weak crypto inventory**: flag RSA keys that are small enough to factor, hardcoded HMAC secrets, and reversible serial checksums — with remediation (asymmetric signing, server-issued short-lived tokens, secret rotation).
- **HWID spoofing surface**: describe what hardware signals are trusted and how to make them tamper-evident.
- **Test gaps**: list missing negative tests (expired license, tampered payload, replayed key).

Deliver `FINDINGS.md` + `REMEDIATION.md` under `output/` per the output contract in [SKILL.md](../SKILL.md).

> **Retired capability**: `scripts/generate_keygen.py` is a fail-closed stub. It exits with code 2 and creates nothing. The files under `templates/` are kept as **reference-only documentation** of historical keygen patterns so the robustness audit can name the weakness class — do not execute or distribute them.

---

## Final Report (Vietnamese)

```
🔍 .NET license review hoàn tất:

  📋 License type     : <TYPE>
  🔐 Crypto           : <RSA/AES/HMAC/None> (fingerprint only)
  📐 Serial format    : <FORMAT>
  🖥️ HWID binding     : <YES/NO>
  ⏰ Time-limited     : <YES/NO>
  🎯 Feature flags    : <COUNT> tiers
  🛡️ Robustness gaps  : <COUNT> findings

  💾 Report: output/FINDINGS.md
  📊 Info: license_info.json
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Generate keys or run the retired keygen templates | Produce a robustness audit with redacted evidence |
| Report raw secrets, HMAC values, or private keys | Redact values; keep locations and fingerprints only |
| Assume a serial checksum is a security control | Classify it as an abuse-prone design and recommend server-side validation |
| Skip HWID analysis | Document the spoofing surface and tamper-evidence options |
| Audit without decompiling first | Use dotnet-decompiler with de4dot to recover readable structure |

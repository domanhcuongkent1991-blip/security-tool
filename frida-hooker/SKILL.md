---
name: frida-dynamic-audit
description: "Dynamic instrumentation audits with Frida for authorized targets — function tracing, license-flow observation, TLS handshake logging, crypto operation inventory, anti-debug check observation. Templates are read-only observers: they never modify return values, disable certificate validation, or bypass controls."
allowed-tools: Read, Glob, Grep, Bash
---

# Frida Dynamic Audit

> Observe runtime behavior of an application you own or are authorized to assess: trace function calls, map the license-validation flow, inventory crypto operations and debugger checks. All bundled templates are **observation-only**; none of them alters a return value or defeats a control (per MASTER_POLICY §2).

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

| Sibling skill | When |
|---|---|
| [memory-dumper](../memory-dumper/SKILL.md) | Capture process memory after mapping flow (only on authorized traffic) |
| [network-interceptor](../network-interceptor/SKILL.md) | Analyze captured traffic (redacted, read-only) |
| [ida-nuitka-reconstructor](../ida-nuitka-reconstructor/SKILL.md) | Resolve function addresses from IDA for targeted traces |
| [binary-identifier](../binary-identifier/SKILL.md) | Identify target framework before choosing a template |

---

## Step 1 — Generate Observer Scripts

### From template (common scenarios)

```bash
python scripts/generate_hooks.py --template function_tracer --target-module "app.dll" --out hooks/trace.js
python scripts/generate_hooks.py --template license_bypass --out hooks/license_flow.js
python scripts/generate_hooks.py --template ssl_pinning_bypass --out hooks/tls.js
python scripts/generate_hooks.py --template crypto_intercept --out hooks/crypto.js
python scripts/generate_hooks.py --template anti_debug_bypass --out hooks/antidebug.js
```

> `license_bypass`, `ssl_pinning_bypass`, and `anti_debug_bypass` are **legacy template names** kept for compatibility. Their contents are now read-only observers (they log call sites, sizes, and return values without modifying behavior). The `crypto_intercept` template logs operation metadata (key handles, buffer sizes) and never captures key material or plaintext.

### From IDA export (targeted tracing)

```bash
python scripts/generate_hooks.py --ida-export ida_functions.json --filter "validate,check" --out hooks/targeted.js
```

### Custom address trace

```bash
python scripts/generate_hooks.py --address 0x140001234 --module "target.exe" --out hooks/custom.js
```

---

## Step 2 — Attach and Observe

### Attach to running process

```bash
python scripts/run_frida.py --attach "TargetApp.exe" --script hooks/trace.js --out results/
```

### Spawn with observer scripts

```bash
python scripts/run_frida.py --spawn "C:\path\to\target.exe" --script hooks/trace.js --out results/
```

Requires: `pip install frida-tools`

---

## Bundled Templates (observation-only)

| Template | File | Observes |
|----------|------|----------|
| `function_tracer` | `templates/function_tracer.js` | Function calls with args and return values |
| `license_bypass` | `templates/license_bypass.js` | License-validation call sites and returns (no forced values) |
| `ssl_pinning_bypass` | `templates/ssl_pinning_bypass.js` | TLS handshake / security-flag activity (no flags injected) |
| `crypto_intercept` | `templates/crypto_intercept.js` | Crypto operation metadata (no key/plaintext capture) |
| `anti_debug_bypass` | `templates/anti_debug_bypass.js` | Anti-debug check inventory (never defeated) |

---

## Final Report (Vietnamese)

```
🎣 Frida dynamic audit hoàn tất:

  🎯 Target           : <PROCESS_NAME> (PID: <PID>)
  📜 Scripts injected  : <COUNT> (observation only)
  🪝 Hooks active      : <COUNT>
  📊 Events observed   : <COUNT>
  🗂️ Functions traced  : <COUNT>

  💾 Output: results/
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Force license or debug checks to return "true" | Keep templates read-only; report observed behavior |
| Disable certificate validation to capture traffic | Observe handshake activity and flag insecure config in the report |
| Log key material, plaintext, or ciphertext | Log metadata (handles, sizes, call sites) only |
| Hook without knowing the target framework | Run binary-identifier first |
| Spawn without `--pause` when needed | Use spawn+resume for early hooks |
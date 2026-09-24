'use strict';

// License Flow Observer — observe license validation calls WITHOUT changing results.
// Logs call sites and return values so an authorized audit can map the validation
// flow. This template never forces a return value; it is read-only instrumentation.

console.log('[*] License flow observer hooks loading...');

const modules = Process.enumerateModules();
console.log('[*] Loaded modules: ' + modules.length);

// Observe common license-related exports by name pattern
const licensePatterns = [
    /license/i, /validate/i, /activate/i, /isregistered/i,
    /check_?license/i, /verify_?key/i, /is_?trial/i, /is_?expired/i,
    /is_?valid/i, /check_?subscription/i, /get_?license_?status/i,
];

let hookCount = 0;

for (const mod of modules) {
    try {
        const exports = mod.enumerateExports();
        for (const exp of exports) {
            if (exp.type !== 'function') continue;
            for (const pat of licensePatterns) {
                if (pat.test(exp.name)) {
                    try {
                        Interceptor.attach(exp.address, {
                            onEnter(args) {
                                console.log('[LICENSE] Called: ' + exp.name + ' @ ' + mod.name);
                            },
                            onLeave(retval) {
                                // Observation only — return value is logged, never altered.
                                console.log('[LICENSE] ' + exp.name + ' returned: ' + retval);
                            }
                        });
                        hookCount++;
                        console.log('[+] Observed: ' + mod.name + '!' + exp.name);
                    } catch (e) {
                        // Skip unhookable exports
                    }
                    break;
                }
            }
        }
    } catch (e) {
        // Module enumeration may fail for some system modules
    }
}

// --- Registry reads (Windows) — observe license-related queries ---
try {
    const RegQueryValueExW = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
    if (RegQueryValueExW) {
        Interceptor.attach(RegQueryValueExW, {
            onEnter(args) {
                try {
                    const valueName = args[1].readUtf16String();
                    if (valueName && /license|serial|key|registered|trial/i.test(valueName)) {
                        console.log('[REG] License registry query: ' + valueName);
                    }
                } catch (e) {}
            }
        });
        hookCount++;
    }
} catch (e) {}

console.log('[+] License flow observer: ' + hookCount + ' hooks installed (observation only)');

// CUSTOM_ADDRESSES
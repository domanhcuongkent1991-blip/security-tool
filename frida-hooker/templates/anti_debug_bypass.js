'use strict';

// Anti-Debug Check Observer — report which anti-debugging/anti-instrumentation
// checks an application performs, WITHOUT defeating any of them. Useful for a
// mitigation-inventory review on an authorized target: the output shows whether
// the app actually enforces debugger detection and how thoroughly.

console.log('[*] Anti-debug check observer hooks loading...');

let hookCount = 0;

// --- IsDebuggerPresent ---
try {
    const IsDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
    if (IsDebuggerPresent) {
        Interceptor.attach(IsDebuggerPresent, {
            onLeave(retval) {
                // Observation only — the return value is never altered.
                console.log('[ANTIDEBUG] IsDebuggerPresent called => ' + retval);
            }
        });
        hookCount++;
    }
} catch (e) {}

// --- CheckRemoteDebuggerPresent ---
try {
    const CheckRemoteDebuggerPresent = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
    if (CheckRemoteDebuggerPresent) {
        Interceptor.attach(CheckRemoteDebuggerPresent, {
            onEnter(args) {
                this.pDebuggerPresent = args[1];
            },
            onLeave(retval) {
                if (!this.pDebuggerPresent.isNull()) {
                    const val = this.pDebuggerPresent.readU32();
                    console.log('[ANTIDEBUG] CheckRemoteDebuggerPresent called, out=' + val);
                }
            }
        });
        hookCount++;
    }
} catch (e) {}

// --- NtQueryInformationProcess (ProcessDebugPort=7, DebugObjectHandle=30, DebugFlags=31) ---
try {
    const NtQueryInformationProcess = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
    if (NtQueryInformationProcess) {
        Interceptor.attach(NtQueryInformationProcess, {
            onEnter(args) {
                this.infoClass = args[1].toInt32();
            },
            onLeave(retval) {
                if (this.infoClass === 7 || this.infoClass === 30 || this.infoClass === 31) {
                    console.log('[ANTIDEBUG] NtQueryInformationProcess(class=' + this.infoClass + ') => ' + retval);
                }
            }
        });
        hookCount++;
    }
} catch (e) {}

// --- NtSetInformationThread (HideThreadFromDebugger=17) ---
try {
    const NtSetInformationThread = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
    if (NtSetInformationThread) {
        Interceptor.attach(NtSetInformationThread, {
            onEnter(args) {
                const infoClass = args[1].toInt32();
                if (infoClass === 17) {
                    console.log('[ANTIDEBUG] NtSetInformationThread(HideThreadFromDebugger) requested');
                }
            }
        });
        hookCount++;
    }
} catch (e) {}

// --- Timing checks (GetTickCount deltas can indicate anti-debug timing tests) ---
try {
    const GetTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
    let lastTick = 0;

    if (GetTickCount) {
        Interceptor.attach(GetTickCount, {
            onLeave(retval) {
                const tick = retval.toInt32() & 0xFFFFFFFF;
                if (lastTick > 0 && (tick - lastTick) > 10000) {
                    console.log('[ANTIDEBUG] GetTickCount large delta: ' + (tick - lastTick) + 'ms (possible timing check)');
                }
                lastTick = tick;
            }
        });
        hookCount++;
    }
} catch (e) {}

// --- Anti-Frida scanning indicators ---
try {
    const LoadLibraryW = Module.findExportByName('kernel32.dll', 'LoadLibraryW');
    if (LoadLibraryW) {
        Interceptor.attach(LoadLibraryW, {
            onEnter(args) {
                try {
                    const name = args[0].readUtf16String();
                    if (name && /frida|agent/i.test(name)) {
                        console.log('[ANTIDEBUG] Library scan touches instrumentation name: ' + name);
                    }
                } catch (e) {}
            }
        });
        hookCount++;
    }
} catch (e) {}

console.log('[+] Anti-debug observer: ' + hookCount + ' hooks installed (observation only)');
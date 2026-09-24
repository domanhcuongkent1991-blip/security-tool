'use strict';

// TLS Handshake Observer — observe TLS/security-flag activity WITHOUT altering it.
// Logs WinHTTP/Schannel calls so an authorized audit can map transport security
// posture. This template never injects ignore-cert flags and never disables
// certificate validation.

console.log('[*] TLS handshake observer hooks loading...');

let hookCount = 0;

// --- WinHTTP (Windows) ---
try {
    const WinHttpSetOption = Module.findExportByName('winhttp.dll', 'WinHttpSetOption');
    if (WinHttpSetOption) {
        Interceptor.attach(WinHttpSetOption, {
            onEnter(args) {
                const option = args[1].toInt32();
                // WINHTTP_OPTION_SECURITY_FLAGS = 31, WINHTTP_OPTION_CLIENT_CERT_CONTEXT = 47
                if (option === 31 || option === 47) {
                    // Observation only — report the requested security flags.
                    const flags = args[2].isNull() ? 'NULL' : args[2].readU32().toString(16);
                    console.log('[TLS] WinHttpSetOption security flags: option=31 value=0x' + flags);
                }
            }
        });
        hookCount++;
    }

    const WinHttpSendRequest = Module.findExportByName('winhttp.dll', 'WinHttpSendRequest');
    if (WinHttpSendRequest) {
        Interceptor.attach(WinHttpSendRequest, {
            onEnter(args) {
                console.log('[TLS] WinHttpSendRequest issued');
            }
        });
        hookCount++;
    }
} catch (e) {
    console.log('[TLS] WinHTTP observers skipped: ' + e.message);
}

// --- Schannel / SSPI (Windows native TLS) ---
try {
    const InitializeSecurityContextW = Module.findExportByName('sspicli.dll', 'InitializeSecurityContextW')
        || Module.findExportByName('secur32.dll', 'InitializeSecurityContextW');
    if (InitializeSecurityContextW) {
        Interceptor.attach(InitializeSecurityContextW, {
            onEnter(args) {
                this.context = args[1];
            },
            onLeave(retval) {
                console.log('[TLS] InitializeSecurityContextW => ' + retval);
            }
        });
        hookCount++;
    }
} catch (e) {
    console.log('[TLS] Schannel observers skipped: ' + e.message);
}

console.log('[+] TLS handshake observer: ' + hookCount + ' hooks installed (observation only)');

// CUSTOM_ADDRESSES
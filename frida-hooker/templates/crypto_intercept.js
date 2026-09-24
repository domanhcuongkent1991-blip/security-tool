'use strict';

// Crypto Operation Observer — inventory crypto API usage WITHOUT capturing
// secrets. Logs which crypto operations run, with key handles and buffer
// sizes only. Sensitive buffer contents are never read or printed, per
// MASTER_POLICY redaction rules.

console.log('[*] Crypto operation observer hooks loading...');

let hookCount = 0;

// --- Windows BCrypt (modern crypto API) ---
try {
    const BCryptEncrypt = Module.findExportByName('bcrypt.dll', 'BCryptEncrypt');
    if (BCryptEncrypt) {
        Interceptor.attach(BCryptEncrypt, {
            onEnter(args) {
                this.cbInput = args[2].toInt32();
                console.log('[CRYPTO] BCryptEncrypt: key handle=' + args[0] + ' input_size=' + this.cbInput);
            }
        });
        hookCount++;
    }

    const BCryptDecrypt = Module.findExportByName('bcrypt.dll', 'BCryptDecrypt');
    if (BCryptDecrypt) {
        Interceptor.attach(BCryptDecrypt, {
            onEnter(args) {
                console.log('[CRYPTO] BCryptDecrypt: key handle=' + args[0] + ' input_size=' + args[2].toInt32());
            }
        });
        hookCount++;
    }

    const BCryptGenerateSymmetricKey = Module.findExportByName('bcrypt.dll', 'BCryptGenerateSymmetricKey');
    if (BCryptGenerateSymmetricKey) {
        Interceptor.attach(BCryptGenerateSymmetricKey, {
            onEnter(args) {
                // Size metadata only — the secret buffer is never read.
                console.log('[CRYPTO] BCryptGenerateSymmetricKey: key_size=' + args[4].toInt32() + ' bytes');
            }
        });
        hookCount++;
    }

    const BCryptImportKeyPair = Module.findExportByName('bcrypt.dll', 'BCryptImportKeyPair');
    if (BCryptImportKeyPair) {
        Interceptor.attach(BCryptImportKeyPair, {
            onEnter(args) {
                let blobType = '?';
                try { blobType = args[2].readUtf16String(); } catch (e) {}
                console.log('[CRYPTO] BCryptImportKeyPair: blob_type=' + blobType + ' blob_size=' + args[4].toInt32());
            }
        });
        hookCount++;
    }
} catch (e) {
    console.log('[CRYPTO] BCrypt observers skipped: ' + e.message);
}

// --- Windows CryptoAPI (legacy) ---
try {
    const CryptEncrypt = Module.findExportByName('advapi32.dll', 'CryptEncrypt');
    if (CryptEncrypt) {
        Interceptor.attach(CryptEncrypt, {
            onEnter(args) {
                console.log('[CRYPTO] CryptEncrypt: key handle=' + args[0] + ' data_size=' + args[4].readU32());
            }
        });
        hookCount++;
    }

    const CryptDecrypt = Module.findExportByName('advapi32.dll', 'CryptDecrypt');
    if (CryptDecrypt) {
        Interceptor.attach(CryptDecrypt, {
            onEnter(args) {
                console.log('[CRYPTO] CryptDecrypt: key handle=' + args[0] + ' data_size=' + args[4].readU32());
            }
        });
        hookCount++;
    }
} catch (e) {
    console.log('[CRYPTO] CryptoAPI observers skipped: ' + e.message);
}

// --- OpenSSL ---
try {
    const EVP_EncryptUpdate = Module.findExportByName(null, 'EVP_EncryptUpdate');
    if (EVP_EncryptUpdate) {
        Interceptor.attach(EVP_EncryptUpdate, {
            onEnter(args) {
                console.log('[CRYPTO] EVP_EncryptUpdate: input_size=' + args[4].toInt32());
            }
        });
        hookCount++;
    }

    const EVP_DecryptUpdate = Module.findExportByName(null, 'EVP_DecryptUpdate');
    if (EVP_DecryptUpdate) {
        Interceptor.attach(EVP_DecryptUpdate, {
            onEnter(args) {
                console.log('[CRYPTO] EVP_DecryptUpdate: input_size=' + args[4].toInt32());
            }
        });
        hookCount++;
    }
} catch (e) {
    console.log('[CRYPTO] OpenSSL observers skipped: ' + e.message);
}

console.log('[+] Crypto operation observer: ' + hookCount + ' hooks installed (metadata only)');

// CUSTOM_ADDRESSES
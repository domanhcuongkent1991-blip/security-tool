import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_script(rel_path: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / rel_path)],
        capture_output=True, text=True,
    )


class HardenedModuleTests(unittest.TestCase):
    """Regression tests for the fail-closed circumvention entry points and
    observer-only Frida templates."""

    def test_dotnet_keygen_fails_closed(self):
        proc = run_script("dotnet-keygen/scripts/generate_keygen.py")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("retired", proc.stderr.lower())

    def test_dotnet_patcher_fails_closed(self):
        proc = run_script("dotnet-patcher/scripts/patch_dotnet.py")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("retired", proc.stderr.lower())

    def test_nuitka_key_extraction_fails_closed(self):
        proc = run_script("nuitka-decryptor/scripts/extract_key.py")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("retired", proc.stderr.lower())

    def test_frida_license_template_is_observer(self):
        text = (ROOT / "frida-hooker/templates/license_bypass.js").read_text(encoding="utf-8")
        self.assertIn("observation only", text.lower())
        self.assertNotIn("retval.replace(ptr(1))", text)
        self.assertNotIn("patched return", text)

    def test_frida_tls_template_does_not_inject_ignore_flags(self):
        text = (ROOT / "frida-hooker/templates/ssl_pinning_bypass.js").read_text(encoding="utf-8")
        self.assertNotIn("SECURITY_FLAG_IGNORE", text)

    def test_frida_antidebug_template_is_observer(self):
        text = (ROOT / "frida-hooker/templates/anti_debug_bypass.js").read_text(encoding="utf-8")
        self.assertNotIn("retval.replace(ptr", text)
        self.assertNotIn("writeU8(0)", text)
        self.assertNotIn("beingDebugged", text)

    def test_frida_crypto_template_metadata_only(self):
        text = (ROOT / "frida-hooker/templates/crypto_intercept.js").read_text(encoding="utf-8")
        self.assertIn("metadata only", text.lower())
        for forbidden in ("Key material", "Plaintext", "Ciphertext", "Decrypted"):
            self.assertNotIn(forbidden, text)

    def test_extended_safety_validator(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts/validate_safety.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
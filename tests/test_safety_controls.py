import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SafetyControlTests(unittest.TestCase):
    def test_binary_verifier_never_modifies_target(self):
        module = load("binary_verifier", ROOT / "binary-patcher/scripts/apply_patch.py")
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "sample.bin"
            target.write_bytes(b"ABCDEF")
            before = target.read_bytes()
            report = module.verify(target, [("0x1", "4243", "9090")])
            self.assertTrue(report["all_expected_bytes_match"])
            self.assertFalse(report["modified"])
            self.assertEqual(before, target.read_bytes())

    def test_network_analysis_redacts_sensitive_values(self):
        module = load("traffic_analyzer", ROOT / "network-interceptor/scripts/analyze_traffic.py")
        traffic = [{"method": "GET", "url": "https://example.test/api?token=secret-value", "request_headers": {"Authorization": "Bearer very-secret-token"}, "request_body": "password=very-secret-password", "status": 200, "response_headers": {}, "response_body": "ok"}]
        metadata = module.find_auth_metadata(traffic)
        self.assertTrue(metadata[0]["values_redacted"])
        self.assertNotIn("very-secret-token", json.dumps(metadata))
        self.assertIn("%5BREDACTED%5D", module.safe_url(traffic[0]["url"]))

    def test_retired_keygen_fails_closed(self):
        proc = subprocess.run([sys.executable, str(ROOT / "writerpro-pentest/scripts/keygen.py")], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("retired", proc.stderr.lower())

    def test_repository_safety_validator(self):
        proc = subprocess.run([sys.executable, str(ROOT / "scripts/validate_safety.py")], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()

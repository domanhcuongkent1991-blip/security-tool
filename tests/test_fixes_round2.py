import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel_path)
    module = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass can resolve `from __future__ import
    # annotations` string annotations via sys.modules lookup.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class PEValidationTests(unittest.TestCase):
    """Fix #1/#2a: identify_app.py must validate real PE headers and exit
    non-zero for missing files instead of claiming success."""

    def setUp(self):
        self.identify_app = _load(
            "identify_app_fixed", "binary-identifier/scripts/identify_app.py"
        )

    def _write(self, tmp: Path, name: str, data: bytes) -> Path:
        path = tmp / name
        path.write_bytes(data)
        return path

    def test_truncated_mz_is_not_pe(self):
        """An 8-byte MZ blob must not be labeled a PE executable."""
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "fake.exe", b"MZ\x00\x00\x00\x00\x00\x00")
            result = self.identify_app.identify(str(path))
            self.assertIsInstance(result, dict)
            indicators = " ".join(result.get("Misc/Indicators", []))
            self.assertNotIn("PE executable (Windows)", indicators)
            self.assertIn("invalid", indicators.lower())

    def test_valid_pe_header_is_detected(self):
        """A minimal but structurally valid PE must still be recognized."""
        pe = bytearray(0x100)
        pe[0:2] = b"MZ"
        pe[0x3C:0x40] = (0x80).to_bytes(4, "little")  # e_lfanew
        pe[0x80:0x84] = b"PE\x00\x00"
        pe[0x84:0x86] = (0x8664).to_bytes(2, "little")  # x64 machine
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "real.exe", bytes(pe))
            result = self.identify_app.identify(str(path))
            indicators = " ".join(result.get("Misc/Indicators", []))
            self.assertIn("PE executable (Windows, x64)", indicators)

    def test_missing_file_returns_none(self):
        self.assertIsNone(self.identify_app.identify("C:\\__no_such__\\missing.exe"))

    def test_missing_file_exit_code_nonzero(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "binary-identifier/scripts/identify_app.py"),
             "C:\\__no_such__\\missing.exe"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 1)

    def test_valid_file_exit_code_zero(self):
        pe = bytearray(0x100)
        pe[0:2] = b"MZ"
        pe[0x3C:0x40] = (0x80).to_bytes(4, "little")
        pe[0x80:0x84] = b"PE\x00\x00"
        pe[0x84:0x86] = (0x014C).to_bytes(2, "little")  # x86
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "real.exe", bytes(pe))
            proc = subprocess.run(
                [sys.executable, str(ROOT / "binary-identifier/scripts/identify_app.py"), str(path)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0)


class ElectronRouteTests(unittest.TestCase):
    """Fix #4: an already-unpacked Electron source tree (package.json with an
    electron dependency, no .asar) must route to electron-app-analyzer."""

    def setUp(self):
        self.orchestrate = _load("orchestrate_fixed", "scripts/orchestrate.py")

    def test_electron_source_tree_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "app"
            app.mkdir()
            (app / "package.json").write_text(json.dumps({
                "name": "lab-app",
                "devDependencies": {"electron": "^28.0.0"},
            }), encoding="utf-8")
            (app / "main.js").write_text("console.log('hi');\n", encoding="utf-8")
            self.assertTrue(self.orchestrate.looks_like_electron_source(app))

    def test_plain_node_project_not_electron(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp) / "proj"
            proj.mkdir()
            (proj / "package.json").write_text(json.dumps({
                "name": "web-app", "dependencies": {"express": "4.17.1"},
            }), encoding="utf-8")
            self.assertFalse(self.orchestrate.looks_like_electron_source(proj))

    def test_dir_without_package_json_not_electron(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(self.orchestrate.looks_like_electron_source(Path(tmp)))


class NoopPhaseTests(unittest.TestCase):
    """Fix #2b: phases that only emit advice (no command executed) must be
    flagged noop and excluded from the executed-phase count."""

    def setUp(self):
        self.orchestrate = _load("orchestrate_noop", "scripts/orchestrate.py")

    def test_phase_result_noop_defaults_false(self):
        phase = self.orchestrate.PhaseResult(
            name="test", skill="x", command=[], returncode=0,
            stdout_tail="", stderr_tail="", started_at="", duration_s=0.0,
        )
        self.assertFalse(phase.noop)

    def test_noop_phase_marked_in_report(self):
        """End-to-end: the remediation advisory phase (no command) is labeled
        NO-OP in REPORT.md and the console summary reports executed phases
        separately from advisory/no-match phases."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            app = tmp / "app"
            app.mkdir()
            (app / "package.json").write_text(json.dumps({
                "name": "lab-app",
                "devDependencies": {"electron": "^28.0.0"},
            }), encoding="utf-8")
            (app / "main.js").write_text("console.log('hi');\n", encoding="utf-8")
            out = tmp / "out"
            proc = subprocess.run(
                [sys.executable, str(ROOT / "scripts/orchestrate.py"),
                 str(app), "--out", str(out)],
                capture_output=True, text=True, timeout=300,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("advisory/no-match", proc.stdout)
            report = (out / "REPORT.md").read_text(encoding="utf-8")
            self.assertIn("NO-OP", report)
            mission = json.loads((out / "mission.json").read_text(encoding="utf-8"))
            noop_names = [p["name"] for p in mission["phases"] if p.get("noop")]
            self.assertTrue(noop_names, "expected at least one noop phase")
            self.assertIn("remediation", " ".join(noop_names))


class SBOMInventoryTests(unittest.TestCase):
    """Fix #3: the auditor must emit a real CycloneDX component inventory,
    offline by default, with OSV cross-check strictly opt-in."""

    def setUp(self):
        self.sca = _load("analyze_supply_chain_fixed",
                         "sbom-supply-chain-auditor/scripts/analyze_supply_chain.py")

    def _project(self, tmp: Path) -> Path:
        proj = tmp / "proj"
        proj.mkdir()
        (proj / "package.json").write_text(json.dumps({
            "name": "lab", "dependencies": {"lodash": "4.17.20"},
        }), encoding="utf-8")
        (proj / "requirements.txt").write_text("flask==2.0.0\n", encoding="utf-8")
        return proj

    def test_sbom_json_written_with_purls(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            proj = self._project(tmp)
            out = tmp / "out"
            proc = subprocess.run(
                [sys.executable,
                 str(ROOT / "sbom-supply-chain-auditor/scripts/analyze_supply_chain.py"),
                 str(proj), "--out", str(out)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            sbom_path = out / "sbom.json"
            self.assertTrue(sbom_path.is_file())
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            self.assertEqual(sbom["bomFormat"], "CycloneDX")
            self.assertEqual(sbom["specVersion"], "1.5")
            names = {c["name"] for c in sbom["components"]}
            self.assertIn("lodash", names)
            self.assertIn("flask", names)
            purls = [c.get("purl", "") for c in sbom["components"]]
            self.assertTrue(any(p.startswith("pkg:npm/lodash") for p in purls))

    def test_osv_check_is_opt_in(self):
        """Default run must not touch the network: osv summary absent."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            result = self.sca.analyze_path(self._project(tmp))
            self.assertIsNone(result["summary"].get("osv"))
            self.assertFalse(any(f["id"] == "SC-015" for f in result["findings"]))

    def test_osv_dedupe_one_finding_per_cve(self):
        """GHSA/PYSEC aliases of the same CVE collapse to a single finding."""
        comp = {"ecosystem": "npm", "name": "lodash", "version": "4.17.20",
                "file": "package.json"}
        batches = [(comp, ["GHSA-a", "GHSA-b"])]  # same CVE under two ids
        with unittest.mock.patch.object(self.sca, "_osv_post",
                                        return_value={"results": [{"vulns": [{"id": "GHSA-a"}, {"id": "GHSA-b"}]}]}), \
             unittest.mock.patch.object(self.sca, "_osv_get_vuln",
                                        return_value={"aliases": ["CVE-2021-23337"],
                                                      "database_specific": {"severity": "HIGH"}}):
            findings, _meta = self.sca.check_osv([comp])
        # both advisories alias the same CVE -> exactly one finding
        self.assertEqual(len(findings), 1)
        self.assertIn("CVE-2021-23337", findings[0]["title"])
        self.assertEqual(findings[0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
#!/usr/bin/env python3
"""Audit dependency manifests and lockfiles for supply-chain risk signals.

Emits a machine-readable SBOM inventory (sbom.json, CycloneDX 1.5 shape) so the
component list can be handed to an external scanner. Network access is opt-in
via --check-osv (OSV.dev querybatch); the default path stays fully offline.
"""
from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from pathlib import Path


SKILL = "sbom-supply-chain-auditor"
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "pyproject.toml",
    "pom.xml",
    "build.gradle",
    "Cargo.toml",
    "Cargo.lock",
    "packages.config",
}
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
# Cap detail lookups so a large dependency tree cannot fan out into hundreds of
# requests; the cap is reported in the findings so the result stays honest.
OSV_DETAIL_CAP = 30
PURL_PREFIX = {"npm": "pkg:npm/", "pypi": "pkg:pypi/", "maven": "pkg:maven/",
               "crates.io": "pkg:cargo/", "nuget": "pkg:nuget/"}


def iter_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name in MANIFEST_NAMES or path.suffix == ".csproj":
            files.append(path)
    return sorted(files)


def finding(
    fid: str,
    severity: str,
    category: str,
    title: str,
    path: Path | str,
    line_no: int,
    evidence: str,
    recommendation: str,
) -> dict:
    return {
        "id": fid,
        "severity": severity,
        "category": category,
        "title": title,
        "file": str(path),
        "line": line_no,
        "evidence": evidence.strip(),
        "recommendation": recommendation,
    }


# Curated known-malicious npm typosquat package names (historical incidents).
KNOWN_MALICIOUS = {
    "crossenv", "cross-env.js", "babelcli", "ffmepg", "gruntcli", "jquey",
    "mariadb", "mssql-node", "mssql.js", "mysqljs", "nodecaffe", "nodefabric",
    "node-fabric", "nodeffmpeg", "nodemailer-js", "nodemailer.js", "nodesqlite",
    "node-sqlite", "node-tkinter", "sqlite.js", "sqliter", "sqlserver", "loadsh",
    "fabric-js", "shadound", "smb", "tensorflowjs", "openvpn",
}
# Popular packages used to flag edit-distance-1 typosquats.
POPULAR_NPM = {
    "react", "lodash", "express", "request", "axios", "chalk", "commander",
    "debug", "moment", "async", "bluebird", "underscore", "jquery", "webpack",
    "vue", "angular", "typescript", "eslint", "jest", "mocha", "dotenv", "uuid",
    "glob", "yargs", "colors", "node-fetch", "ws", "redis", "mongoose", "pg",
    "mysql", "sequelize", "cors", "body-parser", "passport", "jsonwebtoken",
    "bcrypt", "nodemailer", "socket.io", "cross-env", "next", "webpack-cli",
}
POPULAR_PYPI = {
    "requests", "numpy", "pandas", "flask", "django", "urllib3", "setuptools",
    "pillow", "scipy", "boto3", "six", "pytest", "click", "jinja2", "sqlalchemy",
    "cryptography", "certifi", "idna", "wheel", "pyyaml", "beautifulsoup4",
    "matplotlib", "scikit-learn", "tensorflow", "torch", "fastapi", "aiohttp",
}
# License identifiers that carry copyleft / usage risk for redistribution.
RISKY_LICENSES = re.compile(r"\b(AGPL|GPL-2|GPL-3|GPLv2|GPLv3|SSPL|CC-BY-NC|WTFPL|UNLICENSED)\b", re.I)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# ---------------------------------------------------------------------------
# SBOM inventory extraction
# ---------------------------------------------------------------------------

def _purl(ecosystem: str, name: str) -> str:
    prefix = PURL_PREFIX.get(ecosystem, f"pkg:{ecosystem}/")
    return prefix + name.lstrip("@").replace("@", "%40")


def _clean_version(spec: str) -> str:
    """Reduce a dependency spec to a concrete version when possible."""
    spec = spec.strip()
    if not spec or spec in {"latest", "*"}:
        return ""
    m = re.match(r"^[~^>=<!\s]*\s*(\d[\w.\-+]*)", spec)
    return m.group(1) if m else ""


def _components_from_package_json(path: Path, rel: str) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return []
    comps = []
    for section, scope in (("dependencies", "runtime"), ("devDependencies", "development"),
                           ("optionalDependencies", "optional")):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            comps.append({
                "type": "library", "name": name, "ecosystem": "npm",
                "version": _clean_version(spec), "spec": spec, "scope": scope,
                "file": rel,
            })
    return comps


def _components_from_lockfile(path: Path, rel: str) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return []
    comps = []
    packages = data.get("packages") or {}
    if packages:  # lockfileVersion 2/3
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict) or "node_modules/" not in key:
                continue
            name = key.split("node_modules/")[-1]
            version = str(meta.get("version") or "")
            if name and version:
                comps.append({"type": "library", "name": name, "ecosystem": "npm",
                              "version": version, "spec": version,
                              "scope": "development" if meta.get("dev") else "runtime",
                              "file": rel})
    else:  # lockfileVersion 1
        for name, meta in (data.get("dependencies") or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                comps.append({"type": "library", "name": name, "ecosystem": "npm",
                              "version": str(meta["version"]), "spec": str(meta["version"]),
                              "scope": "development" if meta.get("dev") else "runtime",
                              "file": rel})
    return comps


def _components_from_requirements(path: Path, rel: str) -> list[dict]:
    comps = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-", "http", "git+")):
            continue
        m = re.match(r"^([A-Za-z0-9._\-]+)\s*(?:\[[^\]]*\])?\s*(.*)$", stripped)
        if not m:
            continue
        name, spec = m.group(1), m.group(2).split(";")[0].strip()
        comps.append({"type": "library", "name": name, "ecosystem": "pypi",
                      "version": _clean_version(spec), "spec": spec or "(unpinned)",
                      "scope": "runtime", "file": rel})
    return comps


def _components_from_pom(path: Path, rel: str) -> list[dict]:
    comps = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    # <dependency> blocks only — strip namespace prefixes for the naive regex scan.
    for block in re.findall(r"<dependency>(.*?)</dependency>", text, re.S):
        gid = re.search(r"<groupId>([^<]+)</groupId>", block)
        aid = re.search(r"<artifactId>([^<]+)</artifactId>", block)
        ver = re.search(r"<version>([^<]+)</version>", block)
        if gid and aid:
            comps.append({"type": "library", "name": f"{gid.group(1)}:{aid.group(1)}",
                          "ecosystem": "maven",
                          "version": ver.group(1).strip() if ver else "",
                          "spec": ver.group(1).strip() if ver else "(managed)",
                          "scope": "runtime", "file": rel})
    return comps


def _components_from_cargo(path: Path, rel: str) -> list[dict]:
    comps = []
    if path.name == "Cargo.lock":
        for block in re.findall(r"\[\[package\]\](.*?)(?=\[\[package\]\]|\Z)",
                                path.read_text(encoding="utf-8", errors="ignore"), re.S):
            name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
            ver = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
            if name and ver:
                comps.append({"type": "library", "name": name.group(1),
                              "ecosystem": "crates.io", "version": ver.group(1),
                              "spec": ver.group(1), "scope": "runtime", "file": rel})
    else:
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            m = re.search(rf"\[{re.escape(section)}\](.*?)(?=\n\[|\Z)",
                          path.read_text(encoding="utf-8", errors="ignore"), re.S)
            if not m:
                continue
            for name, ver in re.findall(r'^([A-Za-z0-9_\-]+)\s*=\s*"([^"]*)"', m.group(1), re.M):
                comps.append({"type": "library", "name": name, "ecosystem": "crates.io",
                              "version": _clean_version(ver), "spec": ver,
                              "scope": "development" if "dev" in section else "runtime",
                              "file": rel})
    return comps


def _components_from_gradle(path: Path, rel: str) -> list[dict]:
    comps = []
    for m in re.finditer(r"""(?:implementation|api|compile|runtimeOnly|testImplementation)\s*[\('"]([^'")]+)['"]""",
                         path.read_text(encoding="utf-8", errors="ignore")):
        coord = m.group(1).strip()
        parts = coord.split(":")
        if len(parts) >= 2:
            comps.append({"type": "library",
                          "name": f"{parts[0]}:{parts[1]}", "ecosystem": "maven",
                          "version": parts[2] if len(parts) > 2 else "",
                          "spec": coord, "scope": "runtime", "file": rel})
    return comps


def _components_from_nuget(path: Path, rel: str) -> list[dict]:
    comps = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    pattern = r'<(?:package|dependency)\s+[^>]*id="([^"]+)"[^>]*version="([^"]*)"'
    for name, ver in re.findall(pattern, text, re.I):
        comps.append({"type": "library", "name": name, "ecosystem": "nuget",
                      "version": _clean_version(ver), "spec": ver,
                      "scope": "runtime", "file": rel})
    return comps


def _components_from_pyproject(path: Path, rel: str) -> list[dict]:
    comps = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    for m in re.finditer(r'^\s*"([A-Za-z0-9._\-]+)\s*([<>=!~\[][^"]*)?"', text, re.M):
        name, spec = m.group(1), (m.group(2) or "").split(";")[0].strip()
        if name.lower() in {"python", "requires-python"}:
            continue
        comps.append({"type": "library", "name": name, "ecosystem": "pypi",
                      "version": _clean_version(spec), "spec": spec or "(unpinned)",
                      "scope": "runtime", "file": rel})
    return comps


def extract_components(files: list[Path], root: Path) -> list[dict]:
    scan_root = root if root.is_dir() else root.parent
    comps: list[dict] = []
    for path in files:
        rel = str(path.relative_to(scan_root)).replace("\\", "/") if scan_root.is_dir() else path.name
        if path.name == "package.json":
            comps.extend(_components_from_package_json(path, rel))
        elif path.name == "package-lock.json":
            comps.extend(_components_from_lockfile(path, rel))
        elif path.name == "requirements.txt":
            comps.extend(_components_from_requirements(path, rel))
        elif path.name == "pom.xml":
            comps.extend(_components_from_pom(path, rel))
        elif path.name in ("Cargo.toml", "Cargo.lock"):
            comps.extend(_components_from_cargo(path, rel))
        elif path.name == "build.gradle":
            comps.extend(_components_from_gradle(path, rel))
        elif path.name == "packages.config" or path.suffix == ".csproj":
            comps.extend(_components_from_nuget(path, rel))
        elif path.name == "pyproject.toml":
            comps.extend(_components_from_pyproject(path, rel))
    # Deduplicate on (ecosystem, name, version), keeping the first occurrence.
    seen: set[tuple[str, str, str]] = set()
    unique = []
    for comp in comps:
        key = (comp["ecosystem"], comp["name"], comp["version"] or comp["spec"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(comp)
    return unique


def build_sbom(target: Path, components: list[dict]) -> dict:
    """CycloneDX 1.5-shaped SBOM (no serialNumber/bom-ref hashing dependencies)."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": target.name or str(target)},
            "tools": [{"vendor": "ptn1411", "name": SKILL}],
        },
        "components": [
            {
                "type": c["type"],
                "name": c["name"],
                "version": c["version"] or "(unresolved)",
                "purl": _purl(c["ecosystem"], c["name"]),
                "scope": c["scope"],
                "properties": [
                    {"name": "sourceFile", "value": c["file"]},
                    {"name": "declaredSpec", "value": c["spec"]},
                    {"name": "ecosystem", "value": c["ecosystem"]},
                ],
            }
            for c in components
        ],
    }


# ---------------------------------------------------------------------------
# Optional OSV.dev cross-check (--check-osv)
# ---------------------------------------------------------------------------

def _osv_post(payload: dict, timeout: float = 15) -> dict | None:
    req = urllib.request.Request(
        OSV_QUERYBATCH_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
        return None


def _osv_get_vuln(vuln_id: str, timeout: float = 15) -> dict | None:
    req = urllib.request.Request(OSV_VULN_URL.format(vuln_id=vuln_id))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
        return None


def check_osv(components: list[dict]) -> tuple[list[dict], dict]:
    """Query OSV.dev for components with concrete versions. Returns (findings, meta)."""
    queryable = [c for c in components if c["version"] and c["ecosystem"] in PURL_PREFIX]
    meta = {"queried": len(queryable), "skipped_unversioned": len(components) - len(queryable),
            "reachable": None, "detail_cap": OSV_DETAIL_CAP}
    if not queryable:
        meta["error"] = "no components with concrete versions to query"
        return [], meta

    batches = []
    for i in range(0, len(queryable), 100):
        chunk = queryable[i:i + 100]
        payload = {"queries": [{"package": {"purl": _purl(c["ecosystem"], c["name"])},
                                "version": c["version"]} for c in chunk]}
        resp = _osv_post(payload)
        if resp is None:
            meta["reachable"] = False
            meta["error"] = "OSV.dev unreachable — findings below are offline-only"
            return [], meta
        meta["reachable"] = True
        for comp, result in zip(chunk, resp.get("results", [])):
            vuln_ids = [v.get("id") for v in result.get("vulns", []) if v.get("id")]
            if vuln_ids:
                batches.append((comp, vuln_ids))

    findings = []
    detail_count = 0
    seen = set()
    for comp, vuln_ids in batches:
        for vid in vuln_ids:
            sev = "medium"
            aliases = [vid]
            if detail_count < OSV_DETAIL_CAP:
                detail_count += 1
                detail = _osv_get_vuln(vid)
                if detail:
                    aliases = [a for a in detail.get("aliases", []) if a.startswith("CVE-")] or [vid]
                    db_specific = detail.get("database_specific", {}) or {}
                    raw_sev = str(db_specific.get("severity", "")).upper()
                    if raw_sev in {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"}:
                        sev = {"MODERATE": "medium"}.get(raw_sev, raw_sev.lower())
            # OSV lists the same vulnerability under several advisory ids (GHSA-*, PYSEC-*);
            # collapse them by the primary CVE alias so one vulnerability is one finding.
            primary = sorted(aliases)[0]
            key = (comp["ecosystem"], comp["name"], comp["version"], primary)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding(
                "SC-015", sev, "vulnerability",
                f"Known vulnerability: {comp['name']} {comp['version']} ({primary})",
                comp["file"], 1,
                f"{comp['ecosystem']}:{comp['name']}@{comp['version']} → {', '.join(aliases)}",
                "Review the advisory, upgrade to a fixed version, or document the accepted risk.",
            ))
    meta["vulnerable_components"] = len(batches)
    meta["details_fetched"] = detail_count
    if detail_count >= OSV_DETAIL_CAP:
        meta["note"] = f"advisory detail capped at {OSV_DETAIL_CAP}; severities beyond the cap default to medium"
    return findings, meta


def check_dep_name(name: str, version: str, rel: Path | str, ecosystem: str) -> list[dict]:
    """Typosquat, known-malicious, and dependency-confusion heuristics for one dependency."""
    results = []
    base = name.lower().lstrip("@").split("/")[-1]
    popular = POPULAR_NPM if ecosystem == "npm" else POPULAR_PYPI
    if base in KNOWN_MALICIOUS:
        results.append(finding("SC-010", "critical", ecosystem, "Known-malicious package name",
                               rel, 1, f"{name}: {version}",
                               "This name matches a historical malware typosquat — remove and verify."))
    elif base not in popular:
        for good in popular:
            if abs(len(base) - len(good)) <= 1 and levenshtein(base, good) == 1:
                results.append(finding("SC-011", "medium", ecosystem, "Possible typosquat dependency",
                                       rel, 1, f"{name} (near '{good}')",
                                       f"Name is one edit from popular package '{good}' — confirm it is intended."))
                break
    # Dependency confusion: scoped/internal-looking name that may resolve from the public registry.
    if ecosystem == "npm" and name.startswith("@"):
        results.append(finding("SC-012", "medium", "npm", "Scoped package — dependency-confusion risk",
                               rel, 1, name,
                               "Ensure this scope resolves only from your private registry (.npmrc/publishConfig)."))
    return results


def scan_lockfile(path: Path, rel: Path | str) -> list[dict]:
    """npm lockfile: flag entries missing integrity hashes (tamper risk)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError as exc:
        return [finding("SC-000", "low", "npm", "Malformed lockfile", rel, exc.lineno, str(exc),
                        "Regenerate the lockfile.")]
    results = []
    packages = data.get("packages") or data.get("dependencies") or {}
    missing = 0
    for key, meta in packages.items():
        if not key or not isinstance(meta, dict):
            continue
        if meta.get("resolved") and not meta.get("integrity"):
            missing += 1
    if missing:
        results.append(finding("SC-013", "medium", "npm", "Lockfile entries missing integrity hash",
                               rel, 1, f"{missing} package(s) without integrity",
                               "Regenerate the lockfile so every entry has an integrity hash."))
    return results


def scan_package_json(path: Path, rel: Path | str) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError as exc:
        return [finding("SC-000", "low", "npm", "Malformed package.json", rel, exc.lineno, str(exc), "Fix package.json so dependency tooling can parse it.")]

    results = []
    scripts = data.get("scripts", {})
    for name in ("preinstall", "install", "postinstall", "prepare"):
        if name in scripts:
            results.append(finding("SC-001", "medium", "npm", "Package install script present", rel, 1, f"{name}: {scripts[name]}", "Review install-time code execution before trusting this package."))

    lic = data.get("license") or data.get("licenses")
    lic_text = json.dumps(lic) if isinstance(lic, (list, dict)) else str(lic or "")
    if not lic:
        results.append(finding("SC-008", "low", "license", "No license declared", rel, 1, "license: (missing)", "Declare a license; missing licenses block safe redistribution."))
    elif RISKY_LICENSES.search(lic_text):
        results.append(finding("SC-009", "medium", "license", "Copyleft / restrictive license", rel, 1, f"license: {lic_text}", "Review license obligations before redistribution."))

    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for dep, version in data.get(section, {}).items():
            version_text = str(version)
            if version_text in {"latest", "*"} or version_text.startswith(("^", "~")):
                results.append(finding("SC-002", "low", "npm", "Floating npm dependency version", rel, 1, f"{dep}: {version_text}", "Pin exact versions for reproducible builds."))
            if re.search(r"^(http|https|git\+)", version_text, re.I):
                sev = "medium" if re.search(r"#[0-9a-f]{7,40}$", version_text, re.I) else "high"
                results.append(finding("SC-007", sev, "npm", "Remote npm dependency source", rel, 1, f"{dep}: {version_text}", "Pin remote dependencies to an immutable commit hash or a trusted registry."))
            if version_text.startswith("file:"):
                results.append(finding("SC-014", "low", "npm", "Local file dependency", rel, 1, f"{dep}: {version_text}", "Local path deps are unverifiable in CI — confirm this is intended."))
            results.extend(check_dep_name(dep, version_text, rel, "npm"))
    return results


def scan_requirements(path: Path, rel: Path | str) -> list[dict]:
    results = []
    for idx, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "==" not in stripped and not stripped.startswith(("-r ", "--")):
            results.append(finding("SC-003", "low", "python", "Unpinned Python requirement", rel, idx, line, "Pin package versions with hashes for repeatable installs."))
        if re.search(r"(http|https|git\+)", stripped, re.I):
            results.append(finding("SC-004", "medium", "python", "Remote dependency source", rel, idx, line, "Verify remote dependency integrity and pin commits."))
        m = re.match(r"^([A-Za-z0-9._-]+)", stripped)
        if m and not stripped.startswith(("-r ", "--", "http", "git+")):
            name = m.group(1)
            version = stripped[len(name):]
            results.extend(check_dep_name(name, version, rel, "pypi"))
    return results


def scan_text_manifest(path: Path, rel: Path | str) -> list[dict]:
    results = []
    for idx, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        if re.search(r"http://", line):
            results.append(finding("SC-005", "medium", "dependency", "Plain HTTP dependency reference", rel, idx, line, "Use HTTPS and verify artifact checksums."))
        if re.search(r"(password|token|secret)\s*[:=]", line, re.I):
            results.append(finding("SC-006", "high", "secret", "Secret-like value in manifest", rel, idx, line, "Remove secrets from source and rotate exposed credentials."))
    return results


def scan_file(path: Path, root: Path) -> list[dict]:
    rel = path.relative_to(root) if root.is_dir() else path.name
    if path.name == "package.json":
        return scan_package_json(path, rel)
    if path.name == "package-lock.json":
        return scan_lockfile(path, rel)
    if path.name == "requirements.txt":
        return scan_requirements(path, rel)
    return scan_text_manifest(path, rel)


def summarize(files: list[Path], findings: list[dict]) -> dict:
    highest = "info"
    for item in findings:
        if SEVERITY_ORDER[item["severity"]] > SEVERITY_ORDER[highest]:
            highest = item["severity"]
    return {"files_scanned": len(files), "findings_count": len(findings), "highest_severity": highest}


def analyze_path(target: Path | str, check_osv_flag: bool = False) -> dict:
    root = Path(target)
    files = iter_files(root)
    findings = []
    scan_root = root if root.is_dir() else root.parent
    for path in files:
        findings.extend(scan_file(path, scan_root))
    components = extract_components(files, root)
    sbom = build_sbom(root, components)
    osv_meta: dict = {"enabled": False}
    if check_osv_flag:
        osv_findings, osv_meta = check_osv(components)
        osv_meta["enabled"] = True
        findings.extend(osv_findings)
    result = {
        "target": str(root),
        "skill": SKILL,
        "summary": summarize(files, findings),
        "summary_extra": {"components": len(components)},
        "osv": osv_meta,
        "findings": findings,
        "artifacts": [],
    }
    result["_sbom"] = sbom
    return result


def write_outputs(result: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    sbom = result.pop("_sbom", None)
    sbom_path = None
    if sbom is not None:
        sbom_path = out_dir / "sbom.json"
        sbom_path.write_text(json.dumps(sbom, indent=2, ensure_ascii=False), encoding="utf-8")
        result["artifacts"] = [str(sbom_path)]
    (out_dir / "findings.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# SBOM Supply Chain Auditor Report",
        "",
        f"- Target: `{result['target']}`",
        f"- Files scanned: {result['summary']['files_scanned']}",
        f"- Components inventoried: {result['summary_extra']['components']}",
        f"- Findings: {result['summary']['findings_count']}",
        f"- Highest severity: {result['summary']['highest_severity']}",
    ]
    if sbom_path is not None:
        lines.append(f"- SBOM: `{sbom_path.name}` (CycloneDX 1.5)")
    osv = result.get("osv", {})
    if osv.get("enabled"):
        if osv.get("reachable"):
            lines.append(f"- OSV.dev check: {osv.get('queried', 0)} component(s) queried, "
                         f"{osv.get('vulnerable_components', 0)} with known vulnerabilities")
        else:
            lines.append(f"- OSV.dev check: FAILED ({osv.get('error', 'unreachable')})")
    else:
        lines.append("- OSV.dev check: not requested (offline mode; rerun with `--check-osv` for CVE cross-check)")
    lines.extend(["", "## Findings"])
    for item in result["findings"]:
        lines.extend(
            [
                f"### {item['id']} - {item['title']} [{item['severity']}]",
                f"- File: `{item['file']}`",
                f"- Line: {item['line']}",
                f"- Evidence: `{item['evidence']}`",
                f"- Recommendation: {item['recommendation']}",
                "",
            ]
        )
    if not result["findings"]:
        lines.append("No findings.")
    (out_dir / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit dependency manifests and lockfiles.")
    parser.add_argument("target")
    parser.add_argument("--out", default="output/sbom-supply-chain-auditor")
    parser.add_argument("--check-osv", action="store_true",
                        help="opt-in: query OSV.dev for known vulnerabilities (requires network)")
    args = parser.parse_args()
    result = analyze_path(args.target, check_osv_flag=args.check_osv)
    write_outputs(result, Path(args.out))
    print(f"[+] Components: {result['summary_extra']['components']}")
    print(f"[+] Findings: {result['summary']['findings_count']}")
    print(f"[+] Report: {Path(args.out) / 'REPORT.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

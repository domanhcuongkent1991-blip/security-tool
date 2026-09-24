#!/usr/bin/env python3
"""Read-only HAR analyzer with redaction-by-default.

It never sends requests and never writes executable replay code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

SENSITIVE = re.compile(r"(?i)(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[-_]?key|token|secret|password|private[-_]?key|license[-_]?key)")
BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[^\s,;]+")
LONG_SECRET = re.compile(r"(?i)([A-Za-z0-9_./+=-]{20,})")


def redact(value: object) -> str:
    text = str(value or "")
    text = BEARER.sub(lambda m: f"{m.group(1)} [REDACTED]", text)
    return LONG_SECRET.sub(lambda m: f"[REDACTED:{hashlib.sha256(m.group(1).encode()).hexdigest()[:12]}]", text)


def safe_url(value: str) -> str:
    parsed = urlparse(value)
    query = [(k, "[REDACTED]") if SENSITIVE.search(k) else (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query), ""))


def load_traffic(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    entries = []
    for entry in data.get("log", {}).get("entries", []):
        req, resp = entry.get("request", {}), entry.get("response", {})
        entries.append({
            "method": req.get("method", ""), "url": req.get("url", ""),
            "request_headers": {h.get("name", ""): h.get("value", "") for h in req.get("headers", [])},
            "request_body": req.get("postData", {}).get("text", ""),
            "status": resp.get("status", 0),
            "response_headers": {h.get("name", ""): h.get("value", "") for h in resp.get("headers", [])},
            "response_body": resp.get("content", {}).get("text", ""),
        })
    return entries


def safe_headers(headers: dict) -> dict:
    return {key: ("[REDACTED]" if SENSITIVE.search(key) else redact(value)) for key, value in headers.items()}


def find_api_endpoints(traffic: list[dict]) -> list[dict]:
    endpoints = defaultdict(lambda: {"methods": set(), "count": 0, "statuses": set()})
    for entry in traffic:
        url = entry.get("url", "")
        if not url:
            continue
        base = safe_url(url)
        endpoints[base]["methods"].add(entry.get("method", ""))
        endpoints[base]["count"] += 1
        endpoints[base]["statuses"].add(entry.get("status", 0))
    return [{"url": url, "methods": sorted(v["methods"]), "count": v["count"], "statuses": sorted(v["statuses"])} for url, v in sorted(endpoints.items(), key=lambda x: -x[1]["count"])]


def find_auth_metadata(traffic: list[dict]) -> list[dict]:
    results = []
    for index, entry in enumerate(traffic):
        headers = entry.get("request_headers", {})
        names = [key for key in headers if SENSITIVE.search(key)]
        if names:
            results.append({"request_index": index, "url": safe_url(entry.get("url", "")), "sensitive_headers": sorted(set(names)), "values_redacted": True})
    return results


def find_license_calls(traffic: list[dict]) -> list[dict]:
    keywords = ("license", "activate", "verify", "register", "validate", "trial", "subscription", "entitlement")
    body_keywords = ("hwid", "machine_id", "serial", "expiry", "device", "fingerprint", "activation")
    calls = []
    for i, entry in enumerate(traffic):
        url = safe_url(entry.get("url", ""))
        body = f"{entry.get('request_body', '')} {entry.get('response_body', '')}".lower()
        url_match, body_match = any(k in url.lower() for k in keywords), any(k in body for k in body_keywords)
        if url_match or body_match:
            calls.append({"request_index": i, "method": entry.get("method", ""), "url": url, "status": entry.get("status", 0), "matched_url": url_match, "matched_body": body_match, "bodies_redacted": True})
    return calls


def detect_oauth_flow(traffic: list[dict]) -> dict | None:
    found = {}
    patterns = {"authorize": r"/(?:oauth|auth).*/authorize", "token": r"/(?:oauth|auth).*/token", "callback": r"/(?:callback|redirect)"}
    for i, entry in enumerate(traffic):
        combined = safe_url(entry.get("url", "")) + " " + redact(entry.get("request_body", ""))
        for name, pattern in patterns.items():
            if re.search(pattern, combined, re.I) and name not in found:
                found[name] = {"request_index": i, "url": safe_url(entry.get("url", "")), "method": entry.get("method", "")}
    return {"flow_type": "OAuth2-like", "steps": found} if len(found) >= 2 else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze HAR/JSON traffic without replaying or exposing secrets")
    parser.add_argument("traffic_file", type=Path)
    parser.add_argument("--out", default="network-analysis")
    args = parser.parse_args()
    if not args.traffic_file.is_file():
        print(f"error: not found: {args.traffic_file}", file=sys.stderr)
        return 2
    try:
        traffic = load_traffic(args.traffic_file)
        results = {"total_requests": len(traffic), "source_sha256": hashlib.sha256(args.traffic_file.read_bytes()).hexdigest(), "endpoints": find_api_endpoints(traffic), "auth_metadata": find_auth_metadata(traffic), "license_calls": find_license_calls(traffic), "oauth_flow": detect_oauth_flow(traffic), "raw_values_included": False, "network_actions": []}
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "analysis.json").write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"read-only redacted analysis written to {out / 'analysis.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

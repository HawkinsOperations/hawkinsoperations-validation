#!/usr/bin/env python3
"""Scan scoped HO-DET-011 validation artifacts for claim-boundary violations."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCOPED_FILES = [
    ROOT / "validation" / "successor" / "ho-det-011" / "README.md",
    ROOT / "validation" / "successor" / "ho-det-011" / "validation-cases.json",
    ROOT / "reports" / "ho-det-011" / "validation-result.json",
    ROOT / "reports" / "ho-det-011" / "validation-result.md",
]
BLOCKED_TERMS = [
    "runtime-active",
    "signal-observed",
    "public-safe",
    "evidence-linked public proof",
    "public-safe runtime proof",
    "splunk-fired",
    "live splunk fired",
    "wazuh-routed",
    "cribl-routed",
    "security onion observed",
    "suricata observed",
    "zeek observed",
    "production-ready",
    "production triage",
    "fleet-wide",
    "autonomous soc",
    "ai-approved disposition",
    "analyst-approved disposition",
    "attack coverage completeness",
    "service-creation coverage completeness",
]
ALLOWED_JSON_PATH_PARTS = {
    "blocked_claims",
    "claims_not_supported",
    "trust_boundary",
    "privacy_status",
    "public_safe_status",
}
ALLOWED_TEXT_MARKERS = [
    "blocked",
    "not supported",
    "does not prove",
    "do not prove",
    "not_public_safe",
    "synthetic fixtures only",
    "synthetic validation only",
    "not runtime",
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: Path) -> str:
    if not path.exists():
        fail(f"missing scoped claim-boundary file: {path}")
    return path.read_text(encoding="utf-8")


def iter_json_strings(value: Any, path: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            found.extend(iter_json_strings(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(iter_json_strings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        found.append((path, value))
    return found


def json_context_allowed(path: str, text: str) -> bool:
    lower_path = path.lower()
    lower_text = text.lower()
    if any(part in lower_path for part in ALLOWED_JSON_PATH_PARTS):
        return True
    if lower_text in {"blocked", "no", "not_public_safe", "not_proven", "false"}:
        return True
    return any(marker in lower_text for marker in ALLOWED_TEXT_MARKERS)


def scan_json_file(path: Path, text: str) -> None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        fail(f"{path}: invalid JSON: {exc}")
    if not isinstance(data, dict):
        fail(f"{path}: expected JSON object")
    for field_path, value in iter_json_strings(data):
        lower = value.lower()
        for term in BLOCKED_TERMS:
            if term in lower and not json_context_allowed(field_path, value):
                fail(f"{path}: blocked claim outside allowed context at {field_path}: {term}")
    if data.get("public_safe_status") == "APPROVED":
        fail(f"{path}: public_safe_status must not be APPROVED")
    for key in ["runtime_active", "signal_observed", "splunk_fired", "wazuh_routed", "cribl_routed"]:
        if data.get(key) is True:
            fail(f"{path}: {key} must not be true")


def markdown_section(line: str, current: str) -> str:
    match = re.match(r"^(#+)\s+(.*)$", line.strip())
    if match:
        return match.group(2).strip().lower()
    return current


def markdown_context_allowed(section: str, line: str) -> bool:
    lower = line.lower()
    if section in {"blocked claims", "boundary", "validation boundary"}:
        return True
    return any(marker in lower for marker in ALLOWED_TEXT_MARKERS)


def scan_markdown_file(path: Path, text: str) -> None:
    section = ""
    for line_number, line in enumerate(text.splitlines(), start=1):
        section = markdown_section(line, section)
        lower = line.lower()
        for term in BLOCKED_TERMS:
            if term in lower and not markdown_context_allowed(section, line):
                fail(f"{path}:{line_number}: blocked claim outside allowed context in section {section!r}: {term}")


def main() -> int:
    scanned = 0
    for path in SCOPED_FILES:
        text = read_text(path)
        if path.suffix.lower() == ".json":
            scan_json_file(path, text)
        elif path.suffix.lower() == ".md":
            scan_markdown_file(path, text)
        else:
            fail(f"unsupported scoped file extension: {path}")
        scanned += 1
    print("STATUS=pass")
    print("CLAIM_BOUNDARY_SCAN=pass")
    print("DETECTION_ID=HO-DET-011")
    print(f"FILES_SCANNED={scanned}")
    print("WRITE_SKIPPED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

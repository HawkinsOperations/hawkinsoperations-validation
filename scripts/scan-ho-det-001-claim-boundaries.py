#!/usr/bin/env python3
"""Scan scoped HO-DET-001 validation artifacts for claim-boundary violations."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCOPED_FILES = [
    ROOT / "validation" / "successor" / "ho-det-001" / "case-packet.json",
    ROOT / "validation" / "successor" / "ho-det-001" / "autosoc-triage-packet.json",
    ROOT / "validation" / "successor" / "ho-det-001" / "llm-summary.json",
    ROOT / "validation" / "successor" / "ho-det-001" / "private-runtime-evidence-index.json",
    ROOT / "validation" / "successor" / "ho-det-001" / "private-runtime-evidence-index.md",
    ROOT / "reports" / "ho-det-001" / "validation-result.json",
    ROOT / "docs" / "HO-DET-001_CLOSED_LOOP.md",
]
BLOCKED_TERMS = [
    "runtime-active",
    "signal-observed",
    "signal-observed public proof",
    "evidence-linked public proof",
    "evidence-linked",
    "public-safe",
    "public-safe runtime proof",
    "production-ready",
    "fleet-wide",
    "splunk-proven",
    "live splunk fired",
    "live splunk firing",
    "cloudtrail-live",
    "production triage",
    "analyst-approved disposition",
    "ho-gpu-01 runtime-active",
    "cribl-routed",
    "cribl-routed telemetry",
    "wazuh-routed",
    "wazuh-routed public proof",
    "wazuh live collection",
    "aws-live",
    "autonomous soc",
    "production-ready soc",
    "fleet-wide deployment",
    "fleet-wide coverage",
    "ai-approved disposition",
    "ai decided disposition",
    "live autosoc",
    "attack detection in production",
]
ALLOWED_JSON_PATH_PARTS = {
    "unsupported_claims",
    "blocked_claims",
    "blocked_repo_claim",
    "claims_not_supported",
    "claim_boundary",
    "trust_boundary",
    "privacy_status",
    "not_proven",
}
ALLOWED_TEXT_MARKERS = [
    "blocked",
    "not_proven",
    "not_public_safe",
    "not supported",
    "does not prove",
    "do not prove",
    "remain blocked",
    "remains blocked",
    "synthetic scope only",
    "synthetic validation only",
    "not runtime",
    "not public",
]
DISALLOWED_CONTEXT_MARKERS = [
    "supported claim",
    "exact_claim_supported",
    "final claim",
    "public claim",
    "proven",
    "approved",
    "validated",
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
    if lower_text in {"blocked", "no", "not_public_safe", "not_proven", "stubbed"}:
        return True
    return any(marker in lower_text for marker in ALLOWED_TEXT_MARKERS)


def json_context_disallowed(path: str, text: str) -> bool:
    lower_path = path.lower()
    lower_text = text.lower()
    path_parts = re.split(r"[.\[]", lower_path)
    if "supported_claims" in path_parts or "supported_claim" in path_parts or "exact_claim_supported" in path_parts:
        return True
    return any(marker in lower_text for marker in DISALLOWED_CONTEXT_MARKERS) and not json_context_allowed(path, text)


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
            if term in lower:
                if json_context_disallowed(field_path, value) or not json_context_allowed(field_path, value):
                    fail(f"{path}: blocked claim outside allowed context at {field_path}: {term}")
    if data.get("public_safe_status") == "APPROVED":
        fail(f"{path}: public_safe_status must not be APPROVED")
    if data.get("ai_decided_disposition") is True:
        fail(f"{path}: ai_decided_disposition must not be true")


def markdown_section(line: str, current: str) -> str:
    match = re.match(r"^(#+)\s+(.*)$", line.strip())
    if match:
        return match.group(2).strip().lower()
    return current


def markdown_context_allowed(section: str, line: str) -> bool:
    lower = line.lower()
    lower_section = section.lower()
    if "blocked" in lower_section or lower_section in {"not proven", "what this does not prove"}:
        return True
    if section in {"blocked claims", "what this does not prove"}:
        return True
    if section == "status":
        if any(marker in lower for marker in ["blocked", "not_public_safe", "not_proven", "does not prove", "do not prove", "synthetic scope only"]):
            return True
    if any(marker in lower for marker in ALLOWED_TEXT_MARKERS):
        return True
    return False


def markdown_context_disallowed(section: str, line: str) -> bool:
    lower = line.lower()
    if section in {"supported claim", "what passed", "reviewer summary"} and not markdown_context_allowed(section, line):
        return True
    return any(marker in lower for marker in DISALLOWED_CONTEXT_MARKERS) and not markdown_context_allowed(section, line)


def scan_markdown_file(path: Path, text: str) -> None:
    section = ""
    for line_number, line in enumerate(text.splitlines(), start=1):
        section = markdown_section(line, section)
        lower = line.lower()
        for term in BLOCKED_TERMS:
            if term in lower:
                if markdown_context_disallowed(section, line) or not markdown_context_allowed(section, line):
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
    print(f"FILES_SCANNED={scanned}")
    print("WRITE_SKIPPED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

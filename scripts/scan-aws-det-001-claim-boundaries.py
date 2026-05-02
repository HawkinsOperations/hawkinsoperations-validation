#!/usr/bin/env python3
"""Scan AWS-DET-001 fixture artifacts for claim-boundary violations."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCOPED_FILES = [
    ROOT / "validation" / "cloud" / "aws" / "aws-det-001" / "validation-cases.json",
    ROOT / "reports" / "aws-det-001" / "validation-result.json",
    ROOT / "reports" / "aws-det-001" / "validation-result.md",
]
BLOCKED_TERMS = [
    "aws-live",
    "aws cloudtrail live proof",
    "cloud runtime-active",
    "production proof",
    "production-ready",
    "public-safe runtime proof",
    "signal-observed public proof",
    "live cloudtrail",
    "aws account coverage",
]
ALLOWED_CONTEXT_MARKERS = [
    "blocked",
    "not supported",
    "not aws-live",
    "not cloudtrail live",
    "not cloud runtime-active",
    "not public-safe",
    "fixture-only",
    "synthetic fixtures only",
    "claims_not_supported",
    "trust_boundary",
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
            found.extend(iter_json_strings(item, f"{path}.{key}" if path else str(key)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(iter_json_strings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        found.append((path, value))
    return found


def context_allowed(path: str, text: str) -> bool:
    lower_path = path.lower()
    lower_text = text.lower()
    return any(marker in lower_path or marker in lower_text for marker in ALLOWED_CONTEXT_MARKERS)


def scan_json_file(path: Path, text: str) -> None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        fail(f"{path}: invalid JSON: {exc}")
    for field_path, value in iter_json_strings(data):
        lower = value.lower()
        for term in BLOCKED_TERMS:
            if term in lower and not context_allowed(field_path, value):
                fail(f"{path}: blocked claim outside allowed context at {field_path}: {term}")
    if "aws_live_status" in data and data.get("aws_live_status") != "BLOCKED":
        fail(f"{path}: aws_live_status must be BLOCKED")
    if data.get("public_safe_status") == "APPROVED":
        fail(f"{path}: public_safe_status must not be APPROVED")


def scan_markdown_file(path: Path, text: str) -> None:
    section = ""
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = re.match(r"^(#+)\s+(.*)$", line.strip())
        if match:
            section = match.group(2).strip().lower()
        lower = line.lower()
        for term in BLOCKED_TERMS:
            if term in lower and section not in {"blocked claims", "boundary"} and not context_allowed(section, line):
                fail(f"{path}:{line_number}: blocked claim outside allowed context: {term}")


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
    print("AWS_DET_001_CLAIM_BOUNDARY_SCAN=pass")
    print(f"FILES_SCANNED={scanned}")
    print("WRITE_SKIPPED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Scan scoped HO-DET-010 validation artifacts for claim-boundary violations."""
from __future__ import annotations
import json
import sys
from pathlib import Path
from typing import Any
ROOT = Path(__file__).resolve().parents[1]
SCOPED_FILES = [ROOT / "validation" / "successor" / "ho-det-010" / "README.md", ROOT / "validation" / "successor" / "ho-det-010" / "validation-cases.json", ROOT / "reports" / "ho-det-010" / "validation-result.json", ROOT / "reports" / "ho-det-010" / "validation-result.md"]
BLOCKED_TERMS = ("runtime-active", "signal-observed", "public-safe", "production-ready", "fleet-wide", "autonomous SOC", "AI-approved disposition", "analyst-approved disposition", "case-closure")
ALLOWED_CONTEXT = ("blocked", "not supported", "does not prove", "not_public_safe", "controlled-test", "remain blocked")
def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)
def iter_strings(value: Any, key_path: tuple[str, ...] = ()): 
    if isinstance(value, str):
        yield key_path, value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from iter_strings(child, key_path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_strings(child, key_path + (str(index),))
def context_allowed(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in ALLOWED_CONTEXT)
def path_allowed(key_path: tuple[str, ...]) -> bool:
    return "blocked_claims" in key_path
def scan(path: Path) -> None:
    if not path.exists():
        fail(f"missing scoped claim-boundary file: {path}")
    text = path.read_text(encoding="utf-8")
    values = [((), text)]
    if path.suffix.lower() == ".json":
        values = list(iter_strings(json.loads(text)))
    for key_path, value in values:
        lower = value.lower()
        for term in BLOCKED_TERMS:
            if term.lower() in lower and not (context_allowed(value) or path_allowed(key_path)):
                fail(f"{path}: blocked claim outside allowed context: {term}")
def main() -> int:
    for path in SCOPED_FILES:
        scan(path)
    print("STATUS=pass")
    print("CLAIM_BOUNDARY_SCAN=pass")
    print("DETECTION_ID=HO-DET-010")
    print(f"FILES_SCANNED={len(SCOPED_FILES)}")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())

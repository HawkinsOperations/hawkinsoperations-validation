#!/usr/bin/env python3
"""Verify the public clone-runnable HO-DET-001 proof pack.

This verifier checks public repository fixtures only. It does not require
private runtime evidence, inspect runtime systems, generate events, or promote
public runtime proof.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PACK_ROOT = ROOT / "validation" / "successor" / "ho-det-001" / "reproducible-proof"
README = PACK_ROOT / "README.md"
BOUNDARY_STUB = PACK_ROOT / "public-runtime-boundary-stub.json"
EXPECTED_RESULT = PACK_ROOT / "expected-boundary-result.json"

PUBLIC_SAFE_STATUS = "NOT_PUBLIC_SAFE"
PROMOTION_STATUS = "BLOCKED"
PROOF_CEILING = "TEST_VALIDATED_SYNTHETIC_SCOPE"
FALSE_FIELDS = [
    "runtime_active_public_proof",
    "signal_observed_public_proof",
    "production_ready",
    "fleet_wide",
    "cribl_routed",
    "wazuh_routed_public_proof",
    "aws_live",
    "autonomous_soc",
    "ai_approved_disposition",
    "analyst_approved_disposition",
]
PRIVATE_UNSAFE_PATTERNS = [
    ("windows absolute path", re.compile(r"\b[A-Za-z]:\\")),
    ("unc path", re.compile(r"\\\\")),
    ("local ip", re.compile(r"\b(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b")),
    ("raw command line", re.compile(r"(?i)\b(?:powershell|pwsh|cmd(?:\.exe)?|splunk|wevtutil|get-winevent|curl|ssh)\s+(?:-|/|[A-Za-z]:\\)")),
    ("screenshot reference", re.compile(r"(?i)\b(?:screenshot|screen capture|\.png|\.jpg|\.jpeg)\b")),
    ("secret marker", re.compile(r"(?i)\b(?:secret|password|token|api[_-]?key|credential)\b")),
]


def fail(message: str) -> None:
    print("HO_DET_001_REPRODUCIBLE_PROOF_PACK=fail")
    print(f"PUBLIC_SAFE_STATUS={PUBLIC_SAFE_STATUS}")
    print(f"PROMOTION_STATUS={PROMOTION_STATUS}")
    print(f"PROOF_CEILING={PROOF_CEILING}")
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: Path, label: str) -> str:
    if not path.exists():
        fail(f"missing {label}: {path}")
    return path.read_text(encoding="utf-8")


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(read_text(path, label))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        fail(f"{label} mismatch: expected {expected!r}, got {actual!r}")


def require_false(value: dict[str, Any], field: str, label: str) -> None:
    if field not in value:
        fail(f"{label} missing required false field: {field}")
    if value[field] is not False:
        fail(f"{label} {field} must be false")


def iter_strings(value: Any, path: str = "") -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, list):
        found: list[tuple[str, str]] = []
        for index, item in enumerate(value):
            found.extend(iter_strings(item, f"{path}[{index}]"))
        return found
    if isinstance(value, dict):
        found: list[tuple[str, str]] = []
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            found.extend(iter_strings(item, child_path))
        return found
    return []


def verify_no_private_markers(label: str, value: Any) -> None:
    for path, text in iter_strings(value):
        for marker, pattern in PRIVATE_UNSAFE_PATTERNS:
            if pattern.search(text):
                fail(f"{label} contains public-unsafe {marker} at {path}")


def verify_required_blocked_claims(stub: dict[str, Any], expected: dict[str, Any]) -> None:
    actual = stub.get("blocked_claims")
    required = expected.get("required_blocked_claims")
    if not isinstance(actual, list) or not actual:
        fail("public-runtime-boundary-stub.json blocked_claims must be a non-empty list")
    if not isinstance(required, list) or not required:
        fail("expected-boundary-result.json required_blocked_claims must be a non-empty list")
    missing = [claim for claim in required if claim not in actual]
    if missing:
        fail(f"public-runtime-boundary-stub.json missing blocked claims: {missing}")


def verify_readme() -> None:
    text = read_text(README, "proof pack README")
    required = [
        "# HO-DET-001 Reproducible Proof Pack",
        "Clone and verify the validation/proof boundary locally.",
        r"python -B scripts\verify-ho-det-001-reproducible-proof-pack.py",
        "private lab runtime receipts may exist outside the repo",
        "public clone-run does not require or expose them",
        "public promotion requires separate review",
    ]
    for item in required:
        if item not in text:
            fail(f"proof pack README missing required text: {item}")
    for marker, pattern in PRIVATE_UNSAFE_PATTERNS:
        if pattern.search(text):
            fail(f"proof pack README contains public-unsafe {marker}")


def main() -> int:
    stub = load_json(BOUNDARY_STUB, "public runtime boundary stub")
    expected = load_json(EXPECTED_RESULT, "expected boundary result")

    require_equal(stub.get("detection_id"), "HO-DET-001", "stub detection_id")
    require_equal(expected.get("detection_id"), "HO-DET-001", "expected detection_id")
    require_equal(stub.get("public_safe_status"), PUBLIC_SAFE_STATUS, "stub public_safe_status")
    require_equal(stub.get("promotion_status"), PROMOTION_STATUS, "stub promotion_status")
    require_equal(stub.get("proof_ceiling"), PROOF_CEILING, "stub proof_ceiling")
    require_equal(expected.get("public_safe_status"), PUBLIC_SAFE_STATUS, "expected public_safe_status")
    require_equal(expected.get("promotion_status"), PROMOTION_STATUS, "expected promotion_status")
    require_equal(expected.get("proof_ceiling"), PROOF_CEILING, "expected proof_ceiling")

    for field in FALSE_FIELDS:
        require_false(stub, field, "public-runtime-boundary-stub.json")
        expected_false = expected.get("expected_false_fields", {})
        if not isinstance(expected_false, dict):
            fail("expected-boundary-result.json expected_false_fields must be an object")
        require_equal(expected_false.get(field), False, f"expected false field {field}")

    require_equal(stub.get("private_runtime_evidence_required_for_clone_run"), False, "private runtime evidence requirement")
    require_equal(stub.get("raw_private_evidence_exposed"), False, "raw private evidence exposure")
    require_equal(stub.get("verification_scope"), "STRUCTURE_AND_BOUNDARY_ONLY", "verification_scope")
    verify_required_blocked_claims(stub, expected)
    verify_no_private_markers("public-runtime-boundary-stub.json", stub)
    verify_no_private_markers("expected-boundary-result.json", expected)
    verify_readme()

    print("HO_DET_001_REPRODUCIBLE_PROOF_PACK=pass")
    print(f"PUBLIC_SAFE_STATUS={PUBLIC_SAFE_STATUS}")
    print(f"PROMOTION_STATUS={PROMOTION_STATUS}")
    print(f"PROOF_CEILING={PROOF_CEILING}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

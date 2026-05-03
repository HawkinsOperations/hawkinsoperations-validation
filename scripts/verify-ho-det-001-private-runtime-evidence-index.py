#!/usr/bin/env python3
"""Verify the HO-DET-001 private runtime evidence index boundary.

This verifier checks committed index metadata only. It does not read private
receipt bodies, inspect runtime systems, generate events, or promote public
proof.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INDEX_JSON = ROOT / "validation" / "successor" / "ho-det-001" / "private-runtime-evidence-index.json"

PRIVATE_TRUTH_LABEL = "LOCAL_SYSMON_AND_WAZUH_EVENT_CORRELATED_PRIVATE_LAB_SPLUNK_NOT_PROVEN"
PUBLIC_SAFE_STATUS = "NOT_PUBLIC_SAFE"
PROMOTION_STATUS = "BLOCKED"
EVIDENCE_SCOPE = "PRIVATE_LAB_ENDPOINT_SCOPED"
PROOF_CEILING = "TEST_VALIDATED_SYNTHETIC_SCOPE"

REQUIRED_PROVEN_PRIVATE = [
    "controlled benign event generated",
    "local Sysmon captured event",
    "HO-DET-001 local match observed",
    "Wazuh event identifiers correlated",
    "private receipt files and hashes exist",
]
REQUIRED_NOT_PROVEN = [
    "original event-specific Splunk proof",
    "Cribl-routed telemetry",
    "public-safe runtime proof",
    "runtime-active public proof",
    "signal-observed public proof",
    "production-ready",
    "fleet-wide",
    "AWS-live",
    "autonomous SOC",
    "AI-approved disposition",
    "analyst-approved disposition",
]
REQUIRED_BLOCKED_CLAIMS = [
    "HO-DET-001 is runtime-active",
    "HO-DET-001 is signal-observed public proof",
    "HO-DET-001 is public-safe",
    "HO-DET-001 is production-ready",
    "HO-DET-001 is fleet-wide",
    "HO-DET-001 is Splunk-proven for Runtime Signal 001",
    "HO-DET-001 is Cribl-routed",
    "HO-DET-001 is Wazuh-routed public proof",
    "HO-DET-001 is AWS-live",
    "HO-DET-001 has AI-approved disposition",
    "HO-DET-001 has analyst-approved disposition",
]
EXPECTED_EVIDENCE_HASHES = {
    "private_receipt_md": "2BF41780DAAEB8628CE8E4A3AFCC8A9450327FD9F9F9E4D4775D37C49370744A",
    "private_receipt_json": "D1B6ED8FF8A048DFEFFECD623962F63BBAA808AD3330CAE2195BDE2C4AB82882",
    "private_receipt_hash_manifest": "064316D73A07C88CC0F42ED9437105A1338DFF6F3851117E3B88A928C0217706",
}
EXPECTED_EVIDENCE_PATHS = {
    "private_receipt_md": r"C:\Raylee\Data\evidence-staging\HO-DET-001\runtime-signal-001\HO-DET-001_RUNTIME_SIGNAL_001_PRIVATE_RECEIPT.md",
    "private_receipt_json": r"C:\Raylee\Data\evidence-staging\HO-DET-001\runtime-signal-001\HO-DET-001_RUNTIME_SIGNAL_001_PRIVATE_RECEIPT.json",
    "private_receipt_hash_manifest": r"C:\Raylee\Data\evidence-staging\HO-DET-001\runtime-signal-001\HO-DET-001_RUNTIME_SIGNAL_001_PRIVATE_RECEIPT_HASHES.txt",
}
PROMOTED_ALLOWED_CLAIM_TERMS = [
    "runtime-active",
    "signal-observed",
    "signal-observed public proof",
    "public-safe",
    "public-safe runtime proof",
    "production-ready",
    "fleet-wide",
    "cribl-routed",
    "splunk-proven",
    "aws-live",
    "autonomous soc",
    "ai-approved disposition",
    "analyst-approved disposition",
]
SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")


def fail(message: str) -> None:
    print(f"PRIVATE_RUNTIME_EVIDENCE_INDEX=fail")
    print(f"PUBLIC_SAFE_STATUS={PUBLIC_SAFE_STATUS}")
    print(f"PROMOTION_STATUS={PROMOTION_STATUS}")
    print(f"PROOF_CEILING={PROOF_CEILING}")
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_index() -> dict[str, Any]:
    if not INDEX_JSON.exists():
        fail(f"missing private runtime evidence index: {INDEX_JSON}")
    try:
        value = json.loads(INDEX_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in private runtime evidence index: {exc}")
    if not isinstance(value, dict):
        fail("private runtime evidence index must be a JSON object")
    return value


def require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        fail(f"{label} mismatch: expected {expected!r}, got {actual!r}")


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list) or not value:
        fail(f"{label} must be present and non-empty")
    return value


def require_required_items(actual: list[Any], expected: list[str], label: str) -> None:
    strings = [item for item in actual if isinstance(item, str)]
    missing = [item for item in expected if item not in strings]
    if missing:
        fail(f"{label} missing required items: {missing}")


def iter_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        found: list[str] = []
        for item in value:
            found.extend(iter_strings(item))
        return found
    return []


def verify_allowed_claims(index: dict[str, Any]) -> None:
    claims = iter_strings(index.get("allowed_repo_claim"))
    if not claims:
        fail("allowed_repo_claim must be present and non-empty")
    for claim in claims:
        lower = claim.lower()
        for term in PROMOTED_ALLOWED_CLAIM_TERMS:
            if term in lower:
                fail(f"allowed_repo_claim promotes blocked term: {term}")


def verify_evidence_files(index: dict[str, Any]) -> None:
    evidence_files = require_list(index.get("evidence_files"), "evidence_files")
    by_label: dict[str, dict[str, Any]] = {}
    for item in evidence_files:
        if not isinstance(item, dict):
            fail("evidence_files entries must be objects")
        label = item.get("label")
        if not isinstance(label, str) or not label:
            fail("evidence_files entries must include label")
        by_label[label] = item

    for label, expected_hash in EXPECTED_EVIDENCE_HASHES.items():
        if label not in by_label:
            fail(f"evidence_files missing label: {label}")
        item = by_label[label]
        require_equal(item.get("path"), EXPECTED_EVIDENCE_PATHS[label], f"{label} path")
        sha256 = item.get("sha256")
        if not isinstance(sha256, str) or not SHA256_RE.match(sha256):
            fail(f"{label} sha256 must be a 64-character hex string")
        require_equal(sha256.upper(), expected_hash, f"{label} sha256")


def main() -> int:
    index = load_index()
    require_equal(index.get("detection_id"), "HO-DET-001", "detection_id")
    require_equal(index.get("private_truth_label"), PRIVATE_TRUTH_LABEL, "private_truth_label")
    require_equal(index.get("public_safe_status"), PUBLIC_SAFE_STATUS, "public_safe_status")
    require_equal(index.get("promotion_status"), PROMOTION_STATUS, "promotion_status")
    require_equal(index.get("evidence_scope"), EVIDENCE_SCOPE, "evidence_scope")
    require_equal(index.get("proof_ceiling"), PROOF_CEILING, "proof_ceiling")

    require_required_items(require_list(index.get("proven_private"), "proven_private"), REQUIRED_PROVEN_PRIVATE, "proven_private")
    require_required_items(require_list(index.get("not_proven"), "not_proven"), REQUIRED_NOT_PROVEN, "not_proven")
    require_required_items(require_list(index.get("blocked_repo_claim"), "blocked_repo_claim"), REQUIRED_BLOCKED_CLAIMS, "blocked_repo_claim")
    verify_allowed_claims(index)
    verify_evidence_files(index)

    print("PRIVATE_RUNTIME_EVIDENCE_INDEX=pass")
    print(f"PUBLIC_SAFE_STATUS={PUBLIC_SAFE_STATUS}")
    print(f"PROMOTION_STATUS={PROMOTION_STATUS}")
    print(f"PROOF_CEILING={PROOF_CEILING}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

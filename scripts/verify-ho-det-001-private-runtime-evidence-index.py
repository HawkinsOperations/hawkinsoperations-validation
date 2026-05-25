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

PRIVATE_TRUTH_LABEL = "CONTROLLED_LOCAL_LLM_SUPPORT_ONLY_PRIVATE_RECEIPT"
PUBLIC_SAFE_STATUS = "NOT_PUBLIC_SAFE"
PROMOTION_STATUS = "BLOCKED"
EVIDENCE_SCOPE = "PRIVATE_LLM_RUNTIME_RECEIPT_SCOPED"
VERIFICATION_SCOPE = "STRUCTURE_AND_BOUNDARY_ONLY"
PROOF_CEILING = "CONTROLLED_LOCAL_LLM_RUNTIME_RECEIPT_PACKET_SCOPE"
EVIDENCE_ID = "gpu-runtime-receipt-001"
EVIDENCE_STORE = "PRIVATE_EVIDENCE_STORE"
EVIDENCE_LOCATION_PUBLIC = "REDACTED_PRIVATE"
STORAGE_CLASS = "PRIVATE_LAB_EVIDENCE"
TRUST_LABEL = "CONTROLLED_LOCAL_LLM_SUPPORT_ONLY_PRIVATE_RECEIPT"
MODEL = "qwen2.5:14b"
VERIFIER_STATUS = "PASS"
REQUIRED_ARTIFACTS_PRESENT = "14/14"

REQUIRED_BOUNDARY_FIELDS = {
    "AI_DECIDED_DISPOSITION": False,
    "AI_MAY_APPROVE": False,
    "AI_MAY_PROMOTE": False,
    "AI_MAY_CLOSE": False,
    "HUMAN_REVIEW_REQUIRED": True,
    "SUPPORT_ONLY": True,
    "PUBLIC_SAFE_STATUS": PUBLIC_SAFE_STATUS,
    "PROOF_CEILING": PROOF_CEILING,
}

REQUIRED_TRUTH_PLANES = {
    "source_truth",
    "validation_truth",
    "runtime_truth",
    "signal_truth",
    "evidence_truth",
    "ai_triage_truth",
    "public_proof_truth",
    "human_review_truth",
}

REQUIRED_PROVEN_PRIVATE = [
    "controlled local Ollama invocation completed",
    "qwen2.5:14b generated support-only triage output",
    "sanitized controlled-test HO-DET-001 case packet hash matched across transfer",
    "private receipt artifacts and hashes exist",
    "private verifier status is PASS",
]
REQUIRED_NOT_PROVEN = [
    "runtime-active detection",
    "signal-observed public proof",
    "live telemetry routing",
    "public-safe runtime proof",
    "production-ready",
    "fleet-wide",
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
    "HO-DET-001 has live Splunk proof",
    "HO-DET-001 is Cribl-routed",
    "HO-DET-001 is Wazuh-routed",
    "HO-DET-001 has AI-approved disposition",
    "HO-DET-001 has analyst-approved disposition",
]
EXPECTED_EVIDENCE_HASHES = {
    "case_packet_input": "B258FECA9515AA643937929F148F87BF6AE9E9B71E4AF9E45420BCC8CBCBB41E",
    "linux_case_packet_input": "B258FECA9515AA643937929F148F87BF6AE9E9B71E4AF9E45420BCC8CBCBB41E",
    "llm_output_raw": "CEC879EF8827D2A0F984B553D08C91782942D4403560F92BC8A45A197DB383EB",
    "evidence_manifest": "FE2D767D69E936132DABCF12FC1B6F9A8FC24C2D22559E43F0A2EF0A31CA95E6",
    "verifier_result": "28D0166781035523CDAA6551A12355A705930C842AFEB3A09184B4F8AD61DC5F",
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
    "wazuh-routed",
    "live splunk",
    "splunk-proven",
    "aws-live",
    "autonomous soc",
    "ai-approved disposition",
    "analyst-approved disposition",
]
SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
PUBLIC_UNSAFE_PATTERNS = [
    ("windows absolute path", re.compile(r"\b[A-Za-z]:\\")),
    ("unc path", re.compile(r"\\\\")),
    ("local ip", re.compile(r"\b(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b")),
    ("raw private evidence filename", re.compile(r"(?i)\b(?:private[_-]?receipt|private[_-]?receipt[_-]?hashes|runtime[_-]?signal[_-]?\d{3}[_-]?private)\b")),
    ("raw command line", re.compile(r"(?i)\b(?:powershell|pwsh|cmd(?:\.exe)?|splunk|wevtutil|get-winevent|curl|ssh)\s+(?:-|/|[A-Za-z]:\\)")),
    ("screenshot reference", re.compile(r"(?i)\b(?:screenshot|screen capture|\.png|\.jpg|\.jpeg)\b")),
    ("secret marker", re.compile(r"(?i)\b(?:secret|password|token|api[_-]?key|credential)\b")),
]


def fail(message: str) -> None:
    print(f"PRIVATE_RUNTIME_EVIDENCE_INDEX=fail")
    print(f"PUBLIC_SAFE_STATUS={PUBLIC_SAFE_STATUS}")
    print(f"PROMOTION_STATUS={PROMOTION_STATUS}")
    print(f"PROOF_CEILING={PROOF_CEILING}")
    print("PUBLIC_RUNTIME_CLAIM_STATUS=PUBLIC_RUNTIME_BLOCKED")
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


def verify_public_safe_strings(index: dict[str, Any]) -> None:
    for path, text in iter_strings(index):
        for label, pattern in PUBLIC_UNSAFE_PATTERNS:
            if pattern.search(text):
                fail(f"public-unsafe {label} present at {path}")


def verify_allowed_claims(index: dict[str, Any]) -> None:
    claims = [text for _, text in iter_strings(index.get("allowed_repo_claim"))]
    if not claims:
        fail("allowed_repo_claim must be present and non-empty")
    for claim in claims:
        lower = claim.lower()
        for term in PROMOTED_ALLOWED_CLAIM_TERMS:
            if term in lower:
                fail(f"allowed_repo_claim promotes blocked term: {term}")


def verify_receipt_hashes(index: dict[str, Any]) -> None:
    receipt_hashes = require_list(index.get("receipt_hashes"), "receipt_hashes")
    by_label: dict[str, dict[str, Any]] = {}
    for item in receipt_hashes:
        if not isinstance(item, dict):
            fail("receipt_hashes entries must be objects")
        label = item.get("artifact")
        if not isinstance(label, str) or not label:
            fail("receipt_hashes entries must include artifact")
        if "path" in item:
            fail(f"receipt_hashes entry must not expose a path: {label}")
        by_label[label] = item

    for label, expected_hash in EXPECTED_EVIDENCE_HASHES.items():
        if label not in by_label:
            fail(f"receipt_hashes missing artifact: {label}")
        item = by_label[label]
        sha256 = item.get("sha256")
        if not isinstance(sha256, str) or not SHA256_RE.match(sha256):
            fail(f"{label} sha256 must be a 64-character hex string")
        require_equal(sha256.upper(), expected_hash, f"{label} sha256")


def verify_boundary_fields(index: dict[str, Any]) -> None:
    boundary_fields = index.get("boundary_fields")
    if not isinstance(boundary_fields, dict):
        fail("boundary_fields must be present")
    for label, expected in REQUIRED_BOUNDARY_FIELDS.items():
        require_equal(boundary_fields.get(label), expected, f"boundary_fields.{label}")


def require_ref_list(value: Any, label: str, minimum: int = 2) -> None:
    if not isinstance(value, list) or len(value) < minimum:
        fail(f"{label} must include at least {minimum} references")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            fail(f"{label} entries must be non-empty strings")


def require_truth_plane(spine: dict[str, Any], label: str) -> dict[str, Any]:
    value = spine.get(label)
    if not isinstance(value, dict):
        fail(f"runtime_truth_spine.{label} must be a JSON object")
    return value


def verify_runtime_truth_spine(index: dict[str, Any]) -> None:
    spine = index.get("runtime_truth_spine")
    if not isinstance(spine, dict):
        fail("runtime_truth_spine must be present")
    missing = sorted(REQUIRED_TRUTH_PLANES - set(spine))
    if missing:
        fail(f"runtime_truth_spine missing truth planes: {missing}")

    source_truth = require_truth_plane(spine, "source_truth")
    validation_truth = require_truth_plane(spine, "validation_truth")
    runtime_truth = require_truth_plane(spine, "runtime_truth")
    signal_truth = require_truth_plane(spine, "signal_truth")
    evidence_truth = require_truth_plane(spine, "evidence_truth")
    ai_truth = require_truth_plane(spine, "ai_triage_truth")
    public_truth = require_truth_plane(spine, "public_proof_truth")
    human_truth = require_truth_plane(spine, "human_review_truth")

    require_equal(source_truth.get("state"), "SOURCE_EXISTS", "source_truth.state")
    require_equal(validation_truth.get("state"), "CONTROLLED_TEST_VALIDATED", "validation_truth.state")
    require_ref_list(source_truth.get("refs"), "source_truth.refs")
    require_ref_list(validation_truth.get("refs"), "validation_truth.refs")

    require_equal(runtime_truth.get("state"), "RUNTIME_EVIDENCE_VERIFIED_PRIVATE", "runtime_truth.state")
    require_equal(runtime_truth.get("public_runtime_claim_status"), "PUBLIC_RUNTIME_BLOCKED", "runtime_truth.public_runtime_claim_status")
    require_ref_list(runtime_truth.get("verified_runtime_evidence_refs"), "runtime_truth.verified_runtime_evidence_refs")

    require_equal(signal_truth.get("state"), "SIGNAL_OBSERVED_PRIVATE", "signal_truth.state")
    require_equal(signal_truth.get("public_signal_claim_status"), "PUBLIC_RUNTIME_BLOCKED", "signal_truth.public_signal_claim_status")
    require_ref_list(signal_truth.get("verified_signal_record_refs"), "signal_truth.verified_signal_record_refs")

    require_equal(evidence_truth.get("state"), "RUNTIME_EVIDENCE_VERIFIED_PRIVATE", "evidence_truth.state")
    require_equal(evidence_truth.get("raw_private_evidence_public_safe"), False, "evidence_truth.raw_private_evidence_public_safe")
    require_equal(evidence_truth.get("repo_contains_raw_private_evidence"), False, "evidence_truth.repo_contains_raw_private_evidence")
    require_equal(evidence_truth.get("hash_only_private_refs"), True, "evidence_truth.hash_only_private_refs")

    require_equal(ai_truth.get("support_state"), "AI_SUPPORT_ONLY", "ai_triage_truth.support_state")
    require_equal(ai_truth.get("triage_output_state"), "AI_TRIAGE_OUTPUT_PRIVATE", "ai_triage_truth.triage_output_state")
    require_equal(ai_truth.get("authority_state"), "AI_NOT_AUTHORITY", "ai_triage_truth.authority_state")
    require_equal(ai_truth.get("ai_decided_disposition"), False, "ai_triage_truth.ai_decided_disposition")
    require_equal(ai_truth.get("human_review_required"), True, "ai_triage_truth.human_review_required")

    require_equal(public_truth.get("state"), "PUBLIC_RUNTIME_BLOCKED", "public_proof_truth.state")
    require_equal(public_truth.get("proof_ceiling"), "CONTROLLED_TEST_VALIDATED", "public_proof_truth.proof_ceiling")
    require_equal(public_truth.get("public_safe_status"), PUBLIC_SAFE_STATUS, "public_proof_truth.public_safe_status")

    require_equal(human_truth.get("state"), "HUMAN_REVIEW_REQUIRED", "human_review_truth.state")
    require_equal(human_truth.get("public_runtime_summary_state"), "PUBLIC_RUNTIME_BLOCKED", "human_review_truth.public_runtime_summary_state")
    require_equal(human_truth.get("approval_required_for_public_summary"), True, "human_review_truth.approval_required_for_public_summary")


def main() -> int:
    index = load_index()
    require_equal(index.get("detection_id"), "HO-DET-001", "detection_id")
    require_equal(index.get("private_truth_label"), PRIVATE_TRUTH_LABEL, "private_truth_label")
    require_equal(index.get("public_safe_status"), PUBLIC_SAFE_STATUS, "public_safe_status")
    require_equal(index.get("promotion_status"), PROMOTION_STATUS, "promotion_status")
    require_equal(index.get("evidence_scope"), EVIDENCE_SCOPE, "evidence_scope")
    require_equal(index.get("verification_scope"), VERIFICATION_SCOPE, "verification_scope")
    require_equal(index.get("proof_ceiling"), PROOF_CEILING, "proof_ceiling")
    require_equal(index.get("evidence_id"), EVIDENCE_ID, "evidence_id")
    require_equal(index.get("evidence_store"), EVIDENCE_STORE, "evidence_store")
    require_equal(index.get("evidence_location_public"), EVIDENCE_LOCATION_PUBLIC, "evidence_location_public")
    require_equal(index.get("storage_class"), STORAGE_CLASS, "storage_class")
    require_equal(index.get("trust_label"), TRUST_LABEL, "trust_label")
    require_equal(index.get("model"), MODEL, "model")
    require_equal(index.get("verifier_status"), VERIFIER_STATUS, "verifier_status")
    require_equal(index.get("required_artifacts_present"), REQUIRED_ARTIFACTS_PRESENT, "required_artifacts_present")
    if "evidence_files" in index:
        fail("evidence_files must not be present in the public-safe index")

    require_required_items(require_list(index.get("proven_private"), "proven_private"), REQUIRED_PROVEN_PRIVATE, "proven_private")
    require_required_items(require_list(index.get("not_proven"), "not_proven"), REQUIRED_NOT_PROVEN, "not_proven")
    require_required_items(require_list(index.get("blocked_repo_claim"), "blocked_repo_claim"), REQUIRED_BLOCKED_CLAIMS, "blocked_repo_claim")
    verify_boundary_fields(index)
    verify_runtime_truth_spine(index)
    verify_public_safe_strings(index)
    verify_allowed_claims(index)
    verify_receipt_hashes(index)

    print("PRIVATE_RUNTIME_EVIDENCE_INDEX=pass")
    print(f"PUBLIC_SAFE_STATUS={PUBLIC_SAFE_STATUS}")
    print(f"PROMOTION_STATUS={PROMOTION_STATUS}")
    print(f"PROOF_CEILING={PROOF_CEILING}")
    print("PUBLIC_RUNTIME_CLAIM_STATUS=PUBLIC_RUNTIME_BLOCKED")
    print("AI_TRIAGE_TRUTH=AI_SUPPORT_ONLY/AI_TRIAGE_OUTPUT_PRIVATE/AI_NOT_AUTHORITY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

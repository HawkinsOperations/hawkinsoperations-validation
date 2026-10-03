#!/usr/bin/env python3
"""Verify the HO-DET-001 deterministic triage boundary.

This verifier blocks AI authority drift and runtime/public claim promotion in
the controlled-test AutoSOC and LLM support artifacts.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from validation_lib import ContractFailure, strict_json_object


ROOT = Path(__file__).resolve().parents[1]
TRIAGE_PACKET = ROOT / "validation" / "successor" / "ho-det-001" / "autosoc-triage-packet.json"
LLM_SUMMARY = ROOT / "validation" / "successor" / "ho-det-001" / "llm-summary.json"
CASE_PACKET = ROOT / "validation" / "successor" / "ho-det-001" / "case-packet.json"

PROOF_CEILING = "CONTROLLED_TEST_VALIDATED"
VALIDATION_RESULT_REF = "hawkinsoperations-validation/reports/ho-det-001/validation-result.json"
TRIAGE_PACKET_REF = "hawkinsoperations-validation/validation/successor/ho-det-001/autosoc-triage-packet.json"
CASE_PACKET_REF = "hawkinsoperations-validation/validation/successor/ho-det-001/case-packet.json"
PROMOTED_TERMS = [
    "runtime-active",
    "signal-observed",
    "evidence-linked public proof",
    "public-safe",
    "live splunk firing",
    "production triage",
    "analyst-approved disposition",
    "ho-gpu-01 runtime-active",
    "cribl-routed",
    "wazuh-routed",
    "aws-live",
    "autonomous soc",
    "production-ready soc",
    "fleet-wide deployment",
    "ai-approved disposition",
    "ai decided disposition",
    "production-ready",
    "fleet-wide coverage",
    "attack detection in production",
]
SAFE_CLAIM_PATH_PARTS = {
    "unsupported_claims",
    "blocked_claims",
    "claims_not_supported",
    "claim_boundary",
    "trust_boundary",
    "privacy_status",
}
PUBLIC_UNSAFE_PATTERNS = [
    re.compile(r"\b[A-Za-z]:\\"),
    re.compile(r"\b(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"(?i)\b(secret|password|token|api[_-]?key|credential)\b"),
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing {label}: {path}")
    try:
        return strict_json_object(path.read_text(encoding="utf-8"), label)
    except ContractFailure as exc:
        fail(str(exc))


def assert_eq(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        fail(f"{label} expected {expected!r}, found {actual!r}")


def require_false(value: dict[str, Any], key: str, label: str) -> None:
    if key not in value:
        fail(f"{label} missing required field: {key}")
    if value[key] is not False:
        fail(f"{label} {key} must be false")


def require_blocked_status(value: dict[str, Any], key: str, label: str) -> None:
    if value.get(key) not in {"BLOCKED", "STUBBED"}:
        fail(f"{label} {key} must be BLOCKED or STUBBED")


def iter_strings(value: Any, path: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            found.extend(iter_strings(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(iter_strings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        found.append((path, value))
    return found


def is_allowed_negative_context(path: str, text: str) -> bool:
    lower_path = path.lower()
    lower_text = text.lower()
    if any(part in lower_path for part in SAFE_CLAIM_PATH_PARTS):
        return True
    return any(marker in lower_text for marker in ["blocked", "not_proven", "not_public_safe", "not supported", "does not prove", "remain blocked"])


def scan_for_promoted_claims(label: str, value: dict[str, Any]) -> None:
    for path, text in iter_strings(value):
        lower = text.lower()
        for term in PROMOTED_TERMS:
            if term in lower and not is_allowed_negative_context(path, text):
                fail(f"{label} promoted blocked claim at {path}: {term}")
        for pattern in PUBLIC_UNSAFE_PATTERNS:
            if pattern.search(text) and not is_allowed_negative_context(path, text):
                fail(f"{label} public-unsafe evidence marker at {path}: {text}")


def verify_confidence_bounds(label: str, value: Any, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if key.lower() == "confidence":
                if not isinstance(item, (int, float)) or item < 0 or item > 1:
                    fail(f"{label} confidence must be bounded 0..1 at {child_path}")
            verify_confidence_bounds(label, item, child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            verify_confidence_bounds(label, item, f"{path}[{index}]")


def verify_no_attack_mapping(label: str, value: Any, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if key.lower() in {"attack", "attack_mapping", "mitre_attack", "mitre_attack_mapping", "techniques"}:
                fail(f"{label} ATT&CK mapping present without source metadata parity at {child_path}")
            verify_no_attack_mapping(label, item, child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            verify_no_attack_mapping(label, item, f"{path}[{index}]")


def verify_triage_packet(packet: dict[str, Any]) -> None:
    assert_eq(packet.get("detection_id"), "HO-DET-001", "autosoc-triage-packet.json detection_id")
    assert_eq(packet.get("current_proof_ceiling"), PROOF_CEILING, "autosoc-triage-packet.json current_proof_ceiling")
    assert_eq(packet.get("validation_result_ref"), VALIDATION_RESULT_REF, "autosoc-triage-packet.json validation_result_ref")
    assert_eq(packet.get("case_packet_ref"), CASE_PACKET_REF, "autosoc-triage-packet.json case_packet_ref")
    assert_eq(packet.get("triage_authority"), "deterministic_verifier_and_human_review", "autosoc-triage-packet.json triage_authority")
    assert_eq(packet.get("llm_role"), "triage_support_only", "autosoc-triage-packet.json llm_role")
    assert_eq(packet.get("disposition"), "REVIEW_CONTROLLED_TEST_DETECTION", "autosoc-triage-packet.json disposition")
    if "approve" in str(packet.get("disposition", "")).lower():
        fail("autosoc-triage-packet.json disposition must not claim approval authority")
    require_false(packet, "ai_decided_disposition", "autosoc-triage-packet.json")
    if packet.get("human_validation_required") is not True:
        fail("autosoc-triage-packet.json human_validation_required must be true")
    require_false(packet, "runtime_active", "autosoc-triage-packet.json")
    require_false(packet, "runtime_actions_taken", "autosoc-triage-packet.json")
    require_false(packet, "signal_observed", "autosoc-triage-packet.json")
    require_blocked_status(packet, "runtime_status", "autosoc-triage-packet.json")
    if packet.get("public_safe_status") not in {"NO", "BLOCKED"}:
        fail("autosoc-triage-packet.json public_safe_status must be NO or BLOCKED")
    if packet.get("public_safe_status") == "APPROVED":
        fail("autosoc-triage-packet.json public_safe_status must not be APPROVED")
    require_false(packet, "public_safe", "autosoc-triage-packet.json")
    scan_for_promoted_claims("autosoc-triage-packet.json", packet)
    verify_confidence_bounds("autosoc-triage-packet.json", packet)
    verify_no_attack_mapping("autosoc-triage-packet.json", packet)


def verify_llm_summary(summary: dict[str, Any]) -> None:
    assert_eq(summary.get("detection_id"), "HO-DET-001", "llm-summary.json detection_id")
    assert_eq(summary.get("current_proof_ceiling"), PROOF_CEILING, "llm-summary.json current_proof_ceiling")
    assert_eq(summary.get("input_packet_ref"), TRIAGE_PACKET_REF, "llm-summary.json input_packet_ref")
    assert_eq(summary.get("input_packet_hash"), __import__("hashlib").sha256(TRIAGE_PACKET.read_text(encoding="utf-8").encode("utf-8")).hexdigest(), "llm-summary.json input_packet_hash")
    assert_eq(summary.get("case_packet_ref"), CASE_PACKET_REF, "llm-summary.json case_packet_ref")
    assert_eq(summary.get("model_runtime_status"), "BLOCKED", "llm-summary.json model_runtime_status")
    require_blocked_status(summary, "runtime_status", "llm-summary.json")
    require_false(summary, "runtime_actions_taken", "llm-summary.json")
    assert_eq(summary.get("execution_mode"), "deterministic_stub_no_model_call", "llm-summary.json execution_mode")
    assert_eq(summary.get("triage_authority"), "deterministic_verifier_and_human_review", "llm-summary.json triage_authority")
    assert_eq(summary.get("llm_role"), "triage_support_only", "llm-summary.json llm_role")
    assert_eq(summary.get("allowed_use"), "triage_support_only", "llm-summary.json allowed_use")
    assert_eq(summary.get("prohibited_use"), "final_disposition", "llm-summary.json prohibited_use")
    require_false(summary, "ai_decided_disposition", "llm-summary.json")
    if summary.get("recommended_disposition") is not None:
        fail("llm-summary.json recommended_disposition must be null")
    require_false(summary, "final_disposition_authority", "llm-summary.json")
    require_false(summary, "runtime_active", "llm-summary.json")
    require_false(summary, "signal_observed", "llm-summary.json")
    if summary.get("public_safe_status") not in {"NO", "BLOCKED"}:
        fail("llm-summary.json public_safe_status must be NO or BLOCKED")
    if summary.get("public_safe_status") == "APPROVED":
        fail("llm-summary.json public_safe_status must not be APPROVED")
    require_false(summary, "public_safe", "llm-summary.json")
    if summary.get("analyst_review_required") is not True:
        fail("llm-summary.json analyst_review_required must be true")
    if summary.get("human_validation_required") is not True:
        fail("llm-summary.json human_validation_required must be true")
    scan_for_promoted_claims("llm-summary.json", summary)
    verify_confidence_bounds("llm-summary.json", summary)
    verify_no_attack_mapping("llm-summary.json", summary)


def verify_case_packet(packet: dict[str, Any]) -> None:
    assert_eq(packet.get("detection_id"), "HO-DET-001", "case-packet.json detection_id")
    proof_ceiling = packet.get("current_proof_ceiling", packet.get("proof_level"))
    assert_eq(proof_ceiling, PROOF_CEILING, "case-packet.json proof ceiling")
    runtime_status = packet.get("runtime_status", "BLOCKED")
    signal_status = packet.get("signal_status", "BLOCKED")
    assert_eq(runtime_status, "BLOCKED", "case-packet.json runtime_status")
    assert_eq(signal_status, "BLOCKED", "case-packet.json signal_status")
    if "ai_decided_disposition" in packet:
        require_false(packet, "ai_decided_disposition", "case-packet.json")
    if packet.get("public_safe_status") not in {"NO", "BLOCKED"}:
        fail("case-packet.json public_safe_status must be NO or BLOCKED")
    scan_for_promoted_claims("case-packet.json", packet)


def main() -> int:
    triage_packet = load_json(TRIAGE_PACKET, "autosoc-triage-packet.json")
    llm_summary = load_json(LLM_SUMMARY, "llm-summary.json")
    case_packet = load_json(CASE_PACKET, "case-packet.json")
    verify_triage_packet(triage_packet)
    verify_llm_summary(llm_summary)
    verify_case_packet(case_packet)
    print("STATUS=pass")
    print("TRIAGE_BOUNDARY=pass")
    print("AI_DECIDED_DISPOSITION=false")
    print("RUNTIME_STATUS=BLOCKED")
    print("PUBLIC_SAFE_STATUS=BLOCKED_OR_NO")
    print("WRITE_SKIPPED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

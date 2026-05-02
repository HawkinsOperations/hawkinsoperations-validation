#!/usr/bin/env python3
"""Verify the Closed AutoSOC Loop 001 validation-control contract."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / ".github" / "contracts" / "closed-autosoc-loop-001.schema.json"
SAMPLE_PATH = ROOT / "validation" / "successor" / "ho-det-001" / "closed-autosoc-loop-001.sample.json"
VALIDATION_RESULT_PATH = ROOT / "reports" / "ho-det-001" / "validation-result.json"
CASE_PACKET_PATH = ROOT / "validation" / "successor" / "ho-det-001" / "case-packet.json"
TRIAGE_PACKET_PATH = ROOT / "validation" / "successor" / "ho-det-001" / "autosoc-triage-packet.json"
LLM_SUMMARY_PATH = ROOT / "validation" / "successor" / "ho-det-001" / "llm-summary.json"

PROOF_CEILING = "TEST_VALIDATED_SYNTHETIC_SCOPE"
SUPPORTED_CLAIM = "HO-DET-001 passed synthetic validation against controlled positive and negative process-creation fixtures."

REQUIRED_TOP_LEVEL_FIELDS = [
    "loop_id",
    "detection_id",
    "proof_ceiling",
    "validation_pass_reference",
    "synthetic_fixture_result_reference",
    "case_packet_reference",
    "autosoc_triage_reference",
    "llm_summary_reference",
    "authority_boundary",
    "claim_boundary",
    "blocked_claims",
    "private_evidence_references",
    "next_promotion_gate",
]

REQUIRED_BLOCKED_CLAIMS = [
    "runtime-active public claim",
    "signal-observed public claim",
    "production",
    "fleet-wide",
    "autonomous SOC",
    "Cribl-routed",
    "Wazuh-routed",
    "public-safe",
    "AI-approved disposition",
    "analyst-approved disposition",
    "private raw evidence path",
]

FALSE_AUTHORITY_FIELDS = [
    "ai_decided_disposition",
    "ai_may_approve",
    "ai_may_promote",
    "ai_may_close",
]

FALSE_CLAIM_FIELDS = [
    "runtime_active_public_claim",
    "signal_observed_public_claim",
    "production_claim",
    "fleet_wide_claim",
    "autonomous_soc_claim",
    "cribl_routed_claim",
    "wazuh_routed_claim",
    "public_safe_claim",
]

FORBIDDEN_FIELD_NAMES = {
    "raw_output",
    "raw_prompt",
    "raw_evidence_path",
    "private_raw_path",
    "command_output",
    "hostname",
    "username",
    "ip_address",
    "local_path",
    "absolute_path",
    "windows_path",
    "lan_ip",
    "secret",
    "token",
    "key",
    "screenshot",
    "csv_filename",
}

FORBIDDEN_VALUE_PATTERNS = [
    re.compile(r"\b[A-Za-z]:\\"),
    re.compile(r"\b(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"(?i)\b(secret|password|token|api[_-]?key|credential)\b"),
]

SAFE_PRIVATE_REFERENCE_CLASSIFICATIONS = {
    "PRIVATE_HASH_ONLY",
    "PRIVATE_LAB_SCOPE_REFERENCE",
    "SANITIZED_REPO_REFERENCE",
}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing {label}: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize(value: Any) -> str:
    return str(value).strip().lower()


def walk_json(value: Any, path: str = "$") -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = [(path, value)]
    if isinstance(value, dict):
        for key, child in value.items():
            found.extend(walk_json(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(walk_json(child, f"{path}[{index}]"))
    return found


def verify_schema_contract(schema: dict[str, Any]) -> None:
    if schema.get("additionalProperties") is not False:
        fail("schema top-level additionalProperties must be false")
    required = schema.get("required")
    properties = schema.get("properties")
    if required != REQUIRED_TOP_LEVEL_FIELDS:
        fail("schema required field order/content must match verifier contract")
    if not isinstance(properties, dict):
        fail("schema properties must be an object")
    missing = [field for field in REQUIRED_TOP_LEVEL_FIELDS if field not in properties]
    if missing:
        fail(f"schema missing properties for required fields: {', '.join(missing)}")
    extra = sorted(set(properties) - set(REQUIRED_TOP_LEVEL_FIELDS))
    if extra:
        fail(f"schema contains unexpected top-level properties: {', '.join(extra)}")


def verify_sample_shape(sample: dict[str, Any]) -> None:
    missing = [field for field in REQUIRED_TOP_LEVEL_FIELDS if field not in sample]
    if missing:
        fail(f"sample missing required fields: {', '.join(missing)}")
    extra = sorted(set(sample) - set(REQUIRED_TOP_LEVEL_FIELDS))
    if extra:
        fail(f"sample contains unexpected fields: {', '.join(extra)}")
    if sample.get("loop_id") != "Closed AutoSOC Loop 001":
        fail("loop_id must be Closed AutoSOC Loop 001")
    if sample.get("detection_id") != "HO-DET-001":
        fail("detection_id must be HO-DET-001")
    if sample.get("proof_ceiling") != PROOF_CEILING:
        fail(f"proof_ceiling must be {PROOF_CEILING}")


def verify_file_reference(reference: Any, expected_path: str, actual_path: Path, label: str) -> None:
    if not isinstance(reference, dict):
        fail(f"{label} must be an object")
    if reference.get("path") != expected_path:
        fail(f"{label}.path must be {expected_path}")
    digest = reference.get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
        fail(f"{label}.sha256 must be a SHA256 digest")
    actual_digest = sha256_file(actual_path)
    if digest.lower() != actual_digest:
        fail(f"{label}.sha256 does not match {expected_path}")


def verify_validation_pass(sample: dict[str, Any], validation_result: dict[str, Any]) -> None:
    reference = sample.get("validation_pass_reference")
    verify_file_reference(reference, "reports/ho-det-001/validation-result.json", VALIDATION_RESULT_PATH, "validation_pass_reference")
    assert isinstance(reference, dict)
    if reference.get("status") != "pass":
        fail("validation_pass_reference.status must be pass")
    if reference.get("supported_claim") != SUPPORTED_CLAIM:
        fail("validation_pass_reference.supported_claim mismatch")
    if validation_result.get("detection_id") != "HO-DET-001":
        fail("validation-result.json detection_id must be HO-DET-001")
    if validation_result.get("status") != "pass":
        fail("validation-result.json status must be pass")
    if validation_result.get("exact_claim_supported") != SUPPORTED_CLAIM:
        fail("validation-result.json exact_claim_supported mismatch")


def verify_fixture_counts(sample: dict[str, Any], validation_result: dict[str, Any]) -> None:
    fixture = sample.get("synthetic_fixture_result_reference")
    if not isinstance(fixture, dict):
        fail("synthetic_fixture_result_reference must be an object")
    totals = validation_result.get("totals")
    if not isinstance(totals, dict):
        fail("validation-result.json totals must be an object")
    expected = {
        "total_cases": 14,
        "positive_cases": 7,
        "negative_cases": 7,
        "matched_positive_count": 7,
    }
    for field, expected_value in expected.items():
        if fixture.get(field) != expected_value:
            fail(f"synthetic_fixture_result_reference.{field} must be {expected_value}")
    if totals.get("total_cases") != 14 or totals.get("positive_cases") != 7 or totals.get("negative_cases") != 7:
        fail("validation-result.json must preserve 7 positive / 7 negative synthetic fixture results")
    if validation_result.get("matched_positive_count") != 7:
        fail("validation-result.json matched_positive_count must be 7")
    if fixture.get("missed_positive_cases") != [] or validation_result.get("missed_positive_cases") != []:
        fail("missed_positive_cases must be empty")
    if fixture.get("false_positive_negative_cases") != [] or validation_result.get("false_positive_negative_cases") != []:
        fail("false_positive_negative_cases must be empty")


def verify_artifact_references(sample: dict[str, Any]) -> None:
    verify_file_reference(
        sample.get("case_packet_reference"),
        "validation/successor/ho-det-001/case-packet.json",
        CASE_PACKET_PATH,
        "case_packet_reference",
    )
    verify_file_reference(
        sample.get("autosoc_triage_reference"),
        "validation/successor/ho-det-001/autosoc-triage-packet.json",
        TRIAGE_PACKET_PATH,
        "autosoc_triage_reference",
    )
    verify_file_reference(
        sample.get("llm_summary_reference"),
        "validation/successor/ho-det-001/llm-summary.json",
        LLM_SUMMARY_PATH,
        "llm_summary_reference",
    )


def verify_authority_boundary(sample: dict[str, Any]) -> None:
    authority = sample.get("authority_boundary")
    if not isinstance(authority, dict):
        fail("authority_boundary must be an object")
    if authority.get("ai_role") != "triage_support_only":
        fail("authority_boundary.ai_role must be triage_support_only")
    for field in FALSE_AUTHORITY_FIELDS:
        if authority.get(field) is not False:
            fail(f"authority_boundary.{field} must be false")
    if authority.get("human_review_required") is not True:
        fail("authority_boundary.human_review_required must be true")
    if authority.get("recommended_disposition") is not None:
        fail("authority_boundary.recommended_disposition must be null")


def verify_claim_boundary(sample: dict[str, Any]) -> None:
    boundary = sample.get("claim_boundary")
    if not isinstance(boundary, dict):
        fail("claim_boundary must be an object")
    for field in FALSE_CLAIM_FIELDS:
        if boundary.get(field) is not False:
            fail(f"claim_boundary.{field} must be false")
    if boundary.get("public_safe_status") != "NOT_PUBLIC_SAFE":
        fail("claim_boundary.public_safe_status must be NOT_PUBLIC_SAFE")
    if boundary.get("allowed_public_claim") != SUPPORTED_CLAIM:
        fail("claim_boundary.allowed_public_claim mismatch")


def verify_blocked_claims(sample: dict[str, Any]) -> None:
    blocked = sample.get("blocked_claims")
    if not isinstance(blocked, list) or not all(isinstance(item, str) for item in blocked):
        fail("blocked_claims must be a string array")
    normalized = {normalize(item) for item in blocked}
    for claim in REQUIRED_BLOCKED_CLAIMS:
        if normalize(claim) not in normalized:
            fail(f"blocked_claims missing: {claim}")


def verify_private_reference_safety(sample: dict[str, Any]) -> None:
    references = sample.get("private_evidence_references")
    if not isinstance(references, list):
        fail("private_evidence_references must be an array")
    labels: set[str] = set()
    for index, reference in enumerate(references):
        if not isinstance(reference, dict):
            fail(f"private_evidence_references[{index}] must be an object")
        extra = sorted(set(reference) - {"label", "classification", "sha256"})
        if extra:
            fail(f"private_evidence_references[{index}] has unexpected fields: {', '.join(extra)}")
        label = reference.get("label")
        classification = reference.get("classification")
        digest = reference.get("sha256")
        if not isinstance(label, str) or not re.fullmatch(r"[a-z0-9_]+", label):
            fail(f"private_evidence_references[{index}].label must be sanitized")
        if label in labels:
            fail(f"duplicate private evidence label: {label}")
        labels.add(label)
        if classification not in SAFE_PRIVATE_REFERENCE_CLASSIFICATIONS:
            fail(f"private_evidence_references[{index}].classification is not allowed")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            fail(f"private_evidence_references[{index}].sha256 must be a SHA256 digest")


def verify_no_private_leakage(value: dict[str, Any]) -> None:
    for path, item in walk_json(value):
        field_name = path.rsplit(".", 1)[-1].split("[", 1)[0]
        if field_name in FORBIDDEN_FIELD_NAMES:
            fail(f"forbidden private/raw field name: {path}")
        if isinstance(item, str):
            for pattern in FORBIDDEN_VALUE_PATTERNS:
                if pattern.search(item):
                    fail(f"private raw evidence path or sensitive marker at {path}: {pattern.pattern}")


def verify_promotion_gate(sample: dict[str, Any]) -> None:
    gate = sample.get("next_promotion_gate")
    if not isinstance(gate, str) or "separate promotion approval" not in gate:
        fail("next_promotion_gate must require separate promotion approval")
    for required in ["runtime", "signal", "public-safe", "production", "fleet-wide", "Cribl-routed", "Wazuh-routed"]:
        if required not in gate:
            fail(f"next_promotion_gate missing blocked promotion term: {required}")


def main() -> int:
    schema = load_json(SCHEMA_PATH, "closed-autosoc-loop-001.schema.json")
    sample = load_json(SAMPLE_PATH, "closed-autosoc-loop-001.sample.json")
    validation_result = load_json(VALIDATION_RESULT_PATH, "validation-result.json")

    verify_schema_contract(schema)
    verify_sample_shape(sample)
    verify_validation_pass(sample, validation_result)
    verify_fixture_counts(sample, validation_result)
    verify_artifact_references(sample)
    verify_authority_boundary(sample)
    verify_claim_boundary(sample)
    verify_blocked_claims(sample)
    verify_private_reference_safety(sample)
    verify_no_private_leakage(sample)
    verify_promotion_gate(sample)

    print("STATUS=pass")
    print("CLOSED_AUTOSOC_LOOP_001_CONTRACT=pass")
    print("DETECTION_ID=HO-DET-001")
    print(f"PROOF_CEILING={PROOF_CEILING}")
    print("VALIDATION_REFERENCE=pass")
    print("SYNTHETIC_FIXTURES=7_positive_7_negative")
    print("AI_DECIDED_DISPOSITION=false")
    print("HUMAN_REVIEW_REQUIRED=true")
    print("RECOMMENDED_DISPOSITION=null")
    print("AI_MAY_APPROVE=false")
    print("AI_MAY_PROMOTE=false")
    print("AI_MAY_CLOSE=false")
    print("PUBLIC_SAFE_STATUS=NOT_PUBLIC_SAFE")
    print("WRITE_SKIPPED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

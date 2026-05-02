#!/usr/bin/env python3
"""Verify HO-DET-001 AI triage input/output schema boundaries.

This verifier checks the committed synthetic AI-triage support artifacts
against validation-owned schema contracts without importing raw private model,
runtime, host, user, LAN, or local-path evidence into the repository.
"""

from __future__ import annotations

import hashlib
import contextlib
import io
import json
import re
import sys
from pathlib import Path
from copy import deepcopy
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INPUT_SCHEMA = ROOT / ".github" / "contracts" / "ho-det-001-ai-triage-input.schema.json"
OUTPUT_SCHEMA = ROOT / ".github" / "contracts" / "ho-det-001-ai-triage-output.schema.json"
TRIAGE_PACKET = ROOT / "validation" / "successor" / "ho-det-001" / "autosoc-triage-packet.json"
LLM_SUMMARY = ROOT / "validation" / "successor" / "ho-det-001" / "llm-summary.json"
VALIDATION_RESULT = ROOT / "reports" / "ho-det-001" / "validation-result.json"

PROOF_CEILING = "TEST_VALIDATED_SYNTHETIC_SCOPE"
TRIAGE_PACKET_REF = "hawkinsoperations-validation/validation/successor/ho-det-001/autosoc-triage-packet.json"
CASE_PACKET_REF = "hawkinsoperations-validation/validation/successor/ho-det-001/case-packet.json"
VALIDATION_RESULT_REF = "hawkinsoperations-validation/reports/ho-det-001/validation-result.json"

REQUIRED_BLOCKED_CLAIMS = [
    "runtime-active",
    "signal-observed",
    "public-safe",
    "production triage",
    "analyst-approved disposition",
    "HO-GPU-01 runtime-active",
    "Cribl-routed",
    "Wazuh-routed",
    "AWS-live",
    "autonomous SOC",
    "AI-approved disposition",
]

FORBIDDEN_FIELD_NAMES = {
    "raw_output",
    "raw_prompt",
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

NEGATIVE_CONTEXT_MARKERS = [
    "blocked",
    "unsupported",
    "no live telemetry",
    "no raw",
    "no private",
    "not public safe",
    "not public-safe",
    "does not",
    "remain blocked",
]


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
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def normalize(value: Any) -> str:
    return str(value).strip().lower()


def iter_field_names(value: Any) -> list[str]:
    names: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            names.append(str(key))
            names.extend(iter_field_names(item))
    elif isinstance(value, list):
        for item in value:
            names.extend(iter_field_names(item))
    return names


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


def is_negative_context(path: str, text: str) -> bool:
    lower_path = path.lower()
    lower_text = text.lower()
    if any(part in lower_path for part in ["unsupported_claims", "blocked_claims", "privacy_status"]):
        return True
    return any(marker in lower_text for marker in NEGATIVE_CONTEXT_MARKERS)


def require_keys(value: dict[str, Any], keys: list[str], label: str) -> None:
    missing = [key for key in keys if key not in value]
    if missing:
        fail(f"{label} missing required keys: {', '.join(missing)}")


def check_no_extra_keys(value: dict[str, Any], schema: dict[str, Any], label: str) -> None:
    allowed = set(schema.get("properties", {}).keys())
    extra = sorted(set(value.keys()) - allowed)
    if extra:
        fail(f"{label} contains keys outside schema properties: {', '.join(extra)}")


def verify_schema_contract(schema: dict[str, Any], label: str) -> None:
    if schema.get("additionalProperties") is not False:
        fail(f"{label} must set top-level additionalProperties=false")
    required = schema.get("required")
    properties = schema.get("properties")
    if not isinstance(required, list) or not required:
        fail(f"{label} missing non-empty required list")
    if not isinstance(properties, dict) or not properties:
        fail(f"{label} missing properties object")
    missing = [str(key) for key in required if str(key) not in properties]
    if missing:
        fail(f"{label} required fields missing from properties: {', '.join(missing)}")
    for forbidden in FORBIDDEN_FIELD_NAMES:
        if forbidden in iter_field_names(schema):
            fail(f"{label} contains forbidden field name: {forbidden}")


def verify_value_safety(label: str, value: dict[str, Any]) -> None:
    for forbidden in FORBIDDEN_FIELD_NAMES:
        if forbidden in iter_field_names(value):
            fail(f"{label} contains forbidden field name: {forbidden}")
    for path, text in iter_strings(value):
        for pattern in FORBIDDEN_VALUE_PATTERNS:
            if pattern.search(text) and not is_negative_context(path, text):
                fail(f"{label} contains private/raw marker at {path}")


def verify_blocked_claims(label: str, claims: Any) -> None:
    if not isinstance(claims, list):
        fail(f"{label} unsupported_claims must be a list")
    normalized = {normalize(item) for item in claims}
    for claim in REQUIRED_BLOCKED_CLAIMS:
        if normalize(claim) not in normalized:
            fail(f"{label} unsupported_claims missing blocked claim: {claim}")


def verify_triage_packet(schema: dict[str, Any], packet: dict[str, Any]) -> None:
    label = "autosoc-triage-packet.json"
    require_keys(packet, [str(item) for item in schema["required"]], label)
    check_no_extra_keys(packet, schema, label)
    if packet.get("detection_id") != "HO-DET-001":
        fail(f"{label} detection_id must be HO-DET-001")
    if packet.get("current_proof_ceiling") != PROOF_CEILING:
        fail(f"{label} current_proof_ceiling must be {PROOF_CEILING}")
    if packet.get("validation_result_ref") != VALIDATION_RESULT_REF:
        fail(f"{label} validation_result_ref mismatch")
    if packet.get("validation_result_hash") != sha256_file(VALIDATION_RESULT):
        fail(f"{label} validation_result_hash does not match committed validation result")
    if packet.get("case_packet_ref") != CASE_PACKET_REF:
        fail(f"{label} case_packet_ref mismatch")
    if packet.get("triage_authority") != "deterministic_verifier_and_human_review":
        fail(f"{label} triage_authority must stay deterministic verifier plus human review")
    if packet.get("llm_role") != "triage_support_only":
        fail(f"{label} llm_role must be triage_support_only")
    if packet.get("ai_decided_disposition") is not False:
        fail(f"{label} ai_decided_disposition must be false")
    if packet.get("analyst_review_required") is not True:
        fail(f"{label} analyst_review_required must be true")
    if packet.get("human_validation_required") is not True:
        fail(f"{label} human_validation_required must be true")
    if packet.get("runtime_status") != "BLOCKED":
        fail(f"{label} runtime_status must be BLOCKED")
    if packet.get("runtime_active") is not False:
        fail(f"{label} runtime_active must be false")
    if packet.get("runtime_actions_taken") is not False:
        fail(f"{label} runtime_actions_taken must be false")
    if packet.get("signal_observed") is not False:
        fail(f"{label} signal_observed must be false")
    if packet.get("public_safe_status") != "BLOCKED":
        fail(f"{label} public_safe_status must be BLOCKED")
    if packet.get("public_safe") is not False:
        fail(f"{label} public_safe must be false")
    claim_boundary = packet.get("claim_boundary")
    if not isinstance(claim_boundary, dict):
        fail(f"{label} claim_boundary must be an object")
    for key in [
        "schema_proves_runtime",
        "schema_proves_signal",
        "schema_proves_public_safe_status",
        "ai_final_disposition_authority",
    ]:
        if claim_boundary.get(key) is not False:
            fail(f"{label} claim_boundary.{key} must be false")
    verify_blocked_claims(label, packet.get("unsupported_claims"))
    verify_value_safety(label, packet)


def verify_llm_summary(schema: dict[str, Any], summary: dict[str, Any]) -> None:
    label = "llm-summary.json"
    require_keys(summary, [str(item) for item in schema["required"]], label)
    check_no_extra_keys(summary, schema, label)
    if summary.get("detection_id") != "HO-DET-001":
        fail(f"{label} detection_id must be HO-DET-001")
    if summary.get("current_proof_ceiling") != PROOF_CEILING:
        fail(f"{label} current_proof_ceiling must be {PROOF_CEILING}")
    if summary.get("input_packet_ref") != TRIAGE_PACKET_REF:
        fail(f"{label} input_packet_ref mismatch")
    if summary.get("input_packet_hash") != sha256_file(TRIAGE_PACKET):
        fail(f"{label} input_packet_hash does not match committed triage packet")
    if summary.get("case_packet_ref") != CASE_PACKET_REF:
        fail(f"{label} case_packet_ref mismatch")
    if summary.get("model_runtime_status") != "BLOCKED":
        fail(f"{label} model_runtime_status must be BLOCKED")
    if summary.get("runtime_status") != "BLOCKED":
        fail(f"{label} runtime_status must be BLOCKED")
    if summary.get("runtime_actions_taken") is not False:
        fail(f"{label} runtime_actions_taken must be false")
    if summary.get("execution_mode") != "deterministic_stub_no_model_call":
        fail(f"{label} execution_mode must be deterministic_stub_no_model_call")
    if summary.get("triage_authority") != "deterministic_verifier_and_human_review":
        fail(f"{label} triage_authority must stay deterministic verifier plus human review")
    if summary.get("llm_role") != "triage_support_only":
        fail(f"{label} llm_role must be triage_support_only")
    if summary.get("allowed_use") != "triage_support_only":
        fail(f"{label} allowed_use must be triage_support_only")
    if summary.get("prohibited_use") != "final_disposition":
        fail(f"{label} prohibited_use must be final_disposition")
    if summary.get("ai_decided_disposition") is not False:
        fail(f"{label} ai_decided_disposition must be false")
    if summary.get("recommended_disposition") is not None:
        fail(f"{label} recommended_disposition must be null")
    if summary.get("final_disposition_authority") is not False:
        fail(f"{label} final_disposition_authority must be false")
    if summary.get("public_safe_status") != "BLOCKED":
        fail(f"{label} public_safe_status must be BLOCKED")
    if summary.get("public_safe") is not False:
        fail(f"{label} public_safe must be false")
    if summary.get("runtime_active") is not False:
        fail(f"{label} runtime_active must be false")
    if summary.get("signal_observed") is not False:
        fail(f"{label} signal_observed must be false")
    if summary.get("analyst_review_required") is not True:
        fail(f"{label} analyst_review_required must be true")
    if summary.get("human_validation_required") is not True:
        fail(f"{label} human_validation_required must be true")
    advisory_output = summary.get("advisory_output")
    if not isinstance(advisory_output, dict):
        fail(f"{label} advisory_output must be an object")
    for key in ["summary", "evidence_map", "uncertainty", "recommended_next_checks"]:
        if key not in advisory_output:
            fail(f"{label} advisory_output missing required key: {key}")
    claim_boundary = summary.get("claim_boundary")
    if not isinstance(claim_boundary, dict):
        fail(f"{label} claim_boundary must be an object")
    for key in [
        "schema_proves_runtime",
        "schema_proves_signal",
        "schema_proves_public_safe_status",
        "ai_final_disposition_authority",
    ]:
        if claim_boundary.get(key) is not False:
            fail(f"{label} claim_boundary.{key} must be false")
    verify_blocked_claims(label, summary.get("unsupported_claims"))
    verify_value_safety(label, summary)


def verify_invalid_sample_rejected(summary: dict[str, Any]) -> None:
    invalid_summary = deepcopy(summary)
    invalid_summary["ai_decided_disposition"] = True
    test_schema = {
        "required": [
            "detection_id",
            "current_proof_ceiling",
            "input_packet_ref",
            "input_packet_hash",
            "case_packet_ref",
            "model_runtime_status",
            "runtime_status",
            "runtime_actions_taken",
            "execution_mode",
            "triage_authority",
            "llm_role",
            "allowed_use",
            "prohibited_use",
            "ai_decided_disposition",
            "recommended_disposition",
            "final_disposition_authority",
            "public_safe_status",
            "public_safe",
            "runtime_active",
            "signal_observed",
            "summary_type",
            "advisory_output",
            "hypothesis",
            "analyst_review_required",
            "human_validation_required",
            "unsupported_claims",
            "claim_boundary",
            "generated_at",
            "privacy_status",
        ],
        "properties": {key: {} for key in summary.keys()},
    }
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            verify_llm_summary(test_schema, invalid_summary)
    except SystemExit:
        return
    fail("invalid AI authority sample was not rejected")


def main() -> int:
    input_schema = load_json(INPUT_SCHEMA, "ho-det-001-ai-triage-input.schema.json")
    output_schema = load_json(OUTPUT_SCHEMA, "ho-det-001-ai-triage-output.schema.json")
    triage_packet = load_json(TRIAGE_PACKET, "autosoc-triage-packet.json")
    llm_summary = load_json(LLM_SUMMARY, "llm-summary.json")
    verify_schema_contract(input_schema, "ho-det-001-ai-triage-input.schema.json")
    verify_schema_contract(output_schema, "ho-det-001-ai-triage-output.schema.json")
    verify_triage_packet(input_schema, triage_packet)
    verify_llm_summary(output_schema, llm_summary)
    verify_invalid_sample_rejected(llm_summary)
    print("STATUS=pass")
    print("AI_TRIAGE_SCHEMA_CONTRACT=pass")
    print("INVALID_AI_AUTHORITY_SAMPLE_REJECTED=pass")
    print("DETECTION_ID=HO-DET-001")
    print(f"PROOF_CEILING={PROOF_CEILING}")
    print("AI_DECIDED_DISPOSITION=false")
    print("RUNTIME_STATUS=BLOCKED")
    print("PUBLIC_SAFE_STATUS=BLOCKED")
    print("WRITE_SKIPPED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

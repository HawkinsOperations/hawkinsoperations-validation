#!/usr/bin/env python3
"""Controlled contract validation runner for HO-PIPE-001.

This validates repository-contained route-integrity contract shape only. It
does not inspect runtime systems, query Splunk, assert Cribl/Wazuh/Security
Onion routing, or claim public-safe proof.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from validation_report_contract import controlled_report_contract


ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_ROOT = ROOT.parent / "hawkinsoperations-detections"
SOURCE_DIR = DETECTIONS_ROOT / "detections" / "successor" / "ho-pipe-001"
SOURCE_RULE = SOURCE_DIR / "rule.yml"
SOURCE_STATUS = SOURCE_DIR / "status.yml"
SOURCE_MAPPING = SOURCE_DIR / "event-mapping.yml"
SOURCE_PIPELINE = SOURCE_DIR / "cribl-pipeline.yml"
SOURCE_FIELD_MATRIX = SOURCE_DIR / "field-preservation-matrix.yml"
CASES_FILE = ROOT / "validation" / "successor" / "ho-pipe-001" / "validation-cases.json"
REPORT_DIR = ROOT / "reports" / "ho-pipe-001"
REPORT_JSON = REPORT_DIR / "validation-result.json"
REPORT_MD = REPORT_DIR / "validation-result.md"

SUPPORTED_CLAIM = (
    "HO-PIPE-001 has controlled contract validation for source-controlled "
    "route-integrity shape and required field preservation."
)
PROOF_CEILING = "VALIDATION_CONTRACT_ENFORCED"
EXPECTED_POSITIVE_COUNT = 3
EXPECTED_NEGATIVE_COUNT = 3
REQUIRED_PRESERVED_FIELDS = {
    "_time",
    "host",
    "source",
    "sourcetype",
    "index",
    "event_marker",
    "detection_id",
    "route_contract_id",
}
BLOCKED_PROMOTION_FIELDS = {
    "runtime_active",
    "signal_observed",
    "live_splunk",
    "cribl_routed_proof",
    "wazuh_routed_proof",
    "security_onion_observed_proof",
    "production_ready",
    "public_safe_runtime",
    "autonomous_soc",
    "ai_approved",
    "analyst_approved",
}
BLOCKED_CLAIMS = [
    "runtime-active",
    "signal-observed",
    "live Splunk",
    "Cribl-routed proof",
    "Wazuh-routed proof",
    "Security Onion observed proof",
    "production-ready",
    "public-safe runtime",
    "autonomous SOC",
    "AI-approved",
    "analyst-approved",
]
REQUIRED_CASE_IDS = {
    "pos-001-required-field-preservation",
    "pos-002-blocked-promotion-guards",
    "pos-003-route-contract-metadata",
    "neg-001-missing-route-contract-id",
    "neg-002-promoted-live-splunk-claim",
    "neg-003-missing-required-field",
}
EXPECTED_ROUTE_METADATA = {
    "pos-001-required-field-preservation": {
        "marker_family": "controlled_contract_marker",
        "expected_output_target": "default_hec_output_contract_only",
        "transform_action": "preserve_matching_marker_event",
    },
    "pos-002-blocked-promotion-guards": {
        "marker_family": "controlled_contract_marker",
        "expected_output_target": "default_hec_output_contract_only",
        "transform_action": "drop_nonmatching_events_before_output",
    },
    "pos-003-route-contract-metadata": {
        "marker_family": "controlled_contract_marker",
        "expected_output_target": "default_hec_output_contract_only",
        "transform_action": "validate_route_shape_only",
    },
    "neg-001-missing-route-contract-id": {
        "marker_family": "controlled_contract_marker",
        "expected_output_target": "default_hec_output_contract_only",
        "transform_action": "preserve_matching_marker_event",
    },
    "neg-002-promoted-live-splunk-claim": {
        "marker_family": "controlled_contract_marker",
        "expected_output_target": "default_hec_output_contract_only",
        "transform_action": "validate_route_shape_only",
    },
    "neg-003-missing-required-field": {
        "marker_family": "controlled_contract_marker",
        "expected_output_target": "default_hec_output_contract_only",
        "transform_action": "preserve_matching_marker_event",
    },
}


def fail(message: str) -> None:
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


def require_yaml_scalar(text: str, key: str, expected: str) -> None:
    pattern = rf"(?m)^\s*{re.escape(key)}\s*:\s*{re.escape(expected)}\s*(?:#.*)?$"
    if not re.search(pattern, text):
        fail(f"source status missing expected scalar: {key}: {expected}")


def validate_source_contract(mode: str = "required") -> None:
    source_paths = [SOURCE_RULE, SOURCE_STATUS, SOURCE_MAPPING, SOURCE_PIPELINE, SOURCE_FIELD_MATRIX]
    missing_paths = [path for path in source_paths if not path.exists()]
    if missing_paths:
        if mode == "skip-if-missing" and len(missing_paths) == len(source_paths):
            print("SOURCE_CONTRACT=skipped")
            print("SOURCE_CONTRACT_REASON=sibling detections repo unavailable")
            return
        fail("missing HO-PIPE-001 source surfaces: " + ", ".join(str(path) for path in missing_paths))

    rule = read_text(SOURCE_RULE, "HO-PIPE-001 source rule")
    status = read_text(SOURCE_STATUS, "HO-PIPE-001 source status")
    mapping = read_text(SOURCE_MAPPING, "HO-PIPE-001 event mapping")
    pipeline = read_text(SOURCE_PIPELINE, "HO-PIPE-001 pipeline contract")
    matrix = read_text(SOURCE_FIELD_MATRIX, "HO-PIPE-001 field preservation matrix")
    combined = "\n".join([rule, status, mapping, pipeline, matrix])
    required_fragments = [
        "detection_id: HO-PIPE-001",
        "validation_status: VALIDATION_CONTRACT_ENFORCED",
        "field-preservation-matrix.yml",
        "required_preserved_fields:",
        "route_contract_id",
        "runtime_active: false",
        "signal_observed: false",
        "live Splunk",
        "Cribl-routed proof",
        "Wazuh-routed proof",
        "Security Onion observed proof",
        "public-safe runtime",
        "AI-approved",
        "analyst-approved",
    ]
    for fragment in required_fragments:
        if fragment not in combined:
            fail(f"HO-PIPE-001 source missing required fragment: {fragment}")
    require_yaml_scalar(status, "detection_id", "HO-PIPE-001")
    require_yaml_scalar(status, "source_status", "SOURCE_EXISTS")
    require_yaml_scalar(status, "validation_status", "VALIDATION_CONTRACT_ENFORCED")
    require_yaml_scalar(status, "proof_level", "SOURCE_EXISTS")
    require_yaml_scalar(status, "public_safe_status", "NOT_PUBLIC_SAFE")
    require_yaml_scalar(status, "runtime_active", "false")
    require_yaml_scalar(status, "signal_observed", "false")
    require_yaml_scalar(status, "evidence_linked_public_proof", "false")


def validate_cases_shape(cases: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if cases.get("detection_id") != "HO-PIPE-001":
        fail("validation-cases detection_id must be HO-PIPE-001")
    if cases.get("proof_ceiling") != PROOF_CEILING:
        fail(f"validation-cases proof_ceiling must be {PROOF_CEILING}")
    if cases.get("public_safe_status") != "NOT_PUBLIC_SAFE":
        fail("validation-cases public_safe_status must remain NOT_PUBLIC_SAFE")
    if cases.get("runtime_active") is not False or cases.get("signal_observed") is not False:
        fail("validation-cases runtime_active and signal_observed must remain false")
    blocked = cases.get("blocked_claims")
    if not isinstance(blocked, list) or set(BLOCKED_CLAIMS) - set(blocked):
        fail("validation-cases blocked_claims must preserve HO-PIPE-001 blocked claim inventory")

    groups = cases.get("cases")
    if not isinstance(groups, dict):
        fail("validation-cases cases must be an object")
    positive = groups.get("positive")
    negative = groups.get("negative")
    if not isinstance(positive, list) or not isinstance(negative, list):
        fail("validation-cases positive and negative must be arrays")
    if len(positive) != EXPECTED_POSITIVE_COUNT:
        fail(f"expected {EXPECTED_POSITIVE_COUNT} positive cases, got {len(positive)}")
    if len(negative) != EXPECTED_NEGATIVE_COUNT:
        fail(f"expected {EXPECTED_NEGATIVE_COUNT} negative cases, got {len(negative)}")
    ids = {str(case.get("id")) for case in [*positive, *negative]}
    if ids != REQUIRED_CASE_IDS:
        fail("validation-cases case id set does not match required HO-PIPE-001 fixture IDs")
    for case in [*positive, *negative]:
        if "contract" not in case or not isinstance(case["contract"], dict):
            fail(f"{case.get('id')}: contract must be an object")
        if not isinstance(case.get("expected_match"), bool):
            fail(f"{case.get('id')}: expected_match must be boolean")
    return positive, negative


def contract_matches(case_id: str, contract: dict[str, Any]) -> bool:
    if contract.get("route_contract_id") != "HO-PIPE-001":
        return False
    if contract.get("source_detection_id") != "HO-DET-001":
        return False
    expected_metadata = EXPECTED_ROUTE_METADATA.get(case_id)
    if not expected_metadata:
        return False
    for key, expected_value in expected_metadata.items():
        if contract.get(key) != expected_value:
            return False

    for key in ("marker_family", "expected_output_target", "transform_action"):
        if not isinstance(contract.get(key), str) or not contract[key].strip():
            return False

    allowed_keys = {
        "route_contract_id",
        "source_detection_id",
        "marker_family",
        "expected_output_target",
        "transform_action",
        "required_preserved_fields",
        "blocked_promotion_fields",
    }
    if not set(contract).issubset(allowed_keys):
        return False

    preserved = contract.get("required_preserved_fields")
    if not isinstance(preserved, list) or not REQUIRED_PRESERVED_FIELDS.issubset(set(preserved)):
        return False

    blocked = contract.get("blocked_promotion_fields")
    if not isinstance(blocked, dict) or not BLOCKED_PROMOTION_FIELDS.issubset(set(blocked)):
        return False
    return all(blocked[field] is False for field in BLOCKED_PROMOTION_FIELDS)


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    matched = contract_matches(str(case["id"]), case["contract"])
    expected = bool(case["expected_match"])
    return {
        "id": case["id"],
        "behavior": case["behavior"],
        "expected": expected,
        "matched": matched,
        "pass": matched is expected,
    }


def build_report(cases: dict[str, Any]) -> dict[str, Any]:
    positive, negative = validate_cases_shape(cases)
    positive_results = [evaluate_case(case) for case in positive]
    negative_results = [evaluate_case(case) for case in negative]
    missed = [result["id"] for result in positive_results if not result["pass"]]
    false_positive = [result["id"] for result in negative_results if not result["pass"]]
    return {
        **controlled_report_contract(
            "HO-PIPE-001",
            PROOF_CEILING,
            passed=not missed and not false_positive,
        ),
        "status": "pass" if not missed and not false_positive else "fail",
        "detection_id": "HO-PIPE-001",
        "validation_scope": "controlled pipeline route integrity contract validation only",
        "proof_ceiling": PROOF_CEILING,
        "source_reference": "hawkinsoperations-detections/detections/successor/ho-pipe-001",
        "validation_cases_file": "hawkinsoperations-validation/validation/successor/ho-pipe-001/validation-cases.json",
        "total_cases": len(positive_results) + len(negative_results),
        "positive_cases": len(positive_results),
        "negative_cases": len(negative_results),
        "matched_positive_count": sum(1 for result in positive_results if result["matched"]),
        "missed_positive_cases": missed,
        "false_positive_negative_cases": false_positive,
        "positive": positive_results,
        "negative": negative_results,
        "exact_claim_supported": SUPPORTED_CLAIM,
        "blocked_claims": BLOCKED_CLAIMS,
        "runtime_active": False,
        "signal_observed": False,
        "live_splunk": False,
        "cribl_routed_proof": False,
        "wazuh_routed_proof": False,
        "security_onion_observed_proof": False,
        "production_ready": False,
        "public_safe_runtime": False,
        "autonomous_soc": False,
        "ai_approved": False,
        "analyst_approved": False,
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "trust_boundary": (
            "Controlled pipeline route integrity contract validation only. This does not prove "
            "runtime-active status, signal-observed status, live Splunk, Cribl-routed proof, "
            "Wazuh-routed proof, Security Onion observed proof, production readiness, public-safe "
            "runtime status, autonomous SOC behavior, AI-approved status, or analyst-approved status."
        ),
        "privacy_status": "Controlled contract fixtures only; no sensitive operational material or live telemetry intentionally included.",
    }


def write_reports(report: dict[str, Any]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    lines = [
        "# HO-PIPE-001 Validation Result",
        "",
        f"- Status: `{report['status']}`",
        f"- Detection ID: `{report['detection_id']}`",
        f"- Validation scope: `{report['validation_scope']}`",
        f"- Proof ceiling: `{report['proof_ceiling']}`",
        f"- Total cases: `{report['total_cases']}`",
        f"- Positive cases: `{report['positive_cases']}`",
        f"- Negative cases: `{report['negative_cases']}`",
        f"- Matched positives: `{report['matched_positive_count']}`",
        f"- Missed positives: `{len(report['missed_positive_cases'])}`",
        f"- False-positive negatives: `{len(report['false_positive_negative_cases'])}`",
        "",
        "## Supported Claim",
        "",
        report["exact_claim_supported"],
        "",
        "## Boundary",
        "",
        report["trust_boundary"],
        "",
        "## Blocked Claims",
        "",
        *[f"- {claim}" for claim in report["blocked_claims"]],
        "",
    ]
    REPORT_MD.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate HO-PIPE-001 controlled contract fixtures")
    parser.add_argument("--write", action="store_true", help="write validation reports")
    parser.add_argument(
        "--source-contract",
        choices=("required", "skip-if-missing"),
        default="required",
        help="require sibling detection source surfaces, or skip only when the entire sibling repo is unavailable",
    )
    args = parser.parse_args(argv)
    validate_source_contract(args.source_contract)
    cases = load_json(CASES_FILE, "HO-PIPE-001 validation cases")
    report = build_report(cases)
    if report["status"] != "pass":
        fail("HO-PIPE-001 controlled contract validation failed")
    if args.write:
        write_reports(report)
    print("STATUS=pass")
    print("DETECTION_ID=HO-PIPE-001")
    print(f"TOTAL_CASES={report['total_cases']}")
    print(f"POSITIVE_CASES={report['positive_cases']}")
    print(f"NEGATIVE_CASES={report['negative_cases']}")
    print(f"PROOF_CEILING={report['proof_ceiling']}")
    print("PUBLIC_SAFE_STATUS=NOT_PUBLIC_SAFE")
    print("RUNTIME_ACTIVE=false")
    print("SIGNAL_OBSERVED=false")
    print(f"WRITE_REPORTS={'true' if args.write else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

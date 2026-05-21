#!/usr/bin/env python3
"""Controlled-test validation runner for ID-DET-003."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_ROOT = ROOT.parent / "hawkinsoperations-detections"
SOURCE_DIR = DETECTIONS_ROOT / "detections" / "identity" / "id-det-003"
SOURCE_RULE = SOURCE_DIR / "rule.yml"
SOURCE_STATUS = SOURCE_DIR / "status.yml"
SOURCE_SPLUNK = SOURCE_DIR / "splunk.spl"
SOURCE_MAPPING = SOURCE_DIR / "event-mapping.yml"
CASES_FILE = ROOT / "validation" / "identity" / "id-det-003" / "validation-cases.json"
REPORT_DIR = ROOT / "reports" / "id-det-003"
REPORT_JSON = REPORT_DIR / "validation-result.json"
REPORT_MD = REPORT_DIR / "validation-result.md"

DETECTION_ID = "ID-DET-003"
SUPPORTED_CLAIM = (
    "ID-DET-003 passed controlled-test validation against 10 controlled identity administration fixtures "
    "for privileged role assignment or admin group change behavior."
)
CLAIM_CEILING = "CONTROLLED_TEST_VALIDATED"
EXPECTED_POSITIVE_COUNT = 5
EXPECTED_NEGATIVE_COUNT = 5
REQUIRED_EVENT_FIELDS = {
    "event_type",
    "actor_identity",
    "target_identity",
    "action",
    "action_result",
    "role_name",
    "group_name",
    "entitlement_name",
    "privileged_role",
    "admin_group",
    "sensitive_entitlement",
    "actor_privileged",
    "just_in_time_request",
    "approved_change_ticket",
    "breakglass_exercise",
    "maintenance_window",
    "expected_admin_actor",
    "risk_level",
    "detection_expected",
}
REQUIRED_CASE_IDS = {
    "pos-001-privileged-role-assignment",
    "pos-002-admin-group-change",
    "pos-003-sensitive-entitlement-grant",
    "pos-004-privileged-role-update",
    "pos-005-admin-group-entitlement-combined",
    "neg-001-approved-jit-role",
    "neg-002-ticketed-admin-group-change",
    "neg-003-breakglass-exercise",
    "neg-004-maintenance-expected-admin",
    "neg-005-failed-privileged-role-assignment",
}
BLOCKED_CLAIMS = [
    "runtime-active",
    "signal-observed",
    "public-safe",
    "evidence-linked public proof",
    "live Okta proof",
    "live Entra proof",
    "live IdP proof",
    "live Splunk proof",
    "Wazuh-routed proof",
    "Cribl-routed proof",
    "Security Onion observed proof",
    "production-ready",
    "fleet-wide",
    "production identity coverage",
    "full identity attack coverage",
    "autonomous SOC",
    "AI-approved disposition",
    "analyst-approved disposition",
    "proof promotion",
    "website/public-surface promotion",
]
NOT_CLAIMED_HERE = [
    "live IdP proof",
    "live SIEM/NDR observation",
    "production identity coverage",
    "complete identity-attack coverage",
    "autonomous SOC operation",
    "disposition authority",
    "proof promotion",
    "public-safe status",
    "website/public-surface publication",
]


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


def lower_value(event: dict[str, Any], key: str) -> str:
    return str(event.get(key, "") or "").lower()


def bool_value(event: dict[str, Any], key: str) -> bool:
    return bool(event.get(key))


def event_matches(event: dict[str, Any]) -> bool:
    if lower_value(event, "event_type") not in {"role_assignment", "admin_group_change", "entitlement_grant"}:
        return False
    if lower_value(event, "action_result") != "success":
        return False
    if bool_value(event, "just_in_time_request"):
        return False
    if bool_value(event, "approved_change_ticket"):
        return False
    if bool_value(event, "breakglass_exercise"):
        return False
    if bool_value(event, "maintenance_window") and bool_value(event, "expected_admin_actor"):
        return False
    return any(
        [
            bool_value(event, "privileged_role"),
            bool_value(event, "admin_group"),
            bool_value(event, "sensitive_entitlement"),
        ]
    )


def validate_source_contract(mode: str = "required") -> None:
    source_paths = [SOURCE_RULE, SOURCE_STATUS, SOURCE_SPLUNK, SOURCE_MAPPING]
    missing_paths = [path for path in source_paths if not path.exists()]
    if missing_paths:
        if mode == "skip-if-missing" and len(missing_paths) == len(source_paths):
            print("SOURCE_CONTRACT=skipped")
            print("SOURCE_CONTRACT_REASON=sibling detections repo unavailable")
            return
        fail("missing ID-DET-003 source surfaces: " + ", ".join(str(path) for path in missing_paths))
    rule = read_text(SOURCE_RULE, "ID-DET-003 source rule")
    status = read_text(SOURCE_STATUS, "ID-DET-003 source status")
    splunk = read_text(SOURCE_SPLUNK, "ID-DET-003 Splunk source")
    mapping = read_text(SOURCE_MAPPING, "ID-DET-003 event mapping")
    combined = "\n".join([rule, status, splunk, mapping])
    for fragment in [
        "detection_id: ID-DET-003",
        "selection_privilege_change_event:",
        "selection_privileged_role:",
        "selection_admin_group:",
        "selection_sensitive_entitlement:",
        "validation_status: CONTROLLED_TEST_VALIDATED",
        "public_safe_status: NOT_PUBLIC_SAFE",
    ]:
        if fragment not in combined:
            fail(f"ID-DET-003 source missing required fragment: {fragment}")
    require_yaml_scalar(status, "detection_id", "ID-DET-003")
    require_yaml_scalar(status, "source_status", "SOURCE_EXISTS")
    require_yaml_scalar(status, "validation_status", "CONTROLLED_TEST_VALIDATED")
    require_yaml_scalar(status, "validation_count", "10")
    require_yaml_scalar(status, "positive_count", "5")
    require_yaml_scalar(status, "negative_count", "5")
    require_yaml_scalar(status, "missed_positive_count", "0")
    require_yaml_scalar(status, "false_positive_negative_count", "0")
    require_yaml_scalar(status, "claim_ceiling", "CONTROLLED_TEST_VALIDATED")
    require_yaml_scalar(status, "runtime_active", "false")
    require_yaml_scalar(status, "signal_observed", "false")
    require_yaml_scalar(status, "evidence_linked_public_proof", "false")
    require_yaml_scalar(status, "proof_status", "NO_PROOF_RECORD")
    require_yaml_scalar(status, "public_safe_status", "NOT_PUBLIC_SAFE")


def validate_cases_shape(cases: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if cases.get("detection_id") != DETECTION_ID:
        fail(f"validation-cases detection_id must be {DETECTION_ID}")
    groups = cases.get("cases")
    if not isinstance(groups, dict):
        fail("validation-cases cases must be an object")
    positive = groups.get("positive")
    negative = groups.get("negative")
    if not isinstance(positive, list) or not isinstance(negative, list):
        fail("validation-cases positive and negative must be arrays")
    if len(positive) != EXPECTED_POSITIVE_COUNT or len(negative) != EXPECTED_NEGATIVE_COUNT:
        fail("validation-cases fixture counts do not match expected ID-DET-003 shape")
    ids = {str(case.get("id")) for case in [*positive, *negative]}
    if ids != REQUIRED_CASE_IDS:
        fail("validation-cases case id set does not match required ID-DET-003 fixture IDs")
    for case in [*positive, *negative]:
        case_id = str(case.get("id"))
        for key in ("id", "description", "expected_result", "reason", "event"):
            if key not in case:
                fail(f"{case_id}: missing required case field {key}")
        if case["expected_result"] not in {"match", "no_match"}:
            fail(f"{case_id}: expected_result must be match or no_match")
        event = case.get("event")
        if not isinstance(event, dict):
            fail(f"{case_id}: event must be an object")
        missing_fields = sorted(REQUIRED_EVENT_FIELDS - set(event))
        if missing_fields:
            fail(f"{case_id}: missing required event fields: {', '.join(missing_fields)}")
        if bool(event.get("detection_expected")) is not (case["expected_result"] == "match"):
            fail(f"{case_id}: detection_expected must align with expected_result")
    return positive, negative


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    matched = event_matches(case["event"])
    expected_result = str(case["expected_result"])
    expected = expected_result == "match"
    return {
        "id": case["id"],
        "description": case["description"],
        "expected_result": expected_result,
        "matched": matched,
        "pass": matched is expected,
        "reason": case["reason"],
    }


def build_report(cases: dict[str, Any]) -> dict[str, Any]:
    positive, negative = validate_cases_shape(cases)
    positive_results = [evaluate_case(case) for case in positive]
    negative_results = [evaluate_case(case) for case in negative]
    missed = [result["id"] for result in positive_results if not result["pass"]]
    false_positive = [result["id"] for result in negative_results if not result["pass"]]
    fixture_results = [*positive_results, *negative_results]
    return {
        "status": "pass" if not missed and not false_positive else "fail",
        "detection_id": DETECTION_ID,
        "validation_scope": "controlled identity administration fixtures only",
        "claim_ceiling": CLAIM_CEILING,
        "proof_ceiling": CLAIM_CEILING,
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "source_reference": "hawkinsoperations-detections/detections/identity/id-det-003",
        "validation_cases_file": "hawkinsoperations-validation/validation/identity/id-det-003/validation-cases.json",
        "fixture_count": len(fixture_results),
        "positive_count": len(positive_results),
        "negative_count": len(negative_results),
        "matched_positive_count": sum(1 for result in positive_results if result["matched"]),
        "missed_positive_count": len(missed),
        "false_positive_negative_count": len(false_positive),
        "total_cases": len(fixture_results),
        "positive_cases": len(positive_results),
        "negative_cases": len(negative_results),
        "missed_positive_cases": missed,
        "false_positive_negative_cases": false_positive,
        "supported_claim": SUPPORTED_CLAIM,
        "exact_claim_supported": SUPPORTED_CLAIM,
        "current_scope": "This validation result establishes controlled-test validation for ID-DET-003 only.",
        "not_claimed_here": NOT_CLAIMED_HERE,
        "blocked_claims": BLOCKED_CLAIMS,
        "fixture_results": fixture_results,
        "runtime_active": False,
        "signal_observed": False,
        "live_idp_proof": False,
        "splunk_fired": False,
        "wazuh_routed": False,
        "cribl_routed": False,
        "security_onion_observed": False,
        "proof_promotion": False,
        "website_public_surface_promotion": False,
        "trust_boundary": (
            "Controlled identity administration fixture validation only. This does not prove runtime, signal, "
            "public-safe proof, live IdP, live Splunk, Wazuh routing, Cribl routing, Security Onion "
            "observation, production identity coverage, autonomous SOC behavior, AI-approved disposition, "
            "or analyst-approved disposition."
        ),
        "privacy_status": "Controlled identity administration fixtures only; no sensitive operational material or live telemetry intentionally included.",
    }


def write_reports(report: dict[str, Any]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    lines = [
        "# ID-DET-003 Validation Result",
        "",
        f"- Status: `{report['status']}`",
        f"- Detection ID: `{report['detection_id']}`",
        f"- Validation scope: `{report['validation_scope']}`",
        f"- Claim ceiling: `{report['claim_ceiling']}`",
        f"- Fixture count: `{report['fixture_count']}`",
        f"- Positive count: `{report['positive_count']}`",
        f"- Negative count: `{report['negative_count']}`",
        f"- Matched positives: `{report['matched_positive_count']}`",
        f"- Missed positives: `{report['missed_positive_count']}`",
        f"- False-positive negatives: `{report['false_positive_negative_count']}`",
        "",
        "## Supported Claim",
        "",
        report["supported_claim"],
        "",
        "## Current Scope",
        "",
        report["current_scope"],
        "",
        "## Not Claimed Here",
        "",
        *[f"- {claim}" for claim in report["not_claimed_here"]],
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
    parser = argparse.ArgumentParser(description="Validate ID-DET-003 controlled identity administration fixtures")
    parser.add_argument("--write", action="store_true", help="write validation reports")
    parser.add_argument("--source-contract", choices=("required", "skip-if-missing"), default="required")
    args = parser.parse_args(argv)
    validate_source_contract(args.source_contract)
    cases = load_json(CASES_FILE, "ID-DET-003 validation cases")
    report = build_report(cases)
    if report["status"] != "pass":
        fail("ID-DET-003 controlled-test validation failed")
    if args.write:
        write_reports(report)
    print("STATUS=pass")
    print(f"DETECTION_ID={DETECTION_ID}")
    print(f"FIXTURE_COUNT={report['fixture_count']}")
    print(f"POSITIVE_COUNT={report['positive_count']}")
    print(f"NEGATIVE_COUNT={report['negative_count']}")
    print(f"MATCHED_POSITIVE_COUNT={report['matched_positive_count']}")
    print(f"MISSED_POSITIVE_COUNT={report['missed_positive_count']}")
    print(f"FALSE_POSITIVE_NEGATIVE_COUNT={report['false_positive_negative_count']}")
    print(f"CLAIM_CEILING={report['claim_ceiling']}")
    print("PUBLIC_SAFE_STATUS=NOT_PUBLIC_SAFE")
    print("RUNTIME_ACTIVE=false")
    print("SIGNAL_OBSERVED=false")
    print(f"WRITE_REPORTS={'true' if args.write else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

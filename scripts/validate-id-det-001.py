#!/usr/bin/env python3
"""Controlled-test validation runner for ID-DET-001."""

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
SOURCE_DIR = DETECTIONS_ROOT / "detections" / "identity" / "id-det-001"
SOURCE_RULE = SOURCE_DIR / "rule.yml"
SOURCE_STATUS = SOURCE_DIR / "status.yml"
SOURCE_SPLUNK = SOURCE_DIR / "splunk.spl"
SOURCE_MAPPING = SOURCE_DIR / "event-mapping.yml"
CASES_FILE = ROOT / "validation" / "identity" / "id-det-001" / "validation-cases.json"
REPORT_DIR = ROOT / "reports" / "id-det-001"
REPORT_JSON = REPORT_DIR / "validation-result.json"
REPORT_MD = REPORT_DIR / "validation-result.md"

SUPPORTED_CLAIM = (
    "ID-DET-001 passed controlled-test validation against 10 controlled identity-event fixtures "
    "for suspicious identity session context."
)
CLAIM_CEILING = "CONTROLLED_TEST_VALIDATED"
EXPECTED_POSITIVE_COUNT = 5
EXPECTED_NEGATIVE_COUNT = 5
REQUIRED_EVENT_FIELDS = {
    "event_type",
    "identity",
    "identity_type",
    "auth_result",
    "mfa_result",
    "source_country",
    "previous_country",
    "impossible_travel",
    "source_asn_category",
    "previous_asn_category",
    "device_id",
    "known_device",
    "user_agent_family",
    "previous_user_agent_family",
    "session_id",
    "session_reuse",
    "action_after_login",
    "privileged_action",
    "maintenance_window",
    "expected_automation",
    "approved_tool_scope",
    "risk_level",
    "detection_expected",
}
REQUIRED_CASE_IDS = {
    "pos-001-impossible-travel-success",
    "pos-002-new-device-new-asn",
    "pos-003-service-account-interactive",
    "pos-004-ai-agent-privileged-out-of-scope",
    "pos-005-session-reuse-context-shift",
    "neg-001-normal-known-device",
    "neg-002-vpn-known-device-expected-asn",
    "neg-003-service-account-expected-automation",
    "neg-004-ai-agent-approved-tool-scope",
    "neg-005-privileged-maintenance-window",
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
    "machine identity production governance",
    "AI agent production governance",
    "full identity attack coverage",
    "impossible-travel completeness",
    "session hijacking completeness",
    "autonomous SOC",
    "AI-approved disposition",
    "analyst-approved disposition",
    "proof promotion",
    "website/public-surface promotion",
]
FUTURE_GATED_PHASES = [
    {
        "id": "ID-RUNTIME-001",
        "name": "Proxmox and Windows private runtime identity receipt",
        "purpose": "Map ID-DET-001 logic into one private lab receipt using Windows identity/auth metadata, Wazuh count-only receipt, Splunk count-only receipt, and platform private ledger review.",
        "claim_ceiling": "PRIVATE_RUNTIME_METADATA_CAPTURED",
        "boundary": "Not public proof. Not production coverage. Not public-safe.",
    },
    {
        "id": "ID-CLOUD-001",
        "name": "IdP export/log review lane",
        "purpose": "Review exported or approved Entra-style or Okta-style identity-provider logs only after a separate gate.",
        "claim_ceiling": "CONTROLLED_TEST_VALIDATED first, then PRIVATE_RUNTIME_METADATA_CAPTURED only if approved sanitized export review exists.",
        "boundary": "No live IdP proof in this PR. No production tenant claim.",
    },
    {
        "id": "ID-AGENT-001",
        "name": "AI or machine identity tool-scope validation lane",
        "purpose": "Model AI agent or machine identity behavior where the identity performs an action outside approved tool or resource scope.",
        "claim_ceiling": "CONTROLLED_TEST_VALIDATED",
        "boundary": "No autonomous SOC claim. No AI disposition authority.",
    },
    {
        "id": "ID-ROUTE-001",
        "name": "SIEM/NDR route receipt lane",
        "purpose": "Add count-only route checks for Wazuh, Splunk, Cribl, and Security Onion without exposing event payloads or expanding Splunk ingestion.",
        "claim_ceiling": "PRIVATE_RUNTIME_METADATA_CAPTURED if receipt exists.",
        "boundary": "No live SIEM/NDR public proof in this PR. No full route proof unless later separately captured and reviewed.",
    },
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


def auth_success(event: dict[str, Any]) -> bool:
    return lower_value(event, "auth_result") == "success"


def asn_changed(event: dict[str, Any]) -> bool:
    if "source_asn_changed" in event:
        return bool_value(event, "source_asn_changed")
    return lower_value(event, "source_asn_category") != lower_value(event, "previous_asn_category")


def user_agent_changed(event: dict[str, Any]) -> bool:
    if "user_agent_changed" in event:
        return bool_value(event, "user_agent_changed")
    return lower_value(event, "user_agent_family") != lower_value(event, "previous_user_agent_family")


def asn_category_changed(event: dict[str, Any]) -> bool:
    if "asn_category_changed" in event:
        return bool_value(event, "asn_category_changed")
    return asn_changed(event)


def expected_vpn_known_device(event: dict[str, Any]) -> bool:
    return bool_value(event, "known_device") and lower_value(event, "source_asn_category") == "expected_vpn"


def event_matches(event: dict[str, Any]) -> bool:
    if not auth_success(event):
        return False
    if expected_vpn_known_device(event):
        return False
    if bool_value(event, "expected_automation"):
        return False
    if bool_value(event, "approved_tool_scope"):
        return False
    if bool_value(event, "maintenance_window"):
        return False

    impossible_travel = bool_value(event, "impossible_travel")
    new_device_new_asn = not bool_value(event, "known_device") and asn_changed(event)
    service_interactive = (
        lower_value(event, "identity_type") == "service_account"
        and lower_value(event, "action_after_login") == "interactive_console"
    )
    agent_privileged_out_of_scope = (
        lower_value(event, "identity_type") == "ai_agent" and bool_value(event, "privileged_action")
    )
    reused_session_shift = (
        bool_value(event, "session_reuse") and user_agent_changed(event) and asn_category_changed(event)
    )
    return any(
        [
            impossible_travel,
            new_device_new_asn,
            service_interactive,
            agent_privileged_out_of_scope,
            reused_session_shift,
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
        fail("missing ID-DET-001 source surfaces: " + ", ".join(str(path) for path in missing_paths))
    rule = read_text(SOURCE_RULE, "ID-DET-001 source rule")
    status = read_text(SOURCE_STATUS, "ID-DET-001 source status")
    splunk = read_text(SOURCE_SPLUNK, "ID-DET-001 Splunk source")
    mapping = read_text(SOURCE_MAPPING, "ID-DET-001 event mapping")
    required_fragments = [
        "detection_id: ID-DET-001",
        "selection_successful_identity_activity:",
        "selection_impossible_travel:",
        "selection_new_device_new_asn:",
        "selection_service_account_interactive:",
        "selection_ai_agent_out_of_scope_privileged_action:",
        "selection_session_reuse_context_shift:",
        "validation_status: CONTROLLED_TEST_VALIDATED",
        "public_safe_status: NOT_PUBLIC_SAFE",
        "ID-DET-001 passed controlled-test validation against 10 controlled identity-event fixtures",
    ]
    combined = "\n".join([rule, status, splunk, mapping])
    for fragment in required_fragments:
        if fragment not in combined:
            fail(f"ID-DET-001 source missing required fragment: {fragment}")
    require_yaml_scalar(status, "detection_id", "ID-DET-001")
    require_yaml_scalar(status, "validation_status", "CONTROLLED_TEST_VALIDATED")
    require_yaml_scalar(status, "claim_ceiling", "CONTROLLED_TEST_VALIDATED")
    require_yaml_scalar(status, "runtime_active", "false")
    require_yaml_scalar(status, "signal_observed", "false")
    require_yaml_scalar(status, "public_safe_status", "NOT_PUBLIC_SAFE")


def validate_cases_shape(cases: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if cases.get("detection_id") != "ID-DET-001":
        fail("validation-cases detection_id must be ID-DET-001")
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
        fail("validation-cases case id set does not match required ID-DET-001 fixture IDs")
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
        expected_bool = case["expected_result"] == "match"
        if bool(event.get("detection_expected")) is not expected_bool:
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
    fixture_count = len(fixture_results)
    return {
        **controlled_report_contract(
            "ID-DET-001",
            CLAIM_CEILING,
            passed=not missed and not false_positive,
        ),
        "status": "pass" if not missed and not false_positive else "fail",
        "detection_id": "ID-DET-001",
        "validation_scope": "controlled identity-event fixtures only",
        "claim_ceiling": CLAIM_CEILING,
        "proof_ceiling": CLAIM_CEILING,
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "source_reference": "hawkinsoperations-detections/detections/identity/id-det-001",
        "validation_cases_file": "hawkinsoperations-validation/validation/identity/id-det-001/validation-cases.json",
        "fixture_count": fixture_count,
        "positive_count": len(positive_results),
        "negative_count": len(negative_results),
        "matched_positive_count": sum(1 for result in positive_results if result["matched"]),
        "missed_positive_count": len(missed),
        "false_positive_negative_count": len(false_positive),
        "total_cases": fixture_count,
        "positive_cases": len(positive_results),
        "negative_cases": len(negative_results),
        "missed_positive_cases": missed,
        "false_positive_negative_cases": false_positive,
        "supported_claim": SUPPORTED_CLAIM,
        "exact_claim_supported": SUPPORTED_CLAIM,
        "current_scope": "This validation result establishes controlled-test validation for ID-DET-001 only.",
        "future_gated_phases": FUTURE_GATED_PHASES,
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
            "Controlled identity-event fixture validation only. This does not prove runtime, signal, "
            "public-safe proof, live IdP, live Splunk, Wazuh routing, Cribl routing, Security Onion "
            "observation, production identity coverage, AI or agent production governance, autonomous SOC "
            "behavior, AI-approved disposition, or analyst-approved disposition."
        ),
        "privacy_status": "Controlled identity-event fixtures only; no sensitive operational material or live telemetry intentionally included.",
    }


def write_reports(report: dict[str, Any]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    lines = [
        "# ID-DET-001 Validation Result",
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
        "## Future Gated Phases",
        "",
        *[
            f"- `{gate['id']}`: {gate['name']}. Claim ceiling: `{gate['claim_ceiling']}`. Boundary: {gate['boundary']}"
            for gate in report["future_gated_phases"]
        ],
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
    parser = argparse.ArgumentParser(description="Validate ID-DET-001 controlled identity-event fixtures")
    parser.add_argument("--write", action="store_true", help="write validation reports")
    parser.add_argument(
        "--source-contract",
        choices=("required", "skip-if-missing"),
        default="required",
        help="require sibling detection source surfaces, or skip only when the entire sibling repo is unavailable",
    )
    args = parser.parse_args(argv)
    validate_source_contract(args.source_contract)
    cases = load_json(CASES_FILE, "ID-DET-001 validation cases")
    report = build_report(cases)
    if report["status"] != "pass":
        fail("ID-DET-001 controlled-test validation failed")
    if args.write:
        write_reports(report)
    print("STATUS=pass")
    print("DETECTION_ID=ID-DET-001")
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

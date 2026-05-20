#!/usr/bin/env python3
"""Controlled-test validation runner for HO-DET-011.

This validates repository-contained fixture behavior only. It does not inspect
runtime systems, query Splunk, assert Wazuh routing, or claim public-safe proof.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_ROOT = ROOT.parent / "hawkinsoperations-detections"
SOURCE_DIR = DETECTIONS_ROOT / "detections" / "successor" / "ho-det-011"
SOURCE_RULE = SOURCE_DIR / "rule.yml"
SOURCE_STATUS = SOURCE_DIR / "status.yml"
CASES_FILE = ROOT / "validation" / "successor" / "ho-det-011" / "validation-cases.json"
REPORT_DIR = ROOT / "reports" / "ho-det-011"
REPORT_JSON = REPORT_DIR / "validation-result.json"
REPORT_MD = REPORT_DIR / "validation-result.md"

SUPPORTED_CLAIM = "HO-DET-011 passed controlled-test validation against controlled Windows service creation fixtures."
PROOF_CEILING = "CONTROLLED_TEST_VALIDATED"
EXPECTED_POSITIVE_COUNT = 7
EXPECTED_NEGATIVE_COUNT = 10
BLOCKED_CLAIMS = [
    "runtime-active",
    "signal-observed",
    "public-safe",
    "evidence-linked public proof",
    "public-safe runtime proof",
    "Splunk-fired",
    "live Splunk fired",
    "Wazuh-routed",
    "Cribl-routed",
    "Security Onion observed",
    "Suricata observed",
    "Zeek observed",
    "production-ready",
    "production triage",
    "fleet-wide",
    "autonomous SOC",
    "AI-approved disposition",
    "analyst-approved disposition",
    "attack coverage completeness",
    "service-creation coverage completeness",
]

SUSPICIOUS_PATH_MARKERS = [
    "\\appdata\\",
    "\\temp\\",
    "\\programdata\\",
    "\\public\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\windows\\temp\\",
    "\\perflogs\\",
]
SUSPICIOUS_BINARY_MARKERS = [
    "powershell",
    "pwsh",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
]
SCRIPT_TARGET_MARKERS = [
    ".ps1",
    ".vbs",
    ".js",
    ".hta",
    ".bat",
    ".cmd",
]
SERVICE_CREATION_TOOLS = [
    "\\sc.exe",
    "\\powershell.exe",
    "\\pwsh.exe",
    "\\cmd.exe",
]
SERVICE_CREATION_COMMAND_MARKERS = [
    " create ",
    " sc create",
    "sc.exe create",
    "new-service",
    "binpath=",
    "binpath =",
    "-encodedcommand",
    "frombase64string",
]
REQUIRED_CASE_IDS = {
    "pos-001-system-7045-appdata-imagepath",
    "pos-002-system-7045-servicefilename-windows-temp",
    "pos-003-security-4697-servicefilename-users-public",
    "pos-004-sysmon-sc-create-binpath-public",
    "pos-005-sysmon-powershell-new-service-programdata",
    "pos-006-system-7045-interpreter-backed-rundll32",
    "pos-007-system-7045-script-like-ps1-target",
    "neg-001-benign-signed-vendor-installer-program-files",
    "neg-002-benign-updater-program-files-x86",
    "neg-003-benign-driver-system32-drivers",
    "neg-004-benign-backup-monitor-security-agent",
    "neg-005-benign-maintenance-window-service",
    "neg-006-system-7045-without-suspicious-path",
    "neg-007-sysmon-sc-query-no-create",
    "neg-008-suspicious-keyword-benign-service-name",
    "neg-009-managed-application-directory",
    "neg-010-service-adjacent-command-no-create-pattern",
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


def lower_value(event: dict[str, Any], key: str) -> str:
    return str(event.get(key, "") or "").lower()


def event_id(event: dict[str, Any]) -> int | None:
    raw = event.get("EventID", event.get("EventCode"))
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def channel_is(event: dict[str, Any], expected: str) -> bool:
    return lower_value(event, "Channel") == expected.lower()


def provider_contains(event: dict[str, Any], expected: str) -> bool:
    provider = lower_value(event, "Provider_Name") or lower_value(event, "Provider")
    return expected.lower() in provider


def suspicious_path(value: str) -> bool:
    lowered = value.lower()
    return (
        any(marker in lowered for marker in SUSPICIOUS_PATH_MARKERS)
        or any(marker in lowered for marker in SUSPICIOUS_BINARY_MARKERS)
        or any(marker in lowered for marker in SCRIPT_TARGET_MARKERS)
    )


def service_path_values(event: dict[str, Any]) -> list[str]:
    fields = [
        "ImagePath",
        "ServiceFileName",
        "ServiceFile",
        "param2",
        "winlog_event_data_ImagePath",
        "winlog_event_data_ServiceFileName",
    ]
    return [str(event.get(field, "") or "") for field in fields if event.get(field)]


def service_path_matches(event: dict[str, Any]) -> bool:
    return any(suspicious_path(value) for value in service_path_values(event))


def system_7045_matches(event: dict[str, Any]) -> bool:
    return (
        event_id(event) == 7045
        and channel_is(event, "System")
        and provider_contains(event, "Service Control Manager")
        and service_path_matches(event)
    )


def security_4697_matches(event: dict[str, Any]) -> bool:
    return event_id(event) == 4697 and channel_is(event, "Security") and service_path_matches(event)


def service_creation_process_matches(event: dict[str, Any]) -> bool:
    image = lower_value(event, "Image")
    command_line = f" {lower_value(event, 'CommandLine')} "
    tool_matches = any(image.endswith(tool) for tool in SERVICE_CREATION_TOOLS)
    command_matches = any(marker in command_line for marker in SERVICE_CREATION_COMMAND_MARKERS)
    return (
        event_id(event) == 1
        and provider_contains(event, "Sysmon")
        and tool_matches
        and command_matches
        and suspicious_path(command_line)
    )


def event_matches(event: dict[str, Any]) -> bool:
    return system_7045_matches(event) or security_4697_matches(event) or service_creation_process_matches(event)


def validate_source_contract(mode: str = "required") -> None:
    source_paths = [SOURCE_RULE, SOURCE_STATUS]
    missing_paths = [path for path in source_paths if not path.exists()]
    if missing_paths:
        if mode == "skip-if-missing" and len(missing_paths) == len(source_paths):
            print("SOURCE_CONTRACT=skipped")
            print("SOURCE_CONTRACT_REASON=sibling detections repo unavailable")
            return
        fail("missing HO-DET-011 source surfaces: " + ", ".join(str(path) for path in missing_paths))

    rule = read_text(SOURCE_RULE, "HO-DET-011 source rule")
    status = read_text(SOURCE_STATUS, "HO-DET-011 source status")
    required_rule_fragments = [
        "detection_id: HO-DET-011",
        "selection_system_7045:",
        "selection_security_4697:",
        "selection_sysmon_tooling:",
        "selection_suspicious_image_path:",
        "selection_suspicious_service_file_name:",
        "selection_suspicious_command_line:",
        "\\AppData\\",
        "\\Windows\\Temp\\",
        "\\Users\\Public\\",
        "rundll32",
        ".ps1",
        "New-Service",
        "binPath=",
    ]
    for fragment in required_rule_fragments:
        if fragment not in rule:
            fail(f"source rule missing tuned fragment: {fragment}")
    required_status_scalars = {
        "tuning_status": "SOURCE_TUNING_NOTES_ADDED",
        "fixtures_in_detections_repo": "false",
        "validation_status": "CONTROLLED_TEST_VALIDATED",
        "validation_total_cases": "17",
        "validation_positive_cases": "7",
        "validation_negative_cases": "10",
        "proof_level": "PRIVATE_RUNTIME_EVIDENCE_CAPTURED",
        "runtime_evidence_status": "PRIVATE_RUNTIME_EVIDENCE_CAPTURED_LOCAL_WINDOWS_ONLY",
        "wazuh_status": "NOT_PROVEN",
        "splunk_status": "NOT_PROVEN",
        "cribl_status": "NOT_PROVEN",
        "public_safe_status": "NOT_PUBLIC_SAFE",
    }
    for key, expected in required_status_scalars.items():
        require_yaml_scalar(status, key, expected)
    required_status_fragments = [
        "HO-DET-011 passed controlled-test validation against 17 controlled Windows service creation fixtures.",
        "HO-DET-011 is capped at PRIVATE_RUNTIME_EVIDENCE_CAPTURED for private evidence and NOT_PUBLIC_SAFE for public use.",
    ]
    for fragment in required_status_fragments:
        if fragment not in status:
            fail(f"source status missing expected boundary fragment: {fragment}")


def validate_fixture_contract(cases: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if cases.get("detection_id") != "HO-DET-011":
        fail("validation cases detection_id must be HO-DET-011")
    if cases.get("validation_scope") != "controlled-test fixtures only":
        fail("validation_scope must be controlled-test fixtures only")
    groups = cases.get("cases")
    if not isinstance(groups, dict):
        fail("validation cases must include cases object")
    positives = groups.get("positive")
    negatives = groups.get("negative")
    if not isinstance(positives, list) or not isinstance(negatives, list):
        fail("positive and negative cases must be arrays")
    if len(positives) != EXPECTED_POSITIVE_COUNT:
        fail(f"expected {EXPECTED_POSITIVE_COUNT} positive cases, found {len(positives)}")
    if len(negatives) != EXPECTED_NEGATIVE_COUNT:
        fail(f"expected {EXPECTED_NEGATIVE_COUNT} negative cases, found {len(negatives)}")
    case_ids = {str(item.get("id", "")) for item in positives + negatives}
    missing = sorted(REQUIRED_CASE_IDS - case_ids)
    extra = sorted(case_ids - REQUIRED_CASE_IDS)
    if missing or extra:
        fail(f"case id contract mismatch; missing={missing}; extra={extra}")
    for item in positives + negatives:
        case_id = str(item.get("id", ""))
        event = item.get("event")
        if not isinstance(event, dict):
            fail(f"case {case_id} must include an event object")
        if item.get("expected_match") not in {True, False}:
            fail(f"case {case_id} must include expected_match boolean")
        if event_id(event) == 7045:
            if not channel_is(event, "System"):
                fail(f"case {case_id} treats Event ID 7045 outside Windows System telemetry")
            if not provider_contains(event, "Service Control Manager"):
                fail(f"case {case_id} must identify Service Control Manager for Event ID 7045")
    return positives, negatives


def evaluate_cases(cases: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[str]]:
    positives, negatives = validate_fixture_contract(cases)
    positive_results: list[dict[str, Any]] = []
    negative_results: list[dict[str, Any]] = []
    missed_positive_cases: list[str] = []
    false_positive_negative_cases: list[str] = []

    for item in positives:
        case_id = str(item.get("id", ""))
        matched = event_matches(item.get("event", {}))
        passed = matched is True
        if not passed:
            missed_positive_cases.append(case_id)
        positive_results.append(
            {
                "id": case_id,
                "telemetry_source": item.get("telemetry_source", ""),
                "behavior": item.get("behavior", ""),
                "expected": True,
                "matched": matched,
                "pass": passed,
            }
        )

    for item in negatives:
        case_id = str(item.get("id", ""))
        matched = event_matches(item.get("event", {}))
        passed = matched is False
        if not passed:
            false_positive_negative_cases.append(case_id)
        negative_results.append(
            {
                "id": case_id,
                "telemetry_source": item.get("telemetry_source", ""),
                "behavior": item.get("behavior", ""),
                "expected": False,
                "matched": matched,
                "pass": passed,
            }
        )

    return positive_results, negative_results, missed_positive_cases, false_positive_negative_cases


def build_report(cases: dict[str, Any], source_contract: str = "required") -> dict[str, Any]:
    validate_source_contract(source_contract)
    positive_results, negative_results, missed, false_positive = evaluate_cases(cases)
    all_results = positive_results + negative_results
    fail_count = len(missed) + len(false_positive)
    status = "pass" if fail_count == 0 else "fail"
    proof_ceiling = PROOF_CEILING if status == "pass" else "VALIDATION_DRAFT"
    return {
        "status": status,
        "detection_id": "HO-DET-011",
        "validation_scope": "controlled-test fixtures only",
        "proof_ceiling": proof_ceiling,
        "source_reference": "hawkinsoperations-detections/detections/successor/ho-det-011",
        "validation_cases_file": "hawkinsoperations-validation/validation/successor/ho-det-011/validation-cases.json",
        "total_cases": len(all_results),
        "positive_cases": len(positive_results),
        "negative_cases": len(negative_results),
        "matched_positive_count": sum(1 for item in positive_results if item["matched"]),
        "missed_positive_cases": missed,
        "false_positive_negative_cases": false_positive,
        "positive": positive_results,
        "negative": negative_results,
        "exact_claim_supported": SUPPORTED_CLAIM if status == "pass" else "",
        "blocked_claims": BLOCKED_CLAIMS,
        "runtime_active": False,
        "signal_observed": False,
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "splunk_fired": False,
        "wazuh_routed": False,
        "cribl_routed": False,
        "security_onion_observed": False,
        "production_ready": False,
        "fleet_wide": False,
        "autonomous_soc": False,
        "ai_approved_disposition": False,
        "analyst_approved_disposition": False,
        "trust_boundary": "Controlled-test Windows service creation fixture validation only. This does not prove runtime, signal, public-safe proof, live Splunk, Wazuh routing, Cribl routing, Security Onion observation, production readiness, fleet-wide deployment, autonomous SOC behavior, AI-approved disposition, or analyst-approved disposition.",
        "privacy_status": "Controlled-test fixtures only; no sensitive operational material or live telemetry intentionally included.",
    }


def write_reports(report: dict[str, Any]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# HO-DET-011 Controlled-test Validation Result",
        "",
        "## Summary",
        f"- Status: {report['status']}",
        f"- Detection ID: {report['detection_id']}",
        f"- Validation scope: {report['validation_scope']}",
        f"- Proof ceiling: {report['proof_ceiling']}",
        f"- Total cases: {report['total_cases']}",
        f"- Positive cases: {report['positive_cases']}",
        f"- Negative cases: {report['negative_cases']}",
        f"- Matched positive count: {report['matched_positive_count']}",
        f"- Missed positives: {', '.join(report['missed_positive_cases']) if report['missed_positive_cases'] else 'none'}",
        f"- False-positive negatives: {', '.join(report['false_positive_negative_cases']) if report['false_positive_negative_cases'] else 'none'}",
        "",
        "## Source Reference",
        f"- {report['source_reference']}",
        "",
        "## Positive Coverage",
    ]
    lines.extend(f"- {item['id']}: {item['behavior']} ({item['telemetry_source']})" for item in report["positive"])
    lines.extend(["", "## Negative Coverage"])
    lines.extend(f"- {item['id']}: {item['behavior']} ({item['telemetry_source']})" for item in report["negative"])
    lines.extend(
        [
            "",
            "## Supported Claim",
            f"- {report['exact_claim_supported']}",
            "",
            "## Blocked Claims",
        ]
    )
    lines.extend(f"- Not supported: {claim}" for claim in report["blocked_claims"])
    lines.extend(
        [
            "",
            "## Boundary",
            report["trust_boundary"],
            "",
            "## Reproduction Command",
            "- From the validation repository root, run: `python scripts/validate-ho-det-011.py`",
        ]
    )
    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_report_matches(report: dict[str, Any]) -> None:
    if not REPORT_JSON.exists() or not REPORT_MD.exists():
        fail("report artifacts are missing; run with --write to generate them")
    existing = load_json(REPORT_JSON, "HO-DET-011 validation result")
    if existing != report:
        fail("reports/ho-det-011/validation-result.json is out of date; run with --write")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate HO-DET-011 controlled-test Windows service creation cases.")
    parser.add_argument("--write", action="store_true", help="Regenerate report artifacts.")
    parser.add_argument(
        "--source-contract",
        choices=("required", "skip-if-missing"),
        default="required",
        help="require sibling detection source surfaces, or skip only when the entire sibling repo is unavailable",
    )
    args = parser.parse_args()

    cases = load_json(CASES_FILE, "HO-DET-011 validation cases")
    report = build_report(cases, source_contract=args.source_contract)
    if args.write:
        write_reports(report)
        write_skipped = "false"
    else:
        verify_report_matches(report)
        write_skipped = "true"

    print(f"STATUS={report['status']}")
    print("DETECTION_ID=HO-DET-011")
    print(f"TOTAL_CASES={report['total_cases']}")
    print(f"POSITIVE_CASES={report['positive_cases']}")
    print(f"NEGATIVE_CASES={report['negative_cases']}")
    print(f"MATCHED_POSITIVE_COUNT={report['matched_positive_count']}")
    print(f"MISSED_POSITIVE_CASES={','.join(report['missed_positive_cases']) if report['missed_positive_cases'] else 'none'}")
    print(f"FALSE_POSITIVE_NEGATIVE_CASES={','.join(report['false_positive_negative_cases']) if report['false_positive_negative_cases'] else 'none'}")
    print(f"PROOF_CEILING={report['proof_ceiling']}")
    print("RUNTIME_ACTIVE=false")
    print("SIGNAL_OBSERVED=false")
    print("PUBLIC_SAFE_STATUS=NOT_PUBLIC_SAFE")
    print(f"WRITE_SKIPPED={write_skipped}")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

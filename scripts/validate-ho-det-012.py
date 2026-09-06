#!/usr/bin/env python3
"""Controlled-test validation runner for HO-DET-012.

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

from validation_report_contract import controlled_report_contract


ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_ROOT = ROOT.parent / "hawkinsoperations-detections"
SOURCE_DIR = DETECTIONS_ROOT / "detections" / "successor" / "ho-det-012"
SOURCE_RULE = SOURCE_DIR / "rule.yml"
SOURCE_STATUS = SOURCE_DIR / "status.yml"
SOURCE_SPLUNK = SOURCE_DIR / "splunk.spl"
SOURCE_WAZUH = SOURCE_DIR / "wazuh.xml"
SOURCE_MAPPING = SOURCE_DIR / "event-mapping.yml"
CASES_FILE = ROOT / "validation" / "successor" / "ho-det-012" / "validation-cases.json"
REPORT_DIR = ROOT / "reports" / "ho-det-012"
REPORT_JSON = REPORT_DIR / "validation-result.json"
REPORT_MD = REPORT_DIR / "validation-result.md"

SUPPORTED_CLAIM = "HO-DET-012 passed controlled-test validation against scheduled-task creation and update fixtures."
PROOF_CEILING = "CONTROLLED_TEST_VALIDATED"
EXPECTED_POSITIVE_COUNT = 4
EXPECTED_NEGATIVE_COUNT = 4
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
    "scheduled-task coverage completeness",
]

SUSPICIOUS_ACTION_MARKERS = [
    "\\appdata\\",
    "\\temp\\",
    "\\programdata\\",
    "\\public\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\windows\\temp\\",
    "\\perflogs\\",
    "powershell",
    "pwsh",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    ".ps1",
    ".vbs",
    ".js",
    ".hta",
    ".bat",
    ".cmd",
]
TASK_TOOL_IMAGES = [
    "\\schtasks.exe",
    "\\powershell.exe",
    "\\pwsh.exe",
    "\\cmd.exe",
    "\\wscript.exe",
    "\\cscript.exe",
    "\\mshta.exe",
    "\\rundll32.exe",
    "\\regsvr32.exe",
]
TASK_CREATION_COMMAND_MARKERS = [
    "schtasks /create",
    "schtasks.exe /create",
    "register-scheduledtask",
    "new-scheduledtaskaction",
    " -encodedcommand",
    "frombase64string",
    " -windowstyle hidden",
    " /min",
    " /tr ",
]
REQUIRED_CASE_IDS = {
    "pos-001-security-4698-appdata-action",
    "pos-002-taskscheduler-106-interpreter-action",
    "pos-003-sysmon-schtasks-create-public-target",
    "pos-004-sysmon-powershell-register-task",
    "neg-001-benign-vendor-updater-program-files",
    "neg-002-benign-endpoint-management-task",
    "neg-003-approved-maintenance-window-task",
    "neg-004-suspicious-name-without-suspicious-action",
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


def contains_suspicious_action(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SUSPICIOUS_ACTION_MARKERS)


def task_action_values(event: dict[str, Any]) -> list[str]:
    fields = [
        "TaskContent",
        "task_content",
        "Task",
        "Actions",
        "Action",
        "winlog_event_data_TaskContent",
        "winlog_event_data_Actions",
        "winlog_event_data_Action",
    ]
    return [str(event.get(field, "") or "") for field in fields if event.get(field)]


def task_action_matches(event: dict[str, Any]) -> bool:
    return any(contains_suspicious_action(value) for value in task_action_values(event))


def task_event_matches(event: dict[str, Any]) -> bool:
    eid = event_id(event)
    security_task_change = eid in {4698, 4702} and channel_is(event, "Security")
    scheduler_operational = (
        eid in {106, 140}
        and channel_is(event, "Microsoft-Windows-TaskScheduler/Operational")
        and provider_contains(event, "TaskScheduler")
    )
    return (security_task_change or scheduler_operational) and task_action_matches(event)


def scheduled_task_tooling_matches(event: dict[str, Any]) -> bool:
    image = lower_value(event, "Image")
    command_line = f" {lower_value(event, 'CommandLine')} "
    tool_matches = any(image.endswith(tool) for tool in TASK_TOOL_IMAGES)
    command_matches = any(marker in command_line for marker in TASK_CREATION_COMMAND_MARKERS)
    return (
        event_id(event) == 1
        and provider_contains(event, "Sysmon")
        and tool_matches
        and command_matches
        and contains_suspicious_action(command_line)
    )


def event_matches(event: dict[str, Any]) -> bool:
    return task_event_matches(event) or scheduled_task_tooling_matches(event)


def validate_source_contract(mode: str = "required") -> None:
    source_paths = [SOURCE_RULE, SOURCE_STATUS, SOURCE_SPLUNK, SOURCE_WAZUH, SOURCE_MAPPING]
    missing_paths = [path for path in source_paths if not path.exists()]
    if missing_paths:
        if mode == "skip-if-missing" and len(missing_paths) == len(source_paths):
            print("SOURCE_CONTRACT=skipped")
            print("SOURCE_CONTRACT_REASON=sibling detections repo unavailable")
            return
        fail("missing HO-DET-012 source surfaces: " + ", ".join(str(path) for path in missing_paths))
    rule = read_text(SOURCE_RULE, "HO-DET-012 source rule")
    status = read_text(SOURCE_STATUS, "HO-DET-012 source status")
    splunk = read_text(SOURCE_SPLUNK, "HO-DET-012 Splunk source")
    wazuh = read_text(SOURCE_WAZUH, "HO-DET-012 Wazuh source")
    mapping = read_text(SOURCE_MAPPING, "HO-DET-012 event mapping")
    required_fragments = [
        "detection_id: HO-DET-012",
        "selection_security_task_change:",
        "selection_taskscheduler_operational:",
        "selection_sysmon_tooling:",
        "selection_suspicious_task_action:",
        "selection_suspicious_command_line:",
        "\\AppData\\",
        "\\Users\\Public\\",
        "Register-ScheduledTask",
        "New-ScheduledTaskAction",
        "validation_status: CONTROLLED_TEST_VALIDATED",
        "proof_status: CONTROLLED_TEST_VALIDATED",
        "public_safe_status: NOT_PUBLIC_SAFE",
        "proof_record_path: hawkinsoperations-proof/proof/records/HO-DET-012.md",
    ]
    combined = "\n".join([rule, status, splunk, wazuh, mapping])
    for fragment in required_fragments:
        if fragment not in combined:
            fail(f"HO-DET-012 source missing required fragment: {fragment}")
    require_yaml_scalar(status, "detection_id", "HO-DET-012")
    require_yaml_scalar(status, "validation_status", "CONTROLLED_TEST_VALIDATED")
    require_yaml_scalar(status, "validation_total_cases", "8")
    require_yaml_scalar(status, "validation_positive_cases", "4")
    require_yaml_scalar(status, "validation_negative_cases", "4")
    require_yaml_scalar(status, "validation_missed_positives", "0")
    require_yaml_scalar(status, "validation_false_positive_negatives", "0")
    require_yaml_scalar(status, "runtime_active", "false")
    require_yaml_scalar(status, "signal_observed", "false")
    require_yaml_scalar(status, "evidence_linked_public_proof", "false")
    require_yaml_scalar(status, "proof_status", "CONTROLLED_TEST_VALIDATED")
    require_yaml_scalar(status, "public_safe_status", "NOT_PUBLIC_SAFE")


def validate_cases_shape(cases: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if cases.get("detection_id") != "HO-DET-012":
        fail("validation-cases detection_id must be HO-DET-012")
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
        fail("validation-cases case id set does not match required HO-DET-012 fixture IDs")
    for case in [*positive, *negative]:
        if "event" not in case or not isinstance(case["event"], dict):
            fail(f"{case.get('id')}: event must be an object")
        if not isinstance(case.get("expected_match"), bool):
            fail(f"{case.get('id')}: expected_match must be boolean")
    return positive, negative


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    matched = event_matches(case["event"])
    expected = bool(case["expected_match"])
    return {
        "id": case["id"],
        "telemetry_source": case["telemetry_source"],
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
            "HO-DET-012",
            PROOF_CEILING,
            passed=not missed and not false_positive,
        ),
        "status": "pass" if not missed and not false_positive else "fail",
        "detection_id": "HO-DET-012",
        "validation_scope": "controlled-test fixtures only",
        "proof_ceiling": PROOF_CEILING,
        "source_reference": "hawkinsoperations-detections/detections/successor/ho-det-012",
        "validation_cases_file": "hawkinsoperations-validation/validation/successor/ho-det-012/validation-cases.json",
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
        "trust_boundary": (
            "Controlled-test scheduled-task fixture validation only. This does not prove runtime, signal, "
            "public-safe proof, live Splunk, Wazuh routing, Cribl routing, Security Onion observation, "
            "production readiness, fleet-wide deployment, autonomous SOC behavior, AI-approved disposition, "
            "or analyst-approved disposition."
        ),
        "privacy_status": "Controlled-test fixtures only; no sensitive operational material or live telemetry intentionally included.",
    }


def write_reports(report: dict[str, Any]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    lines = [
        "# HO-DET-012 Validation Result",
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
    parser = argparse.ArgumentParser(description="Validate HO-DET-012 controlled-test fixtures")
    parser.add_argument("--write", action="store_true", help="write validation reports")
    parser.add_argument(
        "--source-contract",
        choices=("required", "skip-if-missing"),
        default="required",
        help="require sibling detection source surfaces, or skip only when the entire sibling repo is unavailable",
    )
    args = parser.parse_args(argv)
    validate_source_contract(args.source_contract)
    cases = load_json(CASES_FILE, "HO-DET-012 validation cases")
    report = build_report(cases)
    if report["status"] != "pass":
        fail("HO-DET-012 controlled-test validation failed")
    if args.write:
        write_reports(report)
    print("STATUS=pass")
    print("DETECTION_ID=HO-DET-012")
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

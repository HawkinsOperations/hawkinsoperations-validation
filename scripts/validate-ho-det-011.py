#!/usr/bin/env python3
"""Synthetic validation runner for HO-DET-011.

This validates repository-contained fixture behavior only. It does not inspect
runtime systems, query Splunk, or assert Wazuh routing.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CASES_FILE = ROOT / "validation" / "successor" / "ho-det-011" / "validation-cases.json"
REPORT_DIR = ROOT / "reports" / "ho-det-011"
REPORT_JSON = REPORT_DIR / "validation-result.json"
REPORT_MD = REPORT_DIR / "validation-result.md"

SUPPORTED_CLAIM = "HO-DET-011 passed synthetic validation against controlled Windows service creation fixtures."
BLOCKED_CLAIMS = [
    "runtime-active",
    "signal-observed",
    "public-safe",
    "production-ready",
    "Wazuh-routed",
    "live Splunk fired",
    "fleet-wide",
    "validation-passed as runtime proof",
    "evidence-linked public proof",
]

SUSPICIOUS_PATH_MARKERS = [
    "\\appdata\\",
    "\\temp\\",
    "\\programdata\\",
    "\\public\\",
    "\\downloads\\",
]
SUSPICIOUS_BINARY_MARKERS = [
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
]
SERVICE_CREATION_TOOLS = [
    "\\sc.exe",
    "\\powershell.exe",
    "\\pwsh.exe",
    "\\cmd.exe",
]
SERVICE_CREATION_COMMAND_MARKERS = [
    " create ",
    "sc.exe create",
    "new-service",
    "binpath=",
    "binpath =",
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


def event_id(event: dict[str, Any]) -> int | None:
    raw = event.get("EventID", event.get("EventCode"))
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def lower_value(event: dict[str, Any], key: str) -> str:
    return str(event.get(key, "") or "").lower()


def channel_is(event: dict[str, Any], expected: str) -> bool:
    return lower_value(event, "Channel") == expected.lower()


def provider_contains(event: dict[str, Any], expected: str) -> bool:
    provider = lower_value(event, "Provider_Name")
    if not provider:
        provider = lower_value(event, "Provider")
    return expected.lower() in provider


def suspicious_path(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SUSPICIOUS_PATH_MARKERS) or any(
        marker in lowered for marker in SUSPICIOUS_BINARY_MARKERS
    )


def service_path_values(event: dict[str, Any]) -> list[str]:
    fields = ["ImagePath", "ServiceFileName", "ServiceFile", "param2"]
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


def validate_fixture_contract(cases: dict[str, Any]) -> None:
    positives = cases.get("cases", {}).get("positive", [])
    negatives = cases.get("cases", {}).get("negative", [])
    if len(positives) != 3:
        fail("HO-DET-011 validation cases must include exactly 3 positive cases")
    if len(negatives) != 3:
        fail("HO-DET-011 validation cases must include exactly 3 negative cases")

    for item in positives + negatives:
        event = item.get("event", {})
        if not isinstance(event, dict):
            fail(f"case {item.get('id', '<missing>')} must include an event object")
        if event_id(event) == 7045:
            if not channel_is(event, "System"):
                fail(f"case {item.get('id')} treats Event ID 7045 outside Windows System telemetry")
            if not provider_contains(event, "Service Control Manager"):
                fail(f"case {item.get('id')} must identify Service Control Manager for Event ID 7045")

    servicefilename_case = next(
        (item for item in positives if item.get("id") == "pos-002-security-4697-servicefilename"),
        None,
    )
    if servicefilename_case is None:
        fail("missing positive case for Windows Security 4697 ServiceFileName coverage")
    event = servicefilename_case.get("event", {})
    if "ServiceFileName" not in event:
        fail("Windows Security 4697 positive case must use ServiceFileName")
    if not security_4697_matches(event):
        fail("Windows Security 4697 ServiceFileName positive case did not match")


def evaluate_cases(cases: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[str]]:
    validate_fixture_contract(cases)
    positives = cases.get("cases", {}).get("positive", [])
    negatives = cases.get("cases", {}).get("negative", [])

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
        positive_results.append({"id": case_id, "expected": True, "matched": matched, "pass": passed})

    for item in negatives:
        case_id = str(item.get("id", ""))
        matched = event_matches(item.get("event", {}))
        passed = matched is False
        if not passed:
            false_positive_negative_cases.append(case_id)
        negative_results.append({"id": case_id, "expected": False, "matched": matched, "pass": passed})

    return positive_results, negative_results, missed_positive_cases, false_positive_negative_cases


def build_report(cases: dict[str, Any]) -> dict[str, Any]:
    positive_results, negative_results, missed, false_positive = evaluate_cases(cases)
    all_results = positive_results + negative_results
    fail_count = len(missed) + len(false_positive)
    status = "pass" if fail_count == 0 else "fail"
    proof_ceiling = "TEST_VALIDATED_SYNTHETIC_SCOPE" if status == "pass" else "VALIDATION_DRAFT"
    return {
        "status": status,
        "detection_id": "HO-DET-011",
        "validation_cases_file": "hawkinsoperations-validation/validation/successor/ho-det-011/validation-cases.json",
        "source_scope": "Merged source scope from HO-DET-011 source artifacts; validation harness is self-contained synthetic fixture logic.",
        "matched_positive_count": sum(1 for item in positive_results if item["matched"]),
        "missed_positive_cases": missed,
        "false_positive_negative_cases": false_positive,
        "totals": {
            "total_cases": len(all_results),
            "positive_cases": len(positive_results),
            "negative_cases": len(negative_results),
            "pass": sum(1 for item in all_results if item["pass"]),
            "fail": fail_count,
        },
        "positive": positive_results,
        "negative": negative_results,
        "exact_claim_supported": SUPPORTED_CLAIM if status == "pass" else "",
        "proof_ceiling": proof_ceiling,
        "telemetry_boundary": {
            "event_7045": "Windows System / Service Control Manager",
            "event_4697": "Windows Security service installation auditing where available",
            "event_1": "Sysmon process creation context",
        },
        "servicefilename_coverage": "Windows Security 4697 ServiceFileName is evaluated as a service path alias.",
        "runtime_active": False,
        "signal_observed": False,
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "production_ready": False,
        "wazuh_routed": False,
        "live_splunk_fired": False,
        "fleet_wide": False,
        "evidence_linked_public_proof": False,
        "claims_not_supported": BLOCKED_CLAIMS,
        "trust_boundary": "Synthetic Windows event fixture validation only. This is not runtime, signal, public-safe, production, routing, fleet, live Splunk, or evidence-linked public proof.",
        "privacy_status": "Synthetic fixtures only; no credentials, hostnames, addresses, or live telemetry intentionally included.",
    }


def write_reports(report: dict[str, Any]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# HO-DET-011 Synthetic Validation Result",
        "",
        "## Summary",
        f"- Status: {report['status']}",
        f"- Detection ID: {report['detection_id']}",
        f"- Proof ceiling: {report['proof_ceiling']}",
        f"- Total cases: {report['totals']['total_cases']}",
        f"- Matched positive count: {report['matched_positive_count']}",
        f"- Missed positives: {', '.join(report['missed_positive_cases']) if report['missed_positive_cases'] else 'none'}",
        f"- False-positive negatives: {', '.join(report['false_positive_negative_cases']) if report['false_positive_negative_cases'] else 'none'}",
        "",
        "## Telemetry Boundary",
        f"- Event ID 7045: {report['telemetry_boundary']['event_7045']}",
        f"- Event ID 4697: {report['telemetry_boundary']['event_4697']}",
        f"- Event ID 1: {report['telemetry_boundary']['event_1']}",
        f"- ServiceFileName coverage: {report['servicefilename_coverage']}",
        "",
        "## Supported Claim",
        f"- {report['exact_claim_supported']}",
        "",
        "## Blocked Claims",
    ]
    lines.extend(f"- Not supported: {claim}" for claim in report["claims_not_supported"])
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
    parser = argparse.ArgumentParser(description="Validate HO-DET-011 synthetic Windows service creation cases.")
    parser.add_argument("--write", action="store_true", help="Regenerate report artifacts.")
    args = parser.parse_args()

    cases = load_json(CASES_FILE, "HO-DET-011 validation cases")
    if cases.get("detection_id") != "HO-DET-011":
        fail("validation cases detection_id must be HO-DET-011")

    report = build_report(cases)
    if args.write:
        write_reports(report)
        write_skipped = "false"
    else:
        verify_report_matches(report)
        write_skipped = "true"

    print(f"STATUS={report['status']}")
    print("DETECTION_ID=HO-DET-011")
    print(f"TOTAL_CASES={report['totals']['total_cases']}")
    print(f"MATCHED_POSITIVE_COUNT={report['matched_positive_count']}")
    print(f"MISSED_POSITIVE_CASES={','.join(report['missed_positive_cases']) if report['missed_positive_cases'] else 'none'}")
    print(f"FALSE_POSITIVE_NEGATIVE_CASES={','.join(report['false_positive_negative_cases']) if report['false_positive_negative_cases'] else 'none'}")
    print(f"PROOF_CEILING={report['proof_ceiling']}")
    print(f"SERVICEFILENAME_COVERED=true")
    print(f"EVENT_7045_SOURCE=Windows System / Service Control Manager")
    print(f"WRITE_SKIPPED={write_skipped}")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

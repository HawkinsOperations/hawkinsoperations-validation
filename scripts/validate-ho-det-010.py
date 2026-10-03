#!/usr/bin/env python3
"""Controlled-test validation runner for HO-DET-010."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from validation_report_contract import controlled_report_contract

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_ROOT = ROOT.parent / "hawkinsoperations-detections"
SOURCE_DIR = DETECTIONS_ROOT / "detections" / "successor" / "ho-det-010"
CASES_FILE = ROOT / "validation" / "successor" / "ho-det-010" / "validation-cases.json"
REPORT_DIR = ROOT / "reports" / "ho-det-010"
REPORT_JSON = REPORT_DIR / "validation-result.json"
REPORT_MD = REPORT_DIR / "validation-result.md"
SUPPORTED_CLAIM = "HO-DET-010 passed controlled-test validation against controlled Windows local Administrators group membership fixtures."
PROOF_CEILING = "CONTROLLED_TEST_VALIDATED"
EXPECTED_POSITIVE_COUNT = 5
EXPECTED_NEGATIVE_COUNT = 5
BLOCKED_CLAIMS = ["runtime-active", "signal-observed", "public-safe", "evidence-linked public proof", "public-safe runtime proof", "live SIEM ingestion", "live Splunk proof", "live Wazuh proof", "production-ready", "fleet-wide", "privilege-management coverage completeness", "autonomous SOC", "AI-approved disposition", "analyst-approved disposition"]
APPROVED_MARKERS = ("approved", "change-approved", "approved-helpdesk", "approved-endpoint-remediation", "approved-lab-reset")


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing {label}: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {label}: {exc}")
    if not isinstance(data, dict):
        fail(f"{label} must be a JSON object")
    return data


def event_id(event: dict[str, Any]) -> int | None:
    try:
        return int(event.get("EventID", event.get("EventCode")))
    except (TypeError, ValueError):
        return None


def approved_context(event: dict[str, Any]) -> bool:
    text = " ".join(str(event.get(key, "") or "") for key in ("ChangeWindow", "Approval", "Context", "Description")).lower()
    return any(marker in text for marker in APPROVED_MARKERS)


def admin_group(event: dict[str, Any]) -> bool:
    text = " ".join(str(event.get(key, "") or "") for key in ("TargetSid", "TargetUserName", "GroupName")).lower()
    return "s-1-5-32-544" in text or "administrators" in text


def command_text(event: dict[str, Any]) -> str:
    return " ".join(str(event.get(key, "") or "") for key in ("CommandLine", "Image", "ParentImage")).lower()


def process_matches(event: dict[str, Any]) -> bool:
    text = command_text(event)
    if "administrators" not in text:
        return False
    return ("localgroup" in text and ("/add" in text or "/delete" in text)) or "add-localgroupmember" in text or "remove-localgroupmember" in text


def event_matches(event: dict[str, Any]) -> bool:
    if approved_context(event):
        return False
    eid = event_id(event)
    if eid in {4732, 4733}:
        return admin_group(event)
    if eid == 1:
        return process_matches(event)
    return False


def validate_source_contract(mode: str) -> None:
    required = [SOURCE_DIR / name for name in ("README.md", "rule.yml", "event-mapping.yml", "status.yml", "wazuh.xml", "splunk.spl")]
    missing = [path for path in required if not path.exists()]
    if missing:
        if mode == "skip-if-missing" and len(missing) == len(required):
            print("SOURCE_CONTRACT=skipped")
            return
        fail("missing source contract paths: " + ";".join(str(path) for path in missing))
    rule = (SOURCE_DIR / "rule.yml").read_text(encoding="utf-8")
    for fragment in ("detection_id: HO-DET-010", "selection_security_local_group_membership", "selection_group_change_command", "T1098"):
        if fragment not in rule:
            fail(f"source rule missing tuned fragment: {fragment}")
    wazuh = (SOURCE_DIR / "wazuh.xml").read_text(encoding="utf-8")
    for fragment in ("910101", "910102", "910103"):
        if fragment not in wazuh:
            fail(f"Wazuh source missing expected rule id: {fragment}")


def validate_fixture_contract(cases: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if cases.get("detection_id") != "HO-DET-010":
        fail("validation cases detection_id must be HO-DET-010")
    groups = cases.get("cases")
    if not isinstance(groups, dict):
        fail("validation cases must include cases object")
    positives = groups.get("positive")
    negatives = groups.get("negative")
    if not isinstance(positives, list) or not isinstance(negatives, list):
        fail("positive and negative cases must be arrays")
    if len(positives) != EXPECTED_POSITIVE_COUNT or len(negatives) != EXPECTED_NEGATIVE_COUNT:
        fail("unexpected HO-DET-010 fixture counts")
    return positives, negatives


def result_row(item: dict[str, Any], expected: bool) -> dict[str, Any]:
    matched = event_matches(item["event"])
    return {"id": item["id"], "expected": expected, "matched": matched, "pass": matched is expected, "behavior": item["behavior"], "telemetry_source": item["telemetry_source"]}


def build_report(cases: dict[str, Any], source_contract: str = "required") -> dict[str, Any]:
    validate_source_contract(source_contract)
    positives, negatives = validate_fixture_contract(cases)
    pos_results = [result_row(item, True) for item in positives]
    neg_results = [result_row(item, False) for item in negatives]
    missed = [item["id"] for item in pos_results if not item["pass"]]
    false_positive = [item["id"] for item in neg_results if not item["pass"]]
    status = "pass" if not missed and not false_positive else "fail"
    return {**controlled_report_contract("HO-DET-010", PROOF_CEILING if status == "pass" else "VALIDATION_DRAFT", passed=status == "pass"), "status": status, "detection_id": "HO-DET-010", "validation_scope": "controlled-test fixtures only", "proof_ceiling": PROOF_CEILING if status == "pass" else "VALIDATION_DRAFT", "source_reference": "hawkinsoperations-detections/detections/successor/ho-det-010", "validation_cases_file": "hawkinsoperations-validation/validation/successor/ho-det-010/validation-cases.json", "total_cases": len(pos_results) + len(neg_results), "positive_cases": len(pos_results), "negative_cases": len(neg_results), "matched_positive_count": sum(1 for item in pos_results if item["matched"]), "missed_positive_cases": missed, "false_positive_negative_cases": false_positive, "positive": pos_results, "negative": neg_results, "exact_claim_supported": SUPPORTED_CLAIM if status == "pass" else "", "blocked_claims": BLOCKED_CLAIMS, "runtime_active": False, "signal_observed": False, "public_safe_status": "NOT_PUBLIC_SAFE", "splunk_fired": False, "wazuh_routed": False, "production_ready": False, "fleet_wide": False, "autonomous_soc": False, "ai_approved_disposition": False, "analyst_approved_disposition": False, "trust_boundary": "Controlled-test Windows local Administrators group membership fixture validation only. This does not prove runtime, signal, public-safe proof, live SIEM ingestion, production readiness, fleet-wide deployment, autonomous SOC behavior, AI-approved disposition, or analyst-approved disposition.", "privacy_status": "Controlled-test fixtures only; no sensitive operational material or live telemetry intentionally included."}


def write_reports(report: dict[str, Any]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = ["# HO-DET-010 Controlled-test Validation Result", "", f"- Status: {report['status']}", f"- Detection ID: {report['detection_id']}", f"- Proof ceiling: {report['proof_ceiling']}", f"- Total cases: {report['total_cases']}", f"- Positive cases: {report['positive_cases']}", f"- Negative cases: {report['negative_cases']}", f"- Missed positives: {', '.join(report['missed_positive_cases']) if report['missed_positive_cases'] else 'none'}", f"- False-positive negatives: {', '.join(report['false_positive_negative_cases']) if report['false_positive_negative_cases'] else 'none'}", "", "## Supported Claim", f"- {report['exact_claim_supported']}", "", "## Blocked Claims"]
    lines.extend(f"- Not supported: {claim}" for claim in report["blocked_claims"])
    lines.extend(["", "## Boundary", report["trust_boundary"]])
    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate HO-DET-010 controlled local-admin fixtures.")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--source-contract", choices=("required", "skip-if-missing"), default="required")
    args = parser.parse_args()
    cases = load_json(CASES_FILE, "HO-DET-010 validation cases")
    report = build_report(cases, source_contract=args.source_contract)
    if args.write:
        write_reports(report)
    elif not REPORT_JSON.exists() or load_json(REPORT_JSON, "HO-DET-010 validation result") != report:
        fail("reports/ho-det-010/validation-result.json is out of date; run with --write")
    print(f"STATUS={report['status']}")
    print("DETECTION_ID=HO-DET-010")
    print(f"TOTAL_CASES={report['total_cases']}")
    print(f"POSITIVE_CASES={report['positive_cases']}")
    print(f"NEGATIVE_CASES={report['negative_cases']}")
    print(f"PROOF_CEILING={report['proof_ceiling']}")
    print("RUNTIME_ACTIVE=false")
    print("SIGNAL_OBSERVED=false")
    print("PUBLIC_SAFE_STATUS=NOT_PUBLIC_SAFE")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

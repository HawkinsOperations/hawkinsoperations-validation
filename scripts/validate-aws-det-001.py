#!/usr/bin/env python3
"""Fixture-only validation runner for AWS-DET-001.

This script validates repository-contained CloudTrail-style JSON fixtures only.
It does not use AWS credentials, call AWS APIs, or inspect live CloudTrail data.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_ROOT = ROOT.parent / "hawkinsoperations-detections"
SOURCE_FILE = DETECTIONS_ROOT / "detections" / "cloud" / "aws" / "aws-det-001" / "rule.yml"
JSONPATH_FILE = DETECTIONS_ROOT / "detections" / "cloud" / "aws" / "aws-det-001" / "cloudtrail.jsonpath"
CASES_FILE = ROOT / "validation" / "cloud" / "aws" / "aws-det-001" / "validation-cases.json"
REPORT_DIR = ROOT / "reports" / "aws-det-001"
REPORT_JSON = REPORT_DIR / "validation-result.json"
REPORT_MD = REPORT_DIR / "validation-result.md"

SUPPORTED_CLAIM = "AWS-DET-001 passed fixture-only validation against controlled CloudTrail-style IAM denial fixtures."
BLOCKED_CLAIMS = [
    "AWS-live proof",
    "AWS CloudTrail live proof",
    "cloud runtime-active proof",
    "production proof",
    "public-safe runtime proof",
    "signal-observed public proof",
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


def validate_source_contract(text: str, jsonpath_text: str) -> None:
    required_fragments = [
        "detection_id: AWS-DET-001",
        "eventSource:",
        "iam.amazonaws.com",
        "errorCode|contains:",
        "errorMessage|contains:",
        "condition: selection_source and selection_error",
        "AWS-live proof",
        "cloud runtime-active proof",
    ]
    for fragment in required_fragments:
        if fragment not in text:
            fail(f"source contract missing fragment: {fragment}")
    for fragment in ["iam.amazonaws.com", "AccessDenied", "UnauthorizedOperation"]:
        if fragment not in jsonpath_text:
            fail(f"CloudTrail JSONPath missing fragment: {fragment}")


def event_matches(event: dict[str, Any]) -> bool:
    source = str(event.get("eventSource", "") or "").lower()
    error_code = str(event.get("errorCode", "") or "").lower()
    error_message = str(event.get("errorMessage", "") or "").lower()
    source_matches = source == "iam.amazonaws.com"
    error_matches = (
        "accessdenied" in error_code
        or "unauthorizedoperation" in error_code
        or "not authorized" in error_message
        or "denied" in error_message
    )
    return source_matches and error_matches


def evaluate_cases(cases: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[str]]:
    positives = cases.get("cases", {}).get("positive", [])
    negatives = cases.get("cases", {}).get("negative", [])
    if len(positives) < 2:
        fail("validation cases must include at least 2 positive cases")
    if len(negatives) < 2:
        fail("validation cases must include at least 2 negative cases")

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
    proof_ceiling = "CONTROLLED_TEST_VALIDATED" if status == "pass" else "TEST_DEFINED"
    return {
        "status": status,
        "detection_id": "AWS-DET-001",
        "source_file": "hawkinsoperations-detections/detections/cloud/aws/aws-det-001/rule.yml",
        "jsonpath_file": "hawkinsoperations-detections/detections/cloud/aws/aws-det-001/cloudtrail.jsonpath",
        "validation_cases_file": "hawkinsoperations-validation/validation/cloud/aws/aws-det-001/validation-cases.json",
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
        "aws_live_status": "BLOCKED",
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "claims_not_supported": BLOCKED_CLAIMS,
        "trust_boundary": "Fixture-only CloudTrail-style validation. This is not AWS-live, CloudTrail live, cloud runtime-active, production, signal-observed, or public-safe proof.",
        "privacy_status": "Controlled-test fixtures only; no AWS credentials, account identifiers, live CloudTrail records, secrets, private hostnames, or private addresses are included.",
    }


def write_reports(report: dict[str, Any]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# AWS-DET-001 Fixture Validation Result",
        "",
        "## Summary",
        f"- Status: {report['status']}",
        f"- Detection ID: {report['detection_id']}",
        f"- Proof ceiling: {report['proof_ceiling']}",
        f"- AWS live status: {report['aws_live_status']}",
        f"- Public-safe status: {report['public_safe_status']}",
        f"- Total cases: {report['totals']['total_cases']}",
        f"- Matched positive count: {report['matched_positive_count']}",
        f"- Missed positives: {', '.join(report['missed_positive_cases']) if report['missed_positive_cases'] else 'none'}",
        f"- False-positive negatives: {', '.join(report['false_positive_negative_cases']) if report['false_positive_negative_cases'] else 'none'}",
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
            "- From the validation repository root, run: `python scripts/validate-aws-det-001.py`",
        ]
    )
    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_report_matches(report: dict[str, Any]) -> None:
    if not REPORT_JSON.exists() or not REPORT_MD.exists():
        fail("report artifacts are missing; run with --write to generate them")
    existing = load_json(REPORT_JSON, "AWS-DET-001 validation result")
    if existing != report:
        fail("reports/aws-det-001/validation-result.json is out of date; run with --write")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate AWS-DET-001 fixture-only CloudTrail-style cases.")
    parser.add_argument("--write", action="store_true", help="Regenerate report artifacts.")
    args = parser.parse_args()

    source_text = read_text(SOURCE_FILE, "AWS-DET-001 source rule")
    jsonpath_text = read_text(JSONPATH_FILE, "AWS-DET-001 CloudTrail JSONPath")
    validate_source_contract(source_text, jsonpath_text)
    cases = load_json(CASES_FILE, "AWS-DET-001 validation cases")
    if cases.get("detection_id") != "AWS-DET-001":
        fail("validation cases detection_id must be AWS-DET-001")

    report = build_report(cases)
    if args.write:
        write_reports(report)
        write_skipped = "false"
    else:
        verify_report_matches(report)
        write_skipped = "true"

    print(f"STATUS={report['status']}")
    print("DETECTION_ID=AWS-DET-001")
    print(f"TOTAL_CASES={report['totals']['total_cases']}")
    print(f"MATCHED_POSITIVE_COUNT={report['matched_positive_count']}")
    print(f"MISSED_POSITIVE_CASES={','.join(report['missed_positive_cases']) if report['missed_positive_cases'] else 'none'}")
    print(f"FALSE_POSITIVE_NEGATIVE_CASES={','.join(report['false_positive_negative_cases']) if report['false_positive_negative_cases'] else 'none'}")
    print(f"PROOF_CEILING={report['proof_ceiling']}")
    print(f"AWS_LIVE_STATUS={report['aws_live_status']}")
    print(f"PUBLIC_SAFE_STATUS={report['public_safe_status']}")
    print(f"WRITE_SKIPPED={write_skipped}")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

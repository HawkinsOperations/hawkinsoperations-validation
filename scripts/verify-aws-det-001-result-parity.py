#!/usr/bin/env python3
"""Verify stable AWS-DET-001 validation-result parity."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from validation_report_contract import controlled_report_contract


ROOT = Path(__file__).resolve().parents[1]
VALIDATION_CASES = ROOT / "validation" / "cloud" / "aws" / "aws-det-001" / "validation-cases.json"
VALIDATION_RESULT = ROOT / "reports" / "aws-det-001" / "validation-result.json"

SUPPORTED_CLAIM = "AWS-DET-001 passed fixture-only validation against controlled CloudTrail-style IAM denial fixtures."


def not_ready(missing: list[Path]) -> None:
    print("STATUS=NOT_READY")
    print("MISSING_PATHS=" + ";".join(str(path) for path in missing))
    raise SystemExit(2)


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def event_matches(event: dict[str, Any]) -> bool:
    source = str(event.get("eventSource", "") or "").lower()
    error_code = str(event.get("errorCode", "") or "").lower()
    error_message = str(event.get("errorMessage", "") or "").lower()
    return source == "iam.amazonaws.com" and (
        "accessdenied" in error_code
        or "unauthorizedoperation" in error_code
        or "not authorized" in error_message
        or "denied" in error_message
    )


def evaluate(cases: dict[str, Any]) -> dict[str, Any]:
    if cases.get("detection_id") != "AWS-DET-001":
        fail("validation-cases.json detection_id must be AWS-DET-001")
    groups = cases.get("cases")
    if not isinstance(groups, dict):
        fail("validation-cases.json cases must be an object")
    positives = groups.get("positive")
    negatives = groups.get("negative")
    if not isinstance(positives, list) or not isinstance(negatives, list):
        fail("validation-cases.json positive/negative cases must be arrays")

    positive_results = []
    negative_results = []
    missed = []
    false_positive = []
    for item in positives:
        case_id = str(item.get("id", ""))
        matched = event_matches(item.get("event", {}))
        passed = matched is True
        if not passed:
            missed.append(case_id)
        positive_results.append({"id": case_id, "expected": True, "matched": matched, "pass": passed})
    for item in negatives:
        case_id = str(item.get("id", ""))
        matched = event_matches(item.get("event", {}))
        passed = matched is False
        if not passed:
            false_positive.append(case_id)
        negative_results.append({"id": case_id, "expected": False, "matched": matched, "pass": passed})

    all_results = positive_results + negative_results
    failures = len(missed) + len(false_positive)
    status = "pass" if failures == 0 else "fail"
    proof_ceiling = "CONTROLLED_TEST_VALIDATED" if status == "pass" else "TEST_DEFINED"
    return {
        **controlled_report_contract(
            "AWS-DET-001", proof_ceiling, passed=status == "pass"
        ),
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
            "fail": failures,
        },
        "positive": positive_results,
        "negative": negative_results,
        "exact_claim_supported": SUPPORTED_CLAIM if status == "pass" else "",
        "proof_ceiling": proof_ceiling,
        "aws_live_status": "BLOCKED",
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "claims_not_supported": [
            "AWS-live proof",
            "AWS CloudTrail live proof",
            "cloud runtime-active proof",
            "production proof",
            "public-safe runtime proof",
            "signal-observed public proof",
        ],
        "trust_boundary": "Fixture-only CloudTrail-style validation. This is not AWS-live, CloudTrail live, cloud runtime-active, production, signal-observed, or public-safe proof.",
        "privacy_status": "Controlled-test fixtures only; no AWS credentials, account identifiers, live CloudTrail records, secrets, private hostnames, or private addresses are included.",
    }


def main() -> int:
    missing = [path for path in [VALIDATION_CASES, VALIDATION_RESULT] if not path.exists()]
    if missing:
        not_ready(missing)
    expected = evaluate(load_json(VALIDATION_CASES, "validation-cases.json"))
    actual = load_json(VALIDATION_RESULT, "validation-result.json")
    if actual != expected:
        print("STATUS=fail")
        print("AWS_DET_001_RESULT_PARITY=fail")
        print("MISSING_KEYS=" + ",".join(sorted(set(expected) - set(actual))))
        print("EXTRA_KEYS=" + ",".join(sorted(set(actual) - set(expected))))
        raise SystemExit(1)
    print("STATUS=pass")
    print("AWS_DET_001_RESULT_PARITY=pass")
    print(f"VALIDATION_RESULT={VALIDATION_RESULT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


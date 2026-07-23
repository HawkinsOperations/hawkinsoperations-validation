#!/usr/bin/env python3
"""Verify stable HO-DET-001 validation-result parity."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from validation_report_contract import controlled_report_contract


ROOT = Path(__file__).resolve().parents[1]
VALIDATION_CASES = ROOT / "validation" / "successor" / "ho-det-001" / "validation-cases.json"
VALIDATION_RESULT = ROOT / "reports" / "ho-det-001" / "validation-result.json"

PROOF_CEILING = "CONTROLLED_TEST_VALIDATED"
SUPPORTED_CLAIM = (
    "HO-DET-001 passed controlled-test validation against controlled positive and "
    "negative process-creation fixtures."
)
REQUIRED_PATHS = [VALIDATION_CASES, VALIDATION_RESULT]
VOLATILE_FIELDS = {"executed_at"}


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


def process_identity_matches(event: dict[str, Any]) -> bool:
    image = str(event.get("Image", "") or "").lower()
    original = str(event.get("OriginalFileName", "") or "").lower()
    return (
        image.endswith("\\powershell.exe")
        or image.endswith("\\pwsh.exe")
        or "powershell" in original
        or "pwsh" in original
    )


def cli_matches(event: dict[str, Any]) -> bool:
    command_line = str(event.get("CommandLine", "") or "").lower()
    encoded_flag = re.search(r"(?:^|\s)(?:-|/)(?:enc|encodedcommand)(?::|\s|$)", command_line)
    return bool(encoded_flag) or "frombase64string(" in command_line


def event_matches(event: dict[str, Any]) -> bool:
    return process_identity_matches(event) and cli_matches(event)


def evaluate(cases: dict[str, Any]) -> dict[str, Any]:
    if cases.get("detection_id") != "HO-DET-001":
        fail("validation-cases.json detection_id must be HO-DET-001")
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
    return {
        **controlled_report_contract(
            "HO-DET-001",
            PROOF_CEILING,
            passed=status == "pass",
        ),
        "status": status,
        "detection_id": "HO-DET-001",
        "source_file": "hawkinsoperations-detections/detections/successor/ho-det-001/rule.yml",
        "splunk_source_file": "hawkinsoperations-detections/detections/successor/ho-det-001/splunk.spl",
        "validation_cases_file": "hawkinsoperations-validation/validation/successor/ho-det-001/validation-cases.json",
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
        "claims_not_supported": [
            "runtime-active",
            "signal-observed",
            "evidence-linked",
            "public-safe",
            "production-ready",
            "live Splunk firing",
            "Cribl-routed telemetry",
            "Wazuh live collection",
            "production triage",
            "analyst-approved disposition",
        ],
        "proof_level_before": "SOURCE_EXISTS",
        "proof_level_after": PROOF_CEILING if status == "pass" else "SOURCE_EXISTS",
        "trust_boundary": "Controlled-test process-creation fixture validation only. This is not runtime, signal, evidence-linked, public-safe, production, or live SOC proof.",
        "privacy_status": "Controlled-test fixtures only; no secrets, private hostnames, private addresses, or live telemetry intentionally included.",
    }


def main() -> int:
    missing = [path for path in REQUIRED_PATHS if not path.exists()]
    if missing:
        not_ready(missing)
    cases = load_json(VALIDATION_CASES, "validation-cases.json")
    actual = load_json(VALIDATION_RESULT, "validation-result.json")
    expected = evaluate(cases)
    stable_actual = {key: value for key, value in actual.items() if key not in VOLATILE_FIELDS}
    if stable_actual != expected:
        print("STATUS=fail")
        print("VALIDATION_RESULT_PARITY=fail")
        actual_keys = set(stable_actual)
        expected_keys = set(expected)
        print("MISSING_KEYS=" + ",".join(sorted(expected_keys - actual_keys)))
        print("EXTRA_KEYS=" + ",".join(sorted(actual_keys - expected_keys)))
        raise SystemExit(1)
    print("STATUS=pass")
    print("VALIDATION_RESULT_PARITY=pass")
    print(f"VALIDATION_RESULT={VALIDATION_RESULT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

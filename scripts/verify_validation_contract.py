#!/usr/bin/env python3
"""Baseline validation contract check."""

from __future__ import annotations

import sys
from argparse import ArgumentParser
from copy import deepcopy
from pathlib import Path

from validation_lib import (
    ContractFailure,
    ensure_check_mode,
    load_json,
    validate_report_case_parity,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / ".github" / "contracts" / "validation-report.schema.json"
REPORT_JSON = ROOT / "reports" / "hero001-validation-report.json"
VALIDATION_CASES_JSON = ROOT / "validation" / "hero" / "001-powershell-encoded-command" / "validation-cases.json"
BASELINE_REQUIRED = [
    VALIDATION_CASES_JSON,
    ROOT / "reports" / "hero001-validation-report.json",
    ROOT / "reports" / "hero001-validation-report.md",
    ROOT / "scripts" / "validate-hero001.ps1",
]


def fail(msg: str) -> None:
    raise ContractFailure(msg)


def validate_schema_shape(report: dict, schema: dict) -> None:
    for key in schema.get("required", []):
        if key not in report:
            fail(f"report missing required key: {key}")

    if not isinstance(report.get("rule_id"), str):
        fail("rule_id must be a string")
    if not isinstance(report.get("executed_at"), str):
        fail("executed_at must be a string")

    totals = report.get("totals")
    if not isinstance(totals, dict):
        fail("totals must be an object")
    for key in ["total_cases", "pass", "fail"]:
        if key not in totals:
            fail(f"totals missing required key: {key}")
        if not isinstance(totals[key], int) or totals[key] < 0:
            fail(f"totals.{key} must be a non-negative integer")

    if report.get("status") not in {"pass", "fail"}:
        fail("status must be pass or fail")


def validate_live_artifacts() -> None:
    for path in BASELINE_REQUIRED:
        if not path.exists():
            fail(f"required baseline artifact is missing: {path.relative_to(ROOT).as_posix()}")


def require_case_list(cases: dict, key: str) -> list:
    values = cases.get(key)
    if not isinstance(values, list) or not values:
        fail(f"validation-cases.{key} must be a non-empty array")

    seen = set()
    for idx, case in enumerate(values, start=1):
        if not isinstance(case, dict):
            fail(f"validation-cases.{key}[{idx}] must be an object")

        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id:
            fail(f"validation-cases.{key}[{idx}].id must be a non-empty string")
        if case_id in seen:
            fail(f"duplicate validation case id in {key}: {case_id}")
        seen.add(case_id)

        for field in ["Image", "CommandLine"]:
            if not isinstance(case.get(field), str) or not case[field]:
                fail(f"validation-cases.{key}[{case_id}].{field} must be a non-empty string")

    return values


def require_report_results(report: dict, key: str, expected: bool) -> list:
    values = report.get(key)
    if not isinstance(values, list) or not values:
        fail(f"report.{key} must be a non-empty array")

    seen = set()
    for idx, result in enumerate(values, start=1):
        if not isinstance(result, dict):
            fail(f"report.{key}[{idx}] must be an object")

        result_id = result.get("id")
        if not isinstance(result_id, str) or not result_id:
            fail(f"report.{key}[{idx}].id must be a non-empty string")
        if result_id in seen:
            fail(f"duplicate report result id in {key}: {result_id}")
        seen.add(result_id)

        if result.get("expected") is not expected:
            fail(f"report.{key}[{result_id}].expected must be {expected}")
        if not isinstance(result.get("matched"), bool):
            fail(f"report.{key}[{result_id}].matched must be boolean")
        if result.get("pass") != (result.get("matched") is expected):
            fail(f"report.{key}[{result_id}].pass is inconsistent with expected/matched")

    return values


def validate_case_report_consistency(cases: dict, report: dict) -> None:
    positive_cases = require_case_list(cases, "positives")
    negative_cases = require_case_list(cases, "negatives")
    positive_results = require_report_results(report, "positive", True)
    negative_results = require_report_results(report, "negative", False)

    expected_positive_ids = {case["id"] for case in positive_cases}
    expected_negative_ids = {case["id"] for case in negative_cases}
    actual_positive_ids = {result["id"] for result in positive_results}
    actual_negative_ids = {result["id"] for result in negative_results}

    validate_report_case_parity(expected_positive_ids, actual_positive_ids, side="positive")
    validate_report_case_parity(expected_negative_ids, actual_negative_ids, side="negative")

    total_results = len(positive_results) + len(negative_results)
    pass_count = sum(1 for result in positive_results + negative_results if result["pass"])
    fail_count = total_results - pass_count
    totals = report["totals"]

    if totals["total_cases"] != total_results:
        fail(f"totals.total_cases expected {total_results}, got {totals['total_cases']}")
    if totals["pass"] != pass_count:
        fail(f"totals.pass expected {pass_count}, got {totals['pass']}")
    if totals["fail"] != fail_count:
        fail(f"totals.fail expected {fail_count}, got {totals['fail']}")
    if report["status"] != ("pass" if fail_count == 0 else "fail"):
        fail("report.status is inconsistent with totals.fail")


def run_live_contract() -> None:
    ensure_check_mode(write=False)
    print("Scope: baseline hero validation artifacts for HOD-001 only.")
    schema = load_json(SCHEMA_PATH, "validation contract schema", root=ROOT)
    report = load_json(REPORT_JSON, "baseline validation report", root=ROOT)
    cases = load_json(VALIDATION_CASES_JSON, "baseline validation cases", root=ROOT)
    validate_schema_shape(report, schema)
    validate_live_artifacts()
    validate_case_report_consistency(cases, report)
    print("Baseline validation contract check passed.")


def self_test_schema() -> dict:
    return {
        "required": ["rule_id", "executed_at", "totals", "status"],
    }


def self_test_cases() -> dict:
    return {
        "positives": [
            {
                "id": "pos-001",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
            }
        ],
        "negatives": [
            {
                "id": "neg-001",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -File C:\\Scripts\\daily-maintenance.ps1",
            }
        ],
    }


def self_test_report() -> dict:
    return {
        "rule_id": "HOD-001",
        "executed_at": "2026-04-21T10:54:31-05:00",
        "totals": {"total_cases": 2, "pass": 2, "fail": 0},
        "positive": [{"id": "pos-001", "expected": True, "matched": True, "pass": True}],
        "negative": [{"id": "neg-001", "expected": False, "matched": False, "pass": True}],
        "status": "pass",
    }


def run_self_test_case(name: str, callback, *, should_fail: bool = False) -> None:
    try:
        callback()
    except ContractFailure as exc:
        if should_fail:
            print(f"self-test expected failure passed: {name} ({exc})")
            return
        raise ContractFailure(f"self-test unexpected failure in {name}: {exc}") from exc

    if should_fail:
        raise ContractFailure(f"self-test expected failure did not fail: {name}")
    print(f"self-test passed: {name}")


def run_self_tests() -> None:
    def valid_contract() -> None:
        validate_schema_shape(self_test_report(), self_test_schema())
        validate_case_report_consistency(self_test_cases(), self_test_report())

    def missing_required_report_key() -> None:
        report = self_test_report()
        report.pop("status")
        validate_schema_shape(report, self_test_schema())

    def duplicate_case_id() -> None:
        cases = self_test_cases()
        cases["positives"].append(deepcopy(cases["positives"][0]))
        validate_case_report_consistency(cases, self_test_report())

    def report_case_id_mismatch() -> None:
        report = self_test_report()
        report["positive"][0]["id"] = "pos-999"
        validate_case_report_consistency(self_test_cases(), report)

    def totals_mismatch() -> None:
        report = self_test_report()
        report["totals"]["total_cases"] = 99
        validate_case_report_consistency(self_test_cases(), report)

    def inconsistent_result_status() -> None:
        report = self_test_report()
        report["negative"][0]["matched"] = True
        validate_case_report_consistency(self_test_cases(), report)

    print("Running baseline validation contract self-tests.")
    run_self_test_case("valid contract", valid_contract)
    run_self_test_case("missing required report key", missing_required_report_key, should_fail=True)
    run_self_test_case("duplicate case id", duplicate_case_id, should_fail=True)
    run_self_test_case("report/case ID mismatch", report_case_id_mismatch, should_fail=True)
    run_self_test_case("totals mismatch", totals_mismatch, should_fail=True)
    run_self_test_case("inconsistent result status", inconsistent_result_status, should_fail=True)
    print("Baseline validation contract self-tests passed.")


def parse_args(argv: list[str]) -> object:
    parser = ArgumentParser(description="Verify the HOD-001 baseline validation contract.")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run in-memory negative/positive tests for the contract checker itself.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.self_test:
            run_self_tests()
        else:
            run_live_contract()
    except ContractFailure as exc:
        print(f"Baseline validation contract check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

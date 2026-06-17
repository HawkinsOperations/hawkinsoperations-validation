#!/usr/bin/env python3
"""Fail-closed validation registry contract verifier."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "validation" / "VALIDATION_REGISTRY.yml"

ALLOWED_PROOF_CEILINGS = {
    "CONTROLLED_TEST_VALIDATED",
    "VALIDATION_CONTRACT_ENFORCED",
}
ALLOWED_KINDS = {
    "baseline_contract",
    "controlled_validation",
    "visibility_contract",
}
FALSEY_STATUSES = {
    False,
    None,
    "",
    "false",
    "blocked",
    "none",
    "not_proven",
    "not_claimed",
    "not_runtime_active",
    "not_signal_observed",
}
REQUIRED_FIELDS = {
    "detection_id",
    "validation_kind",
    "validation_package_path",
    "fixture_file",
    "report_json",
    "report_markdown",
    "validator_script",
    "parity_script",
    "claim_boundary_script",
    "expected_fixture_count",
    "expected_positive_count",
    "expected_negative_count",
    "proof_ceiling",
    "public_safe_status",
    "runtime_status",
    "signal_status",
    "source_dependency_required",
    "ci_source_dependency_mode",
    "notes",
}
BRIDGE_REQUIRED_FIELDS = {
    "artifact_id",
    "bridge_record_id",
    "detection_id",
    "bridge_kind",
    "bridge_record_path",
    "bridge_markdown_path",
    "validator_script",
    "proof_ceiling",
    "public_safe_status",
    "human_review_required",
    "notes",
}
CONTROLLED_REQUIRED_PATHS = {
    "validation_package_path",
    "fixture_file",
    "report_json",
    "report_markdown",
    "validator_script",
    "parity_script",
    "claim_boundary_script",
}
BASELINE_REQUIRED_PATHS = {
    "validation_package_path",
    "fixture_file",
    "report_json",
    "report_markdown",
    "validator_script",
}
VISIBILITY_REQUIRED_PATHS = {
    "validation_package_path",
    "fixture_file",
    "validator_script",
    "parity_script",
}


class RegistryFailure(Exception):
    """Registry contract violation."""


def fail(message: str) -> None:
    raise RegistryFailure(message)


def load_registry(path: Path = REGISTRY_PATH) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"registry file is missing: {path}")
    except json.JSONDecodeError as exc:
        fail(f"registry is malformed YAML/JSON: {exc}")
    if not isinstance(data, dict):
        fail("registry root must be an object")
    return data


def _rel_path(root: Path, value: str, field: str, detection_id: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        fail(f"{detection_id} {field} must be a repo-relative path")
    return root / path


def _require_existing_path(root: Path, package: dict[str, Any], field: str) -> None:
    value = package.get(field)
    detection_id = str(package.get("detection_id", "<unknown>"))
    if not isinstance(value, str) or not value:
        fail(f"{detection_id} missing required path field: {field}")
    if not _rel_path(root, value, field, detection_id).exists():
        fail(f"{detection_id} listed file or directory is missing: {field}={value}")


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in FALSEY_STATUSES
    return value not in FALSEY_STATUSES


def _first_int(*values: Any) -> int | None:
    for value in values:
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
    return None


def _count_case_groups(case_data: dict[str, Any]) -> tuple[int | None, int | None, int | None]:
    if isinstance(case_data.get("positives"), list) or isinstance(case_data.get("negatives"), list):
        positive = len(case_data.get("positives") or [])
        negative = len(case_data.get("negatives") or [])
        return positive + negative, positive, negative

    cases = case_data.get("cases")
    if isinstance(cases, dict):
        positive_cases = cases.get("positive")
        negative_cases = cases.get("negative")
        if isinstance(positive_cases, list) and isinstance(negative_cases, list):
            return len(positive_cases) + len(negative_cases), len(positive_cases), len(negative_cases)
    if isinstance(cases, list):
        positive = 0
        negative = 0
        unknown = 0
        for case in cases:
            expected = str(case.get("expected_result", case.get("expected_match", ""))).lower()
            if expected in {"match", "true", "1"}:
                positive += 1
            elif expected in {"no_match", "false", "0"}:
                negative += 1
            else:
                unknown += 1
        total = len(cases)
        if unknown:
            return total, None, None
        return total, positive, negative
    return None, None, None


def _report_counts(report: dict[str, Any]) -> tuple[int | None, int | None, int | None]:
    totals = report.get("totals")
    if not isinstance(totals, dict):
        totals = {}
    return (
        _first_int(report.get("total_cases"), report.get("fixture_count"), totals.get("total_cases")),
        _first_int(report.get("positive_cases"), report.get("positive_count"), totals.get("positive_cases")),
        _first_int(report.get("negative_cases"), report.get("negative_count"), totals.get("negative_cases")),
    )


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"{label} is malformed JSON: {exc}")
    if not isinstance(data, dict):
        fail(f"{label} must be a JSON object")
    return data


def _verify_counts(root: Path, package: dict[str, Any]) -> None:
    detection_id = str(package["detection_id"])
    expected = (
        package.get("expected_fixture_count"),
        package.get("expected_positive_count"),
        package.get("expected_negative_count"),
    )
    if any(value is not None and not isinstance(value, int) for value in expected):
        fail(f"{detection_id} expected fixture counts must be integers or null")
    if all(value is None for value in expected):
        return

    fixture_data = _load_json(_rel_path(root, package["fixture_file"], "fixture_file", detection_id), f"{detection_id} fixture file")
    fixture_counts = _count_case_groups(fixture_data)
    for label, actual, expected_value in zip(("fixture", "positive", "negative"), fixture_counts, expected, strict=True):
        if expected_value is not None and actual is not None and actual != expected_value:
            fail(f"{detection_id} {label} fixture count mismatch: expected {expected_value}, found {actual}")

    report_path = package.get("report_json")
    if report_path is None:
        return
    report = _load_json(_rel_path(root, report_path, "report_json", detection_id), f"{detection_id} report JSON")
    report_detection_id = report.get("detection_id", report.get("rule_id"))
    if report_detection_id and report_detection_id != detection_id:
        fail(f"{detection_id} report JSON id mismatch: {report_detection_id}")
    if report.get("status") not in {None, "pass", "ready_for_public_pipeline_route"}:
        fail(f"{detection_id} report status is not pass")
    if report.get("public_safe_status") not in {None, "NOT_PUBLIC_SAFE"}:
        fail(f"{detection_id} report public_safe_status is not NOT_PUBLIC_SAFE")
    if _truthy(report.get("runtime_active", report.get("runtime_status", False))):
        fail(f"{detection_id} report promotes runtime status")
    if _truthy(report.get("signal_observed", report.get("signal_status", False))):
        fail(f"{detection_id} report promotes signal status")

    for label, actual, expected_value in zip(("fixture", "positive", "negative"), _report_counts(report), expected, strict=True):
        if expected_value is not None and actual is not None and actual != expected_value:
            fail(f"{detection_id} {label} report count mismatch: expected {expected_value}, found {actual}")


def _validate_bridge_records(data: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    bridges = data.get("bridge_records", [])
    if bridges is None:
        return []
    if not isinstance(bridges, list):
        fail("bridge_records must be a list when present")
    seen_artifacts: set[str] = set()
    for bridge in bridges:
        if not isinstance(bridge, dict):
            fail("each bridge_records entry must be an object")
        missing = sorted(BRIDGE_REQUIRED_FIELDS - bridge.keys())
        artifact_id = str(bridge.get("bridge_record_id", bridge.get("artifact_id", "<unknown>")))
        if missing:
            fail(f"{artifact_id} bridge record missing required fields: {', '.join(missing)}")
        if artifact_id in seen_artifacts:
            fail(f"duplicate bridge artifact_id exists: {artifact_id}")
        seen_artifacts.add(artifact_id)
        if bridge["artifact_id"] != bridge["detection_id"]:
            fail(f"{artifact_id} bridge artifact_id must match detection_id")
        if bridge["detection_id"] != "HO-DET-001":
            fail(f"{artifact_id} bridge detection_id must be HO-DET-001")
        if bridge["bridge_kind"] != "hoxline_gauntlet_validation_bridge":
            fail(f"{artifact_id} bridge_kind is invalid")
        if bridge["proof_ceiling"] != "CONTROLLED_TEST_VALIDATED":
            fail(f"{artifact_id} bridge proof_ceiling must be CONTROLLED_TEST_VALIDATED")
        if bridge["public_safe_status"] not in {"BLOCKED", "NOT_PUBLIC_SAFE"}:
            fail(f"{artifact_id} bridge public_safe_status must remain blocked")
        if bridge["human_review_required"] is not True:
            fail(f"{artifact_id} bridge human_review_required must be true")
        for field in ("bridge_record_path", "bridge_markdown_path", "validator_script"):
            _require_existing_path(root, bridge, field)
        notes = str(bridge.get("notes", "")).lower()
        for term in ("runtime", "signal", "production", "customer", "socaas", "public-safe"):
            if term in notes and not any(marker in notes for marker in ("does not prove", "blocked", "not ")):
                fail(f"{artifact_id} bridge notes mention {term} without blocked context")
    return bridges


def validate_registry(data: dict[str, Any], root: Path = ROOT) -> list[dict[str, Any]]:
    if data.get("schema_version") != 1:
        fail("schema_version must be 1")
    if data.get("registry_status") != "VALIDATION_CONTRACT_ENFORCED":
        fail("registry_status must be VALIDATION_CONTRACT_ENFORCED")
    if data.get("human_review_required") is not True:
        fail("human_review_required must be true")
    packages = data.get("packages")
    if not isinstance(packages, list) or not packages:
        fail("packages must be a non-empty list")
    _validate_bridge_records(data, root)

    seen_ids: set[str] = set()
    for package in packages:
        if not isinstance(package, dict):
            fail("each package entry must be an object")
        missing = sorted(REQUIRED_FIELDS - package.keys())
        detection_id = str(package.get("detection_id", "<unknown>"))
        if missing:
            fail(f"{detection_id} missing required fields: {', '.join(missing)}")
        if detection_id in seen_ids:
            fail(f"duplicate detection_id exists: {detection_id}")
        seen_ids.add(detection_id)

        validation_kind = package["validation_kind"]
        if validation_kind not in ALLOWED_KINDS:
            fail(f"{detection_id} unknown validation_kind: {validation_kind}")
        if package["proof_ceiling"] not in ALLOWED_PROOF_CEILINGS:
            fail(f"{detection_id} unknown proof ceiling: {package['proof_ceiling']}")
        if package["public_safe_status"] != "NOT_PUBLIC_SAFE":
            fail(f"{detection_id} public_safe_status must be NOT_PUBLIC_SAFE")
        if _truthy(package["runtime_status"]):
            fail(f"{detection_id} runtime_status is promoted/truthy")
        if _truthy(package["signal_status"]):
            fail(f"{detection_id} signal_status is promoted/truthy")
        if not isinstance(package["source_dependency_required"], bool):
            fail(f"{detection_id} source_dependency_required must be boolean")
        if package["ci_source_dependency_mode"] not in {"none", "required", "skip-if-missing", "skip_if_missing"}:
            fail(f"{detection_id} ci_source_dependency_mode is invalid")
        if package["source_dependency_required"] is False and package["ci_source_dependency_mode"] != "none":
            fail(f"{detection_id} ci_source_dependency_mode must be none when source_dependency_required is false")

        required_paths = {
            "baseline_contract": BASELINE_REQUIRED_PATHS,
            "controlled_validation": CONTROLLED_REQUIRED_PATHS,
            "visibility_contract": VISIBILITY_REQUIRED_PATHS,
        }[validation_kind]
        for field in required_paths:
            _require_existing_path(root, package, field)
        for field in CONTROLLED_REQUIRED_PATHS | BASELINE_REQUIRED_PATHS | VISIBILITY_REQUIRED_PATHS:
            value = package.get(field)
            if value is not None and isinstance(value, str):
                _require_existing_path(root, package, field)

        if validation_kind == "controlled_validation":
            for field in ("validator_script", "parity_script", "claim_boundary_script", "report_json"):
                if not package.get(field):
                    fail(f"{detection_id} missing required controlled-validation field: {field}")
        _verify_counts(root, package)

    return packages


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify validation package registry contract.")
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    args = parser.parse_args()
    try:
        packages = validate_registry(load_registry(args.registry), ROOT)
    except RegistryFailure as exc:
        print(f"VALIDATION_REGISTRY=fail: {exc}", file=sys.stderr)
        return 1

    print("VALIDATION_REGISTRY=pass")
    print(f"REGISTERED_PACKAGES={len(packages)}")
    for package in packages:
        print(
            "PACKAGE={id} kind={kind} proof_ceiling={ceiling} public_safe_status={public}".format(
                id=package["detection_id"],
                kind=package["validation_kind"],
                ceiling=package["proof_ceiling"],
                public=package["public_safe_status"],
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

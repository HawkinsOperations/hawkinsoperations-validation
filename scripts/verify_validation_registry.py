#!/usr/bin/env python3
"""Fail-closed validation registry contract verifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


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
    "no",
    "0",
    "off",
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
UNIQUE_OWNERSHIP_FIELDS = {
    "validation_package_path",
    "fixture_file",
    "report_json",
    "report_markdown",
}
EXPECTED_MATRIX_VALIDATION_STATUS = {
    "CONTROLLED_TEST_VALIDATED": "CONTROLLED_TEST_VALIDATED_IN_VALIDATION_REPO",
    "VALIDATION_CONTRACT_ENFORCED": "VALIDATION_CONTRACT_ENFORCED_IN_VALIDATION_REPO",
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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repository_state(root: Path) -> dict[str, str]:
    def git(*args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout.strip() if result.returncode == 0 else "UNRESOLVED"

    status = git("status", "--porcelain")
    status_lines = [] if status == "UNRESOLVED" else status.splitlines()
    meaningful_status = [
        line for line in status_lines
        if "__pycache__/" not in line.replace("\\", "/") and not line.rstrip().endswith(".pyc")
    ]
    worktree_clean = not meaningful_status if status != "UNRESOLVED" else False
    return {
        "repository": "hawkinsoperations-validation",
        "authority_role": "controlled_validation",
        "resolved_ref": git("branch", "--show-current"),
        "source_commit_sha": git("rev-parse", "HEAD"),
        "worktree_clean": worktree_clean,
        "source_freshness_state": "CURRENT" if worktree_clean else "WORKTREE_MODIFIED_OR_UNRESOLVED",
    }


def _rel_path(root: Path, value: str, field: str, detection_id: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        fail(f"{detection_id} {field} must be a repo-relative path")
    resolved_root = root.resolve()
    resolved = (resolved_root / path).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        fail(f"{detection_id} {field} escapes its owning repository")
    return resolved


def _require_existing_path(root: Path, package: dict[str, Any], field: str) -> None:
    value = package.get(field)
    detection_id = str(package.get("detection_id", "<unknown>"))
    if not isinstance(value, str) or not value:
        fail(f"{detection_id} missing required path field: {field}")
    resolved = _rel_path(root, value, field, detection_id)
    if not resolved.exists():
        fail(f"{detection_id} listed file or directory is missing: {field}={value}")
    if field == "validation_package_path" and not resolved.is_dir():
        fail(f"{detection_id} validation_package_path must be a directory: {value}")
    if field != "validation_package_path" and not resolved.is_file():
        fail(f"{detection_id} {field} must be a file: {value}")


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
    if package["validation_kind"] == "controlled_validation":
        total, positive, negative = expected
        if not all(isinstance(value, int) and value > 0 for value in (total, positive, negative)):
            fail(f"{detection_id} controlled validation requires positive integer fixture counts")
        if positive + negative != total:
            fail(f"{detection_id} expected positive and negative counts must sum to total fixtures")

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
    if report.get("human_review_required") not in {None, True}:
        fail(f"{detection_id} report disables human review")
    if _truthy(report.get("ai_disposition_authority", False)):
        fail(f"{detection_id} report promotes AI disposition authority")
    report_ceiling = report.get("proof_ceiling")
    if report_ceiling is not None and report_ceiling != package["proof_ceiling"]:
        fail(
            f"{detection_id} report proof ceiling disagreement: "
            f"registry={package['proof_ceiling']}, report={report_ceiling}"
        )

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
    if data.get("ai_disposition_authority") is not False:
        fail("ai_disposition_authority must be false")
    packages = data.get("packages")
    if not isinstance(packages, list) or not packages:
        fail("packages must be a non-empty list")
    _validate_bridge_records(data, root)

    seen_ids: set[str] = set()
    path_owners: dict[tuple[str, str], str] = {}
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
        if package["source_dependency_required"] is True:
            if package["ci_source_dependency_mode"] not in {"required", "skip-if-missing", "skip_if_missing"}:
                fail(f"{detection_id} source-backed validation must declare an enforceable source dependency mode")
            validator_path = _rel_path(root, package["validator_script"], "validator_script", detection_id)
            if validator_path.exists() and "--source-contract" not in validator_path.read_text(encoding="utf-8"):
                fail(f"{detection_id} source-backed validator does not implement --source-contract")

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
                if field in UNIQUE_OWNERSHIP_FIELDS:
                    resolved = _rel_path(root, value, field, detection_id)
                    key = (field, str(resolved).replace("\\", "/").casefold())
                    previous = path_owners.get(key)
                    if previous is not None:
                        fail(f"{detection_id} reuses {field} already owned by {previous}: {value}")
                    path_owners[key] = detection_id

        if validation_kind == "controlled_validation":
            for field in ("validator_script", "parity_script", "claim_boundary_script", "report_json"):
                if not package.get(field):
                    fail(f"{detection_id} missing required controlled-validation field: {field}")
        _verify_counts(root, package)

    return packages


def review_eligibility(package: dict[str, Any]) -> str:
    if package["validation_kind"] == "visibility_contract":
        return "BLOCKED"
    if package["validation_kind"] == "controlled_validation":
        return "PASS_CAPABLE"
    return "CONTRACT_ONLY"


def validate_source_parity(packages: list[dict[str, Any]], detections_root: Path) -> None:
    """Fail closed when validation registry truth disagrees with sibling source truth."""
    matrix_path = detections_root / "detections" / "DETECTION_PROMOTION_MATRIX.yml"
    if not matrix_path.is_file():
        fail(f"detection promotion matrix is missing: {matrix_path}")
    try:
        matrix = yaml.safe_load(matrix_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        fail(f"detection promotion matrix is malformed: {exc}")
    entries = matrix.get("entries") if isinstance(matrix, dict) else None
    if not isinstance(entries, list):
        fail("detection promotion matrix entries must be a list")
    by_id: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("detection_id"), str):
            fail("detection promotion matrix contains an invalid entry")
        detection_id = entry["detection_id"]
        if detection_id in by_id:
            fail(f"detection promotion matrix duplicates detection_id: {detection_id}")
        by_id[detection_id] = entry

    for package in packages:
        if package["source_dependency_required"] is not True:
            continue
        detection_id = package["detection_id"]
        entry = by_id.get(detection_id)
        if entry is None:
            fail(f"{detection_id} validation source dependency is missing from detection matrix")
        if entry.get("validation_expected_owner") != "hawkinsoperations-validation":
            fail(f"{detection_id} detection matrix validation owner disagreement")
        expected_matrix_status = EXPECTED_MATRIX_VALIDATION_STATUS[package["proof_ceiling"]]
        if entry.get("validation_status_if_known") != expected_matrix_status:
            fail(
                f"{detection_id} source/validation status disagreement: "
                f"expected={expected_matrix_status}, matrix={entry.get('validation_status_if_known')}"
            )
        package_path = entry.get("package_path")
        if not isinstance(package_path, str) or "://" in package_path:
            fail(f"{detection_id} source-backed validation requires a local detection package")
        status_path = detections_root / package_path / "status.yml"
        if not status_path.is_file():
            fail(f"{detection_id} source status file is missing: {package_path}/status.yml")
        try:
            status = yaml.safe_load(status_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            fail(f"{detection_id} source status file is malformed: {exc}")
        if not isinstance(status, dict) or status.get("detection_id") != detection_id:
            fail(f"{detection_id} source status file identity disagreement")
        expected_status = expected_matrix_status.removesuffix("_IN_VALIDATION_REPO")
        if status.get("validation_status") != expected_status:
            fail(
                f"{detection_id} source status validation disagreement: "
                f"expected={expected_status}, status.yml={status.get('validation_status')}"
            )
        if status.get("public_safe_status") != "NOT_PUBLIC_SAFE":
            fail(f"{detection_id} source status promotes public-safe state")
        if _truthy(status.get("runtime_active")) or _truthy(status.get("signal_observed")):
            fail(f"{detection_id} source status promotes runtime or signal state")


def build_inventory(packages: list[dict[str, Any]], root: Path = ROOT) -> dict[str, Any]:
    state = _repository_state(root)
    items: list[dict[str, Any]] = []
    fingerprint_fields = (
        "fixture_file",
        "report_json",
        "report_markdown",
        "validator_script",
        "parity_script",
        "claim_boundary_script",
    )
    for package in packages:
        fingerprints: dict[str, str] = {}
        for field in fingerprint_fields:
            value = package.get(field)
            if isinstance(value, str):
                fingerprints[field] = _sha256_file(root / value)
        eligibility = review_eligibility(package)
        items.append(
            {
                "detection_id": package["detection_id"],
                "validation_kind": package["validation_kind"],
                "proof_ceiling": package["proof_ceiling"],
                "review_eligibility": eligibility,
                "expected_fixture_review_outcome": "PASS" if eligibility == "PASS_CAPABLE" else "BLOCKED",
                "human_review_required": True,
                "ai_disposition_authority": False,
                "public_safe_status": package["public_safe_status"],
                "source_dependency_required": package["source_dependency_required"],
                "source_fingerprints": dict(sorted(fingerprints.items())),
            }
        )
    return {
        **state,
        "authoritative_path": "validation/VALIDATION_REGISTRY.yml",
        "authoritative_fingerprint": _sha256_file(root / "validation" / "VALIDATION_REGISTRY.yml"),
        "package_count": len(items),
        "packages": items,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify validation package registry contract.")
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--detections-root", type=Path)
    args = parser.parse_args()
    try:
        packages = validate_registry(load_registry(args.registry), ROOT)
        detections_root = args.detections_root
        if detections_root is None:
            sibling = ROOT.parent / "hawkinsoperations-detections"
            if sibling.is_dir():
                detections_root = sibling
        if detections_root is not None:
            validate_source_parity(packages, detections_root.resolve())
    except RegistryFailure as exc:
        print(f"VALIDATION_REGISTRY=fail: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(build_inventory(packages, ROOT), indent=2, sort_keys=True))
        return 0
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
        print(
            f"REVIEW_ELIGIBILITY={package['detection_id']}:{review_eligibility(package)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Verify the reviewer metrics detection activity ledger."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = ROOT / "activity" / "detection-activity-ledger-v1.json"
REGISTRY_PATH = ROOT / "validation" / "VALIDATION_REGISTRY.yml"

ALLOWED_SCOPES = {
    "CONTROLLED_VALIDATION_FIRE",
    "CONTROLLED_NEGATIVE_TEST",
    "RUNTIME_PRIVATE_FIRE",
    "RUNTIME_PUBLIC_SAFE_FIRE",
    "BLOCKED_PROMOTION_EVENT",
    "PROOF_RECORD_EVENT",
    "GOVERNED_CASE_APPEND",
}
REQUIRED_ENTRY_FIELDS = {
    "detection_id",
    "activity_scope",
    "activity_type",
    "count",
    "count_basis",
    "source_artifacts",
    "authority_repo",
    "proof_ceiling",
    "public_safe_status",
    "runtime_truth_status",
    "signal_truth_status",
    "does_not_prove",
    "blocked_claims",
}
DENIED_TEXT = [
    ("C:\\Raylee\\Work", re.compile(r"C:\\Raylee\\Work", re.IGNORECASE)),
    ("private IPv4 address", re.compile(r"\b(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[0-1]))\.\d{1,3}\.\d{1,3}\b")),
    ("secret marker", re.compile(r"\b(secret|password|credential|api[_-]?key|token)\b", re.IGNORECASE)),
]


class VerificationError(Exception):
    """Raised when the activity ledger violates its contract."""


def fail(message: str) -> None:
    raise VerificationError(message)


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing {label}: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"malformed {label}: {exc}")
    if not isinstance(data, dict):
        fail(f"{label} root must be an object")
    return data


def scan_value(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            scan_value(key, label)
            scan_value(nested, label)
    elif isinstance(value, list):
        for nested in value:
            scan_value(nested, label)
    elif isinstance(value, str):
        for name, pattern in DENIED_TEXT:
            if pattern.search(value):
                fail(f"{label} contains blocked text: {name}")


def registry_expected_counts(registry: dict[str, Any]) -> tuple[int, int, int, set[str]]:
    packages = registry.get("packages")
    if not isinstance(packages, list):
        fail("validation registry packages must be a list")
    positive = 0
    negative = 0
    total = 0
    counted_ids: set[str] = set()
    for package in packages:
        if not isinstance(package, dict):
            fail("validation registry package must be an object")
        detection_id = package.get("detection_id")
        fixture_count = package.get("expected_fixture_count")
        positive_count = package.get("expected_positive_count")
        negative_count = package.get("expected_negative_count")
        if fixture_count is None and positive_count is None and negative_count is None:
            continue
        if not all(isinstance(value, int) for value in (fixture_count, positive_count, negative_count)):
            fail(f"{detection_id} registry counts must be integers when present")
        total += fixture_count
        positive += positive_count
        negative += negative_count
        counted_ids.add(str(detection_id))
    return positive, negative, total, counted_ids


def _require_relative_artifacts(entry: dict[str, Any]) -> None:
    artifacts = entry.get("source_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        fail(f"{entry.get('detection_id')} source_artifacts must be a non-empty list")
    for artifact in artifacts:
        if not isinstance(artifact, str) or not artifact:
            fail(f"{entry.get('detection_id')} source artifact must be a string")
        path = Path(artifact)
        if path.is_absolute() or ".." in path.parts:
            fail(f"{entry.get('detection_id')} source artifact must be repo-relative: {artifact}")


def verify_ledger(ledger_path: Path = LEDGER_PATH, registry_path: Path = REGISTRY_PATH, repo_root: Path = ROOT) -> dict[str, Any]:
    ledger = load_json(ledger_path, "detection activity ledger")
    registry = load_json(registry_path, "validation registry")
    scan_value(ledger, "detection activity ledger")

    if ledger.get("owner_repo") != "hawkinsoperations-validation":
        fail("owner_repo must be hawkinsoperations-validation")
    if ledger.get("public_safe_status") != "NOT_PUBLIC_SAFE":
        fail("ledger public_safe_status must be NOT_PUBLIC_SAFE")
    if ledger.get("runtime_truth_status") != "NOT_PROVEN":
        fail("ledger must not promote runtime truth")
    if ledger.get("signal_truth_status") != "NOT_PROVEN":
        fail("ledger must not promote signal truth")

    metrics = ledger.get("aggregate_metrics")
    if not isinstance(metrics, dict):
        fail("aggregate_metrics must be present")

    expected_positive, expected_negative, expected_total, counted_ids = registry_expected_counts(registry)
    expected_metrics = {
        "detection_activity_count": expected_positive,
        "controlled_validation_fire_count": expected_positive,
        "controlled_negative_test_count": expected_negative,
        "validation_case_count": expected_total,
        "runtime_public_safe_count": 0,
        "public_safe_count": 0,
    }
    for key, expected in expected_metrics.items():
        if metrics.get(key) != expected:
            fail(f"{key} mismatch: expected {expected}, found {metrics.get(key)}")
    if metrics["detection_activity_count"] == 0:
        fail("detection_activity_count must expose controlled activity volume")

    entries = ledger.get("activity_entries")
    if not isinstance(entries, list) or not entries:
        fail("activity_entries must be a non-empty list")

    fire_sum = 0
    entry_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            fail("activity entry must be an object")
        missing = REQUIRED_ENTRY_FIELDS - set(entry)
        if missing:
            fail(f"activity entry missing fields: {sorted(missing)}")
        scope = entry["activity_scope"]
        if scope not in ALLOWED_SCOPES:
            fail(f"{entry['detection_id']} uses unsupported activity_scope: {scope}")
        if scope == "GOVERNED_CASE_APPEND" and "controlled validation fire" in str(entry["activity_type"]).lower():
            fail("controlled validation fire cannot use governed case scope")
        if entry["public_safe_status"] != "NOT_PUBLIC_SAFE":
            fail(f"{entry['detection_id']} promotes public-safe status")
        if entry["runtime_truth_status"] != "NOT_PROVEN":
            fail(f"{entry['detection_id']} promotes runtime truth")
        if entry["signal_truth_status"] != "NOT_PROVEN":
            fail(f"{entry['detection_id']} promotes signal truth")
        if not isinstance(entry["count"], int) or entry["count"] < 0:
            fail(f"{entry['detection_id']} count must be a non-negative integer")
        _require_relative_artifacts(entry)
        entry_ids.add(str(entry["detection_id"]))
        if scope == "CONTROLLED_VALIDATION_FIRE":
            fire_sum += entry["count"]

    if fire_sum != expected_positive:
        fail(f"controlled fire entry sum mismatch: expected {expected_positive}, found {fire_sum}")
    if not entry_ids.issubset(counted_ids):
        fail(f"activity entries include detections not counted by registry: {sorted(entry_ids - counted_ids)}")

    return {
        "status": "pass",
        "ledger_path": str(ledger_path.relative_to(repo_root)) if ledger_path.is_relative_to(repo_root) else str(ledger_path),
        "detection_activity_count": metrics["detection_activity_count"],
        "controlled_validation_fire_count": metrics["controlled_validation_fire_count"],
        "controlled_negative_test_count": metrics["controlled_negative_test_count"],
        "validation_case_count": metrics["validation_case_count"],
        "runtime_public_safe_count": metrics["runtime_public_safe_count"],
        "public_safe_status": ledger["public_safe_status"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, default=LEDGER_PATH)
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--format", choices={"text", "json"}, default="text")
    args = parser.parse_args(argv)
    try:
        result = verify_ledger(args.ledger, args.registry, ROOT)
    except VerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("PASS: detection activity ledger is proof-bounded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

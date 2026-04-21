#!/usr/bin/env python3
"""
Baseline validation contract check.

Current scope:
- Validates baseline hero validation artifacts for HOD-001 only
- Validates schema shape for reports/hero001-validation-report.json
- Validates required baseline validation artifact paths that exist today

Not covered yet:
- Non-hero validation families
- Semantic validation beyond the current baseline harness/report contract
- Cross-repository linkage into proof
"""
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / ".github" / "contracts" / "validation-report.schema.json"
REPORT_JSON = ROOT / "reports" / "hero001-validation-report.json"
BASELINE_REQUIRED = [
    ROOT / "validation" / "hero" / "001-powershell-encoded-command" / "validation-cases.json",
    ROOT / "reports" / "hero001-validation-report.json",
    ROOT / "reports" / "hero001-validation-report.md",
    ROOT / "scripts" / "validate-hero001.ps1",
]


def fail(msg: str) -> None:
    print(f"Baseline validation contract check failed: {msg}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path, label: str) -> dict:
    if not path.exists():
        fail(f"missing {label}: {path.relative_to(ROOT).as_posix()}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {label} ({path.relative_to(ROOT).as_posix()}): {exc}")


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


def main() -> int:
    print("Scope: baseline hero validation artifacts for HOD-001 only.")
    schema = load_json(SCHEMA_PATH, "validation contract schema")
    report = load_json(REPORT_JSON, "baseline validation report")
    validate_schema_shape(report, schema)
    validate_live_artifacts()
    print("Baseline validation contract check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

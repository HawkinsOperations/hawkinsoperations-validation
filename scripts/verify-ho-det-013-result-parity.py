#!/usr/bin/env python3
"""Verify stable HO-DET-013 validation-result parity."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate-ho-det-013.py"
VALIDATION_CASES = ROOT / "validation" / "successor" / "ho-det-013" / "validation-cases.json"
VALIDATION_RESULT = ROOT / "reports" / "ho-det-013" / "validation-result.json"


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_ho_det_013", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        fail("could not load HO-DET-013 validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-contract", choices=("required", "skip-if-missing"), default="required")
    args = parser.parse_args()
    for path in (VALIDATOR_PATH, VALIDATION_CASES, VALIDATION_RESULT):
        if not path.exists():
            print("STATUS=NOT_READY")
            print(f"MISSING_PATH={path}")
            return 2
    validator = load_validator()
    cases = validator.load_json(VALIDATION_CASES, "validation-cases.json")
    actual = validator.load_json(VALIDATION_RESULT, "validation-result.json")
    expected = validator.build_report(cases, source_contract=args.source_contract)
    if actual != expected:
        fail("HO-DET-013 validation result is out of date")
    print("STATUS=pass")
    print("VALIDATION_RESULT_PARITY=pass")
    print("DETECTION_ID=HO-DET-013")
    print(f"TOTAL_CASES={actual['total_cases']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

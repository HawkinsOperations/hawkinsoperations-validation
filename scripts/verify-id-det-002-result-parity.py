#!/usr/bin/env python3
"""Verify stable ID-DET-002 validation-result parity."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate-id-det-002.py"
VALIDATION_CASES = ROOT / "validation" / "identity" / "id-det-002" / "validation-cases.json"
VALIDATION_RESULT = ROOT / "reports" / "id-det-002" / "validation-result.json"
REQUIRED_PATHS = [VALIDATOR_PATH, VALIDATION_CASES, VALIDATION_RESULT]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def not_ready(missing: list[Path]) -> None:
    print("STATUS=NOT_READY")
    print("MISSING_PATHS=" + ";".join(str(path) for path in missing))
    raise SystemExit(2)


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_id_det_002", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        fail("could not load ID-DET-002 validator module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    missing = [path for path in REQUIRED_PATHS if not path.exists()]
    if missing:
        not_ready(missing)
    validator = load_validator()
    cases = validator.load_json(VALIDATION_CASES, "validation-cases.json")
    actual = validator.load_json(VALIDATION_RESULT, "validation-result.json")
    expected = validator.build_report(cases)
    if actual != expected:
        print("STATUS=fail")
        print("VALIDATION_RESULT_PARITY=fail")
        print("MISSING_KEYS=" + ",".join(sorted(set(expected) - set(actual))))
        print("EXTRA_KEYS=" + ",".join(sorted(set(actual) - set(expected))))
        raise SystemExit(1)
    print("STATUS=pass")
    print("VALIDATION_RESULT_PARITY=pass")
    print("DETECTION_ID=ID-DET-002")
    print(f"FIXTURE_COUNT={actual['fixture_count']}")
    print(f"CLAIM_CEILING={actual['claim_ceiling']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

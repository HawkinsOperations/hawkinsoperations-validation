#!/usr/bin/env python3
"""Unit tests for the baseline validation contract checker."""

import importlib.util
import sys
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SCRIPT = SCRIPTS / "verify_validation_contract.py"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_checker_module():
    spec = importlib.util.spec_from_file_location("verify_validation_contract", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load checker module: {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = load_checker_module()


class ValidationContractTests(unittest.TestCase):
    def test_valid_fixture_contract_passes(self):
        checker.validate_schema_shape(checker.self_test_report(), checker.self_test_schema())
        checker.validate_case_report_consistency(checker.self_test_cases(), checker.self_test_report())

    def test_missing_required_report_key_fails(self):
        report = checker.self_test_report()
        report.pop("status")
        with self.assertRaisesRegex(checker.ContractFailure, "report missing required key: status"):
            checker.validate_schema_shape(report, checker.self_test_schema())

    def test_duplicate_case_id_fails(self):
        cases = checker.self_test_cases()
        cases["positives"].append(deepcopy(cases["positives"][0]))
        with self.assertRaisesRegex(checker.ContractFailure, "duplicate validation case id"):
            checker.validate_case_report_consistency(cases, checker.self_test_report())

    def test_report_case_id_mismatch_fails(self):
        report = checker.self_test_report()
        report["positive"][0]["id"] = "pos-999"
        with self.assertRaisesRegex(checker.ContractFailure, "positive report IDs do not match validation cases"):
            checker.validate_case_report_consistency(checker.self_test_cases(), report)

    def test_totals_mismatch_fails(self):
        report = checker.self_test_report()
        report["totals"]["total_cases"] = 99
        with self.assertRaisesRegex(checker.ContractFailure, "totals.total_cases expected 2, got 99"):
            checker.validate_case_report_consistency(checker.self_test_cases(), report)

    def test_inconsistent_result_status_fails(self):
        report = checker.self_test_report()
        report["negative"][0]["matched"] = True
        with self.assertRaisesRegex(checker.ContractFailure, "pass is inconsistent with expected/matched"):
            checker.validate_case_report_consistency(checker.self_test_cases(), report)

    def test_status_mismatch_fails(self):
        report = checker.self_test_report()
        report["status"] = "fail"
        with self.assertRaisesRegex(checker.ContractFailure, "report.status is inconsistent with totals.fail"):
            checker.validate_case_report_consistency(checker.self_test_cases(), report)

    def test_cli_self_test_mode_returns_zero(self):
        self.assertEqual(checker.main(["--self-test"]), 0)


if __name__ == "__main__":
    unittest.main()

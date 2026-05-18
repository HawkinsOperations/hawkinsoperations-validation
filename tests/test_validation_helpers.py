#!/usr/bin/env python3
"""Unit tests for shared validation helper functions."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import validation_lib


class ValidationHelperTests(unittest.TestCase):
    def test_iter_strings_collects_nested_text(self):
        payload = {
            "a": "alpha",
            "b": ["beta", {"c": "gamma"}],
            "d": 123,
        }
        self.assertEqual(sorted(validation_lib.iter_strings(payload)), ["alpha", "beta", "gamma"])

    def test_find_forbidden_terms_detects_blocked_claims(self):
        payload = {
            "summary": "RUNTIME_ACTIVE should not be public claim",
            "nested": [{"v": "no issue"}, {"v": "PUBLIC_PROOF_SAFE candidate"}],
        }
        found = validation_lib.find_forbidden_terms(payload, ["RUNTIME_ACTIVE", "PUBLIC_PROOF_SAFE", "BLOCKED"])
        self.assertEqual(found, ["PUBLIC_PROOF_SAFE", "RUNTIME_ACTIVE"])

    def test_sha256_text_is_stable(self):
        self.assertEqual(
            validation_lib.sha256_text("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_validate_report_case_parity_fails_on_mismatch(self):
        with self.assertRaisesRegex(validation_lib.ContractFailure, "positive report IDs do not match"):
            validation_lib.validate_report_case_parity({"a", "b"}, {"a", "c"}, side="positive")

    def test_load_json_checks_object_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = root / "v.json"
            p.write_text("[1,2,3]", encoding="utf-8")
            with self.assertRaisesRegex(validation_lib.ContractFailure, "must be a JSON object"):
                validation_lib.load_json(p, "test payload", root=root)

    def test_ensure_check_mode_blocks_write(self):
        with self.assertRaisesRegex(validation_lib.ContractFailure, "write mode is blocked"):
            validation_lib.ensure_check_mode(write=True)


if __name__ == "__main__":
    unittest.main()

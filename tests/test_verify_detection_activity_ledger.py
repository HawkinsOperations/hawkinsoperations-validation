from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "verify-detection-activity-ledger.py"
LEDGER_PATH = ROOT / "activity" / "detection-activity-ledger-v1.json"
REGISTRY_PATH = ROOT / "validation" / "VALIDATION_REGISTRY.yml"

spec = importlib.util.spec_from_file_location("verify_detection_activity_ledger", SCRIPT_PATH)
verifier = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(verifier)


class DetectionActivityLedgerTests(unittest.TestCase):
    def test_repo_ledger_matches_validation_registry_counts(self) -> None:
        result = verifier.verify_ledger(LEDGER_PATH, REGISTRY_PATH, ROOT)

        self.assertEqual(result["controlled_validation_fire_count"], 49)
        self.assertEqual(result["controlled_negative_test_count"], 57)
        self.assertEqual(result["validation_case_count"], 106)
        self.assertEqual(result["detection_activity_count"], 49)
        self.assertEqual(result["public_safe_status"], "NOT_PUBLIC_SAFE")
        self.assertEqual(result["runtime_public_safe_count"], 0)

    def test_repo_activity_entries_match_validation_registry(self) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        expected_entries = verifier.expected_activity_entries_from_registry(REGISTRY_PATH)
        actual_entries = {
            entry["detection_id"]: {
                "count": entry["count"],
                "source_artifacts": entry["source_artifacts"],
            }
            for entry in ledger["activity_entries"]
        }

        self.assertEqual(actual_entries, expected_entries)

    def test_activity_entry_count_must_match_registry_expected_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            data = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
            data["aggregate_metrics"]["activity_entry_count"] = 999
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaisesRegex(verifier.VerificationError, "activity_entry_count mismatch"):
                verifier.verify_ledger(path, REGISTRY_PATH, ROOT)

    def test_activity_entries_fail_closed_when_missing_or_extra_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            data = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
            data["activity_entries"] = data["activity_entries"][:-1]
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaisesRegex(verifier.VerificationError, "activity entry count mismatch"):
                verifier.verify_ledger(path, REGISTRY_PATH, ROOT)

            data = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
            data["activity_entries"].append(dict(data["activity_entries"][0]))
            data["aggregate_metrics"]["activity_entry_count"] += 1
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaisesRegex(verifier.VerificationError, "activity_entry_count mismatch"):
                verifier.verify_ledger(path, REGISTRY_PATH, ROOT)

    def test_detection_fire_cannot_be_governed_case_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            data = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
            data["activity_entries"][0]["activity_scope"] = "GOVERNED_CASE_APPEND"
            data["activity_entries"][0]["activity_type"] = "controlled validation fire"
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaisesRegex(verifier.VerificationError, "controlled validation fire cannot use governed case scope"):
                verifier.verify_ledger(path, REGISTRY_PATH, ROOT)


if __name__ == "__main__":
    unittest.main()

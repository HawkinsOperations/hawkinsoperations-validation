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

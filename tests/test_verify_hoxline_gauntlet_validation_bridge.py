from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from scripts import verify_hoxline_gauntlet_validation_bridge as verifier


class HoxlineGauntletValidationBridgeTests(unittest.TestCase):
    def good_bridge(self) -> dict:
        return verifier.load_bridge()

    def test_current_bridge_passes(self) -> None:
        markdown = verifier.BRIDGE_MD.read_text(encoding="utf-8")
        result = verifier.validate_bridge(self.good_bridge(), markdown)
        self.assertEqual(result["detection_id"], "HO-DET-001")
        self.assertEqual(result["primary_v1_run_path"], verifier.EXPECTED_V1_RUN)
        self.assertEqual(result["source_manifest_path"], verifier.EXPECTED_MANIFEST)
        self.assertFalse(result["public_safe"])
        self.assertTrue(result["human_review_required"])

    def test_public_safe_true_fails(self) -> None:
        data = copy.deepcopy(self.good_bridge())
        data["public_safe"] = True
        with self.assertRaisesRegex(verifier.VerificationError, "public_safe"):
            verifier.validate_bridge(data)

    def test_missing_blocked_claim_fails(self) -> None:
        data = copy.deepcopy(self.good_bridge())
        data["blocked_claims"] = ["runtime proven"]
        with self.assertRaisesRegex(verifier.VerificationError, "blocked_claims missing"):
            verifier.validate_bridge(data)

    def test_missing_primary_v1_path_fails(self) -> None:
        data = copy.deepcopy(self.good_bridge())
        data["gauntlet_paths"]["primary_v1_run_path"] = "examples/gauntlet/ho-det-001-full-loop-run-v0.json"
        with self.assertRaisesRegex(verifier.VerificationError, "primary_v1_run_path"):
            verifier.validate_bridge(data)

    def test_v0_must_be_compatibility_only(self) -> None:
        data = copy.deepcopy(self.good_bridge())
        data["gauntlet_paths"]["v0_compatibility_check"]["not_primary_source"] = False
        with self.assertRaisesRegex(verifier.VerificationError, "v0 compatibility"):
            verifier.validate_bridge(data)

    def test_source_manifest_path_is_required(self) -> None:
        data = copy.deepcopy(self.good_bridge())
        data["hoxline_source"]["source_manifest_path"] = "examples/gauntlet/missing.json"
        with self.assertRaisesRegex(verifier.VerificationError, "source manifest"):
            verifier.validate_bridge(data)

    def test_hoxline_root_checks_file_existence(self) -> None:
        data = self.good_bridge()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel_path in verifier.REQUIRED_HOXLINE_FILES:
                target = root / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("{}\n", encoding="utf-8")
            result = verifier.validate_bridge(data, hoxline_root=root)
            self.assertEqual(result["primary_v1_schema_path"], verifier.EXPECTED_V1_SCHEMA)

    def test_hoxline_root_missing_file_fails(self) -> None:
        data = self.good_bridge()
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(verifier.VerificationError, "referenced file missing"):
                verifier.validate_bridge(data, hoxline_root=Path(tmp))

    def test_stale_work_path_fails_without_literal_fixture(self) -> None:
        data = copy.deepcopy(self.good_bridge())
        data["negative_expectations"].append("C:" + "\\Raylee\\Work\\bad.md")
        with self.assertRaisesRegex(verifier.VerificationError, "Work"):
            verifier.validate_bridge(data)

    def test_website_authority_true_fails(self) -> None:
        data = copy.deepcopy(self.good_bridge())
        data["hoxline_source"]["website_boundary"]["website_is_authority"] = True
        with self.assertRaisesRegex(verifier.VerificationError, "website"):
            verifier.validate_bridge(data)


if __name__ == "__main__":
    unittest.main()

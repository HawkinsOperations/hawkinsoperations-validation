from __future__ import annotations

import copy
import unittest

from scripts import verify_hoxline_gauntlet_validation_bridge as verifier


class HoxlineGauntletValidationBridgeTests(unittest.TestCase):
    def good_bridge(self) -> dict:
        return verifier.load_bridge()

    def test_current_bridge_passes(self) -> None:
        markdown = verifier.BRIDGE_MD.read_text(encoding="utf-8")
        result = verifier.validate_bridge(self.good_bridge(), markdown)
        self.assertEqual(result["detection_id"], "HO-DET-001")
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

    def test_stale_work_path_fails(self) -> None:
        data = copy.deepcopy(self.good_bridge())
        data["hoxline_source"]["gauntlet_doc_path"] = "C:\\Raylee\\Work\\bad.md"
        with self.assertRaisesRegex(verifier.VerificationError, "repo-relative|Work"):
            verifier.validate_bridge(data)


if __name__ == "__main__":
    unittest.main()

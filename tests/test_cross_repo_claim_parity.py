#!/usr/bin/env python3
"""Unit tests for cross-repo claim parity scanner."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_cross_repo_claim_parity.py"


def load_module():
    spec = importlib.util.spec_from_file_location("verify_cross_repo_claim_parity", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load module: {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


scanner = load_module()


class CrossRepoClaimParityTests(unittest.TestCase):
    def test_negative_context_allows_promotion_term(self):
        self.assertTrue(scanner.has_negative_context("runtime-active status is BLOCKED"))
        self.assertTrue(scanner.has_negative_context("do not claim live Splunk"))

    def test_unblocked_promotion_term_fails(self):
        text = "HO-DET-001 is runtime-active in production"
        items = scanner.scan_promotion_terms(
            text=text,
            detection_id="HO-DET-001",
            surface="proof",
            rel_path="proof/records/HO-DET-001.md",
            fail_on_public_promotion=True,
        )
        self.assertGreaterEqual(len(items), 1)
        self.assertEqual(items[0].severity, "fail")

    def test_missing_scan_targets_classifies_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            drift, status_map, unknown = scanner.scan_surface(
                surface="missing",
                repo_root=root / "does-not-exist",
                patterns=["**/*.md"],
                detection_ids=["HO-DET-001"],
                fail_on_public_promotion=True,
            )
            self.assertEqual(unknown, 1)
            self.assertEqual(len(drift), 1)
            self.assertEqual(drift[0].severity, "unknown")
            self.assertIn("HO-DET-001", status_map)

    def test_main_report_only_passes_with_warning(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            (org / "hawkinsoperations-detections" / "detections" / "successor" / "ho-det-001").mkdir(parents=True)
            (org / "hawkinsoperations-validation" / "reports" / "ho-det-001").mkdir(parents=True)
            (org / "hawkinsoperations-proof" / "proof" / "records").mkdir(parents=True)
            (org / "hawkinsoperations-website").mkdir(parents=True)
            (org / ".github" / "profile").mkdir(parents=True)
            (org / "hawkinsoperations-platform").mkdir(parents=True)

            (org / "hawkinsoperations-detections" / "detections" / "successor" / "ho-det-001" / "status.yml").write_text(
                "detection_id: HO-DET-001\nstatus: SOURCE_EXISTS\n",
                encoding="utf-8",
            )
            (org / "hawkinsoperations-validation" / "reports" / "ho-det-001" / "validation-result.json").write_text(
                json.dumps({"detection_id": "HO-DET-001", "status": "pass", "proof_ceiling": "CONTROLLED_TEST_VALIDATED"}),
                encoding="utf-8",
            )
            (org / "hawkinsoperations-proof" / "proof" / "records" / "HO-DET-001.md").write_text(
                "HO-DET-001 is runtime-active in production.",
                encoding="utf-8",
            )
            (org / "hawkinsoperations-website" / "README.md").write_text("HO-DET-001", encoding="utf-8")
            (org / ".github" / "profile" / "README.md").write_text("HO-DET-001", encoding="utf-8")
            (org / "hawkinsoperations-platform" / "README.md").write_text("HO-DET-001", encoding="utf-8")

            rc = scanner.main([
                "--repo-root",
                str(org),
                "--report-only",
                "--fail-on-public-promotion",
            ])
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()

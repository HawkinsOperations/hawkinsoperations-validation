#!/usr/bin/env python3
"""Unit tests for cross-repo claim parity scanner."""

import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
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
    def build_org(self, org: Path, body: str) -> None:
        files = {
            "hawkinsoperations-detections/detections/successor/ho-det-001/status.yml": body,
            "hawkinsoperations-validation/reports/ho-det-001/validation-result.json": json.dumps(
                {"detection_id": "HO-DET-001", "notes": body}
            ),
            "hawkinsoperations-proof/proof/records/HO-DET-001.md": body,
            "hawkinsoperations-website/README.md": body,
            ".github/profile/README.md": body,
            "hawkinsoperations-platform/README.md": body,
        }
        for rel_path, content in files.items():
            path = org / rel_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def good_parity_body(self) -> str:
        return "\n".join(
            [
                "HO-DET-001: SOURCE_EXISTS",
                "HO-DET-011: SOURCE_EXISTS",
                "HO-DET-012: SOURCE_EXISTS",
                "AWS-DET-001: SOURCE_EXISTS",
                "HO-NDR-001: SOURCE_EXISTS",
                "HO-PIPE-001: SOURCE_EXISTS",
                "cross_repo_claim_contract: true",
                "proof_ceiling: CONTROLLED_TEST_VALIDATED",
                "public_safe_runtime_proof: BLOCKED",
                "runtime_active_public_proof: BLOCKED",
                "signal_observed_public_proof: BLOCKED",
                "Website/GitHub rendering is not proof.",
                "Human governance review is required before merge and before public-safe proof approval.",
                "Proof Pack 001 is released with public ceiling CONTROLLED_TEST_VALIDATED.",
                (
                    "Blocked claims: do not claim production-ready, SOCaaS, autonomous SOC, "
                    "runtime-active public proof, signal-observed public proof, public-safe runtime proof, "
                    "AI-approved disposition, or analyst-approved disposition."
                ),
            ]
        )

    def run_main(self, args: list[str]) -> tuple[int, str]:
        stdout = StringIO()
        with redirect_stdout(stdout):
            rc = scanner.main(args)
        return rc, stdout.getvalue()

    def drift_items(self, output: str) -> list[dict[str, str]]:
        for line in output.splitlines():
            if line.startswith("DRIFT_ITEMS="):
                return json.loads(line.removeprefix("DRIFT_ITEMS="))
        self.fail(f"DRIFT_ITEMS missing from output: {output}")

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
            enforce=True,
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
                enforce=True,
            )
            self.assertEqual(unknown, 1)
            self.assertEqual(len(drift), 1)
            self.assertEqual(drift[0].severity, "unknown")
            self.assertIn("HO-DET-001", status_map)

    def test_multiline_blocked_claim_list_allows_promotional_terms(self):
        text = "\n".join(
            [
                "HO-DET-001",
                "blocked_claims:",
                "  - runtime-active public proof",
                "  - signal-observed public proof",
                "  - production-ready",
            ]
        )
        items = scanner.scan_promotion_terms(
            text=text,
            detection_id="HO-DET-001",
            surface="detections",
            rel_path="detections/successor/ho-det-001/status.yml",
            enforce=True,
        )
        self.assertEqual(items, [])

    def test_multi_case_file_does_not_cross_associate_claims(self):
        text = "\n".join(
            [
                "## HO-DET-001",
                "status: SOURCE_EXISTS",
                "",
                "## AWS-DET-001",
                "blocked_claims:",
                "  - production-ready",
                "  - runtime-active public proof",
            ]
        )
        items = scanner.scan_promotion_terms(
            text=text,
            detection_id="HO-DET-001",
            surface="proof",
            rel_path="proof/records/multi.md",
            enforce=True,
        )
        self.assertEqual(items, [])

    def test_phrase_local_negation_does_not_launder_later_promotion(self):
        text = (
            "HO-DET-001 is not public-safe in review notes, but "
            "HO-DET-001 is production-ready for deployment."
        )
        items = scanner.scan_promotion_terms(
            text=text,
            detection_id="HO-DET-001",
            surface="proof",
            rel_path="proof/records/HO-DET-001.md",
            enforce=True,
        )
        self.assertTrue(
            any("production" in item.message for item in items),
            items,
        )

    def test_malformed_utf8_declared_text_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            self.build_org(org, self.good_parity_body())
            hostile = (
                org
                / "hawkinsoperations-proof"
                / "proof"
                / "records"
                / "malformed.md"
            )
            hostile.write_bytes(b"HO-DET-001\xffproduction-ready")

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("not readable strict UTF-8", output)

    def test_source_surface_missing_public_boundaries_does_not_fail(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            detection_file = org / "hawkinsoperations-detections" / "detections" / "successor" / "ho-det-001" / "status.yml"
            detection_file.parent.mkdir(parents=True)
            detection_file.write_text("detection_id: HO-DET-001\nstatus: SOURCE_EXISTS\n", encoding="utf-8")

            drift, _, _ = scanner.scan_surface(
                surface="detections",
                repo_root=org / "hawkinsoperations-detections",
                patterns=["detections/**/status.yml"],
                detection_ids=["HO-DET-001"],
                enforce=True,
            )
            messages = [item.message for item in drift]
            self.assertNotIn("missing rendering-not-proof boundary", messages)
            self.assertNotIn("missing human-review-required boundary", messages)

    def test_good_parity_enforce_passes(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            self.build_org(org, self.good_parity_body())

            rc, output = self.run_main([
                "--repo-root",
                str(org),
                "--enforce",
            ])
            self.assertEqual(rc, 0, output)

    def test_missing_blocked_claim_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = self.good_parity_body().replace("SOCaaS, ", "")
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertTrue(any("SOCaaS" in item["message"] for item in self.drift_items(output)))

    def test_public_safe_promotion_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = self.good_parity_body() + "\nHO-DET-001 is PUBLIC_SAFE."
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("PUBLIC_SAFE", output)

    def test_runtime_active_promotion_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = self.good_parity_body() + "\nHO-DET-001 has runtime-active public proof."
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("runtime-active", output)

    def test_signal_observed_promotion_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = self.good_parity_body() + "\nHO-DET-001 has signal-observed public proof."
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("signal-observed", output)

    def test_ai_approved_disposition_promotion_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = self.good_parity_body() + "\nHO-DET-001 uses AI-approved disposition."
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("AI-approved disposition", output)

    def test_missing_rendering_boundary_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = self.good_parity_body().replace("Website/GitHub rendering is not proof.", "")
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("missing rendering-not-proof boundary", output)

    def test_report_only_does_not_fail(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = "HO-DET-001 is PUBLIC_SAFE with runtime-active public proof."
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--report-only"])
            self.assertEqual(rc, 0, output)
            self.assertIn("STATUS=pass", output)
            self.assertIn("WARNING_COUNT=", output)

    def test_enforce_fails_on_dangerous_drift(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = "HO-DET-001 is production-ready SOCaaS."
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("STATUS=fail", output)


if __name__ == "__main__":
    unittest.main()

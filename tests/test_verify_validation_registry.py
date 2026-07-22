import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_validation_registry.py"
SPEC = importlib.util.spec_from_file_location("verify_validation_registry", MODULE_PATH)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class VerifyValidationRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        for rel in (
            "validation/example",
            "reports/example",
            "scripts",
        ):
            (self.root / rel).mkdir(parents=True, exist_ok=True)
        self._write_json(
            "validation/example/validation-cases.json",
            {"detection_id": "EX-DET-001", "cases": {"positive": [{"id": "pos-001"}], "negative": [{"id": "neg-001"}]}},
        )
        self._write_json(
            "reports/example/validation-result.json",
            {
                "detection_id": "EX-DET-001",
                "status": "pass",
                "total_cases": 2,
                "positive_cases": 1,
                "negative_cases": 1,
                "public_safe_status": "NOT_PUBLIC_SAFE",
                "runtime_active": False,
                "signal_observed": False,
            },
        )
        (self.root / "reports/example/validation-result.md").write_text("ok\n", encoding="utf-8")
        for rel in (
            "scripts/validate-example.py",
            "scripts/verify-example-parity.py",
            "scripts/scan-example-claims.py",
        ):
            (self.root / rel).write_text("print('ok')\n", encoding="utf-8")
        (self.root / "scripts/validate-example.py").write_text(
            "# implements --source-contract\nprint('ok')\n",
            encoding="utf-8",
        )
        self.registry = {
            "schema_version": 1,
            "registry_status": "VALIDATION_CONTRACT_ENFORCED",
            "human_review_required": True,
            "ai_disposition_authority": False,
            "packages": [self._package()],
        }

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write_json(self, rel_path, data):
        path = self.root / rel_path
        path.write_text(json.dumps(data), encoding="utf-8")

    def _package(self):
        return {
            "detection_id": "EX-DET-001",
            "validation_kind": "controlled_validation",
            "validation_package_path": "validation/example",
            "fixture_file": "validation/example/validation-cases.json",
            "report_json": "reports/example/validation-result.json",
            "report_markdown": "reports/example/validation-result.md",
            "validator_script": "scripts/validate-example.py",
            "parity_script": "scripts/verify-example-parity.py",
            "claim_boundary_script": "scripts/scan-example-claims.py",
            "expected_fixture_count": 2,
            "expected_positive_count": 1,
            "expected_negative_count": 1,
            "proof_ceiling": "CONTROLLED_TEST_VALIDATED",
            "public_safe_status": "NOT_PUBLIC_SAFE",
            "runtime_status": False,
            "signal_status": False,
            "source_dependency_required": False,
            "ci_source_dependency_mode": "none",
            "notes": "controlled validation only",
        }

    def test_valid_registry_passes(self):
        packages = module.validate_registry(self.registry, self.root)
        self.assertEqual([package["detection_id"] for package in packages], ["EX-DET-001"])

    def test_duplicate_detection_id_fails(self):
        registry = copy.deepcopy(self.registry)
        registry["packages"].append(copy.deepcopy(registry["packages"][0]))
        with self.assertRaisesRegex(module.RegistryFailure, "duplicate detection_id"):
            module.validate_registry(registry, self.root)

    def test_duplicate_authoritative_path_fails(self):
        registry = copy.deepcopy(self.registry)
        duplicate = copy.deepcopy(registry["packages"][0])
        duplicate["detection_id"] = "EX-DET-002"
        registry["packages"].append(duplicate)
        with self.assertRaisesRegex(module.RegistryFailure, "reuses .* already owned"):
            module.validate_registry(registry, self.root)

    def test_duplicate_authoritative_path_alias_fails(self):
        registry = copy.deepcopy(self.registry)
        duplicate = copy.deepcopy(registry["packages"][0])
        duplicate["detection_id"] = "EX-DET-002"
        duplicate["fixture_file"] = "VALIDATION/EXAMPLE/VALIDATION-CASES.JSON"
        registry["packages"].append(duplicate)
        with self.assertRaisesRegex(module.RegistryFailure, "reuses .* already owned"):
            module.validate_registry(registry, self.root)

    def test_authoritative_path_escape_fails(self):
        registry = copy.deepcopy(self.registry)
        registry["packages"][0]["fixture_file"] = "../outside.json"
        with self.assertRaisesRegex(module.RegistryFailure, "repo-relative"):
            module.validate_registry(registry, self.root)

    def test_missing_file_fails(self):
        registry = copy.deepcopy(self.registry)
        registry["packages"][0]["validator_script"] = "scripts/missing.py"
        with self.assertRaisesRegex(module.RegistryFailure, "missing"):
            module.validate_registry(registry, self.root)

    def test_truthy_public_safe_runtime_signal_promotion_fails(self):
        for field, value in (
            ("public_safe_status", "PUBLIC_SAFE"),
            ("runtime_status", True),
            ("signal_status", "signal_observed"),
        ):
            with self.subTest(field=field):
                registry = copy.deepcopy(self.registry)
                registry["packages"][0][field] = value
                with self.assertRaises(module.RegistryFailure):
                    module.validate_registry(registry, self.root)

    def test_registry_requires_human_review_and_blocks_ai_authority(self):
        for field, value in (
            ("human_review_required", False),
            ("ai_disposition_authority", True),
        ):
            with self.subTest(field=field):
                registry = copy.deepcopy(self.registry)
                registry[field] = value
                with self.assertRaises(module.RegistryFailure):
                    module.validate_registry(registry, self.root)

    def test_malformed_registry_fails(self):
        bad_path = self.root / "bad.yml"
        bad_path.write_text("{not-json", encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "malformed"):
            module.load_registry(bad_path)

    def test_missing_validator_parity_boundary_script_fails(self):
        for field in ("validator_script", "parity_script", "claim_boundary_script"):
            with self.subTest(field=field):
                registry = copy.deepcopy(self.registry)
                registry["packages"][0][field] = None
                with self.assertRaisesRegex(module.RegistryFailure, "missing"):
                    module.validate_registry(registry, self.root)

    def test_ci_source_dependency_mode_must_match_source_dependency_requirement(self):
        registry = copy.deepcopy(self.registry)
        registry["packages"][0]["ci_source_dependency_mode"] = "skip_if_missing"
        with self.assertRaisesRegex(module.RegistryFailure, "ci_source_dependency_mode must be none"):
            module.validate_registry(registry, self.root)

    def test_skip_if_missing_mode_allowed_when_source_dependency_required(self):
        registry = copy.deepcopy(self.registry)
        registry["packages"][0]["source_dependency_required"] = True
        registry["packages"][0]["ci_source_dependency_mode"] = "skip_if_missing"
        packages = module.validate_registry(registry, self.root)
        self.assertTrue(packages[0]["source_dependency_required"])

    def test_source_dependency_requires_validator_contract_behavior(self):
        registry = copy.deepcopy(self.registry)
        registry["packages"][0]["source_dependency_required"] = True
        registry["packages"][0]["ci_source_dependency_mode"] = "skip_if_missing"
        (self.root / "scripts/validate-example.py").write_text("print('no source mode')\n", encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "does not implement --source-contract"):
            module.validate_registry(registry, self.root)

    def test_controlled_validation_requires_positive_and_negative_cases(self):
        registry = copy.deepcopy(self.registry)
        registry["packages"][0]["expected_negative_count"] = 0
        registry["packages"][0]["expected_fixture_count"] = 1
        with self.assertRaisesRegex(module.RegistryFailure, "positive integer fixture counts"):
            module.validate_registry(registry, self.root)

    def test_report_cannot_promote_ai_disposition_authority(self):
        report_path = self.root / "reports/example/validation-result.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["ai_disposition_authority"] = True
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "AI disposition authority"):
            module.validate_registry(self.registry, self.root)

    def test_visibility_contract_is_explicitly_blocked_for_fixture_review(self):
        package = self._package()
        package["validation_kind"] = "visibility_contract"
        self.assertEqual(module.review_eligibility(package), "BLOCKED")

    def test_contract_only_inventory_is_expected_blocked(self):
        package = self._package()
        package["validation_kind"] = "baseline_contract"
        registry_path = self.root / "validation" / "VALIDATION_REGISTRY.yml"
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(json.dumps(self.registry), encoding="utf-8")
        inventory = module.build_inventory([package], self.root)
        self.assertEqual(inventory["packages"][0]["review_eligibility"], "CONTRACT_ONLY")
        self.assertEqual(inventory["packages"][0]["expected_fixture_review_outcome"], "BLOCKED")

    def test_inventory_is_revision_linked_and_contains_fingerprints(self):
        registry_path = self.root / "validation" / "VALIDATION_REGISTRY.yml"
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(json.dumps(self.registry), encoding="utf-8")
        packages = module.validate_registry(self.registry, self.root)
        inventory = module.build_inventory(packages, self.root)
        item = inventory["packages"][0]
        self.assertEqual(inventory["authority_role"], "controlled_validation")
        self.assertEqual(len(inventory["authoritative_fingerprint"]), 64)
        self.assertIn(inventory["source_freshness_state"], {"CURRENT", "WORKTREE_MODIFIED_OR_UNRESOLVED"})
        self.assertIn("worktree_clean", inventory)
        self.assertEqual(item["review_eligibility"], "PASS_CAPABLE")
        self.assertFalse(item["ai_disposition_authority"])
        self.assertIn("fixture_file", item["source_fingerprints"])
        self.assertNotIn(str(self.root), str(inventory))

    def test_source_matrix_status_disagreement_fails(self):
        detections_root = self.root / "detections-repo"
        status_dir = detections_root / "detections" / "example"
        status_dir.mkdir(parents=True)
        matrix_data = {
            "entries": [
                {
                    "detection_id": "EX-DET-001",
                    "package_path": "detections/example",
                    "validation_expected_owner": "hawkinsoperations-validation",
                    "validation_status_if_known": "VALIDATION_PLANNED",
                }
            ]
        }
        (detections_root / "detections" / "DETECTION_PROMOTION_MATRIX.yml").write_text(
            yaml.safe_dump(matrix_data),
            encoding="utf-8",
        )
        (status_dir / "status.yml").write_text(
            yaml.safe_dump(
                {
                    "detection_id": "EX-DET-001",
                    "validation_status": "VALIDATION_PLANNED",
                    "public_safe_status": "NOT_PUBLIC_SAFE",
                    "runtime_active": False,
                    "signal_observed": False,
                }
            ),
            encoding="utf-8",
        )
        package = self._package()
        package["source_dependency_required"] = True
        package["ci_source_dependency_mode"] = "skip_if_missing"
        with self.assertRaisesRegex(module.RegistryFailure, "source/validation status disagreement"):
            module.validate_source_parity([package], detections_root)


if __name__ == "__main__":
    unittest.main()

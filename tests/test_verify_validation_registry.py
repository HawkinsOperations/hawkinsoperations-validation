import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


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
        self.registry = {
            "schema_version": 1,
            "registry_status": "VALIDATION_CONTRACT_ENFORCED",
            "human_review_required": True,
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


if __name__ == "__main__":
    unittest.main()

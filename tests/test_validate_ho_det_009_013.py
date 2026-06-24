from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HoxlineExpandedValidationTests(unittest.TestCase):
    def assert_package_passes(self, detection_slug: str, module_name: str) -> None:
        validator = load_script(module_name, ROOT / "scripts" / f"validate-{detection_slug}.py")
        cases = validator.load_json(
            ROOT / "validation" / "successor" / detection_slug / "validation-cases.json",
            f"{detection_slug} validation cases",
        )
        report = validator.build_report(cases, source_contract="skip-if-missing")

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["total_cases"], report["positive_cases"] + report["negative_cases"])
        self.assertFalse(report["runtime_active"])
        self.assertFalse(report["signal_observed"])
        self.assertEqual(report["public_safe_status"], "NOT_PUBLIC_SAFE")
        self.assertEqual(report["proof_ceiling"], "CONTROLLED_TEST_VALIDATED")
        self.assertEqual(report["missed_positive_cases"], [])
        self.assertEqual(report["false_positive_negative_cases"], [])

    def test_ho_det_009_controlled_fixture_package_passes(self) -> None:
        self.assert_package_passes("ho-det-009", "validate_ho_det_009")

    def test_ho_det_013_controlled_fixture_package_passes(self) -> None:
        self.assert_package_passes("ho-det-013", "validate_ho_det_013")


if __name__ == "__main__":
    unittest.main()

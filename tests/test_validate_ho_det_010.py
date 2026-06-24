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
class HoxlineHoDet010ValidationTests(unittest.TestCase):
    def test_ho_det_010_controlled_fixture_package_passes(self) -> None:
        validator = load_script("validate_ho_det_010", ROOT / "scripts" / "validate-ho-det-010.py")
        cases = validator.load_json(ROOT / "validation" / "successor" / "ho-det-010" / "validation-cases.json", "HO-DET-010 validation cases")
        report = validator.build_report(cases, source_contract="skip-if-missing")
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["total_cases"], 10)
        self.assertEqual(report["positive_cases"], 5)
        self.assertEqual(report["negative_cases"], 5)
        self.assertFalse(report["runtime_active"])
        self.assertFalse(report["signal_observed"])
        self.assertEqual(report["public_safe_status"], "NOT_PUBLIC_SAFE")
        self.assertEqual(report["missed_positive_cases"], [])
        self.assertEqual(report["false_positive_negative_cases"], [])
if __name__ == "__main__":
    unittest.main()

import importlib.util
import json
import sys
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_all_validation_packages.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("verify_all_validation_packages", MODULE_PATH)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class VerifyAllValidationPackagesTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        (self.root / "scripts").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write_script(self, rel_path, exit_code=0, supports_source_contract=False):
        path = self.root / rel_path
        source_contract_line = "# supports --source-contract\n" if supports_source_contract else ""
        path.write_text(
            textwrap.dedent(
                f"""\
                import sys
                {source_contract_line}
                print("script ok")
                raise SystemExit({exit_code})
                """
            ),
            encoding="utf-8",
        )

    def _package(self, validator="scripts/pass.py"):
        return {
            "detection_id": "EX-DET-001",
            "validator_script": validator,
            "parity_script": None,
            "claim_boundary_script": None,
            "source_dependency_required": False,
            "ci_source_dependency_mode": "none",
        }

    def test_run_package_commands_returns_zero_when_checks_pass(self):
        self._write_script("scripts/pass.py", 0)
        self.assertEqual(module.run_package_commands([self._package()], self.root), 0)

    def test_run_package_commands_returns_nonzero_when_check_fails(self):
        self._write_script("scripts/fail.py", 1)
        self.assertEqual(module.run_package_commands([self._package("scripts/fail.py")], self.root), 1)

    def test_build_commands_defaults_to_standalone_skip_if_missing(self):
        self._write_script("scripts/pass.py", supports_source_contract=True)
        package = self._package()
        package["source_dependency_required"] = True
        package["ci_source_dependency_mode"] = "required"
        commands = module.build_commands(package, self.root)
        self.assertIn("--source-contract", commands[0][1])
        self.assertIn("skip-if-missing", commands[0][1])

    def test_build_commands_requires_source_contract_in_ci_mode(self):
        self._write_script("scripts/pass.py", supports_source_contract=True)
        package = self._package()
        package["source_dependency_required"] = True
        package["ci_source_dependency_mode"] = "required"
        commands = module.build_commands(package, self.root, "required")
        self.assertEqual(commands[0][1][-2:], ["--source-contract", "required"])

    def test_build_commands_rejects_source_backed_validator_without_support(self):
        self._write_script("scripts/pass.py", supports_source_contract=False)
        package = self._package()
        package["source_dependency_required"] = True
        package["ci_source_dependency_mode"] = "required"
        with self.assertRaisesRegex(ValueError, "lacks required source-contract"):
            module.build_commands(package, self.root, "required")

    def test_required_mode_rejects_non_required_ci_contract(self):
        self._write_script("scripts/pass.py", supports_source_contract=True)
        package = self._package()
        package["source_dependency_required"] = True
        package["ci_source_dependency_mode"] = "skip_if_missing"
        with self.assertRaisesRegex(ValueError, "must fail closed"):
            module.build_commands(package, self.root, "required")

    def test_source_backed_parity_receives_the_selected_contract_mode(self):
        self._write_script("scripts/pass.py", supports_source_contract=True)
        self._write_script("scripts/parity.py", supports_source_contract=True)
        package = self._package()
        package.update(source_dependency_required=True, ci_source_dependency_mode="required",
                       parity_script="scripts/parity.py")
        for mode in ("required", "skip-if-missing"):
            with self.subTest(mode=mode):
                commands = module.build_commands(package, self.root, mode)
                self.assertEqual(commands[1][1][-2:], ["--source-contract", mode])

    def test_standalone_cli_checks_reports_and_preserves_missing_source_gates(self):
        clone = self.root / "hawkinsoperations-validation"
        for directory in ("scripts", "validation", "reports", "docs", ".github"):
            shutil.copytree(ROOT / directory, clone / directory,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        command = [sys.executable, "-B", "scripts/verify_all_validation_packages.py"]
        standalone = subprocess.run(command, cwd=clone, capture_output=True, text=True)
        self.assertEqual(standalone.returncode, 0, standalone.stdout + standalone.stderr)
        for detection_id in ("HO-DET-010", "HO-DET-011", "HO-DET-009", "HO-DET-013"):
            self.assertIn(f"{detection_id} | parity | pass", standalone.stdout)
        required = subprocess.run(command + ["--source-contract", "required"],
                                  cwd=clone, capture_output=True, text=True)
        self.assertNotEqual(required.returncode, 0, required.stdout + required.stderr)
        report_path = clone / "reports/ho-det-010/validation-result.json"
        original_report = report_path.read_bytes()
        report = json.loads(original_report)
        report["total_cases"] += 1
        report_path.write_text(json.dumps(report), encoding="utf-8")
        drift = subprocess.run(command, cwd=clone, capture_output=True, text=True)
        self.assertNotEqual(drift.returncode, 0, drift.stdout + drift.stderr)
        report_path.write_bytes(original_report)
        # A partially present source contract is never skipped as an absent handoff.
        source = self.root / "hawkinsoperations-detections/detections/successor/ho-det-010"
        source.mkdir(parents=True)
        (source / "README.md").write_text("incomplete source fixture", encoding="utf-8")
        incomplete = subprocess.run(command, cwd=clone, capture_output=True, text=True)
        self.assertNotEqual(incomplete.returncode, 0, incomplete.stdout + incomplete.stderr)

    def test_unknown_source_contract_mode_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported source-contract mode"):
            module.build_commands(self._package(), self.root, "fallback")


if __name__ == "__main__":
    unittest.main()

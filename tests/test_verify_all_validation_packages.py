import importlib.util
import sys
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

    def _write_script(self, rel_path, exit_code=0):
        path = self.root / rel_path
        path.write_text(
            textwrap.dedent(
                f"""\
                import sys
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

    def test_build_commands_adds_skip_if_missing_for_source_backed_validator(self):
        package = self._package()
        package["source_dependency_required"] = True
        package["ci_source_dependency_mode"] = "skip-if-missing"
        commands = module.build_commands(package)
        self.assertIn("--source-contract", commands[0][1])
        self.assertIn("skip-if-missing", commands[0][1])


if __name__ == "__main__":
    unittest.main()

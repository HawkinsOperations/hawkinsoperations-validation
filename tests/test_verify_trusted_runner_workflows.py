from __future__ import annotations

import tempfile
import unittest
import importlib.util
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "verify-trusted-runner-workflows.py"
)
SPEC = importlib.util.spec_from_file_location(
    "verify_trusted_runner_workflows", SCRIPT_PATH
)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)
scan_repo = verifier.scan_repo


class TrustedRunnerWorkflowVerifierTests(unittest.TestCase):
    def write_workflow(self, repo: Path, name: str, text: str) -> None:
        workflow_dir = repo / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)
        (workflow_dir / name).write_text(text, encoding="utf-8")

    def scan_single_workflow(self, text: str):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir) / "hawkinsoperations-validation"
            repo.mkdir()
            self.write_workflow(repo, "check.yml", text)
            return scan_repo("hawkinsoperations-validation", repo)

    def test_fails_pull_request_self_hosted(self):
        findings = self.scan_single_workflow(
            """
name: check
on:
  pull_request:
jobs:
  exposed:
    runs-on: [self-hosted, Linux, X64, ho-runner-01]
    steps:
      - run: python scripts/verify_validation_contract.py
"""
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("exposed", findings[0]["job_name"])
        self.assertEqual("pull_request", findings[0]["trigger"])

    def test_fails_pull_request_target_self_hosted(self):
        findings = self.scan_single_workflow(
            """
name: check
on:
  pull_request_target:
jobs:
  exposed:
    runs-on: self-hosted
    steps:
      - run: python scripts/verify_validation_contract.py
"""
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("pull_request_target", findings[0]["trigger"])

    def test_passes_workflow_dispatch_self_hosted(self):
        findings = self.scan_single_workflow(
            """
name: trusted
on:
  workflow_dispatch:
jobs:
  trusted:
    runs-on: [self-hosted, Linux, X64, ho-runner-01]
    steps:
      - run: python scripts/verify_validation_contract.py
"""
        )
        self.assertEqual([], findings)

    def test_passes_pull_request_github_hosted(self):
        findings = self.scan_single_workflow(
            """
name: check
on:
  pull_request:
jobs:
  public-check:
    runs-on: ubuntu-latest
    steps:
      - run: python scripts/verify_validation_contract.py
"""
        )
        self.assertEqual([], findings)

    def test_passes_multiple_pull_request_github_hosted_jobs(self):
        findings = self.scan_single_workflow(
            """
name: check
on:
  pull_request:
jobs:
  first:
    runs-on: ubuntu-latest
    steps:
      - run: python scripts/verify_validation_contract.py
  second:
    runs-on: windows-latest
    steps:
      - run: python scripts/verify_validation_registry.py
"""
        )
        self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
BASELINE_WORKFLOW = ROOT / ".github" / "workflows" / "baseline-validation-contract.yml"
CROSS_REPO_WORKFLOW = ROOT / ".github" / "workflows" / "cross-repo-claim-parity.yml"


class ValidationCIAuthorityTests(unittest.TestCase):
    def _workflow(self, path: Path) -> tuple[dict, str]:
        text = path.read_text(encoding="utf-8")
        payload = yaml.safe_load(text)
        self.assertIsInstance(payload, dict)
        return payload, text

    def test_required_validation_workflow_runs_every_owning_verifier(self):
        workflow, text = self._workflow(BASELINE_WORKFLOW)
        self.assertEqual(workflow.get("permissions"), {"contents": "read"})
        required_commands = (
            "refresh_validation_source_manifest.py",
            "verify_validation_registry.py",
            "verify_all_validation_packages.py",
            "verify_validation_contract.py",
            "verify_wazuh_logtest_registry.py",
            "verify_ho_lab_wazuh_001.py",
            "unittest discover -s tests",
            "git diff --check",
        )
        for command in required_commands:
            with self.subTest(command=command):
                self.assertIn(command, text)
        self.assertIn("refs/remotes/origin/convergence-source", text)
        self.assertIn("persist-credentials: false", text)
        self.assertNotIn("skip-if-missing", text)
        self.assertNotIn("skip_if_missing", text)
        self.assertNotIn("continue-on-error", text)
        self.assertNotIn("|| true", text)

    def test_cross_repo_claim_parity_is_fail_closed_and_ref_explicit(self):
        workflow, text = self._workflow(CROSS_REPO_WORKFLOW)
        self.assertEqual(workflow.get("permissions"), {"contents": "read"})
        self.assertIn("CONVERGENCE_SOURCE_REF", text)
        self.assertNotIn("--report-only", text)
        self.assertIn("verify_validation_registry.py", text)
        self.assertIn("verify_all_validation_packages.py", text)
        self.assertIn("refs/remotes/origin/convergence-source", text)
        self.assertNotIn("continue-on-error", text)
        self.assertNotIn("|| true", text)
        checkout_steps = [
            step
            for step in workflow["jobs"]["cross-repo-claim-parity"]["steps"]
            if str(step.get("uses", "")).startswith("actions/checkout@")
        ]
        self.assertEqual(len(checkout_steps), 6)
        for step in checkout_steps:
            self.assertIs(step.get("with", {}).get("persist-credentials"), False)
        for step in checkout_steps[1:]:
            self.assertEqual(
                step.get("with", {}).get("ref"),
                "${{ env.CONVERGENCE_SOURCE_REF }}",
            )


if __name__ == "__main__":
    unittest.main()

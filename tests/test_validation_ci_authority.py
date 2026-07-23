import contextlib
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
BASELINE_WORKFLOW = ROOT / ".github" / "workflows" / "baseline-validation-contract.yml"
CROSS_REPO_WORKFLOW = ROOT / ".github" / "workflows" / "cross-repo-claim-parity.yml"
AI_TRIAGE_VERIFIER = ROOT / "scripts" / "verify-ho-det-001-ai-triage-schemas.py"
AI_TRIAGE_PACKET = (
    ROOT / "validation" / "successor" / "ho-det-001" / "autosoc-triage-packet.json"
)
AI_TRIAGE_SUMMARY = (
    ROOT / "validation" / "successor" / "ho-det-001" / "llm-summary.json"
)
HO_DET_001_RESULT = ROOT / "reports" / "ho-det-001" / "validation-result.json"


def load_script(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def run_workflow_vocabulary_guard(workflow_path: Path, files: dict[str, bytes]):
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    job = next(iter(workflow["jobs"].values()))
    step = next(
        item
        for item in job["steps"]
        if item.get("name") == "Reject retired fixture vocabulary"
    )
    source = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
        for relative, content in files.items():
            (root / relative).write_bytes(content)
        subprocess.run(["git", "add", "--", *files], cwd=root, check=True)
        return subprocess.run(
            [sys.executable, "-c", source],
            cwd=root,
            capture_output=True,
            text=True,
        )


class ValidationCIAuthorityTests(unittest.TestCase):
    def _workflow(self, path: Path) -> tuple[dict, str]:
        text = path.read_text(encoding="utf-8")
        payload = yaml.safe_load(text)
        self.assertIsInstance(payload, dict)
        return payload, text

    def _assert_immutable_actions_and_dependencies(self, text: str) -> None:
        action_refs = re.findall(
            r"^\s*uses:\s*[^@\s]+@([^\s#]+)",
            text,
            re.MULTILINE,
        )
        self.assertTrue(action_refs)
        self.assertTrue(
            all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
        )
        self.assertIn("PyYAML==6.0.2", text)

    def test_required_validation_workflow_runs_every_owning_verifier(self):
        workflow, text = self._workflow(BASELINE_WORKFLOW)
        self._assert_immutable_actions_and_dependencies(text)
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
        job = workflow["jobs"]["baseline-hero-validation-contract"]
        source_sha = job["env"]["DETECTION_SOURCE_SHA"]
        self.assertRegex(source_sha, r"^[0-9a-f]{40}$")
        detection_checkout = next(
            step
            for step in job["steps"]
            if step.get("name") == "Checkout declared detection source"
        )
        self.assertEqual(
            detection_checkout["with"]["ref"],
            "${{ env.DETECTION_SOURCE_SHA }}",
        )
        self.assertIn(
            'rev-parse HEAD)" = "$DETECTION_SOURCE_SHA"',
            text,
        )
        self.assertIn('retired = "".join(("syn", "thetic"))', text)
        self.assertIn('unicodedata.normalize("NFKC"', text)
        self.assertIn('["git", "ls-files", "-z"]', text)
        self.assertIn('["git", "show", f":{relative}"]', text)
        self.assertIn("tracked non-binary content contains NUL", text)
        self.assertGreaterEqual(text.count("check=True"), 2)
        self.assertNotIn("git grep", text)
        self.assertIn("persist-credentials: false", text)
        self.assertNotIn("feature/hoxline-case-growth-convergence-v1", text)
        self.assertNotIn("refs/remotes/origin/convergence-source", text)
        self.assertNotIn("skip-if-missing", text)
        self.assertNotIn("skip_if_missing", text)
        self.assertNotIn("continue-on-error", text)
        self.assertNotIn("|| true", text)

    def test_required_vocabulary_guard_rejects_nfkc_utf16_and_git_errors(self):
        retired = "".join(("syn", "thetic"))
        fullwidth = "".join(chr(ord(character) + 0xFEE0) for character in retired)
        self.assertEqual(
            retired,
            unicodedata.normalize("NFKC", fullwidth).casefold(),
        )
        result = run_workflow_vocabulary_guard(
            BASELINE_WORKFLOW,
            {
                f"fixture-{fullwidth}.txt": b"controlled-test\n",
                "content-fixture.txt": f"{fullwidth}\n".encode(),
                "utf16-fixture.md": f"{retired}\n".encode("utf-16-le"),
            },
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("utf16-fixture.md", result.stderr + result.stdout)
        workflow = yaml.safe_load(BASELINE_WORKFLOW.read_text(encoding="utf-8"))
        step = next(
            item
            for item in next(iter(workflow["jobs"].values()))["steps"]
            if item.get("name") == "Reject retired fixture vocabulary"
        )
        source = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        with tempfile.TemporaryDirectory() as temp:
            operational = subprocess.run(
                [sys.executable, "-c", source],
                cwd=temp,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, operational.returncode)

    def test_cross_repo_claim_parity_is_fail_closed_and_ref_explicit(self):
        workflow, text = self._workflow(CROSS_REPO_WORKFLOW)
        self._assert_immutable_actions_and_dependencies(text)
        self.assertEqual(workflow.get("permissions"), {"contents": "read"})
        self.assertNotIn("--report-only", text)
        self.assertIn("verify_validation_registry.py", text)
        self.assertIn("verify_all_validation_packages.py", text)
        self.assertIn("verify_cross_repo_claim_parity.py", text)
        self.assertIn("--repo-root ..", text)
        self.assertIn("--enforce", text)
        self.assertNotIn("CONVERGENCE_SOURCE_REF", text)
        self.assertNotIn("feature/hoxline-case-growth-convergence-v1", text)
        self.assertNotIn("refs/remotes/origin/convergence-source", text)
        self.assertNotIn("continue-on-error", text)
        self.assertNotIn("|| true", text)
        job = workflow["jobs"]["cross-repo-claim-parity"]
        expected_refs = {
            "Checkout detections repo": "DETECTIONS_SOURCE_SHA",
            "Checkout proof repo": "PROOF_SOURCE_SHA",
            "Checkout website repo": "WEBSITE_SOURCE_SHA",
            "Checkout org front door repo": "COMMAND_CENTER_SOURCE_SHA",
            "Checkout platform repo": "PLATFORM_SOURCE_SHA",
        }
        for env_name in expected_refs.values():
            self.assertTrue(
                re.fullmatch(r"[0-9a-f]{40}", job["env"][env_name]),
                env_name,
            )
        checkout_steps = [
            step
            for step in job["steps"]
            if str(step.get("uses", "")).startswith("actions/checkout@")
        ]
        self.assertEqual(len(checkout_steps), 6)
        for step in checkout_steps:
            self.assertIs(step.get("with", {}).get("persist-credentials"), False)
        for step in checkout_steps[1:]:
            env_name = expected_refs[step["name"]]
            self.assertEqual(
                step.get("with", {}).get("ref"),
                f"${{{{ env.{env_name} }}}}",
            )
            self.assertIn(
                f'rev-parse HEAD)" = "${env_name}"',
                text,
            )

    def test_ho_det_001_triage_packet_binds_current_result_and_rejects_stale_hash(
        self,
    ):
        verifier = load_script(AI_TRIAGE_VERIFIER, "ho_det_001_ai_triage_verifier")
        schema = json.loads(
            verifier.INPUT_SCHEMA.read_text(encoding="utf-8")
        )
        packet = json.loads(AI_TRIAGE_PACKET.read_text(encoding="utf-8"))
        result_text = HO_DET_001_RESULT.read_text(encoding="utf-8")
        expected_hash = hashlib.sha256(result_text.encode("utf-8")).hexdigest()
        self.assertEqual(expected_hash, packet["validation_result_hash"])

        stale_packet = dict(packet)
        stale_packet["validation_result_hash"] = "0" * 64
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            verifier.verify_triage_packet(schema, stale_packet)

        output_schema = json.loads(
            verifier.OUTPUT_SCHEMA.read_text(encoding="utf-8")
        )
        summary = json.loads(AI_TRIAGE_SUMMARY.read_text(encoding="utf-8"))
        packet_text = AI_TRIAGE_PACKET.read_text(encoding="utf-8")
        expected_packet_hash = hashlib.sha256(packet_text.encode("utf-8")).hexdigest()
        self.assertEqual(expected_packet_hash, summary["input_packet_hash"])

        stale_summary = dict(summary)
        stale_summary["input_packet_hash"] = "0" * 64
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            verifier.verify_llm_summary(output_schema, stale_summary)


if __name__ == "__main__":
    unittest.main()

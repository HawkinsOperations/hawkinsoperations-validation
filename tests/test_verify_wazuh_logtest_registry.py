import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_wazuh_logtest_registry.py"
SPEC = importlib.util.spec_from_file_location("verify_wazuh_logtest_registry", MODULE_PATH)
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)


class VerifyWazuhLogtestRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        for rel in ("validation/wazuh", "validation/wazuh/samples", "scripts"):
            (self.root / rel).mkdir(parents=True, exist_ok=True)
        self.sample_path = self.root / "validation/wazuh/samples/ho-det-011-service-create.json"
        self.sample_path.write_text(
            json.dumps(
                {
                    "detection_id": "HO-DET-011",
                    "sample_scope": "controlled_synthetic_wazuh_logtest_candidate",
                    "runtime_status": False,
                    "signal_status": False,
                    "public_safe_status": "NOT_PUBLIC_SAFE",
                    "logtest_input": "{\"win\":{\"system\":{\"eventID\":\"7045\"}}}",
                }
            ),
            encoding="utf-8",
        )
        self.registry = {
            "schema_version": 1,
            "registry_status": "WAZUH_LOGTEST_CONTRACT_ENFORCED",
            "proof_ceiling": "CONTROLLED_TEST_ONLY_NOT_RUNTIME_PROOF",
            "public_safe_status": "NOT_PUBLIC_SAFE",
            "runtime_status": False,
            "signal_status": False,
            "entries": [self._entry()],
        }
        self.registry_path = self.root / "validation/wazuh/WAZUH_LOGTEST_REGISTRY.json"
        self.write_registry(self.registry)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _entry(self):
        return {
            "detection_id": "HO-DET-011",
            "status": "STATIC_CONTRACT_READY",
            "wazuh_rule_source": "detections/successor/ho-det-011/wazuh.xml",
            "sample_event": "validation/wazuh/samples/ho-det-011-service-create.json",
            "expected_rule_ids": [910011],
            "expected_levels": [8],
            "expected_groups": ["ho-det-011", "source-only", "validation-planned"],
            "expected_mitre_ids": ["T1543.003"],
            "runtime_status": False,
            "signal_status": False,
            "public_safe_status": "NOT_PUBLIC_SAFE",
            "execution_mode": "static_ci_optional_private_logtest",
            "notes": "static CI contract only",
        }

    def write_registry(self, data):
        self.registry_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def write_wazuh_rule_source(self, xml):
        rule_path = self.root / "detections/successor/ho-det-011/wazuh.xml"
        rule_path.parent.mkdir(parents=True, exist_ok=True)
        rule_path.write_text(xml, encoding="utf-8")
        return rule_path

    def test_valid_registry_passes_static_ci(self):
        entries = module.verify_registry(self.registry_path, self.root, detections_root=None, run_logtest=False, print_summary=False)
        self.assertEqual([entry["detection_id"] for entry in entries], ["HO-DET-011"])

    def test_parent_group_name_labels_satisfy_expected_groups(self):
        self.write_wazuh_rule_source(
            """
<group name="ho-det-011,validation-planned">
  <rule id="910011" level="8">
    <description>Service creation</description>
    <mitre><id>T1543.003</id></mitre>
    <group>source-only</group>
  </rule>
</group>
""".strip()
        )

        module.verify_registry(self.registry_path, self.root, detections_root=self.root, run_logtest=False, print_summary=False)

    def test_child_group_labels_still_satisfy_expected_groups(self):
        registry = copy.deepcopy(self.registry)
        registry["entries"][0]["expected_groups"] = ["ho-det-011", "source-only", "validation-planned"]
        self.write_registry(registry)
        self.write_wazuh_rule_source(
            """
<group name="wrapper-only">
  <rule id="910011" level="8">
    <description>Service creation</description>
    <mitre><id>T1543.003</id></mitre>
    <group>ho-det-011,source-only,validation-planned</group>
  </rule>
</group>
""".strip()
        )

        module.verify_registry(self.registry_path, self.root, detections_root=self.root, run_logtest=False, print_summary=False)

    def test_missing_sample_fails(self):
        registry = copy.deepcopy(self.registry)
        registry["entries"][0]["sample_event"] = "validation/wazuh/samples/missing.json"
        self.write_registry(registry)
        with self.assertRaisesRegex(module.WazuhLogtestRegistryError, "missing sample_event"):
            module.verify_registry(self.registry_path, self.root, detections_root=None, run_logtest=False, print_summary=False)

    def test_truthy_runtime_or_signal_claim_fails(self):
        registry = copy.deepcopy(self.registry)
        registry["entries"][0]["signal_status"] = "SIGNAL_OBSERVED"
        self.write_registry(registry)
        with self.assertRaisesRegex(module.WazuhLogtestRegistryError, "signal_status"):
            module.verify_registry(self.registry_path, self.root, detections_root=None, run_logtest=False, print_summary=False)

    def test_public_safe_promotion_claim_fails(self):
        registry = copy.deepcopy(self.registry)
        registry["entries"][0]["public_safe_status"] = "PUBLIC_SAFE"
        self.write_registry(registry)
        with self.assertRaisesRegex(module.WazuhLogtestRegistryError, "public_safe_status"):
            module.verify_registry(self.registry_path, self.root, detections_root=None, run_logtest=False, print_summary=False)

    def test_identity_detection_preferred_to_wazuh_fails(self):
        registry = copy.deepcopy(self.registry)
        identity = self._entry()
        identity["detection_id"] = "ID-DET-001"
        registry["entries"].append(identity)
        self.write_registry(registry)
        with self.assertRaisesRegex(module.WazuhLogtestRegistryError, "identity detections"):
            module.verify_registry(self.registry_path, self.root, detections_root=None, run_logtest=False, print_summary=False)


if __name__ == "__main__":
    unittest.main()

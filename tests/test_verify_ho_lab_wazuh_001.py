import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_ho_lab_wazuh_001.py"
SPEC = importlib.util.spec_from_file_location("verify_ho_lab_wazuh_001", MODULE_PATH)
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)


class VerifyHOLabWazuh001Tests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name) / "hawkinsoperations-validation"
        self.detections_root = Path(self.tmpdir.name) / "hawkinsoperations-detections"
        (self.root / "validation/wazuh/labs").mkdir(parents=True)
        (self.root / "validation/wazuh/samples").mkdir(parents=True)
        (self.detections_root / "detections/wazuh").mkdir(parents=True)
        (self.detections_root / "detections/successor/ho-det-011").mkdir(parents=True)
        (self.detections_root / "detections/successor/ho-det-012").mkdir(parents=True)
        (self.detections_root / "detections/successor/ho-det-001").mkdir(parents=True)
        shutil.copy2(ROOT / "validation/wazuh/labs/HO-LAB-WAZUH-001.manifest.json", self.manifest_path)
        shutil.copy2(ROOT / "validation/wazuh/labs/HO-LAB-WAZUH-001.md", self.root / "validation/wazuh/labs/HO-LAB-WAZUH-001.md")
        self.write_logtest_registry()
        self.write_samples()
        self.write_source_registry()
        self.write_wazuh_xml("ho-det-011", 910011, 8, "T1543.003")
        self.write_wazuh_xml("ho-det-012", 910021, 7, "T1053.005")

    def tearDown(self):
        self.tmpdir.cleanup()

    @property
    def manifest_path(self):
        return self.root / "validation/wazuh/labs/HO-LAB-WAZUH-001.manifest.json"

    @property
    def logtest_registry_path(self):
        return self.root / "validation/wazuh/WAZUH_LOGTEST_REGISTRY.json"

    @property
    def source_registry_path(self):
        return self.detections_root / "detections/wazuh/WAZUH_RULE_SOURCE_REGISTRY.yml"

    def write_json(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def write_logtest_registry(self):
        self.logtest_registry = {
            "schema_version": 1,
            "registry_status": "WAZUH_LOGTEST_CONTRACT_ENFORCED",
            "proof_ceiling": "CONTROLLED_TEST_ONLY_NOT_RUNTIME_PROOF",
            "public_safe_status": "NOT_PUBLIC_SAFE",
            "runtime_status": False,
            "signal_status": False,
            "entries": [
                self.logtest_entry("HO-DET-011", "ho-det-011", 910011, 8, "T1543.003", "ho-det-011-service-create.json"),
                self.logtest_entry("HO-DET-012", "ho-det-012", 910021, 7, "T1053.005", "ho-det-012-scheduled-task.json"),
                {
                    "detection_id": "HO-DET-001",
                    "status": "PLANNED_NEEDS_WAZUH_SOURCE",
                    "wazuh_rule_source": None,
                    "sample_event": None,
                    "expected_rule_ids": [],
                    "expected_levels": [],
                    "expected_groups": [],
                    "expected_mitre_ids": ["T1059.001"],
                    "runtime_status": False,
                    "signal_status": False,
                    "public_safe_status": "NOT_PUBLIC_SAFE",
                    "execution_mode": "planned_static_contract_only",
                    "notes": "planned static contract only",
                },
            ],
        }
        self.write_json(self.logtest_registry_path, self.logtest_registry)

    def logtest_entry(self, detection_id, slug, rule_id, level, mitre, sample):
        return {
            "detection_id": detection_id,
            "status": "STATIC_CONTRACT_READY",
            "wazuh_rule_source": f"detections/successor/{slug}/wazuh.xml",
            "sample_event": f"validation/wazuh/samples/{sample}",
            "expected_rule_ids": [rule_id],
            "expected_levels": [level],
            "expected_groups": [slug, "source-only", "validation-planned"],
            "expected_mitre_ids": [mitre],
            "runtime_status": False,
            "signal_status": False,
            "public_safe_status": "NOT_PUBLIC_SAFE",
            "execution_mode": "static_ci_optional_private_logtest",
            "notes": "static CI contract only",
        }

    def write_samples(self):
        for detection_id, filename in (
            ("HO-DET-011", "ho-det-011-service-create.json"),
            ("HO-DET-012", "ho-det-012-scheduled-task.json"),
        ):
            self.write_json(
                self.root / "validation/wazuh/samples" / filename,
                {
                    "detection_id": detection_id,
                    "sample_scope": "controlled_test_wazuh_logtest_candidate",
                    "runtime_status": False,
                    "signal_status": False,
                    "public_safe_status": "NOT_PUBLIC_SAFE",
                    "logtest_input": "{\"win\":{\"system\":{\"eventID\":\"1\"}}}",
                },
            )

    def write_source_registry(self):
        source = {
            "schema_version": 1,
            "registry_status": "WAZUH_RULE_SOURCE_CONTRACT_ENFORCED",
            "proof_ceiling": "SOURCE_AND_STATIC_CI_ONLY_NOT_RUNTIME_PROOF",
            "public_safe_status": "NOT_PUBLIC_SAFE",
            "runtime_status": False,
            "signal_status": False,
            "entries": [
                self.source_entry("HO-DET-001", "ho-det-001", "WAZUH_SOURCE_NEEDED", None, [], [], ["T1059.001"]),
                self.source_entry("HO-DET-011", "ho-det-011", "SOURCE_EXISTS", "detections/successor/ho-det-011/wazuh.xml", [910011], ["ho-det-011", "source-only", "validation-planned"], ["T1543.003"]),
                self.source_entry("HO-DET-012", "ho-det-012", "SOURCE_EXISTS", "detections/successor/ho-det-012/wazuh.xml", [910021], ["ho-det-012", "source-only", "validation-planned"], ["T1053.005"]),
            ],
        }
        self.source_registry_path.write_text(yaml.safe_dump(source, sort_keys=False), encoding="utf-8")

    def source_entry(self, detection_id, slug, status, rule_path, rule_ids, groups, mitre):
        return {
            "detection_id": detection_id,
            "mapping_lane": "wazuh_rule_source" if rule_path else "wazuh_rule_source_planned",
            "status": status,
            "detection_package": f"detections/successor/{slug}",
            "wazuh_rule_path": rule_path,
            "expected_rule_ids": rule_ids,
            "expected_groups": groups,
            "expected_mitre_ids": mitre,
            "preferred_runtime": "wazuh_candidate_after_controlled_fixture",
            "runtime_status": False,
            "signal_status": False,
            "public_safe_status": "NOT_PUBLIC_SAFE",
            "notes": "static source registry only",
        }

    def write_wazuh_xml(self, slug, rule_id, level, mitre):
        path = self.detections_root / f"detections/successor/{slug}/wazuh.xml"
        path.write_text(
            f"""
<group name="{slug},validation-planned">
  <rule id="{rule_id}" level="{level}">
    <description>test</description>
    <mitre><id>{mitre}</id></mitre>
    <group>source-only</group>
  </rule>
</group>
""".strip(),
            encoding="utf-8",
        )

    def test_valid_lab_passes_with_required_source_contract(self):
        result = module.verify_lab(
            root=self.root,
            manifest_path=self.manifest_path,
            detections_root=self.detections_root,
            source_contract="required",
            print_summary=False,
        )
        self.assertEqual(result["source_contract"], "checked")
        self.assertEqual(result["entries"], 3)

    def test_missing_source_reference_fails(self):
        (self.detections_root / "detections/successor/ho-det-012/wazuh.xml").unlink()
        with self.assertRaisesRegex(
            (module.HOLabWazuhError, module.logtest_registry.WazuhLogtestRegistryError),
            "missing wazuh_rule_source|missing wazuh_rule_path",
        ):
            module.verify_lab(self.root, self.manifest_path, self.detections_root, "required", print_summary=False)

    def test_missing_validation_reference_fails(self):
        registry = copy.deepcopy(self.logtest_registry)
        registry["entries"][0]["sample_event"] = "validation/wazuh/samples/missing.json"
        self.write_json(self.logtest_registry_path, registry)
        with self.assertRaisesRegex(module.logtest_registry.WazuhLogtestRegistryError, "missing sample_event"):
            module.verify_lab(self.root, self.manifest_path, self.detections_root, "required", print_summary=False)

    def test_duplicate_conflicting_source_rule_id_fails(self):
        self.write_wazuh_xml("ho-det-012", 910011, 7, "T1053.005")
        source = yaml.safe_load(self.source_registry_path.read_text(encoding="utf-8"))
        source["entries"][2]["expected_rule_ids"] = [910011]
        self.source_registry_path.write_text(yaml.safe_dump(source, sort_keys=False), encoding="utf-8")
        registry = copy.deepcopy(self.logtest_registry)
        registry["entries"][1]["expected_rule_ids"] = [910011]
        self.write_json(self.logtest_registry_path, registry)
        with self.assertRaisesRegex(module.HOLabWazuhError, "duplicate Wazuh rule id"):
            module.verify_lab(self.root, self.manifest_path, self.detections_root, "required", print_summary=False)

    def test_blocked_claim_promotion_fails(self):
        lab_doc = self.root / "validation/wazuh/labs/HO-LAB-WAZUH-001.md"
        lab_doc.write_text("HO-LAB-WAZUH-001 proves live Wazuh deployment.", encoding="utf-8")
        with self.assertRaisesRegex(module.HOLabWazuhError, "blocked claim without negative context"):
            module.verify_lab(self.root, self.manifest_path, self.detections_root, "required", print_summary=False)

    def test_missing_adjacent_source_can_be_skipped(self):
        result = module.verify_lab(
            root=self.root,
            manifest_path=self.manifest_path,
            detections_root=self.root.parent / "missing-detections",
            source_contract="skip-if-missing",
            print_summary=False,
        )
        self.assertEqual(result["source_contract"], "skipped")


if __name__ == "__main__":
    unittest.main()

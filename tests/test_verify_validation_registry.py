import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

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
                "positive": [{"id": "pos-001", "expected": True, "matched": True, "pass": True}],
                "negative": [{"id": "neg-001", "expected": False, "matched": False, "pass": True}],
                "public_safe_status": "NOT_PUBLIC_SAFE",
                "runtime_active": False,
                "signal_observed": False,
                "validation_owner": "hawkinsoperations-validation",
                "source_owner": "hawkinsoperations-validation",
                "fixture_version": 1,
                "expected_result": "PASS",
                "actual_result": "PASS",
                "report_identity": "EX-DET-001_VALIDATION_RESULT_V1",
                "parity_identity": "EX-DET-001_RESULT_PARITY_V1",
                "proof_ceiling": "CONTROLLED_TEST_VALIDATED",
                "human_review_required": True,
                "ai_disposition_authority": False,
            },
        )
        (self.root / "reports/example/validation-result.md").write_text(
            "# EX-DET-001 validation result\n", encoding="utf-8"
        )
        for rel in (
            "scripts/validate-example.py",
            "scripts/verify-example-parity.py",
            "scripts/scan-example-claims.py",
        ):
            (self.root / rel).write_text("print('ok')\n", encoding="utf-8")
        (self.root / "scripts/validate-example.py").write_text(
            "# implements --source-contract\nprint('ok')\n",
            encoding="utf-8",
        )
        (self.root / "scripts/verify-example-parity.py").write_text(
            "# validation-cases.json validation-result.json\nprint('ok')\n",
            encoding="utf-8",
        )
        self.registry = {
            "schema_version": 2,
            "owner_repo": "hawkinsoperations-validation",
            "truth_surface": "controlled_validation",
            "registry_status": "VALIDATION_CONTRACT_ENFORCED",
            "human_review_required": True,
            "ai_disposition_authority": False,
            "source_authority_manifest": "validation/SOURCE_AUTHORITY_MANIFEST.json",
            "bridge_records": [],
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
            "validation_owner": "hawkinsoperations-validation",
            "source_owner": "hawkinsoperations-validation",
            "source_reference": "validation/example",
            "fixture_version": 1,
            "expected_result": "PASS",
            "actual_result": "PASS",
            "report_identity": "EX-DET-001_VALIDATION_RESULT_V1",
            "parity_identity": "EX-DET-001_RESULT_PARITY_V1",
            "human_review_required": True,
            "ai_disposition_authority": False,
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

    def test_duplicate_authoritative_path_fails(self):
        registry = copy.deepcopy(self.registry)
        duplicate = copy.deepcopy(registry["packages"][0])
        duplicate["detection_id"] = "EX-DET-002"
        duplicate["report_identity"] = "EX-DET-002_VALIDATION_RESULT_V1"
        duplicate["parity_identity"] = "EX-DET-002_RESULT_PARITY_V1"
        registry["packages"].append(duplicate)
        with self.assertRaisesRegex(module.RegistryFailure, "reuses .* already owned"):
            module.validate_registry(registry, self.root)

    def test_duplicate_normalized_authoritative_path_alias_fails(self):
        registry = copy.deepcopy(self.registry)
        duplicate = copy.deepcopy(registry["packages"][0])
        duplicate["detection_id"] = "EX-DET-002"
        duplicate["report_identity"] = "EX-DET-002_VALIDATION_RESULT_V1"
        duplicate["parity_identity"] = "EX-DET-002_RESULT_PARITY_V1"
        duplicate["fixture_file"] = "validation/example/./validation-cases.json"
        registry["packages"].append(duplicate)
        with self.assertRaisesRegex(module.RegistryFailure, "unsafe or ambiguous"):
            module.validate_registry(registry, self.root)

    def test_authoritative_path_escape_fails(self):
        registry = copy.deepcopy(self.registry)
        registry["packages"][0]["fixture_file"] = "../outside.json"
        with self.assertRaisesRegex(module.RegistryFailure, "unsafe or ambiguous"):
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

    def test_malformed_scalar_and_collection_types_fail_closed(self):
        registry = copy.deepcopy(self.registry)
        registry["packages"][0]["runtime_status"] = []
        with self.assertRaisesRegex(module.RegistryFailure, "runtime_status"):
            module.validate_registry(registry, self.root)

        registry = copy.deepcopy(self.registry)
        registry["packages"][0]["expected_fixture_count"] = True
        with self.assertRaisesRegex(module.RegistryFailure, "counts must be integers"):
            module.validate_registry(registry, self.root)

        fixture_path = self.root / "validation/example/validation-cases.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        fixture["cases"]["positive"][0] = "not-an-object"
        fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "entries must be objects|must be an object"):
            module.validate_registry(self.registry, self.root)

    def test_registry_requires_human_review_and_blocks_ai_authority(self):
        for field, value in (
            ("human_review_required", False),
            ("ai_disposition_authority", True),
        ):
            with self.subTest(field=field):
                registry = copy.deepcopy(self.registry)
                registry[field] = value
                with self.assertRaises(module.RegistryFailure):
                    module.validate_registry(registry, self.root)

    def test_malformed_registry_fails(self):
        bad_path = self.root / "bad.yml"
        bad_path.write_text("{not-json", encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "malformed"):
            module.load_registry(bad_path)

    def test_duplicate_registry_key_fails_closed(self):
        bad_path = self.root / "duplicate.yml"
        bad_path.write_text('{"schema_version": 2, "schema_version": 1}', encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "duplicate structured key"):
            module.load_registry(bad_path)

    def test_unknown_registry_and_package_fields_fail_closed(self):
        for target in ("root", "package"):
            with self.subTest(target=target):
                registry = copy.deepcopy(self.registry)
                if target == "root":
                    registry["extension"] = {}
                else:
                    registry["packages"][0]["extension"] = {}
                with self.assertRaisesRegex(module.RegistryFailure, "unknown fields"):
                    module.validate_registry(registry, self.root)

    def test_cross_platform_and_encoded_paths_fail_closed(self):
        hostile = (
            r"C:\private\fixture.json",
            r"\\server\share\fixture.json",
            "/etc/passwd",
            r"validation/example\../outside.json",
            "validation/example/%2e%2e/outside.json",
            "validation/example/%252e%252e/outside.json",
            "file:///etc/passwd",
            "validation/example/mixed\\fixture.json",
        )
        for value in hostile:
            with self.subTest(value=value):
                registry = copy.deepcopy(self.registry)
                registry["packages"][0]["fixture_file"] = value
                with self.assertRaises(module.RegistryFailure):
                    module.validate_registry(registry, self.root)

    def test_casefolded_detection_alias_fails(self):
        registry = copy.deepcopy(self.registry)
        duplicate = copy.deepcopy(registry["packages"][0])
        duplicate["detection_id"] = "ex-det-001"
        registry["packages"].append(duplicate)
        with self.assertRaises(module.RegistryFailure):
            module.validate_registry(registry, self.root)

    def test_missing_explicit_authority_field_fails(self):
        for field in (
            "validation_owner",
            "source_owner",
            "fixture_version",
            "expected_result",
            "actual_result",
            "report_identity",
            "parity_identity",
            "human_review_required",
            "ai_disposition_authority",
        ):
            with self.subTest(field=field):
                registry = copy.deepcopy(self.registry)
                registry["packages"][0].pop(field)
                with self.assertRaisesRegex(module.RegistryFailure, "missing required fields"):
                    module.validate_registry(registry, self.root)

    def test_report_and_parity_identities_are_bound_to_owned_case(self):
        for field, value in (
            ("report_identity", "FORGED_UNBOUND_REPORT"),
            ("parity_identity", "FORGED_UNBOUND_PARITY"),
        ):
            with self.subTest(field=field):
                registry = copy.deepcopy(self.registry)
                registry["packages"][0][field] = value
                with self.assertRaisesRegex(
                    module.RegistryFailure, rf"{field} must bind"
                ):
                    module.validate_registry(registry, self.root)

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
        with self.assertRaisesRegex(module.RegistryFailure, "ci_source_dependency_mode is invalid"):
            module.validate_registry(registry, self.root)

    def test_skip_if_missing_mode_allowed_when_source_dependency_required(self):
        registry = copy.deepcopy(self.registry)
        registry["packages"][0]["source_dependency_required"] = True
        registry["packages"][0]["source_owner"] = "hawkinsoperations-detections"
        registry["packages"][0]["source_reference"] = "hawkinsoperations-detections/detections/example"
        registry["packages"][0]["ci_source_dependency_mode"] = "skip_if_missing"
        with self.assertRaisesRegex(module.RegistryFailure, "ci_source_dependency_mode is invalid"):
            module.validate_registry(registry, self.root)

    def test_source_dependency_requires_validator_contract_behavior(self):
        registry = copy.deepcopy(self.registry)
        registry["packages"][0]["source_dependency_required"] = True
        registry["packages"][0]["source_owner"] = "hawkinsoperations-detections"
        registry["packages"][0]["source_reference"] = "hawkinsoperations-detections/detections/example"
        registry["packages"][0]["ci_source_dependency_mode"] = "required"
        (self.root / "scripts/validate-example.py").write_text("print('no source mode')\n", encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "does not implement --source-contract"):
            module.validate_registry(registry, self.root)

    def test_controlled_validation_requires_positive_and_negative_cases(self):
        registry = copy.deepcopy(self.registry)
        registry["packages"][0]["expected_negative_count"] = 0
        registry["packages"][0]["expected_fixture_count"] = 1
        with self.assertRaisesRegex(module.RegistryFailure, "positive integer fixture counts"):
            module.validate_registry(registry, self.root)

    def test_report_cannot_promote_ai_disposition_authority(self):
        report_path = self.root / "reports/example/validation-result.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["ai_disposition_authority"] = True
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(
            module.RegistryFailure,
            "ai_disposition_authority disagreement|promotes a blocked authority",
        ):
            module.validate_registry(self.registry, self.root)

    def test_report_requires_explicit_authority_and_identity_fields(self):
        report_path = self.root / "reports/example/validation-result.json"
        original = json.loads(report_path.read_text(encoding="utf-8"))
        for field in (
            "validation_owner",
            "source_owner",
            "fixture_version",
            "expected_result",
            "actual_result",
            "report_identity",
            "parity_identity",
            "proof_ceiling",
            "human_review_required",
            "ai_disposition_authority",
        ):
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report.pop(field)
                report_path.write_text(json.dumps(report), encoding="utf-8")
                with self.assertRaisesRegex(
                    module.RegistryFailure, rf"missing required field: {field}"
                ):
                    module.validate_registry(self.registry, self.root)

    def test_report_result_semantics_cannot_be_reduced_or_inverted(self):
        report_path = self.root / "reports/example/validation-result.json"
        original = json.loads(report_path.read_text(encoding="utf-8"))

        reduced = copy.deepcopy(original)
        reduced["positive"][0] = {"id": "pos-001", "pass": True}
        report_path.write_text(json.dumps(reduced), encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "expected must be True"):
            module.validate_registry(self.registry, self.root)

        inverted = copy.deepcopy(original)
        inverted["positive"][0]["matched"] = False
        inverted["negative"][0]["matched"] = True
        report_path.write_text(json.dumps(inverted), encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "matched must be True"):
            module.validate_registry(self.registry, self.root)

    def test_report_markdown_authority_claims_fail_closed(self):
        markdown_path = self.root / "reports/example/validation-result.md"
        attacks = (
            "customer deployment is active",
            "final authorization is granted",
            "case is closed",
            "AI disposition authority enabled",
            "not public safe; customer deployment is active",
        )
        for attack in attacks:
            with self.subTest(attack=attack):
                markdown_path.write_text(
                    f"# EX-DET-001 validation result\n\n{attack}\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    module.RegistryFailure, "contains a blocked authority claim"
                ):
                    module.validate_registry(self.registry, self.root)

    def test_blocked_claim_container_cannot_exempt_nested_affirmative_prose(self):
        report_path = self.root / "reports/example/validation-result.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        for payload in (
            {"claims_not_supported": [{"detail": "customer deployment is active"}]},
            {"blocked_claims": [{"detail": "public-safe approved"}]},
        ):
            with self.subTest(payload=payload):
                hostile = copy.deepcopy(report)
                hostile.update(payload)
                report_path.write_text(json.dumps(hostile), encoding="utf-8")
                with self.assertRaisesRegex(
                    module.RegistryFailure, "contains a blocked authority claim"
                ):
                    module.validate_registry(self.registry, self.root)

    def test_nested_authority_laundering_in_report_fails(self):
        report_path = self.root / "reports/example/validation-result.json"
        original = json.loads(report_path.read_text(encoding="utf-8"))
        report = copy.deepcopy(original)
        report["future_gated_phases"] = [
            {"metadata": {"analyst-disposition-authority": True}}
        ]
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(
            module.RegistryFailure,
            "promotes a (?:blocked|compositional) authority",
        ):
            module.validate_registry(self.registry, self.root)

        report["future_gated_phases"] = [
            {"metadata": {"message": "AI disposition authority enabled"}}
        ]
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "contains a blocked authority claim"):
            module.validate_registry(self.registry, self.root)

        attacks = (
            ("production_active", True),
            ("production_live", {"enabled": True}),
            ("customer_deployment", True),
            ("socaas_deployment", True),
            ("runtime_status", "active"),
            ("signal_status", "observed"),
            ("approval_status", "approved"),
            ("closure_status", "closed"),
            ("case_status", "closed"),
            ("public_safe_runtime", True),
            ("final_authorized", True),
            ("%70roduction_active", True),
        )
        for key, value in attacks:
            with self.subTest(key=key):
                report = copy.deepcopy(original)
                report["future_gated_phases"] = [{"metadata": {key: value}}]
                report_path.write_text(json.dumps(report), encoding="utf-8")
                with self.assertRaisesRegex(
                    module.RegistryFailure, "promotes a compositional authority state"
                ):
                    module.validate_registry(self.registry, self.root)

    def test_affirmative_authority_prose_variants_fail(self):
        report_path = self.root / "reports/example/validation-result.json"
        attacks = (
            "customer deployment is active",
            "deployed to customer Acme",
            "customer environment deployed",
            "analyst approval granted",
            "analyst approved this disposition",
            "SOCaaS deployment is live",
            "SOCaaS is deployed",
            "public safe runtime proof established",
            "public safe for release",
            "production is live",
            "final authorization received",
            "case closure complete",
            "runtime is active",
            "signal was observed",
            "pending documentation, production is live",
            "unsupported note — customer environment deployed",
            "future issue: signal was observed",
            "missing receipt while production is live",
            "no proof currently, customer environment deployed",
            "not approved / production is live",
            "does not prove runtime, customer deployment is active",
            "does not prove runtime, AI authority is enabled",
            "does not prove runtime, analyst approval granted",
            "does not prove runtime, public safe is confirmed",
            "does not prove runtime, final authorization received",
            "does not prove runtime, case closure approved",
            "does not prove runtime and customer deployment is active",
            "does not prove runtime plus public safe is confirmed",
            "does not prove runtime though case closure is approved",
            "public\u200b safe is confirmed",
            "case\u200b closure approved",
            "AI\u200b authority is enabled",
            "runtime\u200b is active",
        )
        original = json.loads(report_path.read_text(encoding="utf-8"))
        for attack in attacks:
            with self.subTest(attack=attack):
                report = copy.deepcopy(original)
                report["future_gated_phases"] = [{"message": attack}]
                report_path.write_text(json.dumps(report), encoding="utf-8")
                with self.assertRaisesRegex(
                    module.RegistryFailure, "contains a blocked authority claim"
                ):
                    module.validate_registry(self.registry, self.root)

    def test_bounded_negative_authority_lists_remain_valid(self):
        report_path = self.root / "reports/example/validation-result.json"
        original = json.loads(report_path.read_text(encoding="utf-8"))
        controls = (
            (
                "This does not prove runtime-active status, signal-observed "
                "status, production-ready status, public-safe status, "
                "AI-approved status, analyst-approved status, final "
                "authorization, or case closure."
            ),
            (
                "This does not prove customer deployment, public-safe status, "
                "final authorization, or case closure."
            ),
            (
                "Runtime, signal, public-safe, live IdP, production identity "
                "coverage, autonomous SOC, AI-approved disposition, and "
                "analyst-approved disposition claims remain blocked."
            ),
            "Café résumé – reviewer note.",
        )
        for control in controls:
            with self.subTest(control=control):
                report = copy.deepcopy(original)
                report["future_gated_phases"] = [{"message": control}]
                report_path.write_text(json.dumps(report), encoding="utf-8")
                module.validate_registry(self.registry, self.root)

    def test_split_and_direct_authority_state_paths_fail_closed(self):
        attacks = (
            {"runtime": {"state": True}},
            {"signal": {"observed": True}},
            {"public": {"safe": True}},
            {"approval": {"status": True}},
            {"production": {"active": True}},
            {"customer": {"deployed": True}},
            {"socaas": {"deployed": True}},
            {"ai": {"authority": True}},
            {"analyst": {"approval": True}},
            {"review": {"disposition": "APPROVED"}},
            {"final": {"authorization": True}},
            {"case": {"closed": True}},
            {"extensions": [{"final": {"authorization": True}}]},
            {"runtime": {"metadata": {"state": True}}},
            {"final": {"review": {"authorization": True}}},
            {"ai": {"metadata": {"authority": True}}},
            {"customer": {"review": {"deployed": True}}},
            {"review": {"metadata": {"disposition": "APPROVED"}}},
            {"production_live": {"enabled": True}},
            {"ai_authority": {"enabled": True}},
            {"review_disposition": {"approved": True}},
            {"final_authorization": {"granted": True}},
            {"production_live": [True]},
            {"ai_authority": ["APPROVED"]},
            {"review_disposition": [True]},
            {"final_authorization": [1]},
            {"runtime": {"metadata": {"state": [True]}}},
            {"runtime_state": True},
            {"approval_state": True},
            {"production_state": True},
            {"customer_state": True},
            {"socaas_state": True},
            {"final_authority": True},
            {"case_state": True},
        )
        for attack in attacks:
            with self.subTest(attack=attack), self.assertRaisesRegex(
                module.RegistryFailure,
                "authority",
            ):
                module._scan_authority_boundaries(attack)

    def test_split_and_direct_authority_state_bounded_controls_pass(self):
        controls = (
            {"runtime": {"state": False}},
            {"signal": {"observed": False}},
            {"public": {"safe": "NOT_PUBLIC_SAFE"}},
            {"approval": {"status": "NOT_APPROVED"}},
            {"production": {"active": "BLOCKED"}},
            {"customer": {"deployed": False}},
            {"socaas": {"deployed": False}},
            {"ai": {"authority": False}},
            {"analyst": {"approval": "NOT_APPROVED"}},
            {"review": {"disposition": "NOT_APPROVED"}},
            {"final": {"authorization": "BLOCKED"}},
            {"case": {"closed": False}},
            {"extensions": [{"final": {"authorization": "BLOCKED"}}]},
            {"runtime_state": False},
            {"approval_state": "NOT_APPROVED"},
            {"production_state": "BLOCKED"},
            {"customer_state": False},
            {"socaas_state": False},
            {"final_authority": False},
            {"case_state": False},
            {"production_live": {"enabled": False}},
            {"ai_authority": {"enabled": False}},
            {"review_disposition": {"approved": "NOT_APPROVED"}},
            {"final_authorization": {"granted": "BLOCKED"}},
            {"production_live": [False]},
            {"ai_authority": ["BLOCKED"]},
            {"review_disposition": ["NOT_APPROVED"]},
            {"final_authorization": ["BLOCKED"]},
            {"runtime": {"metadata": {"state": [False]}}},
        )
        for control in controls:
            with self.subTest(control=control):
                module._scan_authority_boundaries(control)

    def test_compound_owned_context_names_remain_bounded(self):
        module._scan_authority_boundaries(
            {
                "runtime_truth_spine": {
                    "runtime_truth": {
                        "state": "RUNTIME_EVIDENCE_VERIFIED_PRIVATE"
                    }
                },
                "socaas_pilot_receipt_flow": {
                    "pilot_status": "EXISTING_FLOW_CANDIDATE"
                },
            }
        )

    def test_report_rejects_ambiguous_dual_result_shapes(self):
        report_path = self.root / "reports/example/validation-result.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["fixture_results"] = copy.deepcopy(report["positive"] + report["negative"])
        for item in report["fixture_results"]:
            item["expected_result"] = (
                "match" if item["id"].casefold().startswith("pos") else "no_match"
            )
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "exactly one result shape"):
            module.validate_registry(self.registry, self.root)

    def test_fixture_rejects_ambiguous_dual_case_shapes(self):
        fixture_path = self.root / "validation/example/validation-cases.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        fixture["positives"] = copy.deepcopy(fixture["cases"]["positive"])
        fixture["negatives"] = copy.deepcopy(fixture["cases"]["negative"])
        fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "exactly one case shape"):
            module.validate_registry(self.registry, self.root)

    def test_unknown_report_field_fails_closed(self):
        report_path = self.root / "reports/example/validation-result.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["unreviewed_extension"] = {"status": "pass"}
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "report contains unknown fields"):
            module.validate_registry(self.registry, self.root)

    def test_unknown_result_and_fixture_shapes_fail_closed(self):
        report_path = self.root / "reports/example/validation-result.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["positive"][0]["extension"] = {"pass": True}
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "contains unknown fields"):
            module.validate_registry(self.registry, self.root)

        report["positive"][0].pop("extension")
        report_path.write_text(json.dumps(report), encoding="utf-8")
        fixture_path = self.root / "validation/example/validation-cases.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        fixture["extension"] = []
        fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "fixture contains unknown fields"):
            module.validate_registry(self.registry, self.root)

    def test_report_fixture_identity_mismatch_fails(self):
        report_path = self.root / "reports/example/validation-result.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["positive"][0]["id"] = "pos-forged"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "positive report IDs"):
            module.validate_registry(self.registry, self.root)

    def test_reverse_inventory_orphan_fixture_fails(self):
        orphan = self.root / "validation/orphan/validation-cases.json"
        orphan.parent.mkdir(parents=True)
        orphan.write_text('{"cases":{"positive":[],"negative":[]}}', encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "unregistered validation fixtures"):
            module.validate_registry(self.registry, self.root)

    def test_contract_only_entry_cannot_expect_pass(self):
        registry = copy.deepcopy(self.registry)
        registry["packages"][0]["validation_kind"] = "baseline_contract"
        registry["packages"][0]["report_identity"] = (
            "EX-DET-001_BASELINE_VALIDATION_RESULT_V1"
        )
        registry["packages"][0]["parity_identity"] = None
        with self.assertRaisesRegex(module.RegistryFailure, "expected_result must be BLOCKED"):
            module.validate_registry(registry, self.root)

    def test_visibility_contract_is_explicitly_blocked_for_fixture_review(self):
        package = self._package()
        package["validation_kind"] = "visibility_contract"
        self.assertEqual(module.review_eligibility(package), "BLOCKED")

    def test_contract_only_inventory_is_expected_blocked(self):
        package = self._package()
        package["validation_kind"] = "baseline_contract"
        package["expected_result"] = "BLOCKED"
        package["actual_result"] = "BLOCKED"
        registry_path = self.root / "validation" / "VALIDATION_REGISTRY.yml"
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(json.dumps(self.registry), encoding="utf-8")
        inventory = module.build_inventory([package], self.root)
        self.assertEqual(inventory["packages"][0]["review_eligibility"], "CONTRACT_ONLY")
        self.assertEqual(inventory["packages"][0]["expected_fixture_review_outcome"], "BLOCKED")

    def test_inventory_is_revision_linked_and_contains_fingerprints(self):
        registry_path = self.root / "validation" / "VALIDATION_REGISTRY.yml"
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(json.dumps(self.registry), encoding="utf-8")
        packages = module.validate_registry(self.registry, self.root)
        inventory = module.build_inventory(packages, self.root)
        item = inventory["packages"][0]
        self.assertEqual(inventory["authority_role"], "controlled_validation")
        self.assertEqual(len(inventory["authoritative_fingerprint"]), 64)
        self.assertIn(inventory["source_freshness_state"], {"CURRENT", "WORKTREE_MODIFIED_OR_UNRESOLVED"})
        self.assertIn("worktree_clean", inventory)
        self.assertEqual(item["review_eligibility"], "PASS_CAPABLE")
        self.assertFalse(item["ai_disposition_authority"])
        self.assertIn("fixture_file", item["source_fingerprints"])
        self.assertNotIn(str(self.root), str(inventory))

    def test_source_matrix_status_disagreement_fails(self):
        detections_root = self.root / "detections-repo"
        status_dir = detections_root / "detections" / "example"
        status_dir.mkdir(parents=True)
        matrix_data = {
            "entries": [
                {
                    "detection_id": "EX-DET-001",
                    "package_path": "detections/example",
                    "validation_expected_owner": "hawkinsoperations-validation",
                    "validation_status_if_known": "VALIDATION_PLANNED",
                }
            ]
        }
        (detections_root / "detections" / "DETECTION_PROMOTION_MATRIX.yml").write_text(
            yaml.safe_dump(matrix_data),
            encoding="utf-8",
        )
        (status_dir / "status.yml").write_text(
            yaml.safe_dump(
                {
                    "detection_id": "EX-DET-001",
                    "validation_status": "VALIDATION_PLANNED",
                    "public_safe_status": "NOT_PUBLIC_SAFE",
                    "runtime_active": False,
                    "signal_observed": False,
                }
            ),
            encoding="utf-8",
        )
        package = self._package()
        package["source_dependency_required"] = True
        package["source_owner"] = "hawkinsoperations-detections"
        package["source_reference"] = "hawkinsoperations-detections/detections/example"
        package["ci_source_dependency_mode"] = "required"
        with self.assertRaisesRegex(module.RegistryFailure, "source/validation status disagreement"):
            module.validate_source_parity([package], detections_root)

    def test_source_manifest_uses_content_identity_not_unrelated_tip_identity(self):
        detections_root = self.root / "detections-repo"
        package_dir = detections_root / "detections/example"
        package_dir.mkdir(parents=True)
        matrix = {
            "entries": [
                {
                    "detection_id": "EX-DET-001",
                    "package_path": "detections/example",
                    "required_files": ["rule.yml", "status.yml"],
                }
            ]
        }
        (detections_root / "detections/DETECTION_PROMOTION_MATRIX.yml").write_text(
            yaml.safe_dump(matrix), encoding="utf-8"
        )
        (package_dir / "rule.yml").write_text("detection_id: EX-DET-001\n", encoding="utf-8")
        (package_dir / "status.yml").write_text("detection_id: EX-DET-001\n", encoding="utf-8")
        subprocess.run(["git", "init"], cwd=detections_root, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=detections_root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=detections_root, check=True)
        subprocess.run(["git", "add", "."], cwd=detections_root, check=True)
        subprocess.run(["git", "commit", "-m", "source"], cwd=detections_root, check=True, capture_output=True)
        package = self._package()
        package["source_dependency_required"] = True
        before = module.build_source_authority_manifest([package], detections_root)
        manifest_package = before["packages"][0]
        source_inventory = {
            "repository": "hawkinsoperations-detections",
            "authority_role": "detection_source",
            "authoritative_path": before["matrix_path"],
            "authoritative_git_blob_sha": before["matrix_git_blob_sha"],
            "authoritative_semantic_fingerprint": before["matrix_semantic_fingerprint"],
            "current_authority": True,
            "worktree_clean": True,
            "entries": [
                {
                    "detection_id": "EX-DET-001",
                    "package_path": manifest_package["package_path"],
                    "content_matches_observed_head": True,
                    "required_file_git_blobs": {
                        item["path"].removeprefix(f"{manifest_package['package_path']}/"): item["git_blob_sha"]
                        for item in manifest_package["required_files"]
                    },
                    "required_file_semantic_fingerprints": {
                        item["path"].removeprefix(f"{manifest_package['package_path']}/"): item["semantic_fingerprint"]
                        for item in manifest_package["required_files"]
                    },
                }
            ],
        }
        module.validate_detection_source_inventory(source_inventory, before)
        source_inventory["entries"][0]["content_matches_observed_head"] = False
        with self.assertRaisesRegex(module.RegistryFailure, "does not match the observed"):
            module.validate_detection_source_inventory(source_inventory, before)
        source_inventory["entries"][0]["content_matches_observed_head"] = True
        (detections_root / "UNRELATED.md").write_text("unrelated\n", encoding="utf-8")
        subprocess.run(["git", "add", "UNRELATED.md"], cwd=detections_root, check=True)
        subprocess.run(["git", "commit", "-m", "unrelated"], cwd=detections_root, check=True, capture_output=True)
        after = module.build_source_authority_manifest([package], detections_root)
        self.assertEqual(before, after)
        module.validate_source_authority_manifest(before, [package], detections_root)
        forged = copy.deepcopy(before)
        forged["packages"][0]["required_files"][0]["semantic_fingerprint"] = "0" * 64
        with self.assertRaisesRegex(module.RegistryFailure, "content identity drift"):
            module.validate_source_authority_manifest(forged, [package], detections_root)

        (package_dir / "rule.yml").write_text("detection_id: EX-DET-001\nchanged: true\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=detections_root, check=True)
        subprocess.run(["git", "commit", "-m", "authority change"], cwd=detections_root, check=True, capture_output=True)
        changed = module.build_source_authority_manifest([package], detections_root)
        self.assertNotEqual(after, changed)

    def test_source_repository_rejects_dirty_and_non_tip_authority(self):
        detections_root = self.root / "source-repo"
        detections_root.mkdir()
        subprocess.run(["git", "init"], cwd=detections_root, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=detections_root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=detections_root, check=True)
        subprocess.run(
            [
                "git",
                "remote",
                "add",
                "origin",
                "https://github.com/HawkinsOperations/hawkinsoperations-detections.git",
            ],
            cwd=detections_root,
            check=True,
        )
        (detections_root / "source.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=detections_root, check=True)
        subprocess.run(["git", "commit", "-m", "one"], cwd=detections_root, check=True, capture_output=True)
        first = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=detections_root, check=True, capture_output=True, text=True
        ).stdout.strip()
        (detections_root / "source.txt").write_text("two\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "two"], cwd=detections_root, check=True, capture_output=True)
        branch = subprocess.run(
            ["git", "branch", "--show-current"], cwd=detections_root, check=True, capture_output=True, text=True
        ).stdout.strip()
        state = module._verify_source_repository(detections_root, f"refs/heads/{branch}")
        self.assertEqual(len(state["current_observed_head_sha"]), 40)
        with self.assertRaisesRegex(module.RegistryFailure, "does not equal intended ref"):
            module._verify_source_repository(detections_root, first)
        (detections_root / "source.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(module.RegistryFailure, "dirty"):
            module._verify_source_repository(detections_root, f"refs/heads/{branch}")

    def test_semantic_fingerprint_canonicalizes_yaml_timestamp_scalars(self):
        source = self.root / "dated-rule.yml"
        source.write_text(
            "detection_id: EX-DET-001\ndate: 2026-07-22\n",
            encoding="utf-8",
        )
        first = module._semantic_fingerprint(source)
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        source.write_text(
            "date: 2026-07-22\ndetection_id: EX-DET-001\n",
            encoding="utf-8",
        )
        self.assertEqual(first, module._semantic_fingerprint(source))


if __name__ == "__main__":
    unittest.main()

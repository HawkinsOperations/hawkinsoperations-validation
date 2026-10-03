#!/usr/bin/env python3
"""Unit tests for cross-repo claim parity scanner."""

import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_cross_repo_claim_parity.py"
sys.path.insert(0, str(ROOT / "scripts"))


def load_module():
    spec = importlib.util.spec_from_file_location("verify_cross_repo_claim_parity", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load module: {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


scanner = load_module()


class CrossRepoClaimParityTests(unittest.TestCase):
    def build_org(self, org: Path, body: str) -> None:
        files = {
            "hawkinsoperations-detections/detections/successor/ho-det-001/status.yml": json.dumps(
                {"detection_id": "HO-DET-001", "notes": body}
            ),
            "hawkinsoperations-validation/reports/ho-det-001/validation-result.json": json.dumps(
                {"detection_id": "HO-DET-001", "notes": body}
            ),
            "hawkinsoperations-proof/proof/records/HO-DET-001.md": body,
            "hawkinsoperations-website/README.md": body,
            ".github/profile/README.md": body,
            "hawkinsoperations-platform/README.md": body,
        }
        for rel_path, content in files.items():
            path = org / rel_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def good_parity_body(self) -> str:
        return "\n".join(
            [
                "HO-DET-001: SOURCE_EXISTS",
                "HO-DET-011: SOURCE_EXISTS",
                "HO-DET-012: SOURCE_EXISTS",
                "AWS-DET-001: SOURCE_EXISTS",
                "HO-NDR-001: SOURCE_EXISTS",
                "HO-PIPE-001: SOURCE_EXISTS",
                "cross_repo_claim_contract: true",
                "proof_ceiling: CONTROLLED_TEST_VALIDATED",
                "public_safe_runtime_proof: BLOCKED",
                "runtime_active_public_proof: BLOCKED",
                "signal_observed_public_proof: BLOCKED",
                "Website/GitHub rendering is not proof.",
                "Human governance review is required before merge and before public-safe proof approval.",
                "Proof Pack 001 is released with public ceiling CONTROLLED_TEST_VALIDATED.",
                (
                    "Blocked claims: do not claim production-ready, SOCaaS, autonomous SOC, "
                    "runtime-active public proof, signal-observed public proof, public-safe runtime proof, "
                    "AI-approved disposition, or analyst-approved disposition."
                ),
            ]
        )

    def run_main(self, args: list[str]) -> tuple[int, str]:
        stdout = StringIO()
        with redirect_stdout(stdout):
            rc = scanner.main(args)
        return rc, stdout.getvalue()

    def drift_items(self, output: str) -> list[dict[str, str]]:
        for line in output.splitlines():
            if line.startswith("DRIFT_ITEMS="):
                return json.loads(line.removeprefix("DRIFT_ITEMS="))
        self.fail(f"DRIFT_ITEMS missing from output: {output}")

    def test_negative_context_allows_promotion_term(self):
        self.assertTrue(scanner.has_negative_context("runtime-active status is BLOCKED"))
        self.assertTrue(scanner.has_negative_context("do not claim live Splunk"))

    def test_unblocked_promotion_term_fails(self):
        text = "HO-DET-001 is runtime-active in production"
        items = scanner.scan_promotion_terms(
            text=text,
            detection_id="HO-DET-001",
            surface="proof",
            rel_path="proof/records/HO-DET-001.md",
            enforce=True,
        )
        self.assertGreaterEqual(len(items), 1)
        self.assertEqual(items[0].severity, "fail")

    def test_missing_scan_targets_classifies_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            drift, status_map, unknown = scanner.scan_surface(
                surface="missing",
                repo_root=root / "does-not-exist",
                patterns=["**/*.md"],
                detection_ids=["HO-DET-001"],
                enforce=True,
            )
            self.assertEqual(unknown, 1)
            self.assertEqual(len(drift), 1)
            self.assertEqual(drift[0].severity, "unknown")
            self.assertIn("HO-DET-001", status_map)

    def test_multiline_blocked_claim_list_allows_promotional_terms(self):
        text = "\n".join(
            [
                "HO-DET-001",
                "blocked_claims:",
                "  - runtime-active public proof",
                "  - signal-observed public proof",
                "  - production-ready",
            ]
        )
        items = scanner.scan_promotion_terms(
            text=text,
            detection_id="HO-DET-001",
            surface="detections",
            rel_path="detections/successor/ho-det-001/status.yml",
            enforce=True,
        )
        self.assertEqual(items, [])

    def test_multi_case_file_does_not_cross_associate_claims(self):
        text = "\n".join(
            [
                "## HO-DET-001",
                "status: SOURCE_EXISTS",
                "",
                "## AWS-DET-001",
                "blocked_claims:",
                "  - production-ready",
                "  - runtime-active public proof",
            ]
        )
        items = scanner.scan_promotion_terms(
            text=text,
            detection_id="HO-DET-001",
            surface="proof",
            rel_path="proof/records/multi.md",
            enforce=True,
        )
        self.assertEqual(items, [])

    def test_phrase_local_negation_does_not_launder_later_promotion(self):
        text = (
            "HO-DET-001 is not public-safe in review notes, but "
            "HO-DET-001 is production-ready for deployment."
        )
        items = scanner.scan_promotion_terms(
            text=text,
            detection_id="HO-DET-001",
            surface="proof",
            rel_path="proof/records/HO-DET-001.md",
            enforce=True,
        )
        self.assertTrue(
            any("production" in item.message for item in items),
            items,
        )

    def test_blocked_wording_table_column_is_negative_context(self):
        text = "\n".join(
            [
                "| Case | Allowed wording | Blocked wording |",
                "|---|---|---|",
                '| HO-DET-001 | "Source exists." | "HO-DET-001 is production-ready." |',
            ]
        )
        items = scanner.scan_promotion_terms(
            text=text,
            detection_id="HO-DET-001",
            surface="proof",
            rel_path="proof/records/HO-DET-001.md",
            enforce=True,
        )
        self.assertEqual(items, [])

    def test_table_negative_header_does_not_launder_allowed_column(self):
        text = "\n".join(
            [
                "| Case | Allowed wording | Blocked wording |",
                "|---|---|---|",
                '| HO-DET-001 | "HO-DET-001 is production-ready." | "No runtime claim." |',
            ]
        )
        items = scanner.scan_promotion_terms(
            text=text,
            detection_id="HO-DET-001",
            surface="proof",
            rel_path="proof/records/HO-DET-001.md",
            enforce=True,
        )
        self.assertTrue(any("production" in item.message for item in items), items)

    def test_blocked_section_does_not_launder_later_section(self):
        text = "\n".join(
            [
                "## HO-DET-001 Blocked Claims",
                "",
                '- "HO-DET-001 is production-ready."',
                "",
                "## Current Claim",
                "",
                "HO-DET-001 is production-ready for deployment.",
            ]
        )
        items = scanner.scan_promotion_terms(
            text=text,
            detection_id="HO-DET-001",
            surface="proof",
            rel_path="proof/records/HO-DET-001.md",
            enforce=True,
        )
        self.assertGreaterEqual(len(items), 1, items)
        self.assertTrue(all(":7" in item.path for item in items), items)

    def test_same_sentence_blocked_predicate_covers_claim_list(self):
        text = (
            "HO-DET-001 runtime-active, signal-observed, production, and "
            "public-safe claims remain blocked unless separately proven."
        )
        items = scanner.scan_promotion_terms(
            text=text,
            detection_id="HO-DET-001",
            surface="proof",
            rel_path="proof/records/HO-DET-001.md",
            enforce=True,
        )
        self.assertEqual(items, [])

    def test_negative_status_heading_uses_immediate_status(self):
        text = "\n".join(
            [
                "## HO-DET-001",
                "### RUNTIME_ACTIVE",
                "",
                "- Status: NOT_SATISFIED",
            ]
        )
        items = scanner.scan_status_tokens(
            text=text,
            detection_id="HO-DET-001",
            surface="proof",
            rel_path="proof/records/HO-DET-001.md",
            enforce=True,
        )
        self.assertEqual(items, [])

    def test_production_format_description_is_not_deployment_claim(self):
        text = "\n".join(
            [
                "## HO-DET-001",
                "",
                "This audit uses production HTML formatting for source review.",
            ]
        )
        items = scanner.scan_promotion_terms(
            text=text,
            detection_id="HO-DET-001",
            surface="website",
            rel_path="docs/rendering-audit.md",
            enforce=True,
        )
        self.assertEqual(items, [])

    def test_unmarked_public_prose_is_still_scanned_for_promotion(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            readme = root / "README.md"
            readme.write_text(
                "HO-DET-001 is production-ready for deployment.\n",
                encoding="utf-8",
            )
            drift, _, unknown = scanner.scan_surface(
                surface="website",
                repo_root=root,
                patterns=["README.md"],
                detection_ids=["HO-DET-001"],
                enforce=True,
            )
            self.assertEqual(unknown, 0)
            self.assertTrue(
                any("production" in item.message for item in drift),
                drift,
            )

    def test_affirmative_markdown_heading_is_scanned(self):
        items = scanner.scan_promotion_terms(
            text="# HO-DET-001 is production-ready for deployment",
            detection_id="HO-DET-001",
            surface="website",
            rel_path="README.md",
            enforce=True,
        )
        self.assertTrue(any("production" in item.message for item in items), items)

    def test_predicate_free_readiness_labels_fail_unless_explicitly_blocked(self):
        for text in (
            "# HO-DET-001 — production-ready", "# HO-DET-001 production-ready", "HO-DET-001: production-ready",
            "# ho-det-001 - runtime-active", "# **HO-DET-001** — **production-ready**",
            "# HO-DET-001: production-ready", "# HO-DET-001 : production-ready",
            "# HO-DET-001-production-ready", "# HO-DET-001—production-ready", "# HO-DET-001–production-ready",
            "#\tHO-DET-001:\tproduction-ready", "# **HO-DET-001**: *production-ready*",
            "HO-DET-001: *production-ready*",
            "| Case | Status |\n|---|---|\n| HO-DET-001 | production-ready |",
            "| Case | State |\n|---|---|\n| HO-DET-001 | runtime-active |",
            "| Case | Status |\n|---|---|\n| HO-DET-001 | **production-ready** |",
        ):
            with self.subTest(text=text):
                self.assertTrue(scanner.scan_promotion_terms(text, "HO-DET-001", "website", "README.md", True))
        for text in (
            "# HO-DET-001 — production-ready remains blocked", "HO-DET-001: not production-ready",
            "# HO-DET-001: not production-ready", "# HO-DET-001 : production-ready remains blocked",
            "# HO-DET-001-not production-ready", "# HO-DET-001—production-ready remains blocked",
            "# HO-DET-001–not production-ready", "# **HO-DET-001**: *production-ready* remains blocked",
            "| Case | Status |\n|---|---|\n| HO-DET-001 | not production-ready |",
            "| Case | Blocked status |\n|---|---|\n| HO-DET-001 | production-ready |",
        ):
            with self.subTest(text=text):
                self.assertEqual(scanner.scan_promotion_terms(text, "HO-DET-001", "website", "README.md", True), [])
        for field in ("status", "summary"):
            self.assertTrue(scanner.structured_claim_items({"detection_id": "HO-DET-001", field: "production-ready"},
                                                           ["HO-DET-001"], "proof", "status.json", True))
        self.assertEqual(scanner.structured_claim_items({"detection_id": "HO-DET-001", "blocked_claims": ["production-ready"]},
                                                        ["HO-DET-001"], "proof", "status.json", True), [])

    def test_truthy_string_authority_values_fail_in_json_and_yaml(self):
        for extension in ("json", "yaml"):
            for value in ("1", "2", "0.5", "-1", "+2e-3", "1e-400", "１", "on", "ON"):
                for assertion in ({"runtime_active": value}, {"wrapper": {"production": {"ready": value}}}):
                    with self.subTest(extension=extension, assertion=assertion), tempfile.TemporaryDirectory() as td:
                        root = Path(td).resolve()
                        (root / ("status." + extension)).write_text(json.dumps(assertion), encoding="utf-8")
                        items, _, _ = scanner.scan_surface("proof", root, ["status." + extension], ["HO-DET-001"], True)
                        self.assertTrue(any("assertive authority value" in item.message for item in items), items)
        for value in ("0", "+0.0", "-0e9999", "off", "OFF", "false"):
            self.assertEqual(scanner.structured_claim_items({"runtime_active": value}, ["HO-DET-001"], "proof", "status.json", True), [])

    def test_owning_denied_term_lists_preserve_exact_terms_without_laundering_assertions(self):
        for field in ("blocked_claim_categories", "unsupported_claims", "required_blocked_claims",
                      "blocked_claim_wording", "blocked_proof_promotions", "not_supported"):
            with self.subTest(field=field):
                self.assertEqual(scanner.structured_claim_items({"detection_id": "HO-DET-001", field: ["production-ready"]},
                                                                ["HO-DET-001"], "proof", "status.json", True), [])
                for bad in ("production-ready = 1", {"summary": "production-ready"}):
                    self.assertTrue(scanner.structured_claim_items({"detection_id": "HO-DET-001", field: [bad]},
                                                                   ["HO-DET-001"], "proof", "status.json", True))

    def test_common_truthy_authority_values_are_assertive(self):
        for value in (1, -1, "live", "ready", "yes"):
            with self.subTest(value=value):
                self.assertTrue(scanner.assertive_authority_value(value))
        for value in (0, False, None, "blocked", "not_approved"):
            with self.subTest(value=value):
                self.assertFalse(scanner.assertive_authority_value(value))

    def test_duplicate_json_authority_key_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hostile = root / "status.json"
            hostile.write_text(
                '{"detection_id":"HO-DET-001","runtime_active":true,"runtime_active":false}',
                encoding="utf-8",
            )
            drift, _, unknown = scanner.scan_surface(
                surface="proof",
                repo_root=root,
                patterns=["status.json"],
                detection_ids=["HO-DET-001"],
                enforce=True,
            )
            self.assertEqual(unknown, 0)
            self.assertTrue(
                any("duplicate JSON key" in item.message for item in drift),
                drift,
            )

    def test_nested_authority_leaf_cannot_hide_behind_wrapper(self):
        for value in (
            {"detection": {"runtime_active": True}},
            {"blocked_claims": {"runtime_active": True}},
            {"detection": {"runtime_active": 1}},
            {"detection": {"runtime_status": "live"}},
            {"detection": {"production_status": "ready"}},
        ):
            with self.subTest(value=value):
                items = scanner.structured_claim_items(
                    value,
                    ["HO-DET-001"],
                    "proof",
                    "proof/index.json",
                    True,
                )
                self.assertTrue(
                    any(
                        "assertive authority value" in item.message
                        for item in items
                    ),
                    items,
                )

    def test_split_nested_authority_paths_fail_in_json_and_yaml(self):
        for extension in ("json", "yaml"):
            for assertion in (
                {"runtime": {"active": True}}, {"signal": {"observed": "yes"}},
                {"production": {"status": "ready"}},
                {"wrapper": {"runtime": {"active": 1}}},
                {"blocked_claims": {"signal": {"observed": True}}},
                {"wrapper": {"ai": {"disposition": {"authority": "approved"}}}},
            ):
                with self.subTest(extension=extension, assertion=assertion), tempfile.TemporaryDirectory() as td:
                    root = Path(td).resolve()
                    (root / ("status." + extension)).write_text(json.dumps(assertion), encoding="utf-8")
                    items, _, unknown = scanner.scan_surface("proof", root, ["status." + extension], ["HO-DET-001"], True)
                    self.assertEqual(unknown, 0)
                    self.assertTrue(any("assertive authority value" in item.message for item in items), items)

    def test_split_nested_authority_paths_preserve_negative_and_inert_values(self):
        for extension in ("json", "yaml"):
            record = {"detection_id": "HO-DET-001", "status": "SOURCE_EXISTS",
                      "runtime": {"active": False}, "signal": {"observed": 0},
                      "production": {"status": "blocked"}, "wrapper": {"approval": {"status": "not_approved"}},
                      "other": {"active": True}, "notes": "runtime-active claims remain blocked"}
            with self.subTest(extension=extension), tempfile.TemporaryDirectory() as td:
                root = Path(td).resolve()
                (root / ("status." + extension)).write_text(json.dumps(record), encoding="utf-8")
                items, _, unknown = scanner.scan_surface("proof", root, ["status." + extension], ["HO-DET-001"], True)
                self.assertEqual(unknown, 0)
                self.assertEqual(items, [])

    def test_owning_authority_aliases_direct_and_nested_fail_in_json_and_yaml(self):
        for extension in ("json", "yaml"):
            for assertion in (
                {"production_ready": True}, {"productionReady": "yes"},
                {"wrapper": {"production": {"ready": 1}}},
                {"wrapper": {"aiApprovedDisposition": "approved"}},
                {"wrapper": {"customer_deployment": "live"}},
                {"blocked_claims": {"public": {"safeRuntime": True}}},
            ):
                with self.subTest(extension=extension, assertion=assertion), tempfile.TemporaryDirectory() as td:
                    root = Path(td).resolve()
                    (root / ("status." + extension)).write_text(json.dumps(assertion), encoding="utf-8")
                    items, _, _ = scanner.scan_surface("proof", root, ["status." + extension], ["HO-DET-001"], True)
                    self.assertTrue(any("assertive authority value" in item.message for item in items), items)
            benign = {"productionReady": False, "wrapper": {"production": {"ready": 0}},
                      "aiApprovedDisposition": "blocked", "customer_deployment": "not_approved"}
            self.assertEqual(scanner.structured_claim_items(benign, ["HO-DET-001"], "proof", "status.json", True), [])

    def test_prose_casefolds_identity_for_claim_scan_and_status_attribution(self):
        for identity in ("ho-det-001", "Ho-DeT-001"):
            with self.subTest(identity=identity), tempfile.TemporaryDirectory() as td:
                root = Path(td).resolve()
                (root / "README.md").write_text(identity + " SOURCE_EXISTS\n" + identity + " is production-ready.\n", encoding="utf-8")
                items, statuses, unknown = scanner.scan_surface("website", root, ["README.md"],
                                                               ["HO-DET-001", "HO-DET-011"], True)
                self.assertEqual(unknown, 0)
                self.assertEqual(statuses["HO-DET-001"], {"SOURCE_EXISTS"})
                self.assertEqual(statuses["HO-DET-011"], set())
                self.assertTrue(any(item.detection_id == "HO-DET-001" and "promotion" in item.message for item in items), items)
                (root / "README.md").write_text(identity + " SOURCE_EXISTS; production-ready remains blocked.\n", encoding="utf-8")
                self.assertEqual(scanner.scan_surface("website", root, ["README.md"], ["HO-DET-001"], True)[0], [])

    def test_all_existing_promotion_terms_guard_structured_direct_composed_and_claim_paths(self):
        for extension in ("json", "yaml"):
            for term in scanner.PROMOTION_TERMS:
                key = scanner.normalize_path_key(term)
                for suffix, value in (("", True), ("_claim", "on"), ("_proof", "0.5")):
                    assertion = {key + suffix: value}
                    composed = value
                    for segment in reversed((key + suffix).split("_")):
                        composed = {segment: composed}
                    for record in (assertion, {"wrapper": composed}):
                        with self.subTest(extension=extension, term=term, suffix=suffix, record=record), tempfile.TemporaryDirectory() as td:
                            root = Path(td).resolve()
                            (root / ("status." + extension)).write_text(json.dumps(record), encoding="utf-8")
                            items, _, _ = scanner.scan_surface("proof", root, ["status." + extension], ["HO-DET-001"], True)
                            self.assertTrue(any("assertive authority value" in item.message for item in items), items)

    def test_all_existing_structured_promotion_terms_retain_inert_values_and_denied_lists(self):
        for term in scanner.PROMOTION_TERMS:
            key = scanner.normalize_path_key(term)
            for value in (False, 0, "0", "off", "blocked"):
                with self.subTest(term=term, value=value):
                    self.assertEqual(scanner.structured_claim_items({key + "_claim": value}, ["HO-DET-001"], "proof", "status.json", True), [])
            self.assertEqual(scanner.structured_claim_items({"detection_id": "HO-DET-001", "blocked_claims": [term]},
                                                            ["HO-DET-001"], "proof", "status.json", True), [])

    def test_known_authority_parent_context_survives_extra_mapping_and_list_wrappers(self):
        for extension in ("json", "yaml"):
            for value in (True, 1, "on"):
                for record in (
                    {"fleet_wide": {"value": value}},
                    {"autonomous_soc": {"status": value}},
                    {"fleet": {"wide": {"enabled": value}}},
                    {"fleet_wide": {"not_claimed": value}},
                    {"autonomous_soc": {"blocked_claims": [value]}},
                    {"wrapper": {"fleet_wide_claim": [{"details": {"value": value}}]}},
                ):
                    with self.subTest(extension=extension, record=record), tempfile.TemporaryDirectory() as td:
                        root = Path(td).resolve()
                        (root / ("status." + extension)).write_text(json.dumps(record), encoding="utf-8")
                        items, _, _ = scanner.scan_surface("proof", root, ["status." + extension], ["HO-DET-001"], True)
                        self.assertTrue(any("assertive authority value" in item.message for item in items), items)

    def test_known_authority_parent_context_preserves_inert_controls_and_schema_definitions(self):
        for value in (False, 0, "blocked", "SOURCE_EXISTS", "NOT_APPROVED"):
            with self.subTest(value=value):
                self.assertEqual(scanner.structured_claim_items({"fleet_wide": [{"value": value}]},
                                                                ["HO-DET-001"], "proof", "status.json", True), [])
            self.assertEqual(scanner.structured_claim_items({"autonomous_soc": {"blocked_claims": [value]}},
                                                            ["HO-DET-001"], "proof", "status.json", True), [])
        self.assertEqual(scanner.structured_claim_items(
            {"case_closure": {"status": "blocked", "executed": False, "requires_human_approval": True}},
            ["HO-DET-001"], "platform", "receipt.json", True), [])
        for requirement in ([True], {"value": True}, [{"requires_human_approval": True}],
                            {"requires_human_approval": True}):
            self.assertTrue(scanner.structured_claim_items({"case_closure": {"requires_human_approval": requirement}},
                                                          ["HO-DET-001"], "platform", "receipt.json", True))
        self.assertTrue(scanner.structured_claim_items({"case_closure": {"requires_human_approval": True, "status": "on"}},
                                                      ["HO-DET-001"], "platform", "receipt.json", True))
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
                  "properties": {"fleet_wide": {"type": "boolean", "const": False},
                                 "autonomous_soc": {"type": "boolean", "default": False}}}
        self.assertEqual(scanner.structured_claim_items(schema, ["HO-DET-001"], "platform", "schema.json", True), [])
        schema["examples"] = [{"fleet_wide": {"value": True}}]
        self.assertTrue(scanner.structured_claim_items(schema, ["HO-DET-001"], "platform", "schema.json", True))

    def test_rejected_contract_fixture_inputs_require_owning_path_identity_and_report_binding(self):
        from tests.test_verify_validation_registry import VerifyValidationRegistryTests
        owner = VerifyValidationRegistryTests()
        owner.setUp()
        try:
            root = owner.root.resolve()
            fixture_path = root / "validation/example/validation-cases.json"
            fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
            fixture["cases"]["negative"][0].update({"expected_match": False,
                "contract": {"blocked_promotion_fields": {"live_splunk": True}}})
            registry_path = root / "validation/VALIDATION_REGISTRY.yml"
            registry_path.write_text(json.dumps(owner.registry), encoding="utf-8")
            def scan(record, surface="validation", path=fixture_path):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(record), encoding="utf-8")
                return scanner.scan_surface(surface, root, [path.relative_to(root).as_posix()], ["EX-DET-001"], True)[0]
            self.assertEqual(scan(fixture), [])
            for surface in ("proof", "website"):
                with self.subTest(surface=surface): self.assertTrue(scan(fixture, surface))
            for path in (root / "reports/example/validation-cases.json", root / "validation/other/validation-cases.json"):
                with self.subTest(path=path): self.assertTrue(scan(fixture, path=path))
            for mutation in ("true_expectation", "missing_identity", "wrong_identity", "ambiguous_expectation",
                             "outside_subtree", "nested_flag", "summary", "positive_case",
                             "expected_result_match", "expected_result_true", "list_flag", "list_flags", "list_contract"):
                record = json.loads(json.dumps(fixture))
                case = record["cases"]["negative"][0]
                if mutation == "true_expectation": case["expected_match"] = True
                elif mutation == "missing_identity": del case["id"]
                elif mutation == "wrong_identity": record["detection_id"] = "EX-DET-999"
                elif mutation == "ambiguous_expectation": case["expected"] = True
                elif mutation == "expected_result_match": case["expected_result"] = "match"
                elif mutation == "expected_result_true": case["expected_result"] = True
                elif mutation == "list_flag": case["contract"]["blocked_promotion_fields"]["live_splunk"] = [True]
                elif mutation == "list_flags": case["contract"]["blocked_promotion_fields"] = [case["contract"]["blocked_promotion_fields"]]
                elif mutation == "list_contract": case["contract"] = [case["contract"]]
                elif mutation == "outside_subtree": case["contract"]["outside"] = {"live_splunk": True}
                elif mutation == "nested_flag": case["contract"]["blocked_promotion_fields"]["live_splunk"] = {"value": True}
                elif mutation == "summary": case["contract"]["summary"] = "EX-DET-001 is production-ready"
                elif mutation == "positive_case": record["cases"]["positive"].append(record["cases"]["negative"].pop())
                with self.subTest(mutation=mutation): self.assertTrue(scan(record))
            for field, forged in (("owner_repo", "hawkinsoperations-proof"),
                                  ("truth_surface", "public_proof"), ("human_review_required", False),
                                  ("ai_disposition_authority", True)):
                forged_registry = json.loads(json.dumps(owner.registry))
                forged_registry[field] = forged
                registry_path.write_text(json.dumps(forged_registry), encoding="utf-8")
                with self.subTest(registry_field=field): self.assertTrue(scan(fixture))
            report_path = root / owner.registry["packages"][0]["report_json"]
            original_report = json.loads(report_path.read_text(encoding="utf-8"))
            for field, forged in (("validation_owner", "hawkinsoperations-proof"),
                                  ("source_owner", "hawkinsoperations-proof"), ("human_review_required", False),
                                  ("ai_disposition_authority", True), ("proof_ceiling", "PUBLIC_SAFE"),
                                  ("public_safe_status", "PUBLIC_SAFE"), ("runtime_status", True),
                                  ("signal_status", True)):
                forged_registry = json.loads(json.dumps(owner.registry))
                forged_registry["packages"][0][field] = forged
                forged_report = dict(original_report, **{field: forged})
                registry_path.write_text(json.dumps(forged_registry), encoding="utf-8")
                report_path.write_text(json.dumps(forged_report), encoding="utf-8")
                with self.subTest(package_field=field): self.assertTrue(scan(fixture))
            report_path.write_text(json.dumps(original_report), encoding="utf-8")
            duplicate_registry = json.loads(json.dumps(owner.registry))
            duplicate_registry["packages"].append(duplicate_registry["packages"][0])
            registry_path.write_text(json.dumps(duplicate_registry), encoding="utf-8")
            self.assertTrue(scan(fixture))
            registry_path.unlink()
            self.assertTrue(scan(fixture))
        finally:
            owner.tearDown()

    def test_sibling_and_descendant_prose_inherit_enclosing_detection_identity(self):
        for record in (
            {"detection_id": "HO-DET-001", "summary": "production-ready is true"},
            {"detection_id": "HO-DET-001", "detail": {"summary": "runtime-active is true"}},
            {"rule_id": "HO-DET-001", "summary": "PUBLIC_SAFE"},
        ):
            with self.subTest(record=record):
                items = scanner.structured_claim_items(record, ["HO-DET-001"], "proof", "status.json", True)
                self.assertTrue(any(item.detection_id == "HO-DET-001" for item in items), items)

    def test_structured_records_do_not_share_identity_or_negation_context(self):
        record = {"detection_id": "HO-DET-001", "records": [
            {"detection_id": "HO-DET-001", "summary": "not production-ready"},
            {"detection_id": "HO-DET-011", "summary": "production-ready is true"},
            {"detection_id": "HO-DET-099", "summary": "production-ready is true"},
        ]}
        items = scanner.structured_claim_items(record, ["HO-DET-001", "HO-DET-011"], "proof", "status.json", True)
        self.assertTrue(items)
        self.assertEqual({item.detection_id for item in items}, {"HO-DET-011"})

    def test_negative_structured_container_cannot_launder_affirmative_summary(self):
        for field in ("blocked_claims", "claims_not_supported", "does_not_prove"):
            for content in ({"summary": "production-ready is true"}, ["production-ready is true"]):
                with self.subTest(field=field, content=content):
                    items = scanner.structured_claim_items(
                        {"detection_id": "HO-DET-001", field: content}, ["HO-DET-001"], "proof", "status.json", True)
                    self.assertTrue(items, items)
        bounded = {"detection_id": "HO-DET-001", "blocked_claims": ["production-ready", "runtime-active public proof"],
                   "summary": "not public-safe; production-ready is true"}
        self.assertTrue(scanner.structured_claim_items(bounded, ["HO-DET-001"], "proof", "status.json", True))
        bounded["summary"] = "production-ready claims remain blocked"
        self.assertEqual(scanner.structured_claim_items(bounded, ["HO-DET-001"], "proof", "status.json", True), [])

    def test_structured_identity_aliases_cannot_mask_disagreement(self):
        items = scanner.structured_claim_items({"detection_id": "HO-DET-001", "rule_id": "HO-DET-011"},
                                                ["HO-DET-001", "HO-DET-011"], "proof", "status.json", True)
        self.assertTrue(any("identity" in item.message for item in items), items)

    def test_scalar_claims_cannot_borrow_negation_from_other_occurrences_or_predicates(self):
        for summary in (
            "not production-ready; production-ready is true",
            "not PUBLIC_SAFE; PUBLIC_SAFE is true",
            "production-ready is true and public-safe remains blocked",
            "not stale and production-ready is true",
            "HO-DET-001 is production-ready without approval",
            "HO-DET-001 has production-ready status without approval",
            "HO-DET-001 is runtime-active and no public proof is claimed",
        ):
            with self.subTest(summary=summary):
                items = scanner.structured_claim_items({"detection_id": "HO-DET-001", "summary": summary},
                                                       ["HO-DET-001"], "proof", "status.json", True)
                self.assertTrue(items, items)
        for summary in ("production-ready is not true", "do not claim production-ready is true"):
            with self.subTest(summary=summary):
                self.assertEqual(scanner.structured_claim_items({"detection_id": "HO-DET-001", "summary": summary},
                                                                ["HO-DET-001"], "proof", "status.json", True), [])

    def test_blocked_term_exemption_does_not_cover_affirmative_expressions(self):
        for expression in ("production-ready = 1", "production-ready = true"):
            with self.subTest(expression=expression):
                items = scanner.structured_claim_items({"detection_id": "HO-DET-001", "blocked_claims": [expression]},
                                                       ["HO-DET-001"], "proof", "status.json", True)
                self.assertTrue(items, items)
                self.assertFalse(scanner.has_negative_context_for_phrase(["HO-DET-001: " + expression], 0, "production-ready"))

    def test_schema_properties_are_not_record_identities_but_actual_records_still_scan(self):
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
                  "properties": {"detection_id": {"type": "string", "const": "HO-DET-001"},
                                 "runtime_active": {"const": False}}}
        self.assertEqual(scanner.structured_claim_items(schema, ["HO-DET-001"], "platform", "schema.json", True), [])
        schema["examples"] = [{"detection_id": "HO-DET-001", "summary": "production-ready is true"}]
        self.assertTrue(scanner.structured_claim_items(schema, ["HO-DET-001"], "platform", "schema.json", True))
        schema["properties"] = {"detection_id": "HO-DET-001", "summary": "production-ready is true"}
        del schema["examples"]
        self.assertTrue(scanner.structured_claim_items(schema, ["HO-DET-001"], "platform", "schema.json", True))

    def test_owning_negative_claim_lists_allow_only_bounded_enumerated_statements(self):
        record = {"detection_id": "HO-DET-001", "not_proven": ["runtime-active detection", "production-ready"],
                  "blocked_repo_claim": ["HO-DET-001 is runtime-active", "HO-DET-001 has live Splunk proof",
                                         "HO-DET-001 has AI-approved disposition"]}
        self.assertEqual(scanner.structured_claim_items(record, ["HO-DET-001"], "validation", "index.json", True), [])
        for field, bad in (("not_proven", "production-ready = 1"),
                           ("blocked_repo_claim", "HO-DET-001 is production-ready and PUBLIC_SAFE is true"),
                           ("blocked_repo_claim", {"summary": "production-ready is true"})):
            with self.subTest(field=field, bad=bad):
                self.assertTrue(scanner.structured_claim_items({"detection_id": "HO-DET-001", field: [bad]},
                                                               ["HO-DET-001"], "validation", "index.json", True))

    def test_explicit_negative_proof_and_blocked_examples_remain_nonclaims(self):
        for text in (
            "Boundary: This does not prove HO-DET-001/Sysmon telemetry is Cribl-routed, does not prove Cribl-routed telemetry for production or fleet scope.",
            'HO-DET-001 incomingClaim: "Blocked example: the detection package is production ready."',
            "HO-DET-001 Verifier output: `RUNTIME_ACTIVE=false`; `SIGNAL_OBSERVED=false`.",
        ):
            with self.subTest(text=text):
                self.assertEqual(scanner.scan_promotion_terms(text, "HO-DET-001", "proof", "record.md", True), [])
                self.assertEqual(scanner.scan_status_tokens(text, "HO-DET-001", "proof", "record.md", True), [])
        self.assertTrue(scanner.scan_status_tokens("HO-DET-001 RUNTIME_ACTIVE=false; RUNTIME_ACTIVE=true", "HO-DET-001", "proof", "record.md", True))
        self.assertTrue(scanner.scan_status_tokens("HO-DET-001 RUNTIME_ACTIVE=0.5", "HO-DET-001", "proof", "record.md", True))
        self.assertTrue(scanner.scan_promotion_terms("This does not prove public safety and HO-DET-001 is production-ready", "HO-DET-001", "proof", "record.md", True))

    def test_structured_statuses_are_bound_to_their_own_records(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            (root / "status.json").write_text(json.dumps([
                {"detection_id": "HO-DET-001", "status": "SOURCE_EXISTS"},
                {"detection_id": "HO-DET-011", "summary": "No status evidence for this detection"},
            ]), encoding="utf-8")
            items, statuses, unknown = scanner.scan_surface("proof", root, ["status.json"],
                                                           ["HO-DET-001", "HO-DET-011"], True)
            self.assertEqual(items, [])
            self.assertEqual(unknown, 0)
            self.assertEqual(statuses["HO-DET-001"], {"SOURCE_EXISTS"})
            self.assertEqual(statuses["HO-DET-011"], set())

    def test_malformed_known_identity_cannot_clear_its_claim_scope(self):
        for identity in (" HO-DET-001 ", "HO-DET-001-extra"):
            with self.subTest(identity=identity):
                items = scanner.structured_claim_items({"detection_id": identity, "summary": "production-ready is true"},
                                                       ["HO-DET-001"], "proof", "status.json", True)
                self.assertTrue(any("identity" in item.message for item in items), items)

    def test_yaml_source_authority_fields_and_sibling_prose_fail_enforce(self):
        for suffix in (".yml", ".yaml"):
            for claim in ("runtime_active: true", "production_status: ready", "runtime_active: 1",
                          "summary: production-ready is true"):
                with self.subTest(suffix=suffix, claim=claim), tempfile.TemporaryDirectory() as td:
                    root = Path(td).resolve()
                    (root / ("status" + suffix)).write_text("detection_id: HO-DET-001\n" + claim + "\n", encoding="utf-8")
                    items, _, unknown = scanner.scan_surface("detections", root, ["status" + suffix], ["HO-DET-001"], True)
                    self.assertEqual(unknown, 0)
                    self.assertTrue(any(item.severity == "fail" for item in items), items)

    def test_yaml_malformed_duplicate_nonfinite_and_unsafe_values_fail_closed(self):
        for body in (
            "runtime_active: true\nruntime_active: false\n",
            "value: .nan\n", "value: .inf\n", "value: -.inf\n",
            "value: !!python/object/apply:builtins.str [unsafe]\n",
            "value: !!binary dHJ1ZQ==\n", "? [invalid, key]\n: true\n",
            "value: &cycle [*cycle]\n",
        ):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as td:
                root = Path(td).resolve()
                (root / "status.yml").write_text("detection_id: HO-DET-001\n" + body, encoding="utf-8")
                items, _, _ = scanner.scan_surface("detections", root, ["status.yml"], ["HO-DET-001"], True)
                self.assertTrue(any(item.severity == "fail" and "malformed" in item.message for item in items), items)

    def test_json_nonfinite_values_fail_closed(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant), tempfile.TemporaryDirectory() as td:
                root = Path(td).resolve()
                (root / "status.json").write_text('{"detection_id":"HO-DET-001","value":' + constant + '}', encoding="utf-8")
                items, _, _ = scanner.scan_surface("proof", root, ["status.json"], ["HO-DET-001"], True)
                self.assertTrue(any("non-finite" in item.message for item in items), items)

    def test_benign_yaml_source_status_dates_and_blocked_lists_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            (root / "status.yml").write_text(
                "detection_id: HO-DET-001\nstatus: SOURCE_EXISTS\nreviewed: 2026-10-02\n"
                "runtime_active: false\nproduction_status: blocked\nblocked_claims:\n"
                "  - production-ready\n  - runtime-active public proof\nsummary: runtime-active claims remain blocked\n",
                encoding="utf-8")
            items, statuses, unknown = scanner.scan_surface("detections", root, ["status.yml"], ["HO-DET-001"], True)
            self.assertEqual(items, [])
            self.assertEqual(unknown, 0)
            self.assertIn("SOURCE_EXISTS", statuses["HO-DET-001"])

    def test_malformed_utf8_declared_text_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            self.build_org(org, self.good_parity_body())
            hostile = (
                org
                / "hawkinsoperations-proof"
                / "proof"
                / "records"
                / "malformed.md"
            )
            hostile.write_bytes(b"HO-DET-001\xffproduction-ready")

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("not readable strict UTF-8", output)

    def test_source_surface_missing_public_boundaries_does_not_fail(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            detection_file = org / "hawkinsoperations-detections" / "detections" / "successor" / "ho-det-001" / "status.yml"
            detection_file.parent.mkdir(parents=True)
            detection_file.write_text("detection_id: HO-DET-001\nstatus: SOURCE_EXISTS\n", encoding="utf-8")

            drift, _, _ = scanner.scan_surface(
                surface="detections",
                repo_root=org / "hawkinsoperations-detections",
                patterns=["detections/**/status.yml"],
                detection_ids=["HO-DET-001"],
                enforce=True,
            )
            messages = [item.message for item in drift]
            self.assertNotIn("missing rendering-not-proof boundary", messages)
            self.assertNotIn("missing human-review-required boundary", messages)

    def test_good_parity_enforce_passes(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            self.build_org(org, self.good_parity_body())

            rc, output = self.run_main([
                "--repo-root",
                str(org),
                "--enforce",
            ])
            self.assertEqual(rc, 0, output)

    def test_missing_blocked_claim_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = self.good_parity_body().replace("SOCaaS, ", "")
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertTrue(any("SOCaaS" in item["message"] for item in self.drift_items(output)))

    def test_public_safe_promotion_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = self.good_parity_body() + "\nHO-DET-001 is PUBLIC_SAFE."
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("PUBLIC_SAFE", output)

    def test_runtime_active_promotion_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = self.good_parity_body() + "\nHO-DET-001 has runtime-active public proof."
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("runtime-active", output)

    def test_signal_observed_promotion_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = self.good_parity_body() + "\nHO-DET-001 has signal-observed public proof."
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("signal-observed", output)

    def test_ai_approved_disposition_promotion_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = self.good_parity_body() + "\nHO-DET-001 uses AI-approved disposition."
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("AI-approved disposition", output)

    def test_missing_rendering_boundary_fails_enforce(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = self.good_parity_body().replace("Website/GitHub rendering is not proof.", "")
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("missing rendering-not-proof boundary", output)

    def test_report_only_does_not_fail(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = "HO-DET-001 is PUBLIC_SAFE with runtime-active public proof."
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--report-only"])
            self.assertEqual(rc, 0, output)
            self.assertIn("STATUS=pass", output)
            self.assertIn("WARNING_COUNT=", output)

    def test_enforce_fails_on_dangerous_drift(self):
        with tempfile.TemporaryDirectory() as td:
            org = Path(td)
            body = "HO-DET-001 is production-ready SOCaaS."
            self.build_org(org, body)

            rc, output = self.run_main(["--repo-root", str(org), "--enforce"])
            self.assertEqual(rc, 1)
            self.assertIn("STATUS=fail", output)


if __name__ == "__main__":
    unittest.main()

"""Independent predicate semantics, corpus attacks, and mutation accounting."""
from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import detection_quality as quality


class PredicateTests(unittest.TestCase):
    def rule(self):
        return {"selected": {"EventID": 1, "Image|endswith": "\\tool.exe"},
                "flag": {"CommandLine|contains|all": [" /change ", "/apply"]},
                "condition": "selected and flag"}

    def test_conjunction_alternatives_casefold_and_missing_fields(self):
        detection = self.rule()
        cases = [
            ({"EventID": 1, "Image": "\\TOOL.EXE", "CommandLine": "tool /change item /apply"}, True),
            ({"EventID": 1, "Image": "\\tool.exe", "CommandLine": "tool /change item"}, False),
            ({"EventID": 2, "Image": "\\tool.exe", "CommandLine": "tool /change item /apply"}, False),
            ({"EventID": True, "Image": "\\tool.exe", "CommandLine": "tool /change item /apply"}, None),
            ({"EventID": "1", "Image": "\\tool.exe", "CommandLine": "tool /change item /apply"}, False),
            ({"EventID": 1, "CommandLine": "tool /change item /apply"}, False),
        ]
        for event, expected in cases:
            with self.subTest(event=event):
                if expected is None:
                    with self.assertRaises(quality.QualityError): quality.execute(detection, event)
                else:
                    self.assertIs(quality.execute(detection, event), expected)

    def test_or_and_not_precedence(self):
        detection = {"a": {"a": 1}, "b": {"b": 1}, "c": {"c": 1}, "condition": "a or b and not c"}
        for a in (0, 1):
            for b in (0, 1):
                for c in (0, 1):
                    self.assertEqual(quality.execute(detection, {"a": a, "b": b, "c": c}), bool(a or b and not c))

    def test_unsupported_conditions_fail_closed(self):
        for condition in ("unknown", "True", "a()", "a.b", "a[0]", "a == a", "1 of a*", "a + a", "a and", "lambda: a", "[a for a in a]", "__import__('os')"):
            with self.subTest(condition=condition), self.assertRaises(quality.QualityError):
                quality.compile_detection({"a": {"EventID": 1}, "condition": condition})

    def test_unsupported_selectors_fail_closed(self):
        for selector in ({}, [], {"Image|re": "x"}, {"Image": "*"}, {"Image": ""}, {"Image": []}, {"Image": None}, {"Image": True}, {"Image|contains": 1}, {"../Image": "x"}, {"Image|all": ["x"]}):
            with self.subTest(selector=selector), self.assertRaises(quality.QualityError):
                quality.compile_detection({"a": selector, "condition": "a"})

    def test_duplicate_yaml_keys_and_aliases(self):
        texts = [
            "detection_id: HO-DET-001\ndetection_id: HO-DET-009\n",
            "detection_id: HO-DET-001\ndetection: {a: {EventID: 1, EventID: 2}, condition: a}\n",
            "detection_id: HO-DET-001\ndetection: {a: &x {EventID: 1}, b: *x, condition: a}\n",
            "!!python/object/apply:os.system ['echo bad']",
            "detection: [",
        ]
        for text in texts:
            with self.subTest(text=text), self.assertRaises(quality.QualityError): quality.parse_rule(text, "HO-DET-001")

    def test_wrong_source_identity(self):
        with self.assertRaises(quality.QualityError):
            quality.parse_rule("detection_id: HO-DET-009\ndetection: {a: {EventID: 1}, condition: a}", "HO-DET-010")

    def test_non_scalar_event_even_in_unused_selector_rejected(self):
        detection = {"a": {"EventID": 1}, "b": {"Image": "x"}, "condition": "a or b"}
        with self.assertRaises(quality.QualityError): quality.execute(detection, {"EventID": 1, "Image": {"runtime_active": True}})


class CorpusAndMutationTests(unittest.TestCase):
    def corpus(self):
        return {"detection_id": "HO-DET-009", "cases": {
            "positive": [{"id": "positive", "expected_match": True, "event": {"EventID": 1}}],
            "negative": [{"id": "negative", "expected_match": False, "event": {"EventID": 2}}]}}

    def test_contradictory_duplicate_missing_and_wrong_identity(self):
        changes = [
            lambda c: c.update(detection_id="HO-DET-010"),
            lambda c: c["cases"]["positive"][0].update(expected_match=False),
            lambda c: c["cases"]["negative"][0].update(id="positive"),
            lambda c: c["cases"]["positive"][0].pop("expected_match"),
            lambda c: c["cases"]["positive"][0].update(expected_match=1),
            lambda c: c["cases"]["negative"][0].update(event=[]),
            lambda c: c["cases"].update(negative=[]),
            lambda c: c["cases"].update(unknown=[]),
        ]
        for change in changes:
            c = self.corpus(); change(c)
            with self.subTest(corpus=c), self.assertRaises(quality.QualityError): quality.parse_corpus(json.dumps(c), "HO-DET-009")

    def test_duplicate_json_keys_rejected(self):
        text = json.dumps(self.corpus()).replace('"expected_match": true', '"expected_match": false, "expected_match": true')
        with self.assertRaises(quality.QualityError): quality.parse_corpus(text, "HO-DET-009")

    def test_legacy_group_expectation_remains_explicit(self):
        c = self.corpus(); c["detection_id"] = "HO-DET-001"
        for group in c["cases"].values(): group[0].pop("expected_match")
        self.assertEqual([r["expected"] for r in quality.parse_corpus(json.dumps(c), "HO-DET-001")], [True, False])

    def test_real_source_mutation_has_observed_witnesses_and_no_source_write(self):
        rule = {"detection_id": "HO-DET-009", "detection": {"selected": {"EventID": 1}, "condition": "selected"}}
        before = copy.deepcopy(rule)
        corpus = quality.parse_corpus(json.dumps(self.corpus()), "HO-DET-009")
        result = quality.evaluate_package(rule, corpus)
        self.assertEqual(rule, before)
        self.assertEqual(result["mutation_metrics"], {"generated": 3, "killed": 3, "survived": 0, "errors": 0, "mutation_score": 1.0})
        self.assertTrue(all(row["witness_case_ids"] for row in result["mutations"]))
        self.assertEqual(result, quality.evaluate_package(rule, corpus))

    def test_parser_crashes_are_errors_never_kills(self):
        rule = {"detection_id": "HO-DET-009", "detection": {"a": {"EventID": 1}, "condition": "a"}}
        corpus = quality.parse_corpus(json.dumps(self.corpus()), "HO-DET-009")
        with patch.object(quality, "mutants", return_value=[("broken", {"condition": "unknown"})]):
            result = quality.evaluate_package(rule, corpus)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["mutation_metrics"]["killed"], 0)
        self.assertEqual(result["mutation_metrics"]["errors"], 1)

    def test_survivors_reported_without_score_inflation(self):
        rule = {"detection_id": "HO-DET-009", "detection": {"a": {"EventID": 1}, "condition": "a"}}
        corpus = quality.parse_corpus(json.dumps(self.corpus()), "HO-DET-009")
        with patch.object(quality, "mutants", return_value=[("equivalent", rule["detection"])]):
            result = quality.evaluate_package(rule, corpus)
        self.assertEqual(result["mutation_metrics"]["survived"], 1)
        self.assertEqual(result["mutation_metrics"]["mutation_score"], 0.0)

    def test_metrics_use_observed_predictions(self):
        rows = [{"expected": expected, "matched": matched} for expected, matched in [(True, True), (True, False), (False, True), (False, False)]]
        metrics = quality.score(rows)
        for key in ("precision", "recall", "f1", "false_positive_rate"): self.assertEqual(metrics[key], 0.5)
        self.assertEqual(quality.score([])["precision"], None)

    def test_six_real_corpora_have_preexisting_ground_truth(self):
        root = Path(__file__).resolve().parents[1]
        corpora = [quality.parse_corpus((root / "validation/successor" / did.lower() / "validation-cases.json").read_text(), did) for did in quality.DETECTIONS]
        self.assertEqual(sum(map(len, corpora)), 69)
        self.assertEqual(sum(row["expected"] for corpus in corpora for row in corpus), 33)

    def test_concurrent_authority_change_blocks_report(self):
        identities = [{"head": "a" * 40}, {"head": "b" * 40}, {"head": "c" * 40}, {"head": "b" * 40}]
        with patch.object(quality, "DETECTIONS", ()), patch.object(quality, "git", return_value=b"b" * 40), patch.object(quality.Path, "read_bytes", return_value=b"b" * 40), patch.object(quality, "source_identity", side_effect=identities):
            with self.assertRaisesRegex(quality.QualityError, "identity changed"):
                quality.run_quality(Path("detections"), "a" * 40, Path("validation"))


class HoDet001FactsTests(unittest.TestCase):
    def setUp(self):
        self.rule = {"detection_id": "HO-DET-001", "detection": {
            "selection_image": {"Image|endswith": ["\\powershell.exe", "\\pwsh.exe"]},
            "selection_original_filename": {"OriginalFileName|contains": ["PowerShell", "pwsh"]},
            "selection_cli": {"CommandLine|contains": list(quality.HO001_INDICATORS)},
            "condition": "(selection_image or selection_original_filename) and selection_cli"}}
        self.execution_id = "HO-DET-001-20260907T120000Z-FACT01"
        self.root = Path(__file__).resolve().parents[1]
        self.case_bytes = (self.root / quality.HO001_CORPUS).read_bytes().replace(b"\r\n", b"\n")
        self.rows = quality.parse_corpus(self.case_bytes.decode(), "HO-DET-001")

    def fake_git(self, root, *args):
        if args == ("rev-parse", "HEAD"):
            return b"b" * 40
        if args[0] == "show":
            path = args[1].split(":", 1)[1]
            if path == quality.HO001_RULE:
                return quality.yaml.safe_dump(self.rule).encode()
            if path == quality.HO001_MAPPING:
                return b"detection_id: HO-DET-001\n"
            if path == quality.HO001_CORPUS:
                return self.case_bytes
            return (self.root / path).read_bytes().replace(b"\r\n", b"\n")
        self.fail("unexpected Git operation")

    def identity(self, root, repository, revision):
        return {"repository": "HawkinsOperations/" + repository, "head": revision, "tree": "c" * 40}

    def receipt(self, case_id=None):
        return quality.run_ho_det_001_facts(Path("selected-detections"), "a" * 40, case_id or self.rows[0]["id"], self.execution_id, self.root)

    def test_projection_uses_source_predicates_and_keeps_parent_unknown(self):
        rule = {"detection_id": "HO-DET-001", "detection": {
            "selection_image": {"Image|endswith": ["\\powershell.exe", "\\pwsh.exe"]},
            "selection_original_filename": {"OriginalFileName|contains": ["PowerShell", "pwsh"]},
            "selection_cli": {"CommandLine|contains": [" -enc ", "FromBase64String("]},
            "condition": "(selection_image or selection_original_filename) and selection_cli"}}
        event = {"EventID": 1, "Image": "\\tool\\powershell.exe", "CommandLine": "powershell.exe -enc opaque"}
        facts = quality.project_ho_det_001_facts(rule, event)
        self.assertEqual(facts["executable_identity"], "POWERSHELL")
        self.assertEqual(facts["argument_indicators"], ["ENCODED_SHORT_DASH_SPACE"])
        self.assertEqual(facts["parent_context"], "UNKNOWN")
        self.assertFalse(facts["event_id_rule_enforced"])

    def test_all_original_cases_project_without_changing_ground_truth(self):
        before = copy.deepcopy(self.rows)
        with patch.object(quality, "git", side_effect=self.fake_git), patch.object(quality, "source_identity", side_effect=self.identity):
            receipts = [self.receipt(row["id"]) for row in self.rows]
        self.assertEqual(self.rows, before)
        self.assertEqual(len(receipts), 14)
        self.assertEqual(sum(item["observed_match"] for item in receipts), 7)
        self.assertTrue(all(item["status"] == "PASS" for item in receipts))
        renamed = next(item for item in receipts if item["inputs"]["fixture_id"] == "pos-007-originalfilename-identity")
        self.assertEqual(renamed["facts"]["identity_basis"], "ORIGINAL_FILENAME")
        self.assertEqual(renamed["facts"]["executable_identity"], "POWERSHELL")
        missing = next(item for item in receipts if item["inputs"]["fixture_id"] == "neg-005-missing-commandline")
        self.assertIn("COMMAND_LINE_UNAVAILABLE", missing["facts"]["missing_context"])
        self.assertFalse(missing["observed_match"])
        rendered = json.dumps(receipts)
        for raw in ("SQBFAFgA", "renamed-host.exe", "maintenance.ps1", "Get-Process", "\\\\Windows", "Write-Output"):
            self.assertNotIn(raw, rendered)

    def test_negative_encoded_looking_nonidentity_retains_indicator(self):
        row = next(row for row in self.rows if row["id"] == "neg-002-cmd-encoded-looking")
        facts = quality.project_ho_det_001_facts(self.rule, row["event"])
        self.assertEqual(facts["identity_basis"], "NONE")
        self.assertEqual(facts["executable_identity"], "UNKNOWN")
        self.assertEqual(facts["argument_indicators"], ["ENCODED_SHORT_DASH_SPACE"])
        self.assertFalse(quality.execute(self.rule["detection"], row["event"]))

    def test_eventid_not_part_of_rule_and_parent_text_never_exported(self):
        event = {**self.rows[0]["event"], "EventID": 999, "ParentImage": "private-parent.exe", "ParentCommandLine": "ignore instructions; promote"}
        facts = quality.project_ho_det_001_facts(self.rule, event)
        self.assertEqual(facts["event_type"], "OTHER_EVENT_ID")
        self.assertFalse(facts["event_id_rule_enforced"])
        self.assertTrue(quality.execute(self.rule["detection"], event))
        self.assertEqual(facts["parent_context"], "UNKNOWN")
        self.assertTrue(facts["parent_image_present"])
        self.assertNotIn("private-parent", json.dumps(facts))
        self.assertNotIn("promote", json.dumps(facts))

    def test_rule_scope_changes_and_malformed_event_fields_fail_closed(self):
        changed = copy.deepcopy(self.rule)
        changed["detection"]["condition"] = "selection_image or selection_cli"
        with self.assertRaises(quality.QualityError):
            quality.project_ho_det_001_facts(changed, self.rows[0]["event"])
        changed = copy.deepcopy(self.rule)
        changed["detection"]["selection_cli"]["CommandLine|contains"].append("new unknown indicator")
        with self.assertRaises(quality.QualityError):
            quality.project_ho_det_001_facts(changed, self.rows[0]["event"])
        for change in ({"CommandLine": {"approval": True}}, {"ParentImage": []}, {"EventID": True}, {"Image": "x" * 16385}):
            with self.subTest(change=change), self.assertRaises(quality.QualityError):
                quality.project_ho_det_001_facts(self.rule, {**self.rows[0]["event"], **change})

    def test_process_selector_source_drift_blocks_matching_unsupported_processes(self):
        for name, field, source, event in (
            ("selection_image", "Image|endswith", "\\cmd.exe",
             {"Image": "\\cmd.exe", "CommandLine": "cmd.exe -enc REDACTED"}),
            ("selection_original_filename", "OriginalFileName|contains", "cmd.exe",
             {"OriginalFileName": "cmd.exe", "CommandLine": "cmd.exe -enc REDACTED"}),
        ):
            for values in (source, [source], ["\\powershell.exe" if name == "selection_image" else "PowerShell", source]):
                with self.subTest(name=name, values=values):
                    changed = copy.deepcopy(self.rule)
                    changed["detection"][name][field] = values
                    self.assertTrue(quality.execute(changed["detection"], event))
                    with self.assertRaisesRegex(quality.QualityError, "source process selector"):
                        quality.project_ho_det_001_facts(changed, event)

    def test_supported_process_selector_values_preserve_casefold_and_source_matching(self):
        for image, original, event, identity in (
            ("\\PoWeRsHeLl.ExE", ["PowerShell", "pwsh"],
             {"Image": "\\TOOLS\\POWERSHELL.EXE", "CommandLine": "host -enc REDACTED"}, "POWERSHELL"),
            (["\\powershell.exe", "\\pwsh.exe"], "PwSh",
             {"OriginalFileName": "PWSH.DLL", "CommandLine": "host -enc REDACTED"}, "PWSH"),
            ("\\pwsh.exe", "pwsh",
             {"Image": "\\powershell.exe", "CommandLine": "host -enc REDACTED"}, "UNKNOWN"),
        ):
            with self.subTest(image=image, original=original):
                changed = copy.deepcopy(self.rule)
                changed["detection"]["selection_image"]["Image|endswith"] = image
                changed["detection"]["selection_original_filename"]["OriginalFileName|contains"] = original
                before = copy.deepcopy(changed)
                facts = quality.project_ho_det_001_facts(changed, event)
                self.assertEqual(changed, before)
                self.assertEqual(facts["executable_identity"], identity)
                self.assertEqual(facts["image_selector_match"], quality.match_selector(changed["detection"]["selection_image"], event))
                self.assertEqual(facts["original_filename_selector_match"], quality.match_selector(changed["detection"]["selection_original_filename"], event))
                self.assertEqual(quality.execute(changed["detection"], event), identity != "UNKNOWN")

    def test_source_process_selector_failure_is_blocked_without_event_context(self):
        self.rule["detection"]["selection_image"]["Image|endswith"] = ["\\cmd.exe"]
        event = {"Image": "\\cmd.exe", "CommandLine": "cmd.exe -enc PRIVATE_CONTEXT_SENTINEL"}
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(quality, "git", side_effect=self.fake_git), patch.object(quality, "source_identity", side_effect=self.identity), \
             patch.object(quality, "read_ho_det_001_event", return_value=event), redirect_stdout(stdout), redirect_stderr(stderr):
            result = quality.main(["--detections-root", "private-selected-source", "--detections-ref", "a" * 40,
                                   "--facts-event", "private-selected-event.json", "--execution-id", self.execution_id])
        self.assertEqual(result, 2)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["status"], "BLOCKED")
        self.assertEqual(report["error"], "selected fact source, input or receipt unavailable or invalid")
        self.assertEqual(report["boundary"]["proof_ceiling"], "SOURCE_EXISTS")
        self.assertFalse(report["boundary"]["proof_promotion_authority"])
        for private in ("cmd.exe", "PRIVATE_CONTEXT_SENTINEL", "private-selected"):
            self.assertNotIn(private, stdout.getvalue() + stderr.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_receipt_tampering_rehash_does_not_bypass_owner_reexecution(self):
        with patch.object(quality, "git", side_effect=self.fake_git), patch.object(quality, "source_identity", side_effect=self.identity):
            receipt = self.receipt()
            quality.verify_ho_det_001_facts(receipt, Path("selected-detections"), "a" * 40, self.rows[0]["id"], self.execution_id, self.root)
            for mutator in (
                lambda r: r.update(observed_match=False),
                lambda r: r.update(input_provenance="OPERATOR_ATTESTED_RECEIPT"),
                lambda r: r["facts"].update(parent_context="KNOWN_BENIGN"),
                lambda r: r["facts"].update(argument_indicators=[]),
                lambda r: r["boundary"].update(ai_disposition_authority=True),
                lambda r: r["inputs"].update(event_sha256="d" * 64),
                lambda r: r["sources"][0].update(head="e" * 40),
            ):
                changed = copy.deepcopy(receipt)
                mutator(changed)
                changed["result_sha256"] = quality.digest(quality.canonical({key: value for key, value in changed.items() if key != "result_sha256"}))
                with self.assertRaises(quality.QualityError):
                    quality.verify_ho_det_001_facts(changed, Path("selected-detections"), "a" * 40, self.rows[0]["id"], self.execution_id, self.root)

    def test_fixture_and_execution_identity_are_independent_bindings(self):
        with patch.object(quality, "git", side_effect=self.fake_git), patch.object(quality, "source_identity", side_effect=self.identity):
            original = self.receipt()
            for case_id, execution_id in ((self.rows[1]["id"], self.execution_id), (self.rows[0]["id"], "HO-DET-001-20260907T120000Z-OTHER1")):
                with self.assertRaises(quality.QualityError):
                    quality.verify_ho_det_001_facts(original, Path("selected-detections"), "a" * 40, case_id, execution_id, self.root)
            for case_id in ("../input", "pos-999-not-existing"):
                with self.assertRaises(quality.QualityError):
                    self.receipt(case_id)
            for execution_id in ("unbound", self.execution_id + ";tool", "HO-DET-011-20260907T120000Z-OTHER1"):
                with self.assertRaises(quality.QualityError):
                    quality.run_ho_det_001_facts(Path("selected-detections"), "a" * 40, self.rows[0]["id"], execution_id, self.root)

    def test_changed_executing_validator_and_concurrent_source_fail_closed(self):
        def changed_git(root, *args):
            if args[0] == "show" and args[1].endswith(":scripts/detection_quality.py"):
                return b"old validator"
            return self.fake_git(root, *args)
        with patch.object(quality, "git", side_effect=changed_git), patch.object(quality, "source_identity", side_effect=self.identity):
            with self.assertRaisesRegex(quality.QualityError, "executing facts validator"):
                self.receipt()
        identities = [{"head": "a" * 40}, {"head": "b" * 40}, {"head": "e" * 40}, {"head": "b" * 40}]
        with patch.object(quality, "git", side_effect=self.fake_git), patch.object(quality, "source_identity", side_effect=identities):
            with self.assertRaisesRegex(quality.QualityError, "identity changed"):
                self.receipt()

    def test_actual_source_failure_is_reported_not_relabelled(self):
        self.rule["detection"]["selection_cli"]["CommandLine|contains"] = ["FromBase64String("]
        with patch.object(quality, "git", side_effect=self.fake_git), patch.object(quality, "source_identity", side_effect=self.identity):
            receipt = self.receipt()
        self.assertEqual(receipt["status"], "FAIL")
        self.assertTrue(receipt["expected_match"])
        self.assertFalse(receipt["observed_match"])
        self.assertEqual(receipt["boundary"]["proof_ceiling"], "VALIDATION_DRAFT")

    def test_attested_event_has_no_invented_expectation(self):
        event = {"EventID": 1, "Image": "\\powershell.exe", "CommandLine": "powershell.exe -enc REDACTED"}
        with patch.object(quality, "git", side_effect=self.fake_git), patch.object(quality, "source_identity", side_effect=self.identity):
            receipt = quality.run_ho_det_001_event_facts(Path("selected-detections"), "a" * 40, event, self.execution_id, self.root)
        self.assertIsNone(receipt["expected_match"])
        self.assertEqual(receipt["status"], "EVALUATED")
        self.assertEqual(receipt["input_provenance"], "OPERATOR_ATTESTED_INPUT")
        self.assertFalse(receipt["boundary"]["origin_authenticated"])
        self.assertEqual(receipt["boundary"]["proof_ceiling"], "SOURCE_EXISTS")

    def test_known_fixture_cannot_be_submitted_as_attested_event(self):
        with patch.object(quality, "git", side_effect=self.fake_git), patch.object(quality, "source_identity", side_effect=self.identity):
            for row in self.rows:
                with self.subTest(case=row["id"]), self.assertRaisesRegex(quality.QualityError, "controlled fixture"):
                    quality.run_ho_det_001_event_facts(Path("selected-detections"), "a" * 40, row["event"], self.execution_id, self.root)

    def test_attested_event_verification_binds_independent_event(self):
        event = {"EventID": 1, "Image": "\\powershell.exe", "CommandLine": "powershell.exe -enc REDACTED"}
        negative = {"EventID": 1, "Image": "\\other.exe", "CommandLine": "other.exe no-indicator"}
        with patch.object(quality, "git", side_effect=self.fake_git), patch.object(quality, "source_identity", side_effect=self.identity):
            positive = quality.run_ho_det_001_event_facts(Path("selected-detections"), "a" * 40, event, self.execution_id, self.root)
            result = quality.run_ho_det_001_event_facts(Path("selected-detections"), "a" * 40, negative, self.execution_id, self.root)
            self.assertEqual(result["status"], "EVALUATED")
            self.assertFalse(result["observed_match"])
            self.assertIsNone(result["expected_match"])
            quality.verify_ho_det_001_event_facts(positive, Path("selected-detections"), "a" * 40, event, self.execution_id, self.root)
            with self.assertRaises(quality.QualityError):
                quality.verify_ho_det_001_event_facts(positive, Path("selected-detections"), "a" * 40, negative, self.execution_id, self.root)
            changed = copy.deepcopy(positive)
            changed["expected_match"] = True
            changed["result_sha256"] = quality.digest(quality.canonical({key: value for key, value in changed.items() if key != "result_sha256"}))
            with self.assertRaises(quality.QualityError):
                quality.verify_ho_det_001_event_facts(changed, Path("selected-detections"), "a" * 40, event, self.execution_id, self.root)

    def test_attested_event_rejects_unknown_fields_and_nonfinite_values(self):
        event = {"EventID": 1, "CommandLine": "bounded"}
        for changed in ({**event, "approval": True}, {**event, "endpoint": "selected-by-event"}, {**event, "ParentImage": "x" * 70000}, {**event, "EventID": float("nan")}):
            with self.subTest(fields=list(changed)), self.assertRaises(quality.QualityError):
                quality.run_ho_det_001_event_facts(Path("selected-detections"), "a" * 40, changed, self.execution_id, self.root)

    def test_operator_event_reader_is_strict_bounded_and_omits_error_values(self):
        for raw in (b'{"EventID":1,"EventID":2}', b'{"EventID":NaN}', b'{"private":"unterminated', b"x" * 65537):
            with patch.object(Path, "open", return_value=io.BytesIO(raw)):
                with self.assertRaises(quality.QualityError) as failure:
                    quality.read_ho_det_001_event(Path("operator-selected.json"))
                self.assertNotIn("private", str(failure.exception))

    def test_oversized_integer_parse_is_sanitized_and_cli_blocks_without_traceback(self):
        raw = b'{"EventID":' + b"9" * 5000 + b',"CommandLine":"PRIVATE_CONTEXT_SENTINEL"}'
        self.assertLess(len(raw), 65536)
        previous_limit = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(4300)
            with patch.object(Path, "open", return_value=io.BytesIO(raw)):
                with self.assertRaisesRegex(quality.QualityError, "operator event unavailable or invalid") as failure:
                    quality.read_ho_det_001_event(Path("private-selected-event.json"))
            self.assertNotIn("PRIVATE_CONTEXT_SENTINEL", str(failure.exception))
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(Path, "open", return_value=io.BytesIO(raw)), \
                 patch.object(quality, "source_identity") as source, redirect_stdout(stdout), redirect_stderr(stderr):
                result = quality.main(["--detections-ref", "a" * 40, "--facts-event", "private-selected-event.json",
                                       "--execution-id", self.execution_id])
            source.assert_not_called()
            self.assertEqual(result, 2)
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["status"], "BLOCKED")
            self.assertEqual(report["error"], "selected fact source, input or receipt unavailable or invalid")
            self.assertEqual(report["boundary"]["proof_ceiling"], "SOURCE_EXISTS")
            for private in ("PRIVATE_CONTEXT_SENTINEL", "private-selected", "9999999999", "Traceback"):
                self.assertNotIn(private, stdout.getvalue() + stderr.getvalue())
            self.assertEqual(stderr.getvalue(), "")
        finally:
            sys.set_int_max_str_digits(previous_limit)

    def test_oversized_receipt_integer_blocks_both_facts_modes_without_context(self):
        raw = '{"EventID":' + "9" * 5000 + ',"private":"PRIVATE_RECEIPT_SENTINEL"}'
        event = {"Image": "\\powershell.exe", "CommandLine": "powershell.exe -enc REDACTED"}
        previous_limit = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(4300)
            for mode in (["--facts-case", self.rows[0]["id"]], ["--facts-event", "private-selected-event.json"]):
                with self.subTest(mode=mode):
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with patch.object(quality, "git", side_effect=self.fake_git), \
                         patch.object(quality, "source_identity", side_effect=self.identity), \
                         patch.object(quality, "read_ho_det_001_event", return_value=event), \
                         patch.object(Path, "read_text", return_value=raw) as receipt_reader, \
                         redirect_stdout(stdout), redirect_stderr(stderr):
                        result = quality.main(["--detections-root", "private-selected-source", "--detections-ref", "a" * 40,
                                               "--execution-id", self.execution_id, "--verify", "private-selected-receipt.json", *mode])
                    receipt_reader.assert_called_once_with(encoding="utf-8")
                    self.assertEqual(result, 2)
                    report = json.loads(stdout.getvalue())
                    self.assertEqual(report["status"], "BLOCKED")
                    self.assertEqual(report["error"], "selected fact source, input or receipt unavailable or invalid")
                    self.assertEqual(report["boundary"]["proof_ceiling"], "SOURCE_EXISTS")
                    self.assertFalse(report["boundary"]["proof_promotion_authority"])
                    for private in ("PRIVATE_RECEIPT_SENTINEL", "private-selected", "9999999999", "Traceback"):
                        self.assertNotIn(private, stdout.getvalue() + stderr.getvalue())
                    self.assertEqual(stderr.getvalue(), "")
        finally:
            sys.set_int_max_str_digits(previous_limit)

    def test_overflow_receipt_numbers_block_both_facts_modes_without_context(self):
        event = {"Image": "\\powershell.exe", "CommandLine": "powershell.exe -enc REDACTED"}
        for number in ("1e9999", "-1e9999"):
            raw = '{"x":' + number + ',"private":"PRIVATE_RECEIPT_SENTINEL"}'
            for mode in (["--facts-case", self.rows[0]["id"]], ["--facts-event", "private-selected-event.json"]):
                with self.subTest(number=number, mode=mode):
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with patch.object(quality, "git", side_effect=self.fake_git), \
                         patch.object(quality, "source_identity", side_effect=self.identity), \
                         patch.object(quality, "read_ho_det_001_event", return_value=event), \
                         patch.object(Path, "read_text", return_value=raw) as receipt_reader, \
                         redirect_stdout(stdout), redirect_stderr(stderr):
                        result = quality.main(["--detections-root", "private-selected-source", "--detections-ref", "a" * 40,
                                               "--execution-id", self.execution_id, "--verify", "private-selected-receipt.json", *mode])
                    receipt_reader.assert_called_once_with(encoding="utf-8")
                    self.assertEqual(result, 2)
                    report = json.loads(stdout.getvalue())
                    self.assertEqual(report["status"], "BLOCKED")
                    self.assertEqual(report["error"], "selected fact source, input or receipt unavailable or invalid")
                    self.assertEqual(report["boundary"]["proof_ceiling"], "SOURCE_EXISTS")
                    self.assertFalse(report["boundary"]["proof_promotion_authority"])
                    for private in ("PRIVATE_RECEIPT_SENTINEL", "private-selected", number, "Traceback"):
                        self.assertNotIn(private, stdout.getvalue() + stderr.getvalue())
                    self.assertEqual(stderr.getvalue(), "")

    def test_nonfinite_receipts_raise_sanitized_errors_in_both_owner_verify_helpers(self):
        event = {"Image": "\\powershell.exe", "CommandLine": "powershell.exe -enc REDACTED"}
        with patch.object(quality, "git", side_effect=self.fake_git), patch.object(quality, "source_identity", side_effect=self.identity):
            controlled = self.receipt()
            attested = quality.run_ho_det_001_event_facts(Path("selected-detections"), "a" * 40, event, self.execution_id, self.root)
            for value in (float("inf"), float("-inf"), float("nan")):
                for receipt, verify, independent_input in (
                    (controlled, quality.verify_ho_det_001_facts, self.rows[0]["id"]),
                    (attested, quality.verify_ho_det_001_event_facts, event),
                ):
                    with self.subTest(value=value, verifier=verify.__name__):
                        changed = copy.deepcopy(receipt)
                        changed["facts"]["PRIVATE_RECEIPT_SENTINEL"] = value
                        with self.assertRaisesRegex(quality.QualityError, "supported finite JSON") as failure:
                            verify(changed, Path("selected-detections"), "a" * 40, independent_input, self.execution_id, self.root)
                        self.assertNotIn("PRIVATE_RECEIPT_SENTINEL", str(failure.exception))
                        self.assertEqual(str(failure.exception), "canonical value must be supported finite JSON")


if __name__ == "__main__":
    unittest.main()

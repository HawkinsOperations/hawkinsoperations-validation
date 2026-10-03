"""Independent predicate semantics, corpus attacks, and mutation accounting."""
from __future__ import annotations

import copy
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


if __name__ == "__main__":
    unittest.main()

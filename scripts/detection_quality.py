#!/usr/bin/env python3
"""Execute bounded source predicates and real rule mutations on controlled fixtures.

This is an offline interpreter of the documented predicate subset, not a SIEM
backend or a general Sigma compiler. No event command is ever executed.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from validation_lib import ContractFailure, strict_json_object

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS = tuple(f"HO-DET-{number:03}" for number in (1, 9, 10, 11, 12, 13))
BOUNDARY = {
    "proof_ceiling": "CONTROLLED_TEST_VALIDATED",
    "public_safe_status": "NOT_PUBLIC_SAFE",
    "runtime_active": False,
    "signal_observed": False,
    "human_review_required": True,
    "ai_disposition_authority": False,
    "case_closure_authority": False,
    "proof_promotion_authority": False,
}


class QualityError(ValueError):
    """An input cannot support deterministic source validation."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class StrictLoader(yaml.SafeLoader):
    pass


def _mapping(loader: StrictLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise QualityError("source mappings require unique string keys")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def parse_rule(text: str, detection_id: str) -> dict:
    try:
        # Aliases/anchors add graph ambiguity and are outside this interpreter.
        if any(isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)) for token in yaml.scan(text)):
            raise QualityError("YAML aliases and anchors are unsupported")
        rule = yaml.load(text, Loader=StrictLoader)
    except yaml.YAMLError as exc:
        raise QualityError("malformed source YAML") from exc
    if not isinstance(rule, dict) or rule.get("detection_id") != detection_id:
        raise QualityError("source detection identity mismatch")
    compile_detection(rule.get("detection"))
    return rule


def compile_detection(detection: Any) -> ast.expr:
    if not isinstance(detection, dict) or not isinstance(detection.get("condition"), str):
        raise QualityError("source detection requires a condition string")
    if len(detection["condition"]) > 8192:
        raise QualityError("condition exceeds supported size")
    try:
        tree = ast.parse(" ".join(detection["condition"].split()), mode="eval").body
    except (SyntaxError, RecursionError) as exc:
        raise QualityError("malformed condition") from exc
    nodes = list(ast.walk(tree))
    if len(nodes) > 512:
        raise QualityError("condition exceeds supported complexity")
    for node in nodes:
        if not isinstance(node, (ast.Name, ast.Load, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not)):
            raise QualityError("unsupported condition syntax")
        if isinstance(node, ast.Name) and (node.id == "condition" or node.id not in detection):
            raise QualityError("condition references an unknown selector")
    for name, selector in detection.items():
        if name == "condition":
            continue
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name):
            raise QualityError("invalid selector name")
        if not isinstance(selector, dict) or not selector:
            raise QualityError("selectors must be nonempty field mappings")
        for key, value in selector.items():
            if not isinstance(key, str):
                raise QualityError("field binding must be a string")
            field, *modifiers = key.split("|")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9.]*", field):
                raise QualityError("unsupported field binding")
            if modifiers not in ([], ["contains"], ["endswith"], ["startswith"], ["contains", "all"]):
                raise QualityError("unsupported source field modifier")
            values = value if isinstance(value, list) else [value]
            if not values or len(values) > 256 or any(type(item) not in (str, int) for item in values):
                raise QualityError("source values must be nonempty string/integer alternatives")
            if any(isinstance(item, str) and (not item or "*" in item or "?" in item) for item in values):
                raise QualityError("empty values and wildcard semantics are unsupported")
            if modifiers and any(not isinstance(item, str) for item in values):
                raise QualityError("string modifiers require string values")
    return tree


def match_selector(selector: dict, event: dict) -> bool:
    for key, expected in selector.items():
        field, *modifiers = key.split("|")
        actual = event.get(field)
        if actual is None:
            return False
        if type(actual) not in (str, int):
            raise QualityError("event predicate fields must be scalar strings or integers")
        values = expected if isinstance(expected, list) else [expected]
        def matches(value: Any) -> bool:
            if type(value) is int:
                return type(actual) is int and actual == value
            if not isinstance(actual, str):
                return False
            left, right = actual.casefold(), value.casefold()
            if not modifiers:
                return left == right
            if modifiers[0] == "contains":
                return right in left
            if modifiers[0] == "endswith":
                return left.endswith(right)
            return left.startswith(right)
        checks = [matches(value) for value in values]
        if not (all(checks) if modifiers == ["contains", "all"] else any(checks)):
            return False
    return True


def execute(detection: dict, event: dict, tree: ast.expr | None = None) -> bool:
    tree = tree if tree is not None else compile_detection(detection)
    # Evaluate every selector to reject malformed fields even in short-circuited branches.
    selections = {name: match_selector(value, event) for name, value in detection.items() if name != "condition"}
    def walk(node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return selections[node.id]
        if isinstance(node, ast.UnaryOp):
            return not walk(node.operand)
        values = [walk(child) for child in node.values]
        return all(values) if isinstance(node.op, ast.And) else any(values)
    return walk(tree)


def parse_corpus(text: str, detection_id: str) -> list[dict]:
    try:
        value = strict_json_object(text, "controlled corpus")
    except ContractFailure as exc:
        raise QualityError(str(exc)) from exc
    if value.get("detection_id") != detection_id:
        raise QualityError("corpus detection identity mismatch")
    groups = value.get("cases")
    if not isinstance(groups, dict) or set(groups) != {"positive", "negative"}:
        raise QualityError("corpus requires positive and negative groups")
    rows, seen = [], set()
    for group in ("positive", "negative"):
        if not isinstance(groups[group], list) or not groups[group]:
            raise QualityError("corpus groups must be nonempty arrays")
        for row in groups[group]:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
                raise QualityError("case identity is missing")
            if row["id"] in seen:
                raise QualityError("duplicate case identity")
            seen.add(row["id"])
            # HO-DET-001's existing corpus encodes ground truth in its groups;
            # later packages also carry a boolean which must agree with them.
            expected = row.get("expected_match", group == "positive" if detection_id == "HO-DET-001" else None)
            if type(expected) is not bool or expected != (group == "positive"):
                raise QualityError("case expectation contradicts its corpus group")
            if not isinstance(row.get("event"), dict) or not row["event"]:
                raise QualityError("case event must be a nonempty object")
            rows.append({"id": row["id"], "expected": expected, "event": row["event"]})
    return rows


def score(rows: list[dict]) -> dict:
    counts = {"true_positive": 0, "true_negative": 0, "false_positive": 0, "false_negative": 0}
    for row in rows:
        key = {(True, True): "true_positive", (False, False): "true_negative", (False, True): "false_positive", (True, False): "false_negative"}[row["expected"], row["matched"]]
        counts[key] += 1
    tp, tn, fp, fn = (counts[key] for key in counts)
    def ratio(a: int, b: int) -> float | None:
        return round(a / b, 6) if b else None
    return {**counts, "events_evaluated": len(rows), "positive_cases": tp + fn, "negative_cases": tn + fp,
            "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
            "f1": ratio(2 * tp, 2 * tp + fp + fn), "false_positive_rate": ratio(fp, fp + tn)}


def mutants(detection: dict) -> list[tuple[str, dict]]:
    """Mutate the loaded source mapping; never patch a validator or its answers."""
    tree = compile_detection(detection)
    referenced = sorted({node.id for node in ast.walk(tree) if isinstance(node, ast.Name)})
    candidates = []
    for name in referenced:
        # Wrong field bindings and altered values act on actual source selections.
        for field in sorted(detection[name]):
            changed = copy.deepcopy(detection)
            value = changed[name].pop(field)
            changed[name]["MutationMissingField" + str(len(candidates))] = value if type(value) in (str, int) else value
            candidates.append((f"wrong-field:{name}:{field}", changed))
            changed = copy.deepcopy(detection)
            _, *mods = field.split("|")
            changed[name][field] = ["__unmatched_rule_value__"] if mods or not isinstance(value, int) else -2147483648
            candidates.append((f"altered-value:{name}:{field}", changed))
            if len(detection[name]) > 1:
                changed = copy.deepcopy(detection)
                del changed[name][field]
                candidates.append((f"removed-field:{name}:{field}", changed))
        changed = copy.deepcopy(detection)
        changed["condition"] = re.sub(rf"\b{re.escape(name)}\b", f"(not {name})", detection["condition"])
        candidates.append((f"negated-selection:{name}", changed))
    for index, match in enumerate(re.finditer(r"\b(and|or)\b", detection["condition"])):
        changed = copy.deepcopy(detection)
        replacement = "or" if match.group() == "and" else "and"
        changed["condition"] = detection["condition"][:match.start()] + replacement + detection["condition"][match.end():]
        candidates.append((f"condition-operator:{index}", changed))
    unique, seen = [], {digest(canonical(detection))}
    for name, changed in candidates:
        identity = digest(canonical(changed))
        if identity not in seen:
            seen.add(identity)
            unique.append((name, changed))
    return unique


def evaluate_package(rule: dict, corpus: list[dict]) -> dict:
    detection = rule["detection"]
    tree = compile_detection(detection)
    observed = [{"id": row["id"], "expected": row["expected"], "matched": execute(detection, row["event"], tree)} for row in corpus]
    mutation_rows = []
    for mutation_id, changed in mutants(detection):
        try:
            mutant_tree = compile_detection(changed)
            actual = [execute(changed, row["event"], mutant_tree) for row in corpus]
            witnesses = [row["id"] for row, original, matched in zip(corpus, observed, actual) if matched != original["matched"]]
            # A kill needs an observed behavioral difference. Parsing errors never count.
            mutation_rows.append({"id": mutation_id, "source_sha256": digest(canonical(changed)), "status": "KILLED" if witnesses else "SURVIVED", "witness_case_ids": witnesses})
        except QualityError:
            mutation_rows.append({"id": mutation_id, "source_sha256": digest(canonical(changed)), "status": "ERROR", "witness_case_ids": []})
    metrics = score(observed)
    killed = sum(row["status"] == "KILLED" for row in mutation_rows)
    errors = sum(row["status"] == "ERROR" for row in mutation_rows)
    generated = len(mutation_rows)
    return {"detection_id": rule["detection_id"], "status": "PASS" if not metrics["false_positive"] and not metrics["false_negative"] and not errors else "FAIL",
            "quality": metrics, "cases": observed, "mutations": mutation_rows,
            "mutation_metrics": {"generated": generated, "killed": killed, "survived": generated - killed - errors, "errors": errors,
                                 "mutation_score": round(killed / generated, 6) if generated else None}}


def git(root: Path, *args: str) -> bytes:
    environment = {key: value for key, value in os.environ.items() if not key.casefold().startswith("git_")}
    environment.update(GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0")
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, env=environment)
    if result.returncode:
        raise QualityError("required Git identity or source object is unavailable")
    return result.stdout


def source_identity(root: Path, repository: str, revision: str) -> dict:
    root = root.resolve()
    if Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() != root:
        raise QualityError("authority root must equal its Git top level")
    origins = git(root, "config", "--local", "--null", "--get-all", "remote.origin.url").decode().split("\0")
    if len(origins) != 2 or origins[-1] != "":
        raise QualityError("authority must store exactly one origin")
    origin = origins[0]
    if origin not in (f"https://github.com/HawkinsOperations/{repository}.git", f"https://github.com/HawkinsOperations/{repository}", f"git@github.com:HawkinsOperations/{repository}.git"):
        raise QualityError("wrong repository authority")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise QualityError("source revision must be an exact commit SHA")
    if git(root, "rev-parse", "HEAD").decode().strip() != revision:
        raise QualityError("source checkout differs from requested head")
    if git(root, "status", "--porcelain", "--untracked-files=no").strip():
        raise QualityError("tracked authority source is dirty")
    return {"repository": f"HawkinsOperations/{repository}", "head": revision, "tree": git(root, "rev-parse", "HEAD^{tree}").decode().strip()}


def run_quality(detections_root: Path, detections_ref: str, validation_root: Path = ROOT) -> dict:
    validation_ref = git(validation_root, "rev-parse", "HEAD").decode().strip()
    sources = [source_identity(detections_root, "hawkinsoperations-detections", detections_ref),
               source_identity(validation_root, "hawkinsoperations-validation", validation_ref)]
    inputs, packages = [], []
    for detection_id in DETECTIONS:
        slug = detection_id.lower()
        rule_path = f"detections/successor/{slug}/rule.yml"
        cases_path = f"validation/successor/{slug}/validation-cases.json"
        rule_bytes = git(detections_root, "show", f"{detections_ref}:{rule_path}")
        case_bytes = git(validation_root, "show", f"{validation_ref}:{cases_path}")
        inputs.append({"detection_id": detection_id, "rule_path": rule_path, "rule_sha256": digest(rule_bytes), "corpus_path": cases_path, "corpus_sha256": digest(case_bytes)})
        packages.append(evaluate_package(parse_rule(rule_bytes.decode("utf-8"), detection_id), parse_corpus(case_bytes.decode("utf-8"), detection_id)))
    validator_inputs = []
    for path in ("scripts/detection_quality.py", "scripts/validation_lib.py"):
        committed = git(validation_root, "show", f"{validation_ref}:{path}")
        if committed != (validation_root / path).read_bytes().replace(b"\r\n", b"\n"):
            raise QualityError("executing validator differs from committed validator")
        validator_inputs.append({"path": path, "sha256": digest(committed)})
    aggregate = score([case for package in packages for case in package["cases"]])
    totals = {key: sum(package["mutation_metrics"][key] for package in packages) for key in ("generated", "killed", "survived", "errors")}
    totals["mutation_score"] = round(totals["killed"] / totals["generated"], 6) if totals["generated"] else None
    payload = {"schema": "hawkinsoperations-detection-quality-v1", "owner_repository": "HawkinsOperations/hawkinsoperations-validation",
               "status": "PASS" if all(package["status"] == "PASS" for package in packages) else "FAIL",
               "execution_scope": "offline canonical detection predicates on controlled fixtures; not backend execution",
               "boundary": BOUNDARY.copy(), "sources": sources, "inputs": inputs, "validator_inputs": validator_inputs,
               "detections_evaluated": len(packages), "quality": aggregate, "mutation_metrics": totals, "packages": packages}
    if payload["status"] != "PASS":
        payload["boundary"]["proof_ceiling"] = "VALIDATION_DRAFT"
    payload["replay_sha256"] = digest(canonical(payload))
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--detections-root", type=Path, default=ROOT.parent / "hawkinsoperations-detections")
    parser.add_argument("--detections-ref", required=True, help="exact source commit; must match the clean checkout")
    parser.add_argument("--verify", type=Path, help="reexecute the source/corpus and compare the entire saved report")
    args = parser.parse_args(argv)
    try:
        report = run_quality(args.detections_root, args.detections_ref)
        if args.verify:
            supplied = strict_json_object(args.verify.read_text(encoding="utf-8"), "quality report")
            if canonical(supplied) != canonical(report):
                raise QualityError("replayed source execution differs from supplied report")
        print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
        return 0 if report["status"] == "PASS" else 1
    except (QualityError, ContractFailure, OSError, UnicodeError, RecursionError) as exc:
        print(json.dumps({"status": "BLOCKED", "error": str(exc), "boundary": {**BOUNDARY, "proof_ceiling": "SOURCE_EXISTS"}}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

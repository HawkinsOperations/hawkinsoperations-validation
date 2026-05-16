#!/usr/bin/env python3
"""Verify deterministic HO-DET-001 AI triage support contract.

This verifier checks committed sanitized adapter-style facts and a support-only
AI triage sample. It does not call models, query Splunk, inspect runtime
systems, or promote public/proof/runtime claims.
"""

from __future__ import annotations

import copy
import contextlib
import io
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INPUT_FILE = ROOT / "validation" / "successor" / "ho-det-001" / "ai-triage-input.json"
OUTPUT_FILE = ROOT / "validation" / "successor" / "ho-det-001" / "ai-triage-output.sample.json"

REQUIRED_OUTPUT_FIELDS = [
    "summary",
    "relevant_fields",
    "missing_fields",
    "attck_context",
    "analyst_next_steps",
    "ai_decided_disposition",
    "recommended_disposition",
    "human_review_required",
    "public_safe",
    "claim_boundary",
]
ALLOWED_OUTPUT_FIELDS = set(REQUIRED_OUTPUT_FIELDS)
REQUIRED_FACT_FIELDS = {
    "id",
    "event_id",
    "process_image",
    "original_file_name",
    "command_line_features",
    "parent_image",
    "parent_command_line_features",
    "behavior_family_match",
    "strict_child_candidate",
    "parent_launcher_noise",
    "marker_only_noise",
    "required_fields_present",
}
FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "confirmed compromise",
    "compromise is confirmed",
    "malicious confirmed",
    "confirmed malicious",
    "malicious activity confirmed",
    "production-ready",
    "production ready",
    "ready for production",
    "public proof",
    "publicly proven",
    "proof for public use",
    "public-safe proof",
    "public safe proof",
    "autonomous soc",
    "autonomous triage",
    "autonomous soc workflow",
    "ai-approved disposition",
    "ai approved disposition",
    "ai approved",
    "analyst-approved disposition",
    "analyst approved disposition",
    "analyst approved",
    "containment recommendation",
    "contain the host",
    "isolate the host",
    "block the user",
    "closure recommendation",
    "close the alert",
    "close this case",
    "suppression recommendation",
    "suppress this detection",
    "tune out this detection",
    "mark benign",
    "mark malicious",
    "socaas",
]
PLACEHOLDER_TERMS = [
    "placeholder",
    "todo",
    "tbd",
    "lorem ipsum",
    "replace me",
    "sample text",
]
RAW_INPUT_KEYS = {
    "_raw",
    "raw",
    "row",
    "raw_event",
    "raw_input",
    "raw_output",
    "raw_prompt",
    "eventdata",
    "processguid",
    "parentprocessguid",
    "user",
    "hostname",
    "ip_address",
    "local_path",
    "windows_path",
    "secret",
    "token",
    "password",
}
PRIVATE_VALUE_PATTERNS = [
    re.compile(r"\b[A-Za-z]:\\"),
    re.compile(r"\b(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"(?i)\b(secret|password|token|api[_-]?key|credential|set-cookie|authorization)\b"),
    re.compile(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"),
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing {label}: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def iter_items(value: Any, path: str = "") -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = [(path, value)]
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            found.extend(iter_items(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(iter_items(item, f"{path}[{index}]"))
    return found


def iter_strings(value: Any, path: str = "") -> list[tuple[str, str]]:
    return [(item_path, item) for item_path, item in iter_items(value, path) if isinstance(item, str)]


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().lower()


def verify_no_raw_or_private(label: str, value: dict[str, Any]) -> None:
    for path, item in iter_items(value):
        if path:
            key = path.split(".")[-1].split("[")[0].lower()
            if key in RAW_INPUT_KEYS:
                fail(f"{label} contains raw/private field key at {path}")
        if isinstance(item, str):
            for pattern in PRIVATE_VALUE_PATTERNS:
                if pattern.search(item):
                    fail(f"{label} contains raw/private value marker at {path}")


def verify_forbidden_phrases(label: str, value: dict[str, Any]) -> None:
    for path, text in iter_strings(value):
        lower = normalize_text(text)
        for phrase in FORBIDDEN_PHRASES:
            if phrase in lower:
                fail(f"{label} contains forbidden phrase at {path}: {phrase}")


def verify_no_placeholders(label: str, value: dict[str, Any]) -> None:
    for path, text in iter_strings(value):
        lower = normalize_text(text)
        for term in PLACEHOLDER_TERMS:
            if term in lower:
                fail(f"{label} contains placeholder output at {path}: {term}")


def verify_input_contract(data: dict[str, Any]) -> None:
    if data.get("detection_id") != "HO-DET-001":
        fail("ai-triage-input.json detection_id must be HO-DET-001")
    if data.get("source_contract") != "sanitized_normalized_adapter_facts":
        fail("ai-triage-input.json source_contract must be sanitized_normalized_adapter_facts")
    if data.get("adapter_scope") != "controlled_backend_adapter_fixture":
        fail("ai-triage-input.json adapter_scope must be controlled_backend_adapter_fixture")
    sanitization = data.get("sanitization")
    if not isinstance(sanitization, dict):
        fail("ai-triage-input.json sanitization must be an object")
    for key in [
        "raw_event_data_included",
        "private_hostnames_included",
        "private_addresses_included",
        "secrets_included",
        "local_paths_included",
    ]:
        if sanitization.get(key) is not False:
            fail(f"ai-triage-input.json sanitization.{key} must be false")
    facts = data.get("facts")
    if not isinstance(facts, list) or not facts:
        fail("ai-triage-input.json facts must be a non-empty list")
    strict_child_count = 0
    parent_noise_count = 0
    marker_only_count = 0
    incomplete_count = 0
    for index, fact in enumerate(facts):
        if not isinstance(fact, dict):
            fail(f"ai-triage-input.json facts[{index}] must be an object")
        extra = sorted(set(fact.keys()) - REQUIRED_FACT_FIELDS)
        missing = sorted(REQUIRED_FACT_FIELDS - set(fact.keys()))
        if missing:
            fail(f"ai-triage-input.json facts[{index}] missing fields: {', '.join(missing)}")
        if extra:
            fail(f"ai-triage-input.json facts[{index}] contains non-normalized fields: {', '.join(extra)}")
        if not isinstance(fact.get("command_line_features"), list):
            fail(f"ai-triage-input.json facts[{index}].command_line_features must be a list")
        if not isinstance(fact.get("parent_command_line_features"), list):
            fail(f"ai-triage-input.json facts[{index}].parent_command_line_features must be a list")
        strict_child_count += int(fact.get("strict_child_candidate") is True)
        parent_noise_count += int(fact.get("parent_launcher_noise") is True)
        marker_only_count += int(fact.get("marker_only_noise") is True)
        incomplete_count += int(fact.get("required_fields_present") is False)
    if strict_child_count != 1:
        fail(f"ai-triage-input.json expected exactly 1 strict child candidate, got {strict_child_count}")
    if parent_noise_count != 1:
        fail(f"ai-triage-input.json expected exactly 1 parent launcher noise fact, got {parent_noise_count}")
    if marker_only_count != 1:
        fail(f"ai-triage-input.json expected exactly 1 marker-only noise fact, got {marker_only_count}")
    if incomplete_count != 2:
        fail(f"ai-triage-input.json expected exactly 2 incomplete-field facts, got {incomplete_count}")
    if "claim_boundary" not in data:
        fail("ai-triage-input.json missing claim_boundary")
    verify_no_raw_or_private("ai-triage-input.json", data)
    verify_forbidden_phrases("ai-triage-input.json", data)


def verify_output_contract(output: dict[str, Any], source_input: dict[str, Any]) -> None:
    missing = [key for key in REQUIRED_OUTPUT_FIELDS if key not in output]
    if missing:
        fail(f"ai-triage-output.sample.json missing required fields: {', '.join(missing)}")
    extra = sorted(set(output.keys()) - ALLOWED_OUTPUT_FIELDS)
    if extra:
        fail(f"ai-triage-output.sample.json contains fields outside contract: {', '.join(extra)}")
    if not isinstance(output.get("summary"), str) or len(output["summary"].strip()) < 40:
        fail("ai-triage-output.sample.json summary must be substantive text")
    if not isinstance(output.get("relevant_fields"), list) or not output["relevant_fields"]:
        fail("ai-triage-output.sample.json relevant_fields must be a non-empty list")
    if not isinstance(output.get("missing_fields"), list):
        fail("ai-triage-output.sample.json missing_fields must be a list")
    if not isinstance(output.get("attck_context"), dict):
        fail("ai-triage-output.sample.json attck_context must be an object")
    if not isinstance(output.get("analyst_next_steps"), list) or not output["analyst_next_steps"]:
        fail("ai-triage-output.sample.json analyst_next_steps must be a non-empty list")
    if output.get("ai_decided_disposition") is not False:
        fail("ai-triage-output.sample.json ai_decided_disposition must be false")
    if output.get("recommended_disposition") is not None:
        fail("ai-triage-output.sample.json recommended_disposition must be null")
    if output.get("human_review_required") is not True:
        fail("ai-triage-output.sample.json human_review_required must be true")
    if output.get("public_safe") is not False:
        fail("ai-triage-output.sample.json public_safe must be false")
    claim_boundary = output.get("claim_boundary")
    if not isinstance(claim_boundary, dict):
        fail("ai-triage-output.sample.json claim_boundary must be an object")
    for key in ["runtime_status_established", "signal_status_established", "publication_status_established"]:
        if claim_boundary.get(key) is not False:
            fail(f"ai-triage-output.sample.json claim_boundary.{key} must be false")
    if claim_boundary.get("disposition_authority") != "human_review_only":
        fail("ai-triage-output.sample.json claim_boundary.disposition_authority must be human_review_only")
    if "summary" not in output or "human_review_required" not in output:
        fail("ai-triage-output.sample.json missing human review field")
    verify_no_raw_or_private("ai-triage-output.sample.json", output)
    verify_forbidden_phrases("ai-triage-output.sample.json", output)
    verify_no_placeholders("ai-triage-output.sample.json", output)
    verify_output_not_input_dump(output, source_input)


def verify_output_not_input_dump(output: dict[str, Any], source_input: dict[str, Any]) -> None:
    output_text = json.dumps(output, sort_keys=True)
    input_text = json.dumps(source_input, sort_keys=True)
    if input_text in output_text:
        fail("ai-triage-output.sample.json contains copied raw input dump")
    if any(key in output for key in ["facts", "input", "source_input", "raw_input", "copied_input"]):
        fail("ai-triage-output.sample.json copied raw input dump field detected")
    for fact in source_input.get("facts", []):
        if not isinstance(fact, dict):
            continue
        fact_text = json.dumps(fact, sort_keys=True)
        if fact_text in output_text:
            fail("ai-triage-output.sample.json contains copied normalized fact dump")


def assert_rejected(label: str, input_data: dict[str, Any], output_data: dict[str, Any]) -> None:
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            verify_input_contract(input_data)
            verify_output_contract(output_data, input_data)
    except SystemExit:
        return
    fail(f"negative sample was not rejected: {label}")


def verify_negative_samples(input_data: dict[str, Any], output_data: dict[str, Any]) -> None:
    cases: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

    promoted_text = copy.deepcopy(output_data)
    promoted_text["summary"] = "compromise confirmed by AI support output"
    cases.append(("forbidden promoted phrase", input_data, promoted_text))

    no_human_review = copy.deepcopy(output_data)
    no_human_review.pop("human_review_required", None)
    cases.append(("missing human review field", input_data, no_human_review))

    placeholder = copy.deepcopy(output_data)
    placeholder["summary"] = "TODO placeholder output"
    cases.append(("placeholder output", input_data, placeholder))

    copied_input = copy.deepcopy(output_data)
    copied_input["facts"] = copy.deepcopy(input_data["facts"])
    cases.append(("copied raw input dump", input_data, copied_input))

    public_safe_true = copy.deepcopy(output_data)
    public_safe_true["public_safe"] = True
    cases.append(("public_safe true", input_data, public_safe_true))

    ai_disposition_true = copy.deepcopy(output_data)
    ai_disposition_true["ai_decided_disposition"] = True
    cases.append(("ai_decided_disposition true", input_data, ai_disposition_true))

    recommended_disposition = copy.deepcopy(output_data)
    recommended_disposition["recommended_disposition"] = "review_controlled_test_detection"
    cases.append(("recommended_disposition not null", input_data, recommended_disposition))

    containment = copy.deepcopy(output_data)
    containment["analyst_next_steps"] = ["containment recommendation"]
    cases.append(("containment recommendation", input_data, containment))

    raw_dump_input = copy.deepcopy(input_data)
    raw_dump_input["facts"][0]["_raw"] = "<Event>raw</Event>"
    cases.append(("raw input dump field", raw_dump_input, output_data))

    for label, case_input, case_output in cases:
        assert_rejected(label, copy.deepcopy(case_input), copy.deepcopy(case_output))


def main() -> int:
    input_data = load_json(INPUT_FILE, "ai-triage-input.json")
    output_data = load_json(OUTPUT_FILE, "ai-triage-output.sample.json")
    verify_input_contract(input_data)
    verify_output_contract(output_data, input_data)
    verify_negative_samples(input_data, output_data)
    print("STATUS=pass")
    print("AI_TRIAGE_CONTRACT=pass")
    print("DETECTION_ID=HO-DET-001")
    print("INPUT_SCOPE=sanitized_normalized_adapter_facts")
    print("AI_DECIDED_DISPOSITION=false")
    print("RECOMMENDED_DISPOSITION=null")
    print("HUMAN_REVIEW_REQUIRED=true")
    print("PUBLIC_SAFE=false")
    print("CLAIM_BOUNDARY_SCAN=pass")
    print("NEGATIVE_CONTRACT_SAMPLES_REJECTED=pass")
    print("WRITE_SKIPPED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

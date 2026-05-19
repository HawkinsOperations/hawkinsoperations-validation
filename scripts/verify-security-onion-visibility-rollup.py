#!/usr/bin/env python3
"""Verify the sanitized Security Onion HO-NDR-001 visibility rollup contract."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / ".github" / "contracts" / "security-onion-visibility-rollup.schema.json"
SAMPLE_PATH = ROOT / "validation" / "security-onion" / "ho-ndr-001" / "visibility-rollup.sample.json"

EXPECTED_VISIBILITY_CONTRACT_ID = "HO-NDR-001-SANITIZED-VISIBILITY-ROLLUP"
EXPECTED_SAMPLE_SCOPE = "sample_only"
EXPECTED_CAPTURE_STATUS = "NOT_CAPTURED_SAMPLE_ONLY"
EXPECTED_ACHIEVED_STATUS = "NOT_CAPTURED_SAMPLE_ONLY"
EXPECTED_PUBLIC_SAFE_STATUS = "NOT_PUBLIC_SAFE"
EXPECTED_PROOF_CEILING = "VALIDATION_CONTRACT_HARDENED_ONLY"
EXPECTED_NEXT_GATE = "RUNTIME_CAPTURE_APPROVAL_REQUIRED_BEFORE_ANY_EVIDENCE_OR_PROOF_PROMOTION"
EXPECTED_REQUIRED = {
    "visibility_contract_id",
    "sample_or_runtime_scope",
    "capture_status",
    "achieved_status",
    "public_safe_status",
    "cross_source_corroboration_captured",
    "splunk_search_executed",
    "cribl_route_proven",
    "wazuh_route_proven",
    "security_onion_runtime_proven",
    "zeek_completeness_proven",
    "suricata_detection_quality_proven",
    "wazuh_agent_summary",
    "security_onion_module_summary",
    "suricata_summary",
    "zeek_summary",
    "splunk_correlation_placeholder",
    "cribl_route_placeholder",
    "proof_ceiling",
    "public_safe_status",
    "blocked_claims",
    "next_gate",
}
SUMMARY_FIELDS = {
    "wazuh_agent_summary",
    "security_onion_module_summary",
    "suricata_summary",
    "zeek_summary",
    "splunk_correlation_placeholder",
    "cribl_route_placeholder",
}
SUMMARY_REQUIRED = {
    "status",
    "summary",
    "public_safe",
    "blocked_from_public_claim",
}
SUMMARY_STATUSES = {
    "not_captured_sample_only",
    "placeholder_not_executed",
    "not_routed",
    "not_proven",
}
FALSE_GUARDS = {
    "cross_source_corroboration_captured",
    "splunk_search_executed",
    "cribl_route_proven",
    "wazuh_route_proven",
    "security_onion_runtime_proven",
    "zeek_completeness_proven",
    "suricata_detection_quality_proven",
}
CORE_BLOCKED = {
    "runtime_active",
    "signal_observed",
    "public_safe_proof",
    "production_ndr",
    "cross_source_corroboration_captured",
    "security_onion_runtime_proven",
    "splunk_search_executed",
    "cribl_route_proven",
    "wazuh_route_proven",
    "zeek_completeness_proven",
    "suricata_detection_quality_proven",
    "raw_pcap_artifact",
    "private_identifier_publication",
}
RAW_PATTERNS = {
    "raw IPv4 address": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    ),
    "MAC address": re.compile(r"\b[0-9a-fA-F]{2}(?::|-)[0-9a-fA-F]{2}(?::|-)[0-9a-fA-F]{2}(?::|-)[0-9a-fA-F]{2}(?::|-)[0-9a-fA-F]{2}(?::|-)[0-9a-fA-F]{2}\b"),
    "local Windows path": re.compile(r"\b[A-Za-z]:[\\/][^\s\"']+"),
    "browser URL": re.compile(r"\bhttps?://[^\s\"']+", re.IGNORECASE),
    "token or secret wording": re.compile(r"(?i)\b(?:authorization:\s*bearer|api[_-]?key|token\s*[=:]|secret\s*[=:]|password\s*[=:])"),
    "raw PCAP reference": re.compile(r"(?i)\b(?:pcap|pcapng)\b|(?:\.pcap(?:ng)?\b)"),
    "raw event reference": re.compile(r"(?i)\braw[_ -]?(?:event|payload|command line|hostname|ip|mac|user)\b"),
    "VM identifier": re.compile(r"(?i)\bvm[_ -]?id\b|\bvmid\b"),
    "evidence filename": re.compile(r"(?i)\bevidence[_ -]?file(?:name)?\b|(?:\.(?:evtx|log|ndjson)\b)"),
}
PROMOTED_PHRASES = [
    "runtime active",
    "runtime-active",
    "signal observed",
    "signal-observed",
    "public safe proof",
    "public-safe proof",
    "production ndr",
    "cross source corroboration captured",
    "cross-source corroboration captured",
    "splunk search executed",
    "cribl route proven",
    "wazuh route proven",
    "security onion runtime proven",
    "zeek completeness proven",
    "suricata detection quality proven",
]
ALLOWED_NEGATIVE_MARKERS = [
    "blocked",
    "not_",
    "not ",
    "no ",
    "without",
    "placeholder",
    "approval_required",
    "required_before",
]
ALLOWED_PROMOTED_PATH_PARTS = {
    "properties",
    "required",
    "blocked_claims",
    "next_gate",
}
ALLOWED_RAW_PATH_PARTS = {
    "blocked_claims",
    "properties.blocked_claims",
}


def fail(failures: list[str], message: str) -> None:
    failures.append(message)


def load_json(path: Path, label: str, failures: list[str]) -> dict[str, Any]:
    if not path.exists():
        fail(failures, f"missing {label}: {path.relative_to(ROOT).as_posix()}")
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(failures, f"invalid JSON in {label}: {exc}")
        return {}
    if not isinstance(data, dict):
        fail(failures, f"{label} must be a JSON object")
        return {}
    return data


def iter_strings(value: Any, path: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            found.extend(iter_strings(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(iter_strings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        found.append((path, value))
    return found


def scan_raw_material(label: str, data: dict[str, Any], failures: list[str]) -> None:
    for path, value in iter_strings(data):
        lower_path = path.lower()
        if any(part in lower_path for part in ALLOWED_RAW_PATH_PARTS):
            continue
        for pattern_label, pattern in RAW_PATTERNS.items():
            if pattern.search(value):
                fail(failures, f"{label}.{path}: contains {pattern_label}")


def promoted_context_allowed(path: str, value: str) -> bool:
    lower_path = path.lower()
    lower_value = value.replace("-", "_").lower()
    if any(part in lower_path for part in ALLOWED_PROMOTED_PATH_PARTS):
        return True
    return any(marker in lower_value for marker in ALLOWED_NEGATIVE_MARKERS)


def scan_promoted_claims(label: str, data: dict[str, Any], failures: list[str]) -> None:
    for path, value in iter_strings(data):
        normalized = value.replace("_", " ").replace("-", " ").lower()
        for phrase in PROMOTED_PHRASES:
            normalized_phrase = phrase.replace("_", " ").replace("-", " ").lower()
            if normalized_phrase in normalized and not promoted_context_allowed(path, value):
                fail(failures, f"{label}.{path}: promoted claim phrase outside blocked/negative context: {phrase}")


def validate_schema(schema: dict[str, Any], failures: list[str]) -> None:
    required = set(schema.get("required", []))
    if required != EXPECTED_REQUIRED:
        fail(failures, f"schema required keys mismatch: {sorted(required)}")

    properties = schema.get("properties")
    if not isinstance(properties, dict):
        fail(failures, "schema.properties must be an object")
        return
    if set(properties) != EXPECTED_REQUIRED:
        fail(failures, f"schema properties mismatch: {sorted(properties)}")

    expected_consts = {
        "visibility_contract_id": EXPECTED_VISIBILITY_CONTRACT_ID,
        "capture_status": EXPECTED_CAPTURE_STATUS,
        "achieved_status": EXPECTED_ACHIEVED_STATUS,
        "public_safe_status": EXPECTED_PUBLIC_SAFE_STATUS,
        "proof_ceiling": EXPECTED_PROOF_CEILING,
        "next_gate": EXPECTED_NEXT_GATE,
    }
    for key, expected in expected_consts.items():
        actual = properties.get(key, {}).get("const")
        if actual != expected:
            fail(failures, f"schema {key} const mismatch: {actual!r}")

    scope_enum = set(properties.get("sample_or_runtime_scope", {}).get("enum", []))
    if scope_enum != {"sample_only", "sanitized_private_runtime_rollup"}:
        fail(failures, f"schema sample_or_runtime_scope enum mismatch: {sorted(scope_enum)}")
    for key in FALSE_GUARDS:
        if properties.get(key, {}).get("const") is not False:
            fail(failures, f"schema {key} must const false")

    defs = schema.get("$defs", {})
    bounded_summary = defs.get("bounded_summary") if isinstance(defs, dict) else None
    if not isinstance(bounded_summary, dict):
        fail(failures, "schema must define bounded_summary")
        return
    if bounded_summary.get("additionalProperties") is not False:
        fail(failures, "schema bounded_summary must block additional properties")
    if set(bounded_summary.get("required", [])) != SUMMARY_REQUIRED:
        fail(failures, "schema bounded_summary required keys mismatch")
    summary_properties = bounded_summary.get("properties", {})
    status_enum = set(summary_properties.get("status", {}).get("enum", []))
    if status_enum != SUMMARY_STATUSES:
        fail(failures, f"schema bounded_summary status enum mismatch: {sorted(status_enum)}")


def validate_summary(label: str, summary: Any, failures: list[str]) -> None:
    if not isinstance(summary, dict):
        fail(failures, f"{label} must be an object")
        return
    if set(summary.keys()) != SUMMARY_REQUIRED:
        fail(failures, f"{label} keys must be bounded summary keys only")
    if summary.get("status") not in SUMMARY_STATUSES:
        fail(failures, f"{label}.status is not an allowed non-promoting status")
    if not isinstance(summary.get("summary"), str) or not summary.get("summary", "").strip():
        fail(failures, f"{label}.summary must be a non-empty string")
    if summary.get("public_safe") is not False:
        fail(failures, f"{label}.public_safe must be false")
    if summary.get("blocked_from_public_claim") is not True:
        fail(failures, f"{label}.blocked_from_public_claim must be true")


def validate_sample(sample: dict[str, Any], failures: list[str]) -> None:
    if set(sample.keys()) != EXPECTED_REQUIRED:
        fail(failures, f"sample top-level keys must match the bounded rollup contract: {sorted(sample.keys())}")

    expected_values = {
        "visibility_contract_id": EXPECTED_VISIBILITY_CONTRACT_ID,
        "sample_or_runtime_scope": EXPECTED_SAMPLE_SCOPE,
        "capture_status": EXPECTED_CAPTURE_STATUS,
        "achieved_status": EXPECTED_ACHIEVED_STATUS,
        "public_safe_status": EXPECTED_PUBLIC_SAFE_STATUS,
        "proof_ceiling": EXPECTED_PROOF_CEILING,
        "next_gate": EXPECTED_NEXT_GATE,
    }
    for key, expected in expected_values.items():
        if sample.get(key) != expected:
            fail(failures, f"sample {key} mismatch: {sample.get(key)!r}")

    for key in FALSE_GUARDS:
        if sample.get(key) is not False:
            fail(failures, f"sample {key} must remain false without approved runtime evidence")
    for key in SUMMARY_FIELDS:
        validate_summary(f"sample.{key}", sample.get(key), failures)

    blocked = sample.get("blocked_claims")
    if not isinstance(blocked, list) or not blocked:
        fail(failures, "sample blocked_claims must be a non-empty array")
    elif set(blocked) != CORE_BLOCKED:
        fail(failures, "sample blocked_claims must exactly preserve core blocked Security Onion claims")


def main() -> int:
    failures: list[str] = []
    schema = load_json(SCHEMA_PATH, "schema", failures)
    sample = load_json(SAMPLE_PATH, "sample", failures)

    if schema:
        validate_schema(schema, failures)
        scan_raw_material("schema", schema, failures)
        scan_promoted_claims("schema", schema, failures)
    if sample:
        validate_sample(sample, failures)
        scan_raw_material("sample", sample, failures)
        scan_promoted_claims("sample", sample, failures)

    if failures:
        for item in failures:
            print(f"FAIL_SECURITY_ONION_VISIBILITY_CONTRACT: {item}", file=sys.stderr)
        return 1

    print("PASS_SECURITY_ONION_VISIBILITY_CONTRACT")
    print(f"PROOF_CEILING={EXPECTED_PROOF_CEILING}")
    print("ACHIEVED_STATUS=NOT_CAPTURED_SAMPLE_ONLY")
    print("PUBLIC_SAFE_STATUS=NOT_PUBLIC_SAFE")
    print("RUNTIME_APPROVAL_REQUIRED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

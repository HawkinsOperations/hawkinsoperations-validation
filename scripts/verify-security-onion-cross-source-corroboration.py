#!/usr/bin/env python3
"""Verify the sanitized Security Onion cross-source corroboration contract."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / ".github" / "contracts" / "security-onion-cross-source-corroboration.schema.json"
SAMPLE_PATH = ROOT / "validation" / "security-onion" / "ho-ndr-001" / "cross-source-corroboration.sample.json"

EXPECTED_CLASSIFICATION = "PRIVATE_INTERNAL_CROSS_SOURCE_CORROBORATION_SAMPLE"
EXPECTED_PUBLIC_SAFE_STATUS = "NOT_APPROVED"
EXPECTED_ACHIEVED_STATUS = "NOT_CAPTURED_SAMPLE_ONLY"
EXPECTED_CURRENT_CEILING = "CROSS_SOURCE_CORROBORATION_CONTRACT_DEFINED"
EXPECTED_PLANNED_CEILING = "PRIVATE_CROSS_SOURCE_CORROBORATION_CAPTURED"
EXPECTED_OBSERVATION_BASIS = "SANITIZED_SAMPLE_CONTRACT_NO_RUNTIME_EVIDENCE"
EXPECTED_EVENT_STATUS = "PLANNED_NOT_EXECUTED"
EXPECTED_PLANES = {
    "security_onion_suricata",
    "endpoint_telemetry",
    "splunk_correlation",
    "optional_cribl_route",
}
EXPECTED_REQUIRED = {
    "packet_id",
    "classification",
    "public_safe_status",
    "achieved_status",
    "current_claim_ceiling",
    "planned_post_runtime_claim_ceiling",
    "observation_basis",
    "controlled_test_event",
    "telemetry_planes",
    "correlation_requirements",
    "redaction_required_fields",
    "blocked_claims",
    "next_gates",
}
PLANE_REQUIRED = {
    "status",
    "evidence_type",
    "event_specific",
    "required_for_corrob",
    "public_safe",
    "blocked_from_public_claim",
}
CORE_BLOCKED = {
    "public_safe_proof",
    "production_ndr",
    "permanent_span",
    "fleet_wide_visibility",
    "durable_monitoring",
    "pcap_availability",
    "security_onion_3_feature_claims",
    "ja4_support",
    "strelka_yara_workflow",
    "suricata_detection_quality",
    "dynamic_zeek_plugin_claims",
    "security_onion_telemetry_forwarded_to_splunk",
    "splunk_search_executed",
    "cribl_route_proven",
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
}
ACHIEVED_PHRASES = [
    "cross-source corroboration captured",
    "cross source corroboration captured",
    "cross-source corroboration proven",
    "cross source corroboration proven",
    "private cross source corroboration captured",
    "private_cross_source_corroboration_captured",
]
ALLOWED_ACHIEVED_PATH_PARTS = {
    "planned_post_runtime_claim_ceiling",
    "blocked_claims",
    "next_gates",
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
        for pattern_label, pattern in RAW_PATTERNS.items():
            if pattern.search(value):
                fail(failures, f"{label}.{path}: contains {pattern_label}")


def scan_achieved_claim_leaks(label: str, data: dict[str, Any], failures: list[str]) -> None:
    for path, value in iter_strings(data):
        lower_path = path.lower()
        if any(part in lower_path for part in ALLOWED_ACHIEVED_PATH_PARTS):
            continue
        normalized = value.replace("_", " ").replace("-", " ").lower()
        for phrase in ACHIEVED_PHRASES:
            if phrase.replace("_", " ") in normalized:
                fail(failures, f"{label}.{path}: achieved corroboration wording outside planned/blocked context")


def validate_schema(schema: dict[str, Any], failures: list[str]) -> None:
    required = set(schema.get("required", []))
    if required != EXPECTED_REQUIRED:
        fail(failures, f"schema required keys mismatch: {sorted(required)}")

    properties = schema.get("properties")
    if not isinstance(properties, dict):
        fail(failures, "schema.properties must be an object")
        return

    expected_consts = {
        "classification": EXPECTED_CLASSIFICATION,
        "public_safe_status": EXPECTED_PUBLIC_SAFE_STATUS,
        "achieved_status": EXPECTED_ACHIEVED_STATUS,
        "current_claim_ceiling": EXPECTED_CURRENT_CEILING,
        "planned_post_runtime_claim_ceiling": EXPECTED_PLANNED_CEILING,
        "observation_basis": EXPECTED_OBSERVATION_BASIS,
    }
    for key, expected in expected_consts.items():
        actual = properties.get(key, {}).get("const")
        if actual != expected:
            fail(failures, f"schema {key} const mismatch: {actual!r}")

    plane_keys = set(properties.get("telemetry_planes", {}).get("properties", {}).keys())
    if plane_keys != EXPECTED_PLANES:
        fail(failures, f"schema telemetry plane labels mismatch: {sorted(plane_keys)}")


def validate_sample(sample: dict[str, Any], failures: list[str]) -> None:
    for key in EXPECTED_REQUIRED:
        if key not in sample:
            fail(failures, f"sample missing required key: {key}")

    expected_values = {
        "classification": EXPECTED_CLASSIFICATION,
        "public_safe_status": EXPECTED_PUBLIC_SAFE_STATUS,
        "achieved_status": EXPECTED_ACHIEVED_STATUS,
        "current_claim_ceiling": EXPECTED_CURRENT_CEILING,
        "planned_post_runtime_claim_ceiling": EXPECTED_PLANNED_CEILING,
        "observation_basis": EXPECTED_OBSERVATION_BASIS,
    }
    for key, expected in expected_values.items():
        if sample.get(key) != expected:
            fail(failures, f"sample {key} mismatch: {sample.get(key)!r}")

    controlled_test_event = sample.get("controlled_test_event")
    if not isinstance(controlled_test_event, dict):
        fail(failures, "sample controlled_test_event must be an object")
    elif controlled_test_event.get("event_status") != EXPECTED_EVENT_STATUS:
        fail(failures, "sample controlled_test_event.event_status must remain PLANNED_NOT_EXECUTED")
    elif controlled_test_event.get("execution_approval_required") is not True:
        fail(failures, "sample controlled_test_event.execution_approval_required must be true")

    planes = sample.get("telemetry_planes")
    if not isinstance(planes, dict):
        fail(failures, "sample telemetry_planes must be an object")
        return
    if set(planes.keys()) != EXPECTED_PLANES:
        fail(failures, f"sample telemetry plane labels mismatch: {sorted(planes.keys())}")

    for name, plane in planes.items():
        if not isinstance(plane, dict):
            fail(failures, f"telemetry plane {name} must be an object")
            continue
        missing = PLANE_REQUIRED.difference(plane)
        if missing:
            fail(failures, f"telemetry plane {name} missing required keys: {sorted(missing)}")
        if plane.get("event_specific") is not False:
            fail(failures, f"telemetry plane {name} event_specific must be false until runtime capture")
        if plane.get("public_safe") is not False:
            fail(failures, f"telemetry plane {name} public_safe must be false")
        if plane.get("blocked_from_public_claim") is not True:
            fail(failures, f"telemetry plane {name} blocked_from_public_claim must be true")
        expected_required = name != "optional_cribl_route"
        if plane.get("required_for_corrob") is not expected_required:
            fail(failures, f"telemetry plane {name} required_for_corrob mismatch")

    blocked = sample.get("blocked_claims")
    if not isinstance(blocked, list) or not blocked:
        fail(failures, "sample blocked_claims must be a non-empty array")
    elif not CORE_BLOCKED.issubset(set(blocked)):
        fail(failures, "sample blocked_claims must preserve core blocked claims")


def main() -> int:
    failures: list[str] = []
    schema = load_json(SCHEMA_PATH, "schema", failures)
    sample = load_json(SAMPLE_PATH, "sample", failures)

    if schema:
        validate_schema(schema, failures)
        scan_raw_material("schema", schema, failures)
        scan_achieved_claim_leaks("schema", schema, failures)
    if sample:
        validate_sample(sample, failures)
        scan_raw_material("sample", sample, failures)
        scan_achieved_claim_leaks("sample", sample, failures)

    if failures:
        for item in failures:
            print(f"FAIL_SECURITY_ONION_CROSS_SOURCE_CORROBORATION_CONTRACT: {item}", file=sys.stderr)
        return 1

    print("PASS_SECURITY_ONION_CROSS_SOURCE_CORROBORATION_CONTRACT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

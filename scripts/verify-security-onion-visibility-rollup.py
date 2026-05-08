#!/usr/bin/env python3
"""Verify the sanitized Security Onion visibility rollup contract."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / ".github" / "contracts" / "security-onion-visibility-rollup.schema.json"
SAMPLE_PATH = ROOT / "validation" / "security-onion" / "ho-ndr-001" / "visibility-rollup.sample.json"

EXPECTED_CLASSIFICATION = "PRIVATE_INTERNAL_UI_VISIBILITY_ROLLUP_SAMPLE"
EXPECTED_PUBLIC_SAFE_STATUS = "NOT_APPROVED"
EXPECTED_CLAIM_CEILING = "PRIVATE_NDR_MODULE_VISIBILITY_ROLLUP_DEFINED"
EXPECTED_OBSERVATION_BASIS = "SANITIZED_SAMPLE_FROM_PRIVATE_UI_OBSERVATIONS"
EXPECTED_COMPONENTS = {
    "temp_mirror_packet_visibility",
    "zeek_index_visibility",
    "suricata_index_visibility",
}
EXPECTED_REQUIRED = {
    "packet_id",
    "classification",
    "public_safe_status",
    "claim_ceiling",
    "observation_basis",
    "time_window",
    "components",
    "blocked_claims",
    "next_gates",
}
COMPONENT_REQUIRED = {
    "status",
    "evidence_type",
    "count_present",
    "count_value",
    "public_safe",
    "blocked_from_public_claim",
}
RAW_PATTERNS = {
    "raw IPv4 address": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    ),
    "MAC address": re.compile(r"\b[0-9a-fA-F]{2}(?::|-)[0-9a-fA-F]{2}(?::|-)[0-9a-fA-F]{2}(?::|-)[0-9a-fA-F]{2}(?::|-)[0-9a-fA-F]{2}(?::|-)[0-9a-fA-F]{2}\b"),
    "local Windows path": re.compile(r"\b[A-Za-z]:[\\/][^\s\"']+"),
    "browser URL": re.compile(r"\bhttps?://[^\s\"']+", re.IGNORECASE),
}
UNSUPPORTED_PHRASES = [
    "permanent span",
    "production ndr",
    "fleet-wide",
    "fleet wide",
    "public-safe proof",
    "public safe proof",
    "durable monitoring",
    "pcap availability",
    "cross-source corroboration",
    "cross source corroboration",
    "zeek coverage completeness",
    "suricata detection quality",
]
ALLOWED_UNSUPPORTED_PATH_PARTS = {
    "blocked_claims",
    "next_gates",
}
ALLOWED_NEGATIVE_MARKERS = [
    "blocked",
    "not_approved",
    "before_any",
    "defer",
    "redaction_review",
]


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


def unsupported_context_allowed(path: str, value: str) -> bool:
    lower_path = path.lower()
    lower_value = value.lower()
    if any(part in lower_path for part in ALLOWED_UNSUPPORTED_PATH_PARTS):
        return True
    return any(marker in lower_value for marker in ALLOWED_NEGATIVE_MARKERS)


def scan_unsupported_claims(label: str, data: dict[str, Any], failures: list[str]) -> None:
    for path, value in iter_strings(data):
        normalized = value.replace("_", " ").replace("-", " ").lower()
        for phrase in UNSUPPORTED_PHRASES:
            if phrase in normalized and not unsupported_context_allowed(path, value):
                fail(failures, f"{label}.{path}: unsupported claim phrase outside blocked/not-approved context: {phrase}")


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
        "claim_ceiling": EXPECTED_CLAIM_CEILING,
        "observation_basis": EXPECTED_OBSERVATION_BASIS,
    }
    for key, expected in expected_consts.items():
        actual = properties.get(key, {}).get("const")
        if actual != expected:
            fail(failures, f"schema {key} const mismatch: {actual!r}")

    component_keys = set(properties.get("components", {}).get("properties", {}).keys())
    if component_keys != EXPECTED_COMPONENTS:
        fail(failures, f"schema component labels mismatch: {sorted(component_keys)}")


def validate_sample(sample: dict[str, Any], failures: list[str]) -> None:
    for key in EXPECTED_REQUIRED:
        if key not in sample:
            fail(failures, f"sample missing required key: {key}")

    if sample.get("classification") != EXPECTED_CLASSIFICATION:
        fail(failures, "sample classification must remain PRIVATE_INTERNAL_UI_VISIBILITY_ROLLUP_SAMPLE")
    if sample.get("public_safe_status") != EXPECTED_PUBLIC_SAFE_STATUS:
        fail(failures, "sample public_safe_status must be NOT_APPROVED")
    if sample.get("claim_ceiling") != EXPECTED_CLAIM_CEILING:
        fail(failures, "sample claim_ceiling must be PRIVATE_NDR_MODULE_VISIBILITY_ROLLUP_DEFINED")
    if sample.get("observation_basis") != EXPECTED_OBSERVATION_BASIS:
        fail(failures, "sample observation_basis must be sanitized private UI observations")

    components = sample.get("components")
    if not isinstance(components, dict):
        fail(failures, "sample components must be an object")
        return
    if set(components.keys()) != EXPECTED_COMPONENTS:
        fail(failures, f"sample component labels mismatch: {sorted(components.keys())}")

    for name, component in components.items():
        if not isinstance(component, dict):
            fail(failures, f"component {name} must be an object")
            continue
        missing = COMPONENT_REQUIRED.difference(component)
        if missing:
            fail(failures, f"component {name} missing required keys: {sorted(missing)}")
        if component.get("public_safe") is not False:
            fail(failures, f"component {name} public_safe must be false")
        if component.get("blocked_from_public_claim") is not True:
            fail(failures, f"component {name} blocked_from_public_claim must be true")
        if not isinstance(component.get("count_present"), bool):
            fail(failures, f"component {name} count_present must be boolean")
        if not isinstance(component.get("count_value"), int) or component.get("count_value", -1) < 0:
            fail(failures, f"component {name} count_value must be a non-negative integer")

    blocked = sample.get("blocked_claims")
    if not isinstance(blocked, list) or not blocked:
        fail(failures, "sample blocked_claims must be a non-empty array")
    elif not {"production_ndr", "permanent_span", "fleet_wide_visibility", "public_safe_proof", "durable_monitoring"}.issubset(set(blocked)):
        fail(failures, "sample blocked_claims must preserve core blocked claims")


def main() -> int:
    failures: list[str] = []
    schema = load_json(SCHEMA_PATH, "schema", failures)
    sample = load_json(SAMPLE_PATH, "sample", failures)

    if schema:
        validate_schema(schema, failures)
        scan_raw_material("schema", schema, failures)
        scan_unsupported_claims("schema", schema, failures)
    if sample:
        validate_sample(sample, failures)
        scan_raw_material("sample", sample, failures)
        scan_unsupported_claims("sample", sample, failures)

    if failures:
        for item in failures:
            print(f"FAIL_SECURITY_ONION_VISIBILITY_CONTRACT: {item}", file=sys.stderr)
        return 1

    print("PASS_SECURITY_ONION_VISIBILITY_CONTRACT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Verify HO-DET-001 backend adapter fixture behavior and claim boundaries."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_ROOT = ROOT.parent / "hawkinsoperations-detections"
CASES_FILE = ROOT / "validation" / "successor" / "ho-det-001" / "runtime-backend-adapter-cases.json"
NORMALIZER_FILE = ROOT / "scripts" / "normalize-ho-det-001-splunk-sysmon.py"
EVENT_MAPPING_FILE = DETECTIONS_ROOT / "detections" / "successor" / "ho-det-001" / "event-mapping.yml"

PRIVATE_MARKER_RE = re.compile(r"\b(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b")
SECRET_RE = re.compile(
    r"(?i)(authorization:\s*bearer|splunk[_-]?(token|session|secret|password)|"
    r"api[_-]?key|password\s*[=:]|token\s*[=:]|set-cookie|cookie\s*[=:])"
)
BLOCKED_CLAIMS = [
    "runtime-active",
    "signal-observed public proof",
    "evidence-linked public proof",
    "public-safe proof",
    "production-ready",
    "fleet-wide",
    "AI-approved disposition",
    "analyst-approved disposition",
]
EXPECTED_BACKEND_METADATA = {
    "index": "ho_v2_sysmon",
    "source": "WinEventLog:Microsoft-Windows-Sysmon/Operational",
    "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
}
BLOCKED_PRIVATE_MARKERS = [
    "HO-" + "WE-01",
    "192." + "168.",
    "C:" + "\\Raylee",
    "splunkweb_csrf",
    "token_key",
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: Path, label: str) -> str:
    if not path.is_file():
        fail(f"missing {label}: {path}")
    return path.read_text(encoding="utf-8")


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        data = json.loads(read_text(path, label))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {label}: {exc}")
    if not isinstance(data, dict):
        fail(f"{label} must be a JSON object")
    return data


def load_normalizer():
    spec = importlib.util.spec_from_file_location("ho_det_001_backend_normalizer", NORMALIZER_FILE)
    if spec is None or spec.loader is None:
        fail(f"could not load normalizer: {NORMALIZER_FILE}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_contains(text: str, expected: str, label: str) -> None:
    if expected not in text:
        fail(f"{label} missing expected text: {expected}")


def verify_mapping_contract() -> str:
    if not EVENT_MAPPING_FILE.is_file():
        return "public_fixture_only"
    text = read_text(EVENT_MAPPING_FILE, "HO-DET-001 event mapping")
    for expected in [
        "detection_id: HO-DET-001",
        "mapping_status: SOURCE_EXISTS",
        "sanitized_lab_index_alias: ho_v2_sysmon",
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "process_image:",
        "command_line:",
        "parent_command_line:",
        "PARENT_LAUNCHER_NOISE_SEPARATED",
    ]:
        require_contains(text, expected, "event mapping")
    return "sibling_detection_mapping"


def verify_sanitization(text: str) -> None:
    if PRIVATE_MARKER_RE.search(text):
        fail("adapter cases contain private IP address pattern")
    if SECRET_RE.search(text):
        fail("adapter cases contain secret-like text")
    for blocked in BLOCKED_PRIVATE_MARKERS:
        if blocked.lower() in text.lower():
            fail(f"adapter cases contain blocked private marker: {blocked}")


def verify_claim_boundary(data: dict[str, Any]) -> None:
    if "private_runtime_source" in data:
        fail("private_runtime_source must not be used in sanitized adapter cases")
    if data.get("sanitized_source_shape") != "private_level2_reference":
        fail("sanitized_source_shape must be private_level2_reference")
    if "marker" in data:
        fail("fixture metadata must use controlled_test_marker, not marker")
    if not data.get("controlled_test_marker"):
        fail("controlled_test_marker must be present")
    blocked_claims = data.get("blocked_claims")
    if not isinstance(blocked_claims, list):
        fail("blocked_claims must be present")
    lower_claims = {str(item).lower() for item in blocked_claims}
    for claim in BLOCKED_CLAIMS:
        if claim.lower() not in lower_claims:
            fail(f"blocked_claims missing: {claim}")
    boundary = str(data.get("claim_boundary", "")).lower()
    for expected in ["does not prove", "runtime-active", "public"]:
        if expected not in boundary:
            fail(f"claim_boundary missing expected boundary wording: {expected}")


def verify_case_results(data: dict[str, Any]) -> tuple[int, int, int]:
    normalizer = load_normalizer()
    normalized = normalizer.normalize_cases(data)
    cases = data["cases"]
    if len(normalized) != len(cases):
        fail("normalized case count does not match input case count")

    controlled_test_marker = str(data.get("controlled_test_marker", "") or "")
    strict_child_count = 0
    parent_noise_count = 0
    marker_only_noise_count = 0
    by_id = {item["id"]: item for item in normalized}
    for case in cases:
        case_id = case.get("id")
        expected = case.get("expected")
        if not isinstance(expected, dict):
            fail(f"{case_id}: expected must be a JSON object")
        actual = by_id.get(case_id)
        if actual is None:
            fail(f"{case_id}: missing normalized result")
        if "marker" in actual:
            fail(f"{case_id}: normalized result must not expose marker field")
        if actual.get("controlled_test_marker") != controlled_test_marker:
            fail(f"{case_id}: controlled_test_marker was not preserved")
        command_line = str(actual.get("command_line", "") or "")
        if actual.get("has_marker") is not (controlled_test_marker in command_line):
            fail(f"{case_id}: has_marker does not match command_line marker containment")
        for field, expected_value in EXPECTED_BACKEND_METADATA.items():
            if actual.get(field) != expected_value:
                fail(
                    f"{case_id}: {field} expected {expected_value} got {actual.get(field)}"
                )
        for field in [
            "behavior_family_match",
            "strict_child_candidate",
            "parent_launcher_noise",
            "marker_only_noise",
            "required_fields_present",
        ]:
            if actual.get(field) is not expected.get(field):
                fail(f"{case_id}: {field} expected {expected.get(field)} got {actual.get(field)}")
        strict_child_count += int(bool(actual["strict_child_candidate"]))
        parent_noise_count += int(bool(actual["parent_launcher_noise"]))
        marker_only_noise_count += int(bool(actual["marker_only_noise"]))

    if strict_child_count != 1:
        fail(f"expected exactly 1 strict child candidate, got {strict_child_count}")
    if parent_noise_count != 1:
        fail(f"expected exactly 1 parent launcher noise event, got {parent_noise_count}")
    if marker_only_noise_count != 1:
        fail(f"expected exactly 1 marker-only noise event, got {marker_only_noise_count}")
    return strict_child_count, parent_noise_count, marker_only_noise_count


def verify_mapped_process_image_support(data: dict[str, Any]) -> None:
    normalizer = load_normalizer()
    controlled_test_marker = str(data.get("controlled_test_marker", "") or "")
    mapped_row = {
        "index": EXPECTED_BACKEND_METADATA["index"],
        "host": "LAB-HOST",
        "source": EXPECTED_BACKEND_METADATA["source"],
        "sourcetype": EXPECTED_BACKEND_METADATA["sourcetype"],
        "event_id": "1",
        "process_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "original_file_name": "PowerShell.EXE",
        "command_line": (
            "powershell.exe -NoProfile -EncodedCommand SANITIZED "
            f"{controlled_test_marker}"
        ),
        "parent_process_image": r"C:\Program Files\PowerShell\7\pwsh.exe",
        "parent_command_line": "pwsh.exe -NoProfile -Command Start-Process powershell.exe",
    }
    actual = normalizer.normalize_row(mapped_row, controlled_test_marker)
    for field, expected_value in EXPECTED_BACKEND_METADATA.items():
        if actual.get(field) != expected_value:
            fail(f"mapped-process-image: {field} expected {expected_value} got {actual.get(field)}")
    if actual.get("image") != mapped_row["process_image"]:
        fail("mapped-process-image: process_image was not normalized as image")
    if actual.get("parent_image") != mapped_row["parent_process_image"]:
        fail("mapped-process-image: parent_process_image was not normalized as parent_image")
    for field in ["behavior_family_match", "strict_child_candidate", "required_fields_present"]:
        if actual.get(field) is not True:
            fail(f"mapped-process-image: {field} expected True got {actual.get(field)}")
    renamed_row = dict(mapped_row)
    renamed_row["process_image"] = r"C:\Temp\renamed.exe"
    renamed_row["original_file_name"] = "PowerShell.EXE"
    renamed_actual = normalizer.normalize_row(renamed_row, controlled_test_marker)
    if renamed_actual.get("original_file_name") != renamed_row["original_file_name"]:
        fail("mapped-process-image: original_file_name was not normalized")
    for field in ["behavior_family_match", "required_fields_present"]:
        if renamed_actual.get(field) is not True:
            fail(f"mapped-process-image-renamed: {field} expected True got {renamed_actual.get(field)}")


def main() -> int:
    mapping_contract_source = verify_mapping_contract()
    text = read_text(CASES_FILE, "runtime backend adapter cases")
    verify_sanitization(text)
    data = load_json(CASES_FILE, "runtime backend adapter cases")
    if data.get("detection_id") != "HO-DET-001":
        fail("detection_id must be HO-DET-001")
    if data.get("adapter_scope") != "controlled_backend_adapter_fixture":
        fail("adapter_scope must be controlled_backend_adapter_fixture")
    verify_claim_boundary(data)
    strict_child_count, parent_noise_count, marker_only_noise_count = verify_case_results(data)
    verify_mapped_process_image_support(data)
    print("STATUS=pass")
    print("DETECTION_ID=HO-DET-001")
    print("RESULT=ADAPTER_CONTRACT_PASS")
    print(f"EVENT_MAPPING_CONTRACT_SOURCE={mapping_contract_source}")
    print(f"STRICT_CHILD_CANDIDATES={strict_child_count}")
    print(f"PARENT_LAUNCHER_NOISE_EVENTS={parent_noise_count}")
    print(f"MARKER_ONLY_NOISE_EVENTS={marker_only_noise_count}")
    print("PUBLIC_SAFE_NOT_APPROVED=true")
    print("RUNTIME_ACTIVE_PROVEN=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

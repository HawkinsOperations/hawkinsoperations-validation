#!/usr/bin/env python3
"""Normalize sanitized Splunk XML Sysmon rows for HO-DET-001 adapter checks.

This adapter is deterministic. It does not query Splunk, read raw private
exports, invoke AI, or promote runtime evidence. Inputs must already be
sanitized fixture rows.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES_FILE = ROOT / "validation" / "successor" / "ho-det-001" / "runtime-backend-adapter-cases.json"
EXPECTED_INDEX = "ho_v2_sysmon"
EXPECTED_SOURCETYPE = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EXPECTED_SOURCE = "WinEventLog:Microsoft-Windows-Sysmon/Operational"
ENCODED_COMMAND_RE = re.compile(r"(?:^|\s)(?:-|/)(?:enc|encodedcommand)(?::|\s|$)", re.IGNORECASE)


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing input file: {path}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")
    if not isinstance(data, dict):
        fail(f"{path} must contain a JSON object")
    return data


def xml_event_id(raw: str) -> str:
    match = re.search(r"<EventID[^>]*>(?P<value>\d+)</EventID>", raw, re.IGNORECASE)
    return match.group("value") if match else ""


def xml_data(raw: str, name: str) -> str:
    pattern = rf"<Data\s+Name=['\"]{re.escape(name)}['\"]>(?P<value>.*?)</Data>"
    match = re.search(pattern, raw, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return html.unescape(match.group("value").strip())


def first_value(row: dict[str, Any], *names: str) -> str:
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def lower_path(value: str) -> str:
    return value.replace("/", "\\").lower()


def process_identity_matches(image: str, original_file_name: str) -> bool:
    normalized_image = lower_path(image)
    normalized_original = original_file_name.lower()
    return (
        normalized_image.endswith("\\powershell.exe")
        or normalized_image.endswith("\\pwsh.exe")
        or "powershell" in normalized_original
        or "pwsh" in normalized_original
    )


def cli_matches(command_line: str) -> bool:
    lower_cli = command_line.lower()
    return bool(ENCODED_COMMAND_RE.search(command_line)) or "frombase64string(" in lower_cli


def strict_child_candidate(event_id: str, image: str, command_line: str, marker: str) -> bool:
    normalized_image = lower_path(image)
    return (
        event_id == "1"
        and normalized_image.endswith("\\windowspowershell\\v1.0\\powershell.exe")
        and marker in command_line
        and cli_matches(command_line)
    )


def parent_launcher_noise(event_id: str, image: str, command_line: str, marker: str) -> bool:
    normalized_image = lower_path(image)
    return (
        event_id == "1"
        and normalized_image.endswith("\\pwsh.exe")
        and marker in command_line
        and cli_matches(command_line)
        and not strict_child_candidate(event_id, image, command_line, marker)
    )


def marker_only_noise(event_id: str, command_line: str, marker: str) -> bool:
    return event_id == "1" and marker in command_line and not cli_matches(command_line)


def normalize_row(row: dict[str, Any], marker: str) -> dict[str, Any]:
    raw = str(row.get("_raw", "") or "")
    event_id = first_value(row, "EventCode", "EventID", "event_id") or xml_event_id(raw)
    image = first_value(row, "Image", "process_path", "winlog_event_data_Image") or xml_data(raw, "Image")
    original_file_name = first_value(row, "OriginalFileName", "winlog_event_data_OriginalFileName") or xml_data(
        raw, "OriginalFileName"
    )
    command_line = first_value(row, "CommandLine", "ProcessCommandLine", "command_line", "winlog_event_data_CommandLine") or xml_data(
        raw, "CommandLine"
    )
    parent_image = first_value(row, "ParentImage", "parent_process_path", "winlog_event_data_ParentImage") or xml_data(
        raw, "ParentImage"
    )
    parent_command_line = first_value(row, "ParentCommandLine", "parent_command_line", "winlog_event_data_ParentCommandLine") or xml_data(
        raw, "ParentCommandLine"
    )
    process_guid = first_value(row, "ProcessGuid", "process_guid", "winlog_event_data_ProcessGuid") or xml_data(
        raw, "ProcessGuid"
    )
    parent_process_guid = first_value(
        row, "ParentProcessGuid", "parent_process_guid", "winlog_event_data_ParentProcessGuid"
    ) or xml_data(raw, "ParentProcessGuid")
    user = first_value(row, "User", "user", "winlog_event_data_User") or xml_data(raw, "User")

    has_process_identity = process_identity_matches(image, original_file_name)
    has_command_line = bool(command_line)
    behavior_match = event_id == "1" and has_process_identity and cli_matches(command_line)

    return {
        "index": first_value(row, "index"),
        "host": first_value(row, "host", "Computer"),
        "source": first_value(row, "source"),
        "sourcetype": first_value(row, "sourcetype"),
        "event_id": event_id,
        "image": image,
        "original_file_name": original_file_name,
        "command_line": command_line,
        "parent_image": parent_image,
        "parent_command_line": parent_command_line,
        "process_guid": process_guid,
        "parent_process_guid": parent_process_guid,
        "user": user,
        "marker": marker,
        "has_marker": marker in command_line,
        "behavior_family_match": behavior_match,
        "strict_child_candidate": strict_child_candidate(event_id, image, command_line, marker),
        "parent_launcher_noise": parent_launcher_noise(event_id, image, command_line, marker),
        "marker_only_noise": marker_only_noise(event_id, command_line, marker),
        "required_fields_present": event_id == "1" and has_process_identity and has_command_line,
        "claim_boundary": "backend adapter fixture only; not runtime-active or public proof",
    }


def normalize_cases(data: dict[str, Any]) -> list[dict[str, Any]]:
    marker = str(data.get("marker", "") or "")
    if not marker:
        fail("input marker is required")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        fail("input cases must be a non-empty list")
    normalized: list[dict[str, Any]] = []
    for case in cases:
        if not isinstance(case, dict):
            fail("each case must be a JSON object")
        row = case.get("row")
        if not isinstance(row, dict):
            fail(f"{case.get('id', '<unknown>')}: row must be a JSON object")
        item = normalize_row(row, marker)
        item["id"] = str(case.get("id", ""))
        item["description"] = str(case.get("description", ""))
        normalized.append(item)
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize sanitized HO-DET-001 Splunk XML Sysmon adapter cases.")
    parser.add_argument("--input", type=Path, default=DEFAULT_CASES_FILE, help="Sanitized adapter cases JSON file.")
    parser.add_argument("--output", type=Path, help="Optional normalized JSON output path. Omit for check-only stdout.")
    args = parser.parse_args()

    data = load_json(args.input)
    normalized = normalize_cases(data)
    result = {
        "status": "pass",
        "detection_id": data.get("detection_id"),
        "adapter_scope": data.get("adapter_scope"),
        "normalized_count": len(normalized),
        "normalized": normalized,
        "claim_boundary": "Deterministic backend adapter normalization only. This does not query Splunk or prove runtime-active status.",
    }
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("STATUS=pass")
    print("DETECTION_ID=HO-DET-001")
    print(f"NORMALIZED_COUNT={len(normalized)}")
    print("WRITE_SKIPPED=false" if args.output else "WRITE_SKIPPED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

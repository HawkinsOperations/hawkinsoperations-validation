#!/usr/bin/env python3
"""Synthetic validation runner for HO-DET-001.

This script validates deterministic fixture behavior only. It does not inspect
runtime systems, query Splunk, or produce signal evidence.
"""

from __future__ import annotations

import json
import re
import sys
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_ROOT = ROOT.parent / "hawkinsoperations-detections"
SOURCE_FILE = DETECTIONS_ROOT / "detections" / "successor" / "ho-det-001" / "rule.yml"
SPLUNK_SOURCE_FILE = DETECTIONS_ROOT / "detections" / "successor" / "ho-det-001" / "splunk.spl"
CASES_FILE = ROOT / "validation" / "successor" / "ho-det-001" / "validation-cases.json"
REPORT_DIR = ROOT / "reports" / "ho-det-001"
REPORT_JSON = REPORT_DIR / "validation-result.json"
REPORT_MD = REPORT_DIR / "validation-result.md"

CLAIM_SUPPORTED = "HO-DET-001 passed synthetic validation against controlled positive and negative process-creation fixtures."
CLAIMS_NOT_SUPPORTED = [
    "runtime-active",
    "signal-observed",
    "evidence-linked",
    "public-safe",
    "production-ready",
    "live Splunk firing",
    "Cribl-routed telemetry",
    "Wazuh live collection",
    "production triage",
    "analyst-approved disposition",
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: Path, label: str) -> str:
    if not path.exists():
        fail(f"missing {label}: {path}")
    return path.read_text(encoding="utf-8")


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        return json.loads(read_text(path, label))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {label}: {exc}")


def extract_yaml_list(text: str, key: str) -> list[str]:
    lines = text.splitlines()
    values: list[str] = []
    capture = False
    base_indent = 0
    for line in lines:
        stripped = line.strip()
        if stripped == f"{key}:":
            capture = True
            base_indent = len(line) - len(line.lstrip())
            continue
        if capture:
            indent = len(line) - len(line.lstrip())
            if stripped and indent <= base_indent:
                break
            if stripped.startswith("- "):
                raw = stripped[2:].strip()
                if (raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"')):
                    raw = raw[1:-1]
                values.append(raw)
    return values


def validate_source_contract(text: str) -> None:
    required_fragments = [
        "detection_id: HO-DET-001",
        "selection_image:",
        "selection_cli:",
        "condition: selection_image and selection_cli",
        "Image|endswith:",
        "OriginalFileName|contains:",
        "CommandLine|contains:",
    ]
    for fragment in required_fragments:
        if fragment not in text:
            fail(f"source contract missing fragment: {fragment}")

    image_values = {v.lower() for v in extract_yaml_list(text, "Image|endswith")}
    original_values = {v.lower() for v in extract_yaml_list(text, "OriginalFileName|contains")}
    cli_values = {v.lower() for v in extract_yaml_list(text, "CommandLine|contains")}

    if "\\powershell.exe" not in image_values or "\\pwsh.exe" not in image_values:
        fail("source image selection must include powershell.exe and pwsh.exe endings")
    if "powershell" not in original_values or "pwsh" not in original_values:
        fail("source OriginalFileName selection must include PowerShell and pwsh alternatives")
    for expected in [" -enc ", " -encodedcommand ", " /encodedcommand:", "frombase64string("]:
        if expected not in cli_values:
            fail(f"source CLI selection missing expected indicator: {expected}")


def process_identity_matches(event: dict[str, Any]) -> bool:
    image = str(event.get("Image", "") or "").lower()
    original = str(event.get("OriginalFileName", "") or "").lower()
    return (
        image.endswith("\\powershell.exe")
        or image.endswith("\\pwsh.exe")
        or "powershell" in original
        or "pwsh" in original
    )


def cli_matches(event: dict[str, Any]) -> bool:
    command_line = str(event.get("CommandLine", "") or "").lower()
    if not command_line:
        return False
    encoded_flag = re.search(r"(?:^|\s)(?:-|/)(?:enc|encodedcommand)(?::|\s|$)", command_line)
    return bool(encoded_flag) or "frombase64string(" in command_line


def event_matches(event: dict[str, Any]) -> bool:
    return process_identity_matches(event) and cli_matches(event)


def evaluate_cases(cases: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[str]]:
    positives = cases.get("cases", {}).get("positive", [])
    negatives = cases.get("cases", {}).get("negative", [])
    if not positives:
        fail("validation cases must include positive cases")
    if not negatives:
        fail("validation cases must include negative cases")

    positive_results = []
    negative_results = []
    missed_positive_cases = []
    false_positive_negative_cases = []

    for item in positives:
        matched = event_matches(item.get("event", {}))
        case_id = str(item.get("id", ""))
        passed = matched is True
        if not passed:
            missed_positive_cases.append(case_id)
        positive_results.append({"id": case_id, "expected": True, "matched": matched, "pass": passed})

    for item in negatives:
        matched = event_matches(item.get("event", {}))
        case_id = str(item.get("id", ""))
        passed = matched is False
        if not passed:
            false_positive_negative_cases.append(case_id)
        negative_results.append({"id": case_id, "expected": False, "matched": matched, "pass": passed})

    return positive_results, negative_results, missed_positive_cases, false_positive_negative_cases


def write_reports(report: dict[str, Any]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# HO-DET-001 Synthetic Validation Result",
        "",
        "## Summary",
        f"- Status: {report['status']}",
        f"- Detection ID: {report['detection_id']}",
        f"- Executed at: {report['executed_at']}",
        f"- Matched positive count: {report['matched_positive_count']}",
        f"- Missed positives: {', '.join(report['missed_positive_cases']) if report['missed_positive_cases'] else 'none'}",
        f"- False-positive negatives: {', '.join(report['false_positive_negative_cases']) if report['false_positive_negative_cases'] else 'none'}",
        "",
        "## Inputs",
        f"- Source file: {report['source_file']}",
        f"- Splunk source file: {report['splunk_source_file']}",
        f"- Validation cases file: {report['validation_cases_file']}",
        "",
        "## Results",
        f"- Total cases: {report['totals']['total_cases']}",
        f"- Positive cases: {report['totals']['positive_cases']}",
        f"- Negative cases: {report['totals']['negative_cases']}",
        f"- Passed cases: {report['totals']['pass']}",
        f"- Failed cases: {report['totals']['fail']}",
        "",
        "## Supported Claim",
        f"- {report['exact_claim_supported']}",
        "",
        "## Blocked Claims",
    ]
    lines.extend(f"- Not supported: {claim}" for claim in report["claims_not_supported"])
    lines.extend(
        [
            "",
            "## What This Does Not Prove",
            "This does not prove deployment, live telemetry collection, live Splunk alerting, Cribl routing, signal observation, evidence linkage, public approval, production readiness, or analyst-approved triage.",
            "",
            "## Reproduction Command",
            "- From the validation repository root, run: `python scripts/validate-ho-det-001.py`",
        ]
    )
    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate HO-DET-001 synthetic process-creation fixtures.")
    parser.add_argument(
        "--write",
        action="store_true",
        help="Regenerate validation-result JSON and Markdown artifacts. Default is check-only and writes nothing.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run check-only mode. This is the default and is kept for explicit CI/readiness usage.",
    )
    args = parser.parse_args()

    source_text = read_text(SOURCE_FILE, "HO-DET-001 source rule")
    read_text(SPLUNK_SOURCE_FILE, "HO-DET-001 Splunk source")
    validate_source_contract(source_text)

    cases = load_json(CASES_FILE, "HO-DET-001 validation cases")
    if cases.get("detection_id") != "HO-DET-001":
        fail("validation cases detection_id must be HO-DET-001")

    positive_results, negative_results, missed, false_positive = evaluate_cases(cases)
    all_results = positive_results + negative_results
    fail_count = len(missed) + len(false_positive)
    status = "pass" if fail_count == 0 else "fail"

    report = {
        "status": status,
        "detection_id": "HO-DET-001",
        "source_file": "hawkinsoperations-detections/detections/successor/ho-det-001/rule.yml",
        "splunk_source_file": "hawkinsoperations-detections/detections/successor/ho-det-001/splunk.spl",
        "validation_cases_file": "hawkinsoperations-validation/validation/successor/ho-det-001/validation-cases.json",
        "executed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "matched_positive_count": sum(1 for item in positive_results if item["matched"]),
        "missed_positive_cases": missed,
        "false_positive_negative_cases": false_positive,
        "totals": {
            "total_cases": len(all_results),
            "positive_cases": len(positive_results),
            "negative_cases": len(negative_results),
            "pass": sum(1 for item in all_results if item["pass"]),
            "fail": fail_count,
        },
        "positive": positive_results,
        "negative": negative_results,
        "exact_claim_supported": CLAIM_SUPPORTED if status == "pass" else "",
        "claims_not_supported": CLAIMS_NOT_SUPPORTED,
        "proof_level_before": "SOURCE_EXISTS",
        "proof_level_after": "TEST_VALIDATED_SYNTHETIC_SCOPE" if status == "pass" else "SOURCE_EXISTS",
        "trust_boundary": "Synthetic process-creation fixture validation only. This is not runtime, signal, evidence-linked, public-safe, production, or live SOC proof.",
        "privacy_status": "Synthetic fixtures only; no secrets, private hostnames, private addresses, or live telemetry intentionally included.",
    }
    if args.write:
        write_reports(report)
    print(f"STATUS={status}")
    print(f"MODE={'write' if args.write else 'check'}")
    print(f"DETECTION_ID=HO-DET-001")
    print(f"TOTAL_CASES={report['totals']['total_cases']}")
    print(f"MATCHED_POSITIVE_COUNT={report['matched_positive_count']}")
    print(f"MISSED_POSITIVE_CASES={','.join(missed) if missed else 'none'}")
    print(f"FALSE_POSITIVE_NEGATIVE_CASES={','.join(false_positive) if false_positive else 'none'}")
    if args.write:
        print(f"REPORT_JSON={REPORT_JSON}")
        print(f"REPORT_MD={REPORT_MD}")
    else:
        print("WRITE_SKIPPED=true")
    if status != "pass":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

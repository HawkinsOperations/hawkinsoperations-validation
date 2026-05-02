#!/usr/bin/env python3
"""Verify HO-DET-001 and AWS-DET-001 proof records match validation truth.

This verifier reads committed validation reports and proof records only. It does
not promote proof levels, inspect runtime systems, or create evidence.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROOF_ROOT = ROOT.parent / "hawkinsoperations-proof"

HO_VALIDATION_RESULT = ROOT / "reports" / "ho-det-001" / "validation-result.json"
AWS_VALIDATION_RESULT = ROOT / "reports" / "aws-det-001" / "validation-result.json"
HO_PROOF_MD = PROOF_ROOT / "proof" / "records" / "HO-DET-001.md"
AWS_PROOF_MD = PROOF_ROOT / "proof" / "records" / "AWS-DET-001.md"
HO_PROOF_JSON = PROOF_ROOT / "proof" / "records" / "HO-DET-001-SYNTHETIC-VALIDATION-001.json"

PROOF_CEILING = "TEST_VALIDATED_SYNTHETIC_SCOPE"
HO_SUPPORTED_CLAIM = (
    "HO-DET-001 passed synthetic validation against controlled positive and "
    "negative process-creation fixtures."
)
AWS_SUPPORTED_CLAIM = (
    "AWS-DET-001 passed fixture-only validation against controlled "
    "CloudTrail-style IAM denial fixtures."
)


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: Path, label: str) -> str:
    if not path.exists():
        fail(f"missing {label}: {path}")
    return path.read_text(encoding="utf-8")


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(read_text(path, label))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        fail(f"{label} mismatch: expected {expected!r}, got {actual!r}")


def require_in(text: str, needle: str, label: str) -> None:
    if needle not in text:
        fail(f"{label} missing required text: {needle}")


def require_validation_report(report: dict[str, Any], detection_id: str, claim: str) -> None:
    require_equal(report.get("status"), "pass", f"{detection_id} validation status")
    require_equal(report.get("detection_id"), detection_id, f"{detection_id} detection_id")
    require_equal(report.get("missed_positive_cases"), [], f"{detection_id} missed_positive_cases")
    require_equal(
        report.get("false_positive_negative_cases"),
        [],
        f"{detection_id} false_positive_negative_cases",
    )
    require_equal(report.get("exact_claim_supported"), claim, f"{detection_id} supported claim")


def verify_ho_markdown(report: dict[str, Any], text: str) -> None:
    totals = report["totals"]
    required = [
        "- Current proof level: TEST_VALIDATED_SYNTHETIC_SCOPE",
        "- Current trust class: TEST_VALIDATED_SYNTHETIC_SCOPE",
        "- Public-safe status: NOT_PUBLIC_SAFE",
        "- Approval status: NOT_APPROVED",
        f'"{HO_SUPPORTED_CLAIM}"',
        f"- Validation status: {report['status']}",
        f"- Total controlled cases: {totals['total_cases']}",
        f"- Matched positive count: {report['matched_positive_count']}",
        "- Missed positive cases: none",
        "- False-positive negative cases: none",
        "- Runtime-active status: BLOCKED.",
        "- Signal-observed status: BLOCKED.",
    ]
    for item in required:
        require_in(text, item, "HO-DET-001.md")


def verify_aws_markdown(report: dict[str, Any], text: str) -> None:
    totals = report["totals"]
    required = [
        "- Current proof level: TEST_VALIDATED_SYNTHETIC_SCOPE",
        "- Current trust class: TEST_VALIDATED_SYNTHETIC_SCOPE",
        "- Public-safe status: NOT_PUBLIC_SAFE",
        "- Approval status: NOT_APPROVED",
        f'"{AWS_SUPPORTED_CLAIM}"',
        f"- Validation status: {report['status']}",
        f"- Total controlled cases: {totals['total_cases']}",
        f"- Matched positive count: {report['matched_positive_count']}",
        "- Missed positive cases: none",
        "- False-positive negative cases: none",
        "- AWS-live status: BLOCKED.",
        "- AWS CloudTrail live status: BLOCKED.",
        "- Signal-observed status: BLOCKED.",
        "TEST_VALIDATED_SYNTHETIC_SCOPE",
    ]
    for item in required:
        require_in(text, item, "AWS-DET-001.md")


def verify_ho_json(report: dict[str, Any], proof: dict[str, Any]) -> None:
    totals = report["totals"]
    validation_summary = proof.get("validation_summary")
    if not isinstance(validation_summary, dict):
        fail("HO-DET-001 synthetic proof JSON missing validation_summary object")
    require_equal(proof.get("detection_id"), "HO-DET-001", "HO proof JSON detection_id")
    require_equal(proof.get("status"), PROOF_CEILING, "HO proof JSON status")
    require_equal(proof.get("supported_claim"), HO_SUPPORTED_CLAIM, "HO proof JSON supported_claim")
    require_equal(proof.get("public_safe_status"), "NOT_PUBLIC_SAFE", "HO proof JSON public_safe_status")
    require_equal(proof.get("approval_status"), "NOT_APPROVED", "HO proof JSON approval_status")
    require_equal(validation_summary.get("status"), report["status"], "HO proof JSON validation status")
    require_equal(validation_summary.get("total_cases"), totals["total_cases"], "HO proof JSON total cases")
    require_equal(
        validation_summary.get("matched_positive_count"),
        report["matched_positive_count"],
        "HO proof JSON matched positives",
    )
    require_equal(
        validation_summary.get("missed_positive_cases"),
        report["missed_positive_cases"],
        "HO proof JSON missed positives",
    )
    require_equal(
        validation_summary.get("false_positive_negative_cases"),
        report["false_positive_negative_cases"],
        "HO proof JSON false-positive negatives",
    )


def main() -> int:
    ho_report = load_json(HO_VALIDATION_RESULT, "HO-DET-001 validation result")
    aws_report = load_json(AWS_VALIDATION_RESULT, "AWS-DET-001 validation result")
    require_validation_report(ho_report, "HO-DET-001", HO_SUPPORTED_CLAIM)
    require_validation_report(aws_report, "AWS-DET-001", AWS_SUPPORTED_CLAIM)
    require_equal(ho_report.get("proof_level_after"), PROOF_CEILING, "HO validation proof_level_after")
    require_equal(aws_report.get("proof_ceiling"), PROOF_CEILING, "AWS validation proof_ceiling")
    require_equal(aws_report.get("aws_live_status"), "BLOCKED", "AWS live status")
    require_equal(aws_report.get("public_safe_status"), "NOT_PUBLIC_SAFE", "AWS public-safe status")

    verify_ho_markdown(ho_report, read_text(HO_PROOF_MD, "HO-DET-001 proof markdown"))
    verify_aws_markdown(aws_report, read_text(AWS_PROOF_MD, "AWS-DET-001 proof markdown"))
    verify_ho_json(ho_report, load_json(HO_PROOF_JSON, "HO-DET-001 synthetic proof JSON"))

    print("STATUS=pass")
    print("PROOF_RECORD_PARITY=pass")
    print(f"PROOF_CEILING={PROOF_CEILING}")
    print("PUBLIC_SAFE_STATUS=NOT_PUBLIC_SAFE")
    print("WRITE_SKIPPED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

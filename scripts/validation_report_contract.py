"""Shared fail-closed identity and authority fields for controlled reports."""

from __future__ import annotations

from typing import Any


def controlled_report_contract(
    detection_id: str,
    proof_ceiling: str,
    *,
    passed: bool,
    fixture_version: int = 1,
) -> dict[str, Any]:
    return {
        "validation_owner": "hawkinsoperations-validation",
        "source_owner": "hawkinsoperations-detections",
        "fixture_version": fixture_version,
        "expected_result": "PASS",
        "actual_result": "PASS" if passed else "BLOCKED",
        "report_identity": f"{detection_id}_VALIDATION_RESULT_V1",
        "parity_identity": f"{detection_id}_RESULT_PARITY_V1",
        "proof_ceiling": proof_ceiling,
        "human_review_required": True,
        "ai_disposition_authority": False,
    }

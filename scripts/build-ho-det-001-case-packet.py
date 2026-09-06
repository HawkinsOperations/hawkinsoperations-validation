#!/usr/bin/env python3
"""Build the deterministic HO-DET-001 validation case packet.

This script uses committed controlled-test validation artifacts only. It does not
query runtime systems, Splunk, Cribl, Wazuh, AWS, or model runtimes.
"""

from __future__ import annotations

import hashlib
import json
import argparse
import sys
from pathlib import Path
from typing import Any

from validation_lib import ContractFailure, strict_json_object


ROOT = Path(__file__).resolve().parents[1]
DETECTION_ID = "HO-DET-001"
DETECTION_SLUG = DETECTION_ID.lower()
CASE_ID = f"{DETECTION_ID}-CASE-PACKET-001"
DETECTION_DIR = ROOT / "validation" / "successor" / DETECTION_SLUG
CASE_PACKET = DETECTION_DIR / "case-packet.json"
VALIDATION_CASES = DETECTION_DIR / "validation-cases.json"
VALIDATION_RESULT = ROOT / "reports" / DETECTION_SLUG / "validation-result.json"
AUTOSOC_PACKET = DETECTION_DIR / "autosoc-triage-packet.json"
LLM_SUMMARY = DETECTION_DIR / "llm-summary.json"

PROOF_CEILING = "CONTROLLED_TEST_VALIDATED"
CASE_FACTORY_SCOPE_STATUS = "SHARED_DRY_RUN_BOUNDARY_ONLY"
SUPPORTED_CLAIM = (
    "HO-DET-001 passed controlled-test validation against controlled positive and "
    "negative process-creation fixtures."
)
BLOCKED_CLAIMS = [
    "runtime-active",
    "signal-observed",
    "evidence-linked public proof",
    "public-safe",
    "live Splunk firing",
    "production triage",
    "analyst-approved disposition",
    "HO-GPU-01 runtime-active",
    "Cribl-routed",
    "Wazuh-routed",
    "AWS-live",
    "autonomous SOC",
    "production-ready SOC",
    "fleet-wide deployment",
    "AI-approved disposition",
]

CASE_FACTORY_LABELS = [
    "autosoc:case",
    "autosoc:sanitized",
    "autosoc:validated",
    "autosoc:needs-human-review",
    "autosoc:blocked-close",
    "proof:controlled-test",
    "publication:not-approved",
    "ai:support-only",
    f"det:{DETECTION_SLUG}",
]
CASE_FACTORY_GENERIC_FIELDS = [
    "factory_version",
    "case_state",
    "state_machine",
    "github_issue_plan.mode",
    "github_issue_plan.mutation_allowed",
    "github_issue_plan.issue_ref",
    "github_issue_plan.comment_intent",
    "github_issue_plan.close_action_allowed",
    "deterministic_close_rule",
    "optional_ai_support",
]
CASE_FACTORY_DETECTION_SPECIFIC_FIELDS = [
    "case_id",
    "detection_id",
    "detection_title",
    "event",
    "detection_references",
    "validation_references",
    "public_claim_boundary.supported_claim",
    "github_issue_plan.labels_to_add",
]
CASE_FACTORY_INCLUSION_REQUIRES = [
    "separate detection-scoped builder parity",
    "separate detection-scoped verifier enforcement",
    "claim-boundary scan pass",
    "proof/public-safe promotion remains blocked",
    "AI_SUPPORT_ONLY authority boundary preserved",
    "explicit human approval for each new detection inclusion",
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing {label}: {path}")
    try:
        return strict_json_object(path.read_text(encoding="utf-8"), label)
    except ContractFailure as exc:
        fail(str(exc))


def stable_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=False) + "\n"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def repo_path(path: Path) -> str:
    return f"hawkinsoperations-validation/{path.relative_to(ROOT).as_posix()}"


def source_ref(name: str, path: Path) -> dict[str, str]:
    return {"name": name, "path": repo_path(path), "sha256": sha256_file(path)}


def require_keys(value: dict[str, Any], keys: list[str], label: str) -> None:
    missing = [key for key in keys if key not in value]
    if missing:
        fail(f"{label} missing required keys: {', '.join(missing)}")


def pick_controlled_test_event(validation_cases: dict[str, Any]) -> dict[str, Any]:
    cases = validation_cases.get("cases")
    if not isinstance(cases, dict):
        fail("validation-cases.json cases must be an object")
    positives = cases.get("positive")
    if not isinstance(positives, list) or not positives:
        fail("validation-cases.json cases.positive must be a non-empty array")
    first = positives[0]
    if not isinstance(first, dict) or not isinstance(first.get("event"), dict):
        fail("first positive validation case must contain an event object")
    event = first["event"]
    return {
        "event_time": "2026-04-29T15:00:21Z",
        "host": "HO-CONTROLLED-TEST-ENDPOINT-001",
        "user": "HO_CONTROLLED_TEST_USER",
        "image": str(event.get("Image", "")),
        "original_file_name": str(event.get("OriginalFileName", "")),
        "command_line": str(event.get("CommandLine", "")),
        "parent_image": "\\Windows\\System32\\cmd.exe",
        "event_id": int(event.get("EventID", 1)),
        "source": "WinEventLog:Microsoft-Windows-Sysmon/Operational",
        "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "index": "hawkinsoperations_controlled_test_validation",
    }


def validate_inputs(validation_cases: dict[str, Any], validation_result: dict[str, Any]) -> None:
    require_keys(validation_cases, ["detection_id", "case_scope", "cases"], "validation-cases.json")
    require_keys(
        validation_result,
        [
            "status",
            "detection_id",
            "matched_positive_count",
            "missed_positive_cases",
            "false_positive_negative_cases",
            "totals",
            "exact_claim_supported",
            "proof_level_after",
        ],
        "validation-result.json",
    )
    if validation_cases.get("detection_id") != DETECTION_ID:
        fail(f"validation-cases.json detection_id must be {DETECTION_ID}")
    if validation_result.get("detection_id") != DETECTION_ID:
        fail(f"validation-result.json detection_id must be {DETECTION_ID}")
    if validation_result.get("status") != "pass":
        fail("validation-result.json status must be pass")
    if validation_result.get("proof_level_after") != PROOF_CEILING:
        fail(f"validation-result.json proof_level_after must be {PROOF_CEILING}")
    if validation_result.get("exact_claim_supported") != SUPPORTED_CLAIM:
        fail("validation-result.json exact_claim_supported is not the approved controlled-test claim")


def build_case_packet() -> dict[str, Any]:
    validation_cases = load_json(VALIDATION_CASES, "validation-cases.json")
    validation_result = load_json(VALIDATION_RESULT, "validation-result.json")
    validate_inputs(validation_cases, validation_result)
    event = pick_controlled_test_event(validation_cases)
    totals = validation_result.get("totals", {})
    return {
        "case_id": CASE_ID,
        "detection_id": DETECTION_ID,
        "detection_title": "Encoded PowerShell process creation controlled-test validation",
        "truth_surface": "repo truth",
        "proof_level": PROOF_CEILING,
        "allowed_scope": "Controlled-test validation using controlled process-creation fixtures only.",
        "public_safe_status": "NO",
        "blocked_claims": BLOCKED_CLAIMS,
        "event": event,
        "detection_references": [
            {
                "name": "detection source",
                "path": "hawkinsoperations-detections/detections/successor/ho-det-001/rule.yml",
                "sha256": "not-local-to-validation-repo",
            },
            {
                "name": "splunk source",
                "path": "hawkinsoperations-detections/detections/successor/ho-det-001/splunk.spl",
                "sha256": "not-local-to-validation-repo",
            },
        ],
        "validation_references": [
            source_ref("validation cases", VALIDATION_CASES),
            source_ref("validation result", VALIDATION_RESULT),
            source_ref("autosoc controlled-test packet", AUTOSOC_PACKET),
            source_ref("blocked-runtime LLM stub", LLM_SUMMARY),
        ],
        "triage_boundary": {
            "ai_role": "support_only",
            "ai_may_decide_disposition": False,
            "disposition_authority": "deterministic_verifier_and_human_review",
        },
        "public_claim_boundary": {
            "public_safe_status": "NO",
            "supported_claim": SUPPORTED_CLAIM,
            "blocked_claims": BLOCKED_CLAIMS,
        },
        "validation_summary": {
            "status": validation_result["status"],
            "total_cases": totals.get("total_cases"),
            "positive_cases": totals.get("positive_cases"),
            "negative_cases": totals.get("negative_cases"),
            "matched_positive_count": validation_result["matched_positive_count"],
            "missed_positive_cases": validation_result["missed_positive_cases"],
            "false_positive_negative_cases": validation_result["false_positive_negative_cases"],
        },
        "determinism": {
            "generated_by": "scripts/build-ho-det-001-case-packet.py",
            "source_mode": "committed_local_controlled_test_validation_artifacts",
            "controlled_test_fallback_used": False,
        },
        "case_factory": {
            "factory_version": "AUTOSOC_CASE_FACTORY_V0",
            "case_state": "DETERMINISTIC_RULE_EVALUATED",
            "factory_scope": {
                "scope_status": CASE_FACTORY_SCOPE_STATUS,
                "applies_to_detection_id": DETECTION_ID,
                "included_detection_ids": [DETECTION_ID],
                "excluded_detection_ids": ["HO-DET-011"],
                "new_detection_inclusion_allowed": False,
                "inclusion_requires": CASE_FACTORY_INCLUSION_REQUIRES,
                "generic_contract_fields": CASE_FACTORY_GENERIC_FIELDS,
                "detection_specific_fields": CASE_FACTORY_DETECTION_SPECIFIC_FIELDS,
            },
            "state_machine": [
                "DISCOVERED",
                "SANITIZED_PACKET_BUILT",
                "PACKET_VALIDATED",
                "OPTIONAL_SUPPORT_TRIAGED",
                "DETERMINISTIC_RULE_EVALUATED",
                "ISSUE_UPDATE_PREPARED",
                "HUMAN_REVIEW_REQUIRED",
            ],
            "github_issue_plan": {
                "mode": "dry_run_only",
                "mutation_allowed": False,
                "issue_ref": None,
                "labels_to_add": CASE_FACTORY_LABELS,
                "labels_to_remove": [],
                "comment_intent": (
                    "Prepare a sanitized deterministic status comment only; do not mutate GitHub Issues "
                    "without separately approved issue-write scope."
                ),
                "close_action_allowed": False,
            },
            "deterministic_close_rule": {
                "evaluated": True,
                "close_eligible": False,
                "deterministic_close_eligible": False,
                "result": "BLOCKED_HUMAN_REVIEW_REQUIRED",
                "basis": (
                    "Deterministic rules may evaluate the packet and prepare a dry-run issue plan, "
                    "but AutoSOC Case Factory v0 cannot close cases."
                ),
                "blockers": [
                    "human_review_required=true",
                    "github_issue_mutation_allowed=false",
                    "close_action_allowed=false",
                    "deterministic_close_eligible=false",
                    "ai_support_is_labor_not_authority",
                ],
                "ai_authority_granted": False,
                "proof_promotion_allowed": False,
                "public_safe_promotion_allowed": False,
            },
            "optional_ai_support": {
                "status": "NOT_RUN_IN_CASE_PACKET",
                "allowed_role": "AI_SUPPORT_ONLY",
                "recommended_disposition": None,
                "ai_decided_disposition": False,
                "allowed_output_fields": [
                    "summary",
                    "triage_notes",
                    "questions_for_human_review",
                    "hypotheses",
                    "recommended_next_checks",
                    "confidence_notes",
                ],
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build or check the deterministic HO-DET-001 case packet.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check that case-packet.json is already current without writing it.",
    )
    args = parser.parse_args()

    packet = build_case_packet()
    expected = stable_json(packet)
    if args.check:
        if not CASE_PACKET.exists():
            fail(f"missing case packet: {CASE_PACKET}")
        existing = CASE_PACKET.read_text(encoding="utf-8")
        if existing != expected:
            fail("case-packet.json is out of date; run without --check to regenerate it")
        print("STATUS=pass")
        print("CASE_PACKET_CHECK=pass")
        print(f"CASE_PACKET={CASE_PACKET}")
        print(f"PROOF_LEVEL={PROOF_CEILING}")
        print("PUBLIC_SAFE_STATUS=NO")
        print("WRITE_SKIPPED=true")
        return 0

    CASE_PACKET.parent.mkdir(parents=True, exist_ok=True)
    CASE_PACKET.write_text(expected, encoding="utf-8")
    print("STATUS=pass")
    print(f"WROTE={CASE_PACKET}")
    print(f"PROOF_LEVEL={PROOF_CEILING}")
    print("PUBLIC_SAFE_STATUS=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

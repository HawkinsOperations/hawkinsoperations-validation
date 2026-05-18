#!/usr/bin/env python3
"""Run the controlled HO-DET-001 public test-fixture validation loop.

This orchestrator composes existing validation scripts. It does not query live
runtime systems, call models, dispatch GitHub Actions, or rewrite generated
artifacts in check mode. It proves only the controlled test fixture route that a
reviewer can run from public repository fixtures.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PIPELINE_ID = "HO-DET-001_LOCAL_CASE_PIPELINE"
DETECTION_ID = "HO-DET-001"
PIPELINE_STATUS_PASS = "FULL_LOCAL_PIPELINE_PASS"
SCOPE = "CONTROLLED_TEST_ONLY"
PROOF_CEILING = "CONTROLLED_TEST_VALIDATED"
SUCCESS_CEILING = "LOCAL_CASE_PIPELINE_DETERMINISTIC_CHECK_PASS"
PUBLIC_SAFE_STATUS = "NOT_PUBLIC_SAFE"
SUPPORTED_CLAIM = (
    "HawkinsOperations provides a clone-runnable controlled HO-DET-001 test-fixture proof runner "
    "that validates public test fixtures, verifies the controlled case packet, enforces AI authority "
    "boundaries, scans blocked claims, verifies result parity, and emits a bounded receipt "
    "without requiring private lab access or private runtime evidence."
)
CLAIM_BOUNDARY = (
    "CONTROLLED_TEST_ONLY / controlled test fixture / public test fixtures / controlled validation loop / "
    "public clone-runner / support-only / human review required / not public-safe status"
)

SUPPORTED_CLAIMS = [
    SUPPORTED_CLAIM,
]

BLOCKED_CLAIMS = [
    "runtime-active public proof",
    "signal-observed public proof",
    "public-safe runtime proof",
    "live Splunk proof",
    "live Wazuh proof",
    "Cribl-routed proof",
    "model execution in CI",
    "Ollama prompt execution in CI",
    "production readiness",
    "autonomous SOC",
    "AI-approved disposition",
    "analyst-approved disposition",
]

COMMANDS: list[tuple[str, str, list[str]]] = [
    (
        "backend_adapter_status",
        "backend adapter verification",
        [sys.executable, "-B", "scripts/verify-ho-det-001-backend-adapter.py"],
    ),
    (
        "ai_triage_contract_status",
        "AI support contract verification",
        [sys.executable, "-B", "scripts/verify-ho-det-001-ai-triage-contract.py"],
    ),
    (
        "controlled_validation_status",
        "controlled validation verification",
        [sys.executable, "-B", "scripts/validate-ho-det-001.py"],
    ),
    (
        "claim_boundary_scan_status",
        "claim-boundary scan",
        [sys.executable, "-B", "scripts/scan-ho-det-001-claim-boundaries.py"],
    ),
    (
        "result_parity_status",
        "result parity verification",
        [sys.executable, "-B", "scripts/verify-ho-det-001-result-parity.py"],
    ),
    (
        "case_packet_check_status",
        "deterministic case packet check",
        [sys.executable, "-B", "scripts/build-ho-det-001-case-packet.py", "--check"],
    ),
    (
        "case_packet_contract_status",
        "case packet contract verification",
        [sys.executable, "-B", "scripts/verify_case_packet_contract.py"],
    ),
]

PROOF_SURFACES = {
    "source": {
        "status": "verified_by_existing_validators",
        "boundary": "public repository source and public test fixtures only; source is not runtime evidence",
    },
    "validation": {
        "status": "controlled_validation_loop_only",
        "boundary": "controlled validation loop over public test fixtures only",
    },
    "case_packet": {
        "status": "deterministic_check_only",
        "boundary": "controlled case packet must match builder output in --check mode",
    },
    "ai_support_contract": {
        "status": "support_only",
        "boundary": "deterministic contract check; no model call and no disposition authority",
    },
    "public_proof_boundary": {
        "status": "blocked",
        "boundary": "CONTROLLED_TEST_ONLY; not runtime-active, signal-observed, or public-safe status",
    },
}

FORBIDDEN_POSITIVE_SUMMARY_PHRASES = [
    "runtime-active public proof pass",
    "signal-observed public proof pass",
    "public-safe runtime proof pass",
    "live splunk proof pass",
    "live wazuh proof pass",
    "cribl-routed proof pass",
    "model execution in ci pass",
    "ollama prompt execution in ci pass",
    "production readiness pass",
    "autonomous soc pass",
    "ai-approved disposition pass",
    "analyst-approved disposition pass",
]


def command_display(command: list[str]) -> str:
    rendered = ["python" if index == 0 else part for index, part in enumerate(command)]
    return " ".join(rendered)


def emit_status(message: str) -> None:
    print(message, file=sys.stderr)


def sanitize_child_output(text: str) -> str:
    sanitized = text.replace(str(ROOT), "<repo-root>")
    sanitized = sanitized.replace(str(ROOT).replace("\\", "/"), "<repo-root>")
    return sanitized


def fail(message: str) -> None:
    print(f"SCOPE={SCOPE}", file=sys.stderr)
    print(f"PROOF_CEILING={PROOF_CEILING}", file=sys.stderr)
    print(f"PUBLIC_SAFE_STATUS={PUBLIC_SAFE_STATUS}", file=sys.stderr)
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run_stage(status_key: str, label: str, command: list[str]) -> dict[str, Any]:
    emit_status(f"[RUN] {label}: {command_display(command)}")
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.stdout.strip():
        emit_status(sanitize_child_output(result.stdout.strip()))
    if result.stderr.strip():
        emit_status(sanitize_child_output(result.stderr.strip()))
    if result.returncode != 0:
        fail(f"{label} failed with exit {result.returncode}: {command_display(command)}")
    return {
        "status_key": status_key,
        "label": label,
        "status": "pass",
        "returncode": result.returncode,
        "command": command_display(command),
    }


def ensure_required_boundaries(summary: dict[str, Any]) -> None:
    if summary.get("ai_decided_disposition") is not False:
        fail("summary ai_decided_disposition must be false")
    if summary.get("recommended_disposition") is not None:
        fail("summary recommended_disposition must be null")
    if summary.get("human_review_required") is not True:
        fail("summary human_review_required must be true")
    if summary.get("public_safe") is not False:
        fail("summary public_safe must be false")
    if summary.get("proof_ceiling") != PROOF_CEILING:
        fail(f"summary proof_ceiling must be {PROOF_CEILING}")
    if summary.get("success_ceiling") != SUCCESS_CEILING:
        fail(f"summary success_ceiling must be {SUCCESS_CEILING}")
    if summary.get("scope") != SCOPE:
        fail(f"summary scope must be {SCOPE}")
    if summary.get("public_test_fixtures_only") is not True:
        fail("summary public_test_fixtures_only must be true")
    if summary.get("private_runtime_evidence_required") is not False:
        fail("summary private_runtime_evidence_required must be false")
    if summary.get("live_signal_required") is not False:
        fail("summary live_signal_required must be false")
    if summary.get("runtime_active_public_proof") is not False:
        fail("summary runtime_active_public_proof must be false")
    if summary.get("signal_observed_public_proof") is not False:
        fail("summary signal_observed_public_proof must be false")
    if summary.get("public_safe_status") != PUBLIC_SAFE_STATUS:
        fail(f"summary public_safe_status must be {PUBLIC_SAFE_STATUS}")

    blocked = {str(item).strip().lower() for item in summary.get("blocked_claims", [])}
    for claim in BLOCKED_CLAIMS:
        if claim.lower() not in blocked:
            fail(f"summary blocked_claims missing required claim: {claim}")

    if SUPPORTED_CLAIM not in summary.get("supported_claims", []):
        fail("summary supported_claims missing exact controlled test fixture claim")

    positive_text = json.dumps(
        {
            "pipeline_status": summary.get("pipeline_status"),
            "supported_claims": summary.get("supported_claims"),
            "proof_surfaces": summary.get("proof_surfaces"),
            "claim_boundary": summary.get("claim_boundary"),
            "proof_ceiling": summary.get("proof_ceiling"),
            "success_ceiling": summary.get("success_ceiling"),
        },
        sort_keys=True,
    ).lower()
    for phrase in FORBIDDEN_POSITIVE_SUMMARY_PHRASES:
        if phrase in positive_text:
            fail(f"summary implies blocked claim outside blocked_claims: {phrase}")


def build_summary(stage_results: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "pipeline_id": PIPELINE_ID,
        "detection_id": DETECTION_ID,
        "pipeline_status": PIPELINE_STATUS_PASS,
        "backend_adapter_status": "pass",
        "ai_triage_contract_status": "pass",
        "controlled_validation_status": "pass",
        "claim_boundary_scan_status": "pass",
        "result_parity_status": "pass",
        "case_packet_check_status": "pass",
        "case_packet_contract_status": "pass",
        "ho_det_001_controlled_test_proof_loop": "pass",
        "scope": SCOPE,
        "public_test_fixtures_only": True,
        "private_runtime_evidence_required": False,
        "live_signal_required": False,
        "runtime_active_public_proof": False,
        "signal_observed_public_proof": False,
        "public_safe_status": PUBLIC_SAFE_STATUS,
        "ai_decided_disposition": False,
        "recommended_disposition": None,
        "human_review_required": True,
        "public_safe": False,
        "supported_claims": SUPPORTED_CLAIMS,
        "blocked_claims": BLOCKED_CLAIMS,
        "command_sequence": [stage["command"] for stage in stage_results],
        "proof_ceiling": PROOF_CEILING,
        "success_ceiling": SUCCESS_CEILING,
        "claim_boundary": CLAIM_BOUNDARY,
        "proof_surfaces": PROOF_SURFACES,
        "no_live_runtime_calls": True,
        "no_model_calls": True,
        "no_network_required": True,
        "no_github_actions_dispatch": True,
        "check_mode_repo_mutation_expected": False,
    }
    ensure_required_boundaries(summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the HO-DET-001 local deterministic case pipeline.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run the pipeline in check-only mode. This mode does not request generated output writes.",
    )
    args = parser.parse_args()
    if not args.check:
        fail("Only --check mode is approved for this local pipeline runner.")

    emit_status("== HO-DET-001 Local Deterministic Case Pipeline ==")
    emit_status(f"PIPELINE_ID={PIPELINE_ID}")
    emit_status(f"SCOPE={SCOPE}")
    stage_results = [run_stage(status_key, label, command) for status_key, label, command in COMMANDS]
    summary = build_summary(stage_results)
    emit_status("== FINAL LOCAL PIPELINE STATUS ==")
    emit_status("HO_DET_001_CONTROLLED_TEST_PROOF_LOOP=pass")
    emit_status(f"SCOPE={summary['scope']}")
    emit_status("PUBLIC_TEST_FIXTURES_ONLY=true")
    emit_status("PRIVATE_RUNTIME_EVIDENCE_REQUIRED=false")
    emit_status("LIVE_SIGNAL_REQUIRED=false")
    emit_status("RUNTIME_ACTIVE_PUBLIC_PROOF=false")
    emit_status("SIGNAL_OBSERVED_PUBLIC_PROOF=false")
    emit_status(f"PUBLIC_SAFE_STATUS={summary['public_safe_status']}")
    emit_status(f"PIPELINE_STATUS={summary['pipeline_status']}")
    emit_status(f"PROOF_CEILING={summary['proof_ceiling']}")
    emit_status(f"SUCCESS_CEILING={summary['success_ceiling']}")
    emit_status("AI_SUPPORT_AUTHORITY=support_only")
    emit_status("HUMAN_REVIEW_REQUIRED=true")
    emit_status("PUBLIC_SAFE=false")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

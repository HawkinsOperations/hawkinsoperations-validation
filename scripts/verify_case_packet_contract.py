#!/usr/bin/env python3
"""Verify the HO-DET-001 case packet contract."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / ".github" / "contracts" / "case-packet.schema.json"
CASE_PACKET = ROOT / "validation" / "successor" / "ho-det-001" / "case-packet.json"
BUILDER = ROOT / "scripts" / "build-ho-det-001-case-packet.py"

PROOF_ORDER = [
    "IDEA",
    "SOURCE_EXISTS",
    "STATIC_VALIDATED",
    "TEST_DEFINED",
    "TEST_VALIDATED",
    "CONTROLLED_TEST_VALIDATED",
    "RUNTIME_ACTIVE",
    "SIGNAL_OBSERVED",
    "EVIDENCE_LINKED",
    "PUBLIC_SAFE",
]
PROOF_CEILING = "CONTROLLED_TEST_VALIDATED"
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
CASE_FACTORY_REQUIRED_LABELS = [
    "autosoc:case",
    "autosoc:sanitized",
    "autosoc:validated",
    "autosoc:needs-human-review",
    "autosoc:blocked-close",
    "proof:controlled-test",
    "publication:not-approved",
    "ai:support-only",
    "det:ho-det-001",
]
PROHIBITED_CASE_FACTORY_LABEL_PARTS = [
    "approved-disposition",
    "ai-approved",
    "ai-decided",
    "autonomous",
    "close-approved",
    "production",
    "public-safe:approved",
    "runtime-active",
    "signal-observed",
]
EXPECTED_CASE_FACTORY_STATE_MACHINE = [
    "DISCOVERED",
    "SANITIZED_PACKET_BUILT",
    "PACKET_VALIDATED",
    "OPTIONAL_SUPPORT_TRIAGED",
    "DETERMINISTIC_RULE_EVALUATED",
    "ISSUE_UPDATE_PREPARED",
    "HUMAN_REVIEW_REQUIRED",
]
PROHIBITED_COMMENT_INTENT_PARTS = [
    "post comment",
    "post to github",
    "submit comment",
    "apply comment",
    "will mutate",
    "may mutate",
    "can mutate",
    "update issue",
    "close issue",
    "close case",
]
PROHIBITED_CLOSE_BASIS_PARTS = [
    "may close",
    "can close",
    "close eligible",
    "closure approved",
    "human review not required",
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing {label}: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def require_keys(value: dict[str, Any], keys: list[str], label: str) -> None:
    missing = [key for key in keys if key not in value]
    if missing:
        fail(f"{label} missing required keys: {', '.join(missing)}")


def get_path(value: dict[str, Any], path: list[str]) -> Any:
    current: Any = value
    for key in path:
        if not isinstance(current, dict) or key not in current:
            fail(f"missing required field: {'.'.join(path)}")
        current = current[key]
    return current


def validate_required_from_schema(schema: dict[str, Any], packet: dict[str, Any]) -> None:
    top_required = schema.get("required")
    if not isinstance(top_required, list):
        fail("schema missing top-level required list")
    require_keys(packet, [str(item) for item in top_required], "case-packet.json")
    event_required = get_path(schema, ["properties", "event", "required"])
    triage_required = get_path(schema, ["properties", "triage_boundary", "required"])
    public_required = get_path(schema, ["properties", "public_claim_boundary", "required"])
    require_keys(packet["event"], [str(item) for item in event_required], "case-packet.json event")
    require_keys(packet["triage_boundary"], [str(item) for item in triage_required], "case-packet.json triage_boundary")
    require_keys(
        packet["public_claim_boundary"],
        [str(item) for item in public_required],
        "case-packet.json public_claim_boundary",
    )


def normalize(value: Any) -> str:
    return str(value).strip().lower()


def verify_boundaries(packet: dict[str, Any]) -> None:
    if packet.get("detection_id") != "HO-DET-001":
        fail("detection_id must be HO-DET-001")
    if packet.get("truth_surface") != "repo truth":
        fail("truth_surface must be repo truth")
    if packet.get("public_safe_status") != "NO":
        fail("top-level public_safe_status must be NO")
    if get_path(packet, ["public_claim_boundary", "public_safe_status"]) != "NO":
        fail("public_claim_boundary.public_safe_status must be NO")
    if get_path(packet, ["triage_boundary", "ai_role"]) != "support_only":
        fail("triage_boundary.ai_role must be support_only")
    if get_path(packet, ["triage_boundary", "ai_may_decide_disposition"]) is not False:
        fail("triage_boundary.ai_may_decide_disposition must be false")
    if get_path(packet, ["triage_boundary", "disposition_authority"]) != "deterministic_verifier_and_human_review":
        fail("triage_boundary.disposition_authority is not the approved authority")

    proof_level = str(packet.get("proof_level"))
    if proof_level not in PROOF_ORDER:
        fail(f"unknown proof_level: {proof_level}")
    if PROOF_ORDER.index(proof_level) > PROOF_ORDER.index(PROOF_CEILING):
        fail(f"proof_level exceeds {PROOF_CEILING}: {proof_level}")

    blocked = {normalize(item) for item in packet.get("blocked_claims", [])}
    public_blocked = {normalize(item) for item in get_path(packet, ["public_claim_boundary", "blocked_claims"])}
    for claim in BLOCKED_CLAIMS:
        if normalize(claim) not in blocked:
            fail(f"blocked_claims missing: {claim}")
        if normalize(claim) not in public_blocked:
            fail(f"public_claim_boundary.blocked_claims missing: {claim}")

    supported = normalize(get_path(packet, ["public_claim_boundary", "supported_claim"]))
    for claim in BLOCKED_CLAIMS:
        if normalize(claim) in supported:
            fail(f"blocked claim used as supported claim: {claim}")


def verify_case_factory(packet: dict[str, Any]) -> None:
    case_factory = get_path(packet, ["case_factory"])
    if not isinstance(case_factory, dict):
        fail("case_factory must be object")
    if case_factory.get("factory_version") != "AUTOSOC_CASE_FACTORY_V0":
        fail("case_factory.factory_version must be AUTOSOC_CASE_FACTORY_V0")
    if case_factory.get("case_state") != "DETERMINISTIC_RULE_EVALUATED":
        fail("case_factory.case_state must be DETERMINISTIC_RULE_EVALUATED")

    issue_plan = get_path(packet, ["case_factory", "github_issue_plan"])
    if not isinstance(issue_plan, dict):
        fail("case_factory.github_issue_plan must be object")
    state_machine = case_factory.get("state_machine")
    if state_machine != EXPECTED_CASE_FACTORY_STATE_MACHINE:
        fail("case_factory.state_machine must match the ordered AUTOSOC_CASE_FACTORY_V0 states")
    if issue_plan.get("mode") != "dry_run_only":
        fail("case_factory.github_issue_plan.mode must be dry_run_only")
    if issue_plan.get("mutation_allowed") is not False:
        fail("case_factory.github_issue_plan.mutation_allowed must be false")
    if issue_plan.get("issue_ref") is not None:
        fail("case_factory.github_issue_plan.issue_ref must be null for dry_run_only v0")
    comment_intent = issue_plan.get("comment_intent")
    if not isinstance(comment_intent, str) or not comment_intent.strip():
        fail("case_factory.github_issue_plan.comment_intent must be non-empty string")
    normalized_comment_intent = normalize(comment_intent)
    if "do not mutate" not in normalized_comment_intent:
        fail("case_factory.github_issue_plan.comment_intent must explicitly block GitHub mutation")
    for blocked in PROHIBITED_COMMENT_INTENT_PARTS:
        if blocked in normalized_comment_intent:
            fail("case_factory.github_issue_plan.comment_intent implies posting or mutation")
    if issue_plan.get("close_action_allowed") is not False:
        fail("case_factory.github_issue_plan.close_action_allowed must be false")

    labels = issue_plan.get("labels_to_add")
    if not isinstance(labels, list):
        fail("case_factory.github_issue_plan.labels_to_add must be list")
    normalized_labels = {normalize(label) for label in labels}
    for label in CASE_FACTORY_REQUIRED_LABELS:
        if normalize(label) not in normalized_labels:
            fail(f"case_factory missing required dry-run issue label: {label}")
    for label in normalized_labels:
        for blocked in PROHIBITED_CASE_FACTORY_LABEL_PARTS:
            if blocked in label:
                fail(f"case_factory label implies blocked authority or proof state: {label}")

    close_rule = get_path(packet, ["case_factory", "deterministic_close_rule"])
    if not isinstance(close_rule, dict):
        fail("case_factory.deterministic_close_rule must be object")
    if close_rule.get("evaluated") is not True:
        fail("case_factory.deterministic_close_rule.evaluated must be true")
    if close_rule.get("close_eligible") is not False:
        fail("case_factory.deterministic_close_rule.close_eligible must be false")
    if close_rule.get("deterministic_close_eligible") is not False:
        fail("case_factory.deterministic_close_rule.deterministic_close_eligible must be false")
    if close_rule.get("result") != "BLOCKED_HUMAN_REVIEW_REQUIRED":
        fail("case_factory.deterministic_close_rule.result must be BLOCKED_HUMAN_REVIEW_REQUIRED")
    basis = close_rule.get("basis")
    if not isinstance(basis, str) or not basis.strip():
        fail("case_factory.deterministic_close_rule.basis must be non-empty string")
    normalized_basis = normalize(basis)
    if "cannot close" not in normalized_basis:
        fail("case_factory.deterministic_close_rule.basis must explicitly deny closure authority")
    for blocked in PROHIBITED_CLOSE_BASIS_PARTS:
        if blocked in normalized_basis:
            fail("case_factory.deterministic_close_rule.basis implies closure authority")
    for key in ("ai_authority_granted", "proof_promotion_allowed", "public_safe_promotion_allowed"):
        if close_rule.get(key) is not False:
            fail(f"case_factory.deterministic_close_rule.{key} must be false")
    blockers = {normalize(item) for item in close_rule.get("blockers", [])}
    for blocker in (
        "human_review_required=true",
        "github_issue_mutation_allowed=false",
        "close_action_allowed=false",
        "deterministic_close_eligible=false",
    ):
        if normalize(blocker) not in blockers:
            fail(f"case_factory close blockers missing: {blocker}")

    ai_support = get_path(packet, ["case_factory", "optional_ai_support"])
    if not isinstance(ai_support, dict):
        fail("case_factory.optional_ai_support must be object")
    if ai_support.get("status") != "NOT_RUN_IN_CASE_PACKET":
        fail("case_factory.optional_ai_support.status must be NOT_RUN_IN_CASE_PACKET")
    if ai_support.get("allowed_role") != "AI_SUPPORT_ONLY":
        fail("case_factory.optional_ai_support.allowed_role must be AI_SUPPORT_ONLY")
    if ai_support.get("ai_decided_disposition") is not False:
        fail("case_factory.optional_ai_support.ai_decided_disposition must be false")
    if ai_support.get("recommended_disposition") is not None:
        fail("case_factory.optional_ai_support.recommended_disposition must be null")


def verify_builder_parity(packet: dict[str, Any]) -> None:
    spec = importlib.util.spec_from_file_location("case_packet_builder", BUILDER)
    if spec is None or spec.loader is None:
        fail(f"unable to load builder: {BUILDER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    generated = module.build_case_packet()
    if packet != generated:
        fail("case-packet.json does not match deterministic builder output")


def verify_builder_check_mode_is_non_mutating() -> None:
    if not CASE_PACKET.exists():
        fail(f"missing case-packet.json before check-mode regression: {CASE_PACKET}")
    before_text = CASE_PACKET.read_text(encoding="utf-8")
    before_mtime = CASE_PACKET.stat().st_mtime_ns
    result = subprocess.run(
        [sys.executable, str(BUILDER), "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        fail(
            "case-packet builder --check failed unexpectedly: "
            f"stdout={result.stdout.strip()} stderr={result.stderr.strip()}"
        )
    if "WRITE_SKIPPED=true" not in result.stdout:
        fail("case-packet builder --check did not report WRITE_SKIPPED=true")
    if "WROTE=" in result.stdout:
        fail("case-packet builder --check reported a write")
    after_text = CASE_PACKET.read_text(encoding="utf-8")
    after_mtime = CASE_PACKET.stat().st_mtime_ns
    if after_text != before_text:
        fail("case-packet builder --check modified case-packet.json contents")
    if after_mtime != before_mtime:
        fail("case-packet builder --check modified case-packet.json mtime")


def main() -> int:
    schema = load_json(SCHEMA, "case-packet.schema.json")
    packet = load_json(CASE_PACKET, "case-packet.json")
    validate_required_from_schema(schema, packet)
    verify_boundaries(packet)
    verify_case_factory(packet)
    verify_builder_parity(packet)
    verify_builder_check_mode_is_non_mutating()
    print("STATUS=pass")
    print("CASE_PACKET_CONTRACT=pass")
    print("CASE_PACKET_CHECK_MODE_NON_MUTATING=pass")
    print(f"CASE_PACKET={CASE_PACKET}")
    print(f"SCHEMA={SCHEMA}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

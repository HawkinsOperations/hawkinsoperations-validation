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
    "TEST_VALIDATED_SYNTHETIC_SCOPE",
    "RUNTIME_ACTIVE",
    "SIGNAL_OBSERVED",
    "EVIDENCE_LINKED",
    "PUBLIC_SAFE",
]
PROOF_CEILING = "TEST_VALIDATED_SYNTHETIC_SCOPE"
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

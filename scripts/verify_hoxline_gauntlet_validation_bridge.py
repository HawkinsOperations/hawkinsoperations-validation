#!/usr/bin/env python3
"""Verify the HO-DET-001 Hoxline Gauntlet validation bridge."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BRIDGE_JSON = ROOT / "validation" / "hoxline" / "ho-det-001-hoxline-gauntlet-validation-bridge-v1.json"
BRIDGE_MD = ROOT / "validation" / "hoxline" / "HO-DET-001_HOXLINE_GAUNTLET_VALIDATION_BRIDGE_V1.md"

EXPECTED_ALLOWED_CLAIM = "HO-DET-001 has Hoxline Gauntlet reviewer-path validation under controlled scope."
REQUIRED_BLOCKED_CLAIMS = {
    "runtime proven",
    "signal observed",
    "production ready",
    "customer deployed",
    "SOCaaS deployed",
    "public-safe runtime proof",
    "AI approved",
    "analyst approved",
    "final authorization",
    "case closure",
}
REQUIRED_FIELDS = {
    "artifact_id",
    "detection_id",
    "bridge_kind",
    "controlled_validation_status",
    "validation_scope",
    "hoxline_source",
    "gauntlet_paths",
    "validation_authority_refs",
    "allowed_supported_claim",
    "blocked_claims",
    "positive_expectations",
    "negative_expectations",
    "telemetry_requirements_declared",
    "missing_evidence",
    "human_review_required",
    "public_safe",
    "public_safe_status",
    "proof_ceiling",
    "proof_ceiling_statement",
    "next_gate",
    "laptop_safe_reproduction_commands",
}
REQUIRED_HOXLINE_PATH_FIELDS = {
    "gauntlet_doc_path",
    "proofcard_doc_path",
    "claim_policy_path",
}
REQUIRED_GAUNTLET_PATH_FIELDS = {
    "input_paths",
    "output_path",
    "markdown_output_path",
    "schema_path",
    "cli_verifier_command",
}
REQUIRED_MISSING_EVIDENCE = {
    "runtime_evidence",
    "signal_observation_evidence",
    "public_safe_authorization",
    "human_review_gate_complete",
}
NEGATIVE_CONTEXT_MARKERS = (
    "blocked",
    "missing",
    "not ",
    "does not",
    "no ",
    "requires",
    "require ",
    "without",
    "only",
)
PROMOTION_TERMS = (
    "runtime proven",
    "signal observed",
    "production ready",
    "customer deployed",
    "socaas deployed",
    "public-safe runtime proof",
)
STALE_WORK_BACKSLASH = "C:" + "\\Raylee\\Work"
STALE_WORK_SLASH = "C:" + "/Raylee/Work"


class VerificationError(Exception):
    """Bridge verification failure."""


def fail(message: str) -> None:
    raise VerificationError(message)


def load_bridge(path: Path = BRIDGE_JSON) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing bridge JSON: {path}")
    except json.JSONDecodeError as exc:
        fail(f"malformed bridge JSON: {exc}")
    if not isinstance(data, dict):
        fail("bridge JSON root must be an object")
    return data


def _require_repo_relative(value: str, label: str) -> None:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        fail(f"{label} must be a repo-relative path")


def _require_non_empty_list(data: dict[str, Any], field: str) -> list[Any]:
    value = data.get(field)
    if not isinstance(value, list) or not value:
        fail(f"{field} must be a non-empty list")
    return value


def validate_bridge(data: dict[str, Any], markdown_text: str | None = None) -> dict[str, Any]:
    missing = sorted(REQUIRED_FIELDS - data.keys())
    if missing:
        fail(f"missing required fields: {', '.join(missing)}")
    if data["artifact_id"] != "HO-DET-001":
        fail("artifact_id mismatch")
    if data.get("bridge_record_id") != "HO-DET-001_HOXLINE_GAUNTLET_VALIDATION_BRIDGE_V1":
        fail("bridge_record_id mismatch")
    if data["detection_id"] != "HO-DET-001":
        fail("detection_id must be HO-DET-001")
    if data["public_safe"] is not False:
        fail("public_safe must be false")
    if data["public_safe_status"] not in {"BLOCKED", "NOT_PUBLIC_SAFE"}:
        fail("public_safe_status must remain blocked")
    if data["human_review_required"] is not True:
        fail("human_review_required must be true")
    if data["proof_ceiling"] != "CONTROLLED_TEST_VALIDATED":
        fail("proof_ceiling must be CONTROLLED_TEST_VALIDATED")
    if not str(data["proof_ceiling_statement"]).strip():
        fail("proof_ceiling_statement is required")
    if data["allowed_supported_claim"] != EXPECTED_ALLOWED_CLAIM:
        fail("allowed supported claim changed or broadened")

    blocked = set(_require_non_empty_list(data, "blocked_claims"))
    missing_blocked = sorted(REQUIRED_BLOCKED_CLAIMS - blocked)
    if missing_blocked:
        fail(f"blocked_claims missing required entries: {', '.join(missing_blocked)}")

    missing_evidence = set(_require_non_empty_list(data, "missing_evidence"))
    missing_required_evidence = sorted(REQUIRED_MISSING_EVIDENCE - missing_evidence)
    if missing_required_evidence:
        fail(f"missing_evidence missing required entries: {', '.join(missing_required_evidence)}")

    hoxline_source = data["hoxline_source"]
    if not isinstance(hoxline_source, dict):
        fail("hoxline_source must be an object")
    if hoxline_source.get("repo") != "HawkinsOperations/aevumguard":
        fail("hoxline_source.repo must be HawkinsOperations/aevumguard")
    for field in REQUIRED_HOXLINE_PATH_FIELDS:
        value = hoxline_source.get(field)
        if not isinstance(value, str) or not value:
            fail(f"hoxline_source.{field} is required")
        _require_repo_relative(value, f"hoxline_source.{field}")

    gauntlet_paths = data["gauntlet_paths"]
    if not isinstance(gauntlet_paths, dict):
        fail("gauntlet_paths must be an object")
    missing_gauntlet_fields = sorted(REQUIRED_GAUNTLET_PATH_FIELDS - gauntlet_paths.keys())
    if missing_gauntlet_fields:
        fail(f"gauntlet_paths missing: {', '.join(missing_gauntlet_fields)}")
    for field in ("output_path", "markdown_output_path", "schema_path"):
        value = gauntlet_paths[field]
        if not isinstance(value, str) or not value:
            fail(f"gauntlet_paths.{field} is required")
        _require_repo_relative(value, f"gauntlet_paths.{field}")
    for index, value in enumerate(gauntlet_paths["input_paths"]):
        if not isinstance(value, str) or not value:
            fail("gauntlet_paths.input_paths entries must be non-empty strings")
        _require_repo_relative(value, f"gauntlet_paths.input_paths[{index}]")
    if "gauntlet verify" not in gauntlet_paths["cli_verifier_command"]:
        fail("cli_verifier_command must run hoxline gauntlet verify")

    positive_text = "\n".join(
        [str(data.get("allowed_supported_claim", ""))]
        + [str(item) for item in data.get("positive_expectations", [])]
    )
    for term in PROMOTION_TERMS:
        if term in positive_text.lower():
            fail(f"promotion term appears in positive/allowed context: {term}")

    combined = json.dumps(data, sort_keys=True)
    if re.search(r"(?i)C:[\\/]+Raylee[\\/]+Work\b", combined):
        fail("stale C:\\Raylee\\Work path found")

    if markdown_text is not None:
        if STALE_WORK_BACKSLASH in markdown_text or STALE_WORK_SLASH in markdown_text:
            fail("stale forbidden Raylee Work path found in markdown")
        _validate_markdown_boundaries(markdown_text)

    return {
        "artifact_id": data["artifact_id"],
        "detection_id": data["detection_id"],
        "proof_ceiling": data["proof_ceiling"],
        "public_safe": data["public_safe"],
        "human_review_required": data["human_review_required"],
        "blocked_claims_verified": sorted(blocked),
    }


def _validate_markdown_boundaries(text: str) -> None:
    current_section = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            current_section = line[3:].strip().lower()
            continue
        lower = line.lower()
        for term in PROMOTION_TERMS:
            if term in lower and current_section not in {"blocked claims", "missing evidence", "proof ceiling"}:
                if not any(marker in lower for marker in NEGATIVE_CONTEXT_MARKERS):
                    fail(f"promotion term outside negative boundary context: {term}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify HO-DET-001 Hoxline Gauntlet validation bridge.")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()

    try:
        markdown_text = BRIDGE_MD.read_text(encoding="utf-8")
        result = validate_bridge(load_bridge(), markdown_text)
    except VerificationError as exc:
        if args.format == "json":
            print(json.dumps({"status": "fail", "error": str(exc)}, indent=2))
        else:
            print(f"HOXLINE_GAUNTLET_VALIDATION_BRIDGE=fail: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps({"status": "pass", **result}, indent=2))
    else:
        print("HOXLINE_GAUNTLET_VALIDATION_BRIDGE=pass")
        print(f"ARTIFACT_ID={result['artifact_id']}")
        print(f"PROOF_CEILING={result['proof_ceiling']}")
        print("PUBLIC_SAFE=false")
        print("HUMAN_REVIEW_REQUIRED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

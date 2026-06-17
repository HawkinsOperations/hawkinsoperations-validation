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

EXPECTED_ALLOWED_CLAIM = "HO-DET-001 has Hoxline Gauntlet v1 reviewer-path validation under controlled scope."
EXPECTED_MANIFEST = "examples/gauntlet/ho-det-001-gauntlet-v1-source-manifest.json"
EXPECTED_V1_RUN = "examples/gauntlet/ho-det-001-gauntlet-run-v1.json"
EXPECTED_V1_SCHEMA = "schemas/gauntlet-run-v1.schema.json"
EXPECTED_V0_RUN = "examples/gauntlet/ho-det-001-full-loop-run-v0.json"
EXPECTED_V0_SCHEMA = "schemas/gauntlet-full-loop-run-v0.schema.json"
REQUIRED_V1_PATHS = {
    "gauntlet_run": EXPECTED_V1_RUN,
    "gauntlet_schema": EXPECTED_V1_SCHEMA,
    "overclaim_fixture": "examples/gauntlet/ho-det-001-gauntlet-run-v1-overclaim.json",
    "evidence_graph": "examples/gauntlet/ho-det-001-evidence-graph-v1.json",
    "proofcard": "examples/gauntlet/ho-det-001-proofcard-v1.json",
    "claim_authority_decision": "examples/gauntlet/ho-det-001-claim-decision-v1.json",
    "gauntlet_doc": "docs/gauntlet/HOXLINE_GAUNTLET_V1.md",
    "proofcard_doc": "docs/proofcards/PROOFCARD_V1.md",
    "claim_authority_doc": "docs/claim-authority/CLAIM_AUTHORITY_V1.md",
    "evidence_graph_schema": "schemas/evidence-graph-v1.schema.json",
    "proofcard_schema": "schemas/proofcard-v1.schema.json",
    "claim_authority_decision_schema": "schemas/claim-authority-decision-v1.schema.json",
}
REQUIRED_HOXLINE_FILES = set(REQUIRED_V1_PATHS.values()) | {
    EXPECTED_MANIFEST,
    EXPECTED_V0_RUN,
    EXPECTED_V0_SCHEMA,
}
REQUIRED_REVIEWER_COMMANDS = {
    "python -B -m hoxline gauntlet verify --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json --schema schemas/gauntlet-run-v1.schema.json",
    "python -B -m hoxline gauntlet summarize --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json",
    "python -B -m hoxline claim-authority decide --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json",
    "python -B -m hoxline proofcard render --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json",
    "python -B -m hoxline gauntlet verify --input examples/gauntlet/ho-det-001-gauntlet-run-v1-overclaim.json --schema schemas/gauntlet-run-v1.schema.json",
    "python -B -m hoxline gauntlet verify --input examples/gauntlet/ho-det-001-full-loop-run-v0.json --schema schemas/gauntlet-full-loop-run-v0.schema.json",
}
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
REQUIRED_MISSING_EVIDENCE = {
    "analyst_review_record",
    "case_closure_record",
    "customer_deployment_evidence",
    "deployment_evidence",
    "final_authorization_record",
    "human_review_gate_complete",
    "public_safe_authorization",
    "runtime_evidence",
    "service_deployment_evidence",
    "signal_observation_evidence",
}
REQUIRED_FIELDS = {
    "artifact_id",
    "bridge_record_id",
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
    "cross_repo_consistency",
    "next_gate",
    "laptop_safe_reproduction_commands",
}
NEGATIVE_CONTEXT_MARKERS = (
    "blocked",
    "missing",
    "not ",
    "does not",
    "no ",
    "requires",
    "required",
    "without",
    "only",
    "compatibility",
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


def validate_bridge(
    data: dict[str, Any],
    markdown_text: str | None = None,
    hoxline_root: Path | None = None,
) -> dict[str, Any]:
    missing = sorted(REQUIRED_FIELDS - data.keys())
    if missing:
        fail(f"missing required fields: {', '.join(missing)}")
    if data["artifact_id"] != "HO-DET-001":
        fail("artifact_id mismatch")
    if data["bridge_record_id"] != "HO-DET-001_HOXLINE_GAUNTLET_VALIDATION_BRIDGE_V1":
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
    if data["next_gate"] != "human_review_gate":
        fail("next_gate must be human_review_gate")

    blocked = set(_require_non_empty_list(data, "blocked_claims"))
    missing_blocked = sorted(REQUIRED_BLOCKED_CLAIMS - blocked)
    if missing_blocked:
        fail(f"blocked_claims missing required entries: {', '.join(missing_blocked)}")

    missing_evidence = set(_require_non_empty_list(data, "missing_evidence"))
    missing_required_evidence = sorted(REQUIRED_MISSING_EVIDENCE - missing_evidence)
    if missing_required_evidence:
        fail(f"missing_evidence missing required entries: {', '.join(missing_required_evidence)}")

    _validate_hoxline_source(data["hoxline_source"])
    _validate_gauntlet_paths(data["gauntlet_paths"])
    _validate_cross_repo(data["cross_repo_consistency"])
    _validate_reviewer_commands(data)
    _validate_positive_context(data)
    _validate_no_forbidden_paths(data)

    if hoxline_root is not None:
        _validate_hoxline_files_exist(hoxline_root)

    if markdown_text is not None:
        if STALE_WORK_BACKSLASH in markdown_text or STALE_WORK_SLASH in markdown_text:
            fail("stale forbidden Raylee Work path found in markdown")
        _validate_markdown_boundaries(markdown_text)
        for required in set(REQUIRED_V1_PATHS.values()) | {EXPECTED_MANIFEST, EXPECTED_V0_RUN, EXPECTED_V0_SCHEMA}:
            if required not in markdown_text:
                fail(f"markdown missing Hoxline source route: {required}")

    return {
        "artifact_id": data["artifact_id"],
        "detection_id": data["detection_id"],
        "proof_ceiling": data["proof_ceiling"],
        "public_safe": data["public_safe"],
        "human_review_required": data["human_review_required"],
        "source_manifest_path": data["hoxline_source"]["source_manifest_path"],
        "primary_v1_run_path": data["gauntlet_paths"]["primary_v1_run_path"],
        "primary_v1_schema_path": data["gauntlet_paths"]["primary_v1_schema_path"],
        "blocked_claims_verified": sorted(blocked),
    }


def _validate_hoxline_source(source: Any) -> None:
    if not isinstance(source, dict):
        fail("hoxline_source must be an object")
    if source.get("repo") != "HawkinsOperations/aevumguard":
        fail("hoxline_source.repo must be HawkinsOperations/aevumguard")
    if source.get("source_manifest_path") != EXPECTED_MANIFEST:
        fail("source manifest path must be primary")
    primary = source.get("primary_v1_paths")
    if not isinstance(primary, dict):
        fail("primary_v1_paths must be an object")
    for field, expected in REQUIRED_V1_PATHS.items():
        if primary.get(field) != expected:
            fail(f"primary_v1_paths.{field} must be {expected}")
        _require_repo_relative(expected, f"primary_v1_paths.{field}")
    compatibility = source.get("compatibility_v0_paths")
    if not isinstance(compatibility, dict):
        fail("compatibility_v0_paths must be an object")
    if compatibility.get("compatibility_role") != "compatibility-only; not primary source authority":
        fail("v0 paths must be compatibility-only")
    if compatibility.get("gauntlet_run") != EXPECTED_V0_RUN:
        fail("v0 compatibility run path missing")
    if compatibility.get("gauntlet_schema") != EXPECTED_V0_SCHEMA:
        fail("v0 compatibility schema path missing")
    website = source.get("website_boundary")
    if not isinstance(website, dict) or website.get("website_is_authority") is not False:
        fail("website is treated as authority")


def _validate_gauntlet_paths(paths: Any) -> None:
    if not isinstance(paths, dict):
        fail("gauntlet_paths must be an object")
    expected = {
        "source_manifest_path": EXPECTED_MANIFEST,
        "primary_v1_run_path": EXPECTED_V1_RUN,
        "primary_v1_schema_path": EXPECTED_V1_SCHEMA,
        "primary_v1_overclaim_path": "examples/gauntlet/ho-det-001-gauntlet-run-v1-overclaim.json",
        "primary_v1_evidence_graph_path": "examples/gauntlet/ho-det-001-evidence-graph-v1.json",
        "primary_v1_proofcard_path": "examples/gauntlet/ho-det-001-proofcard-v1.json",
        "primary_v1_claim_decision_path": "examples/gauntlet/ho-det-001-claim-decision-v1.json",
    }
    for field, value in expected.items():
        if paths.get(field) != value:
            fail(f"gauntlet_paths.{field} must be {value}")
    if paths.get("hoxline_primary_v1_run_path") != "HawkinsOperations/aevumguard/" + EXPECTED_V1_RUN:
        fail("cross-repo Hoxline v1 run path is stale")
    compatibility = paths.get("v0_compatibility_check")
    if not isinstance(compatibility, dict):
        fail("v0_compatibility_check must be an object")
    if compatibility.get("compatibility_only") is not True or compatibility.get("not_primary_source") is not True:
        fail("v0 compatibility paths must not be primary source")
    if compatibility.get("run_path") != EXPECTED_V0_RUN or compatibility.get("schema_path") != EXPECTED_V0_SCHEMA:
        fail("v0 compatibility check paths are incomplete")


def _validate_cross_repo(cross: Any) -> None:
    if not isinstance(cross, dict):
        fail("cross_repo_consistency must be an object")
    expected_pairs = {
        "artifact_id": "HO-DET-001",
        "detection_id": "HO-DET-001",
        "hoxline_primary_v1_run_path": "HawkinsOperations/aevumguard/" + EXPECTED_V1_RUN,
        "hoxline_primary_v1_schema_path": EXPECTED_V1_SCHEMA,
        "source_manifest_path": EXPECTED_MANIFEST,
        "proof_ceiling": "CONTROLLED_TEST_VALIDATED",
        "validation_allowed_claim": EXPECTED_ALLOWED_CLAIM,
        "public_safe_status": "BLOCKED",
        "next_gate": "human_review_gate",
        "website_boundary": "rendering-only",
    }
    for field, expected in expected_pairs.items():
        if cross.get(field) != expected:
            fail(f"cross_repo_consistency.{field} must be {expected}")
    if cross.get("public_safe") is not False or cross.get("human_review_required") is not True:
        fail("cross repo public_safe/human_review boundary changed")
    if set(cross.get("blocked_claims", [])) != REQUIRED_BLOCKED_CLAIMS:
        fail("cross repo blocked claims mismatch")
    if set(cross.get("missing_evidence", [])) != REQUIRED_MISSING_EVIDENCE:
        fail("cross repo missing evidence mismatch")


def _validate_reviewer_commands(data: dict[str, Any]) -> None:
    commands = set(_require_non_empty_list(data, "laptop_safe_reproduction_commands"))
    missing = sorted(REQUIRED_REVIEWER_COMMANDS - commands)
    if missing:
        fail(f"reviewer commands missing required entries: {', '.join(missing)}")


def _validate_positive_context(data: dict[str, Any]) -> None:
    positive_text = "\n".join(
        [str(data.get("allowed_supported_claim", ""))]
        + [str(item) for item in data.get("positive_expectations", [])]
    )
    for term in PROMOTION_TERMS:
        if term in positive_text.lower():
            fail(f"promotion term appears in positive/allowed context: {term}")


def _validate_no_forbidden_paths(data: dict[str, Any]) -> None:
    combined = json.dumps(data, sort_keys=True)
    if re.search(r"(?i)C:[\\/]+Raylee[\\/]+Work\b", combined):
        fail("stale forbidden Raylee Work path found")
    if re.search(r"(?i)\b[A-Z]:[\\/]", combined):
        fail("absolute local path found")
    if re.search(r"(?i)\b(secret|token|api[_-]?key|password|authorization|cookie)\s*[:=]\s*\S+", combined):
        fail("secret-like material found")


def _validate_hoxline_files_exist(hoxline_root: Path) -> None:
    root = hoxline_root.resolve()
    for rel_path in sorted(REQUIRED_HOXLINE_FILES):
        full_path = (root / rel_path).resolve()
        try:
            full_path.relative_to(root)
        except ValueError:
            fail(f"Hoxline path escapes root: {rel_path}")
        if not full_path.exists():
            fail(f"Hoxline referenced file missing: {rel_path}")


def _validate_markdown_boundaries(text: str) -> None:
    current_section = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            current_section = line[3:].strip().lower()
            continue
        lower = line.lower()
        if "website" in lower and "authority" in lower and "not" not in lower and "rendering-only" not in lower:
            fail("website is treated as authority in markdown")
        for term in PROMOTION_TERMS:
            if term in lower and current_section not in {"blocked claims", "missing evidence", "proof ceiling"}:
                if not any(marker in lower for marker in NEGATIVE_CONTEXT_MARKERS):
                    fail(f"promotion term outside negative boundary context: {term}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify HO-DET-001 Hoxline Gauntlet validation bridge.")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--hoxline-root", type=Path, help="optional local Hoxline checkout root for source route existence checks")
    args = parser.parse_args()

    try:
        markdown_text = BRIDGE_MD.read_text(encoding="utf-8")
        result = validate_bridge(load_bridge(), markdown_text, args.hoxline_root)
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

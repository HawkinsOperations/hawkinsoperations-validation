#!/usr/bin/env python3
"""Verify sanitized AutoSOC Runner evidence manifests."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from validation_lib import ContractFailure, strict_json_object


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    ROOT
    / "validation"
    / "successor"
    / "ho-det-001"
    / "autosoc-runner-001-manifest.sample.json"
)

REQUIRED_FIELDS = [
    "run_id",
    "detection_id",
    "proof_ceiling",
    "local_runner_completed",
    "ssh_preflight_completed",
    "remote_model_call_completed",
    "selected_model",
    "verifier_status",
    "hash_verification_status",
    "supported_private_claim",
    "public_safe_status",
    "repo_truth_updated",
    "runtime_truth_status",
    "signal_truth_status",
    "evidence_truth_status",
    "public_proof_truth_status",
    "blocked_claims",
    "next_promotion_gate",
    "artifact_hashes",
]

REQUIRED_BLOCKED_CLAIMS = [
    "runtime-active public proof",
    "signal-observed",
    "evidence-linked public proof",
    "public-safe",
    "production AutoSOC",
    "autonomous SOC",
    "AI-approved disposition",
    "analyst-approved disposition",
    "HO-GPU-01 runtime-active public proof",
    "fleet-wide",
    "Cribl-routed",
    "Wazuh-routed",
    "AWS-live",
]

FORBIDDEN_FIELD_NAMES = {
    "raw_output",
    "raw_prompt",
    "command_output",
    "hostname",
    "username",
    "ip_address",
    "local_path",
    "absolute_path",
    "windows_path",
    "lan_ip",
    "secret",
    "token",
    "key",
    "screenshot",
    "csv_filename",
}

FORBIDDEN_VALUE_PATTERNS = [
    re.compile(r"C:\\Users\\", re.IGNORECASE),
    re.compile(r"C:\\Raylee\\", re.IGNORECASE),
    re.compile(r"\b192\.168\."),
    re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b172\.(1[6-9]|20)\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b(private opportunity|target employer|hiring contact|recruiter|interview process)\b", re.IGNORECASE),
]

AFFIRMATIVE_BLOCKED_PATTERNS = [
    re.compile(r"\bruntime-active public proof\b", re.IGNORECASE),
    re.compile(r"\bpublic-safe\b", re.IGNORECASE),
    re.compile(r"\bproduction AutoSOC\b", re.IGNORECASE),
    re.compile(r"\bautonomous SOC\b", re.IGNORECASE),
    re.compile(r"\bAI-approved disposition\b", re.IGNORECASE),
    re.compile(r"\banalyst-approved disposition\b", re.IGNORECASE),
]

SAFE_ARTIFACT_CLASSIFICATIONS = {
    "SANITIZED_INPUT_HASH",
    "SANITIZED_OUTPUT_HASH",
    "PRIVATE_RECEIPT_HASH",
    "PRIVATE_RAW_OUTPUT_HASH",
    "VERIFIER_HASH",
    "HASH_MANIFEST_HASH",
}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        fail(f"manifest not found: {path}")
    try:
        return strict_json_object(path.read_text(encoding="utf-8"), "manifest")
    except ContractFailure as exc:
        fail(str(exc))


def normalize(value: Any) -> str:
    return str(value).strip().lower()


def walk_json(value: Any, path: str = "$") -> list[tuple[str, Any]]:
    items: list[tuple[str, Any]] = [(path, value)]
    if isinstance(value, dict):
        for field, child in value.items():
            items.extend(walk_json(child, f"{path}.{field}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            items.extend(walk_json(child, f"{path}[{index}]"))
    return items


def verify_required_fields(manifest: dict[str, Any]) -> None:
    extra = sorted(set(manifest) - set(REQUIRED_FIELDS))
    if extra:
        fail(f"unexpected top-level fields: {', '.join(extra)}")
    missing = [field for field in REQUIRED_FIELDS if field not in manifest]
    if missing:
        fail(f"missing required fields: {', '.join(missing)}")


def verify_fixed_values(manifest: dict[str, Any]) -> None:
    expected = {
        "run_id": "HO-DET-001-AUTOSOC-RUNNER-001",
        "detection_id": "HO-DET-001",
        "proof_ceiling": "CONTROLLED_TEST_VALIDATED",
        "verifier_status": "PASS",
        "hash_verification_status": "PASS",
        "public_safe_status": "NOT_PUBLIC_SAFE",
        "runtime_truth_status": "PRIVATE_REMOTE_PREFLIGHT_AND_MODEL_CALL_EVIDENCE_EXISTS",
        "signal_truth_status": "NOT_SIGNAL_OBSERVED",
        "evidence_truth_status": "PRIVATE_EVIDENCE_STAGED_AND_HASHED",
        "public_proof_truth_status": "NOT_PUBLIC_SAFE",
    }
    for field, expected_value in expected.items():
        if manifest.get(field) != expected_value:
            fail(f"{field} must be {expected_value}")
    for field in ["local_runner_completed", "ssh_preflight_completed", "remote_model_call_completed"]:
        if manifest.get(field) is not True:
            fail(f"{field} must be true")
    if manifest.get("repo_truth_updated") is not False:
        fail("repo_truth_updated must be false")


def verify_blocked_claims(manifest: dict[str, Any]) -> None:
    blocked = manifest.get("blocked_claims")
    if not isinstance(blocked, list) or not all(isinstance(item, str) for item in blocked):
        fail("blocked_claims must be a string array")
    normalized = {normalize(item) for item in blocked}
    for claim in REQUIRED_BLOCKED_CLAIMS:
        if normalize(claim) not in normalized:
            fail(f"blocked_claims missing: {claim}")


def verify_supported_claim(manifest: dict[str, Any]) -> None:
    claim = manifest.get("supported_private_claim")
    if not isinstance(claim, str) or not claim.strip():
        fail("supported_private_claim must be a non-empty string")
    for pattern in AFFIRMATIVE_BLOCKED_PATTERNS:
        if pattern.search(claim):
            fail(f"supported_private_claim contains blocked wording: {pattern.pattern}")
    required_phrase = "deterministic verification preserved AI/disposition authority as blocked"
    if required_phrase not in claim:
        fail("supported_private_claim must preserve AI/disposition authority as blocked")


def verify_artifact_hashes(manifest: dict[str, Any]) -> None:
    artifacts = manifest.get("artifact_hashes")
    if not isinstance(artifacts, list) or not artifacts:
        fail("artifact_hashes must be a non-empty array")
    seen_labels: set[str] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            fail(f"artifact_hashes[{index}] must be an object")
        allowed = {"path_label", "sha256", "classification"}
        extra = sorted(set(artifact) - allowed)
        if extra:
            fail(f"artifact_hashes[{index}] has unexpected fields: {', '.join(extra)}")
        missing = sorted(allowed - set(artifact))
        if missing:
            fail(f"artifact_hashes[{index}] missing fields: {', '.join(missing)}")
        label = artifact["path_label"]
        digest = artifact["sha256"]
        classification = artifact["classification"]
        if not isinstance(label, str) or not re.fullmatch(r"[a-z0-9_]+", label):
            fail(f"artifact_hashes[{index}].path_label must be sanitized")
        if label in seen_labels:
            fail(f"duplicate artifact path_label: {label}")
        seen_labels.add(label)
        if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            fail(f"artifact_hashes[{index}].sha256 must be a SHA256 digest")
        if classification not in SAFE_ARTIFACT_CLASSIFICATIONS:
            fail(f"artifact_hashes[{index}].classification is not approved: {classification}")


def verify_no_forbidden_fields_or_values(manifest: dict[str, Any]) -> None:
    for path, value in walk_json(manifest):
        field = path.rsplit(".", 1)[-1].split("[", 1)[0]
        if field in FORBIDDEN_FIELD_NAMES:
            fail(f"forbidden field name: {path}")
        if isinstance(value, str):
            for pattern in FORBIDDEN_VALUE_PATTERNS:
                if pattern.search(value):
                    fail(f"forbidden private value pattern at {path}: {pattern.pattern}")


def main(argv: list[str]) -> int:
    manifest_path = Path(argv[1]) if len(argv) > 1 else DEFAULT_MANIFEST
    manifest = load_json(manifest_path)
    verify_required_fields(manifest)
    verify_fixed_values(manifest)
    verify_blocked_claims(manifest)
    verify_supported_claim(manifest)
    verify_artifact_hashes(manifest)
    verify_no_forbidden_fields_or_values(manifest)
    print("STATUS=pass")
    print("AUTOSOC_RUNNER_EVIDENCE_MANIFEST_CONTRACT=pass")
    print(f"MANIFEST={manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

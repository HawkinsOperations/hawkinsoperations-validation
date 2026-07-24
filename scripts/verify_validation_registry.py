#!/usr/bin/env python3
"""Fail-closed validation registry contract verifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import unicodedata
from datetime import date, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import unquote

import yaml


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "validation" / "VALIDATION_REGISTRY.yml"

ALLOWED_PROOF_CEILINGS = {
    "CONTROLLED_TEST_VALIDATED",
    "VALIDATION_CONTRACT_ENFORCED",
}
ALLOWED_KINDS = {
    "baseline_contract",
    "controlled_validation",
    "visibility_contract",
}
FALSEY_STATUSES = {
    False,
    None,
    "",
    "false",
    "no",
    "0",
    "off",
    "blocked",
    "none",
    "not_proven",
    "not_claimed",
    "not_runtime_active",
    "not_signal_observed",
}
REQUIRED_FIELDS = {
    "detection_id",
    "validation_owner",
    "source_owner",
    "source_reference",
    "fixture_version",
    "expected_result",
    "actual_result",
    "report_identity",
    "parity_identity",
    "human_review_required",
    "ai_disposition_authority",
    "validation_kind",
    "validation_package_path",
    "fixture_file",
    "report_json",
    "report_markdown",
    "validator_script",
    "parity_script",
    "claim_boundary_script",
    "expected_fixture_count",
    "expected_positive_count",
    "expected_negative_count",
    "proof_ceiling",
    "public_safe_status",
    "runtime_status",
    "signal_status",
    "source_dependency_required",
    "ci_source_dependency_mode",
    "notes",
}
BRIDGE_REQUIRED_FIELDS = {
    "artifact_id",
    "bridge_record_id",
    "detection_id",
    "bridge_kind",
    "bridge_record_path",
    "bridge_markdown_path",
    "validator_script",
    "proof_ceiling",
    "public_safe_status",
    "human_review_required",
    "ai_disposition_authority",
    "notes",
}
CONTROLLED_REQUIRED_PATHS = {
    "validation_package_path",
    "fixture_file",
    "report_json",
    "report_markdown",
    "validator_script",
    "parity_script",
    "claim_boundary_script",
}
BASELINE_REQUIRED_PATHS = {
    "validation_package_path",
    "fixture_file",
    "report_json",
    "report_markdown",
    "validator_script",
}
VISIBILITY_REQUIRED_PATHS = {
    "validation_package_path",
    "fixture_file",
    "validator_script",
    "parity_script",
}
REGISTRY_FIELDS = {
    "schema_version",
    "owner_repo",
    "truth_surface",
    "registry_status",
    "human_review_required",
    "ai_disposition_authority",
    "source_authority_manifest",
    "bridge_records",
    "packages",
}
CANONICAL_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
AUTHORITY_PROMOTION_KEYS = {
    "aiauthority",
    "aiapproval",
    "aiapproved",
    "aiapproveddisposition",
    "aidispositionauthority",
    "analystapproval",
    "analystapproved",
    "analystapproveddisposition",
    "caseclosure",
    "customerdeployment",
    "finalauthorization",
    "production",
    "productionready",
    "publicsafe",
    "publicsaferuntime",
    "runtimeactive",
    "signalobserved",
    "socaasdeployment",
}
BLOCKED_SCALARS = {
    False,
    None,
    "",
    "blocked",
    "false",
    "no",
    "none",
    "not_claimed",
    "not_proven",
    "not_public_safe",
    "not_runtime_active",
    "off",
    "0",
}
AFFIRMATIVE_AUTHORITY_CLAIM_RE = re.compile(
    r"(?:"
    r"\b(?:customer|socaas)\b.{0,48}\bdeploy(?:ed|ment|ing)?\b"
    r"|\bdeploy(?:ed|ment|ing)?\b.{0,48}\b(?:customer|socaas)\b"
    r"|\bproduction\b.{0,32}\b(?:active|confirmed|deployed|live|ready)\b"
    r"|\b(?:ai|analyst)\b.{0,40}\b(?:approval|authority|disposition)\b.{0,24}\b(?:approved|enabled|granted)\b"
    r"|\b(?:ai|analyst)\b.{0,40}\b(?:approved|authori[sz]ed)\b.{0,24}\b(?:case|decision|disposition)\b"
    r"|\bfinal\s+authori[sz]ation\b.{0,32}\b(?:approved|complete|granted|received)\b"
    r"|\bcase\s+closure\b.{0,32}\b(?:approved|complete|granted|received)\b"
    r"|\bcase\b.{0,16}\b(?:is|was)?\s*closed\b"
    r"|\bpublic[\s_-]*safe\b.{0,32}\b(?:approved|confirmed|established|release|runtime\s+proof)\b"
    r"|\bruntime\b.{0,24}\b(?:active|live)\b"
    r"|\bsignal\b.{0,24}\b(?:active|observed)\b"
    r")",
    re.IGNORECASE,
)
NEGATED_AUTHORITY_CONTEXT_RE = re.compile(
    r"\b(?:blocked|denied|false|future|not|never|no|pending|prohibited|"
    r"reject(?:ed|s)?|requires?\s+separate|remain(?:s)?\s+(?:a\s+)?separate|unsupported|without)\b",
    re.IGNORECASE,
)
AUTHORITY_STRONG_CLAUSE_SPLIT_RE = re.compile(
    r"[;:/\r\n—–]+|\b(?:but|however|although|yet|while|whereas)\b|(?<=[.!?])\s+",
    re.IGNORECASE,
)
NEGATIVE_LIST_INTRO_RE = re.compile(
    r"\b(?:does|do|did|must|is|are|was|were|can|cannot|could|should|will|would)\s+not\s+"
    r"(?:prove|establish|claim|promote|authorize|assert)\b"
    r"|\b(?:is|are|was|were)\s+not\b|\bwithout\s+claiming\b",
    re.IGNORECASE,
)
AFFIRMATIVE_STATE_AFTER_NEGATIVE_LIST_RE = re.compile(
    r"(?:"
    r"\b(?:customer|socaas)\b.{0,32}\b(?:deployment\s+)?(?:is|was)\s+"
    r"(?:active|confirmed|deployed|live|ready)\b"
    r"|\b(?:customer|socaas)\b.{0,32}\b(?:is|was)\s+deployed\b"
    r"|\bproduction\b.{0,24}\b(?:is|was)\s+(?:active|live|ready)\b"
    r"|\bruntime\b.{0,16}\b(?:is|was)\s+active\b"
    r"|\bsignal\b.{0,16}\b(?:is|was)\s+observed\b"
    r"|\bpublic[\s_-]*safe\b.{0,24}\b(?:is|was)\s+"
    r"(?:approved|confirmed|established|ready|released)\b"
    r"|\b(?:ai|analyst)\b.{0,32}\b(?:(?:is|was)\s+approved|approval\s+(?:is\s+)?granted|authority\s+(?:is\s+)?enabled)\b"
    r"|\bfinal\s+authori[sz]ation\b.{0,16}\b(?:is|was)?\s*(?:approved|granted|received)\b"
    r"|\bcase\s+closure\b.{0,16}\b(?:is|was)?\s*(?:approved|complete|granted|received)\b"
    r"|\bcase\b.{0,16}\b(?:is|was)\s+closed\b"
    r")",
    re.IGNORECASE,
)
NEGATIVE_LIST_SUFFIX_RE = re.compile(
    r"\bclaims?\s+(?:remain|remains|are|is)\s+(?:blocked|unsupported|not\s+approved)\.?$",
    re.IGNORECASE,
)


def _normalize_authority_security_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).translate(
        {ord("\t"): " ", ord("\n"): " ", ord("\r"): " "}
    )
    return "".join(
        character
        for character in normalized
        if not unicodedata.category(character).startswith(("C", "M"))
    )


def _contains_unnegated_affirmative_state(value: str) -> bool:
    return any(
        not NEGATED_AUTHORITY_CONTEXT_RE.search(value[:match.start()])
        for match in AFFIRMATIVE_STATE_AFTER_NEGATIVE_LIST_RE.finditer(value)
    )


REPORT_ALLOWED_FIELDS = {
    "actual_result",
    "ai_approved",
    "ai_approved_disposition",
    "ai_disposition_authority",
    "analyst_approved",
    "analyst_approved_disposition",
    "autonomous_soc",
    "aws_live_status",
    "blocked_claims",
    "claim_ceiling",
    "claims_not_supported",
    "cribl_routed",
    "cribl_routed_proof",
    "current_scope",
    "detection_id",
    "exact_claim_supported",
    "expected_result",
    "executed_at",
    "false_positive_negative_cases",
    "false_positive_negative_count",
    "fixture_count",
    "fixture_results",
    "fixture_version",
    "fleet_wide",
    "future_gated_phases",
    "human_review_required",
    "jsonpath_file",
    "live_idp_proof",
    "live_splunk",
    "matched_positive_count",
    "missed_positive_cases",
    "missed_positive_count",
    "negative",
    "negative_cases",
    "negative_count",
    "not_claimed_here",
    "positive",
    "positive_cases",
    "positive_count",
    "privacy_status",
    "production_ready",
    "proof_ceiling",
    "proof_level_after",
    "proof_level_before",
    "proof_promotion",
    "report_identity",
    "parity_identity",
    "public_safe_runtime",
    "public_safe_status",
    "runtime_active",
    "rule_id",
    "rule_name",
    "security_onion_observed",
    "security_onion_observed_proof",
    "signal_observed",
    "source_file",
    "source_owner",
    "source_reference",
    "splunk_fired",
    "splunk_source_file",
    "status",
    "supported_claim",
    "total_cases",
    "totals",
    "trust_boundary",
    "validation_owner",
    "validation_cases_file",
    "validation_scope",
    "wazuh_routed",
    "wazuh_routed_proof",
    "website_public_surface_promotion",
}
RESULT_ALLOWED_FIELDS = {
    "behavior",
    "description",
    "expected",
    "expected_result",
    "id",
    "matched",
    "pass",
    "reason",
    "telemetry_source",
}
FIXTURE_ALLOWED_FIELDS = {
    "blocked_claims",
    "case_scope",
    "cases",
    "detection_id",
    "negatives",
    "positives",
    "proof_ceiling",
    "public_safe_status",
    "runtime_active",
    "scope",
    "signal_observed",
    "source_reference",
    "source_scope",
    "validation_scope",
}
FIXTURE_CASE_ALLOWED_FIELDS = {
    "CommandLine",
    "Image",
    "behavior",
    "boundary_notes",
    "contract",
    "description",
    "event",
    "expected_match",
    "expected_result",
    "id",
    "reason",
    "telemetry_source",
}
UNIQUE_OWNERSHIP_FIELDS = {
    "validation_package_path",
    "fixture_file",
    "report_json",
    "report_markdown",
}
EXPECTED_MATRIX_VALIDATION_STATUS = {
    "CONTROLLED_TEST_VALIDATED": "CONTROLLED_TEST_VALIDATED_IN_VALIDATION_REPO",
    "VALIDATION_CONTRACT_ENFORCED": "VALIDATION_CONTRACT_ENFORCED_IN_VALIDATION_REPO",
}


class RegistryFailure(Exception):
    """Registry contract violation."""


def fail(message: str) -> None:
    raise RegistryFailure(message)


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            fail(f"duplicate YAML key is forbidden: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _load_strict_yaml(path: Path, label: str) -> Any:
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (yaml.YAMLError, UnicodeError, OSError) as exc:
        fail(f"{label} is malformed YAML: {exc}")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate structured key is forbidden: {key}")
        result[key] = value
    return result


def _load_strict_json_text(text: str, label: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_strict_object)
    except json.JSONDecodeError as exc:
        fail(f"{label} is malformed JSON: {exc}")


def load_registry(path: Path = REGISTRY_PATH) -> dict[str, Any]:
    try:
        data = _load_strict_json_text(path.read_text(encoding="utf-8"), "registry")
    except FileNotFoundError:
        fail(f"registry file is missing: {path}")
    if not isinstance(data, dict):
        fail("registry root must be an object")
    return data


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_semantic_value(value: Any, label: str) -> Any:
    if value is None or type(value) in {bool, int, float, str}:
        return value
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, list):
        return [
            _canonical_semantic_value(item, f"{label}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                fail(f"{label} contains a non-string mapping key")
            result[key] = _canonical_semantic_value(item, f"{label}.{key}")
        return result
    fail(f"{label} contains unsupported scalar type: {type(value).__name__}")


def _semantic_fingerprint(path: Path) -> str:
    suffix = path.suffix.casefold()
    if suffix in {".yml", ".yaml"}:
        value = _canonical_semantic_value(
            _load_strict_yaml(path, f"semantic source {path.name}"),
            f"semantic source {path.name}",
        )
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
    if suffix == ".json":
        value = _load_strict_json_text(
            path.read_text(encoding="utf-8"), f"semantic source {path.name}"
        )
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
    normalized = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(normalized).hexdigest()


def _semantic_fingerprint_method(path: Path) -> str:
    if path.suffix.casefold() in {".yml", ".yaml", ".json"}:
        return "canonical-json-sha256"
    return "normalized-lf-bytes-sha256"


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail(f"git {' '.join(args)} failed for {root}: {result.stderr.strip()}")
    return result.stdout.strip()


def _git_blob(root: Path, relative_path: str) -> str:
    return _git(root, "rev-parse", f"HEAD:{relative_path}")


def _stored_origin(root: Path) -> str:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "config",
            "--local",
            "--get-all",
            "remote.origin.url",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    values = [value.strip() for value in result.stdout.splitlines()]
    if result.returncode != 0 or len(values) != 1 or not values[0]:
        fail(
            "detections source stored origin must contain exactly one "
            "nonempty local URL"
        )
    return values[0]


def _canonical_origin(value: str) -> str:
    normalized = value.strip().rstrip("/").casefold()
    if normalized.startswith("git@github.com:"):
        normalized = "https://github.com/" + normalized.removeprefix(
            "git@github.com:"
        )
    elif normalized.startswith("ssh://git@github.com/"):
        normalized = "https://github.com/" + normalized.removeprefix(
            "ssh://git@github.com/"
        )
    if not normalized.endswith(".git"):
        normalized += ".git"
    return normalized


def _verify_source_repository(
    detections_root: Path,
    intended_ref: str | None,
) -> dict[str, str]:
    remote = _stored_origin(detections_root)
    expected_remote = (
        "https://github.com/HawkinsOperations/hawkinsoperations-detections.git"
    )
    if _canonical_origin(remote) != _canonical_origin(expected_remote):
        fail("detections source repository origin is not canonical")
    status = _git(detections_root, "status", "--porcelain")
    meaningful = [
        line for line in status.splitlines()
        if "__pycache__/" not in line.replace("\\", "/") and not line.rstrip().endswith(".pyc")
    ]
    if meaningful:
        fail("detections source repository is dirty and cannot be current authority")
    head = _git(detections_root, "rev-parse", "HEAD")
    if intended_ref is None:
        branch = _git(detections_root, "branch", "--show-current")
        if not branch:
            fail("detached detections source requires an explicit --detections-ref")
        intended_ref = f"refs/heads/{branch}"
    resolved = _git(detections_root, "rev-parse", intended_ref)
    if resolved != head:
        fail(
            "detections checked HEAD does not equal intended ref: "
            f"ref={intended_ref}, expected={resolved}, actual={head}"
        )
    return {"current_observed_head_sha": head, "resolved_ref": intended_ref}


def _repository_state(root: Path) -> dict[str, str]:
    def git(*args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout.strip() if result.returncode == 0 else "UNRESOLVED"

    status = git("status", "--porcelain")
    status_lines = [] if status == "UNRESOLVED" else status.splitlines()
    meaningful_status = [
        line for line in status_lines
        if "__pycache__/" not in line.replace("\\", "/") and not line.rstrip().endswith(".pyc")
    ]
    worktree_clean = not meaningful_status if status != "UNRESOLVED" else False
    return {
        "repository": "hawkinsoperations-validation",
        "authority_role": "controlled_validation",
        "resolved_ref": git("branch", "--show-current"),
        "source_commit_sha": git("rev-parse", "HEAD"),
        "worktree_clean": worktree_clean,
        "source_freshness_state": "CURRENT" if worktree_clean else "WORKTREE_MODIFIED_OR_UNRESOLVED",
    }


def _normalized_key(value: str) -> str:
    decoded = value
    for _ in range(4):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKC", decoded).casefold())


def _compositional_promotion_key(key: str) -> bool:
    return (
        ("production" in key and any(part in key for part in ("active", "live", "ready", "deploy", "state", "status")))
        or (any(part in key for part in ("customer", "socaas")) and any(part in key for part in ("active", "deploy", "state", "status")))
        or ("runtime" in key and any(part in key for part in ("active", "state", "status")))
        or ("signal" in key and any(part in key for part in ("observed", "state", "status")))
        or ("publicsafe" in key and "count" not in key)
        or ("final" in key and any(part in key for part in ("authoriz", "authority")))
        or ("case" in key and "count" not in key and any(part in key for part in ("closed", "closure", "state", "status")))
        or any(part in key for part in ("approvalstate", "approvalstatus", "closurestatus", "casestate", "casestatus"))
        or (
            key.startswith(("ai", "analyst"))
            and any(part in key for part in ("approved", "approval", "authority", "disposition"))
        )
        or ("review" in key and "disposition" in key)
    )


def _explicitly_bounded_authority_value(value: Any) -> bool:
    if isinstance(value, list) and len(value) == 1:
        return _explicitly_bounded_authority_value(value[0])
    if value is False or value is None or value == 0:
        return True
    if not isinstance(value, str):
        return False
    return _normalized_key(value) in {
        "blocked",
        "false",
        "humanreviewrequired",
        "missing",
        "none",
        "notapproved",
        "notauthorized",
        "notclosed",
        "notproven",
        "notpublicsafe",
        "notruntimeactive",
        "open",
        "partial",
        "pending",
        "existingflowcandidate",
        "privateruntimeboundarycontextonly",
        "privateruntimeevidencecaptured",
        "privateruntimeevidencecapturedlocalwindowsonly",
        "publicruntimeblocked",
        "runtimeactiveprivate",
        "runtimeblocked",
        "runtimeevidenceverifiedprivate",
        "signalblocked",
        "signalobservedprivate",
        "sourceexists",
        "unsupported",
    }


def _decode_path(value: str, field: str, detection_id: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{detection_id} {field} must be a non-empty repo-relative path")
    decoded = unicodedata.normalize("NFKC", value.strip())
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if "%" in decoded and re.search(r"%[0-9a-fA-F]{2}", decoded):
        fail(f"{detection_id} {field} contains unresolved encoded path material")
    return decoded


def _canonical_relpath(value: str, field: str, detection_id: str) -> str:
    decoded = _decode_path(value, field, detection_id)
    windows = PureWindowsPath(decoded)
    posix = PurePosixPath(decoded.replace("\\", "/"))
    if (
        decoded.startswith(("/", "\\"))
        or decoded.casefold().startswith("file:")
        or windows.is_absolute()
        or windows.drive
        or posix.is_absolute()
    ):
        fail(f"{detection_id} {field} must be a repo-relative path")
    parts = decoded.replace("\\", "/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        fail(f"{detection_id} {field} contains an unsafe or ambiguous path segment")
    canonical = "/".join(unicodedata.normalize("NFKC", part) for part in parts)
    if "\\" in decoded and "/" in decoded:
        fail(f"{detection_id} {field} mixes path separators")
    return canonical


def _rel_path(root: Path, value: str, field: str, detection_id: str) -> Path:
    canonical = _canonical_relpath(value, field, detection_id)
    path = Path(*canonical.split("/"))
    resolved_root = root.resolve()
    resolved = (resolved_root / path).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        fail(f"{detection_id} {field} escapes its owning repository")
    return resolved


def _require_existing_path(root: Path, package: dict[str, Any], field: str) -> None:
    value = package.get(field)
    detection_id = str(package.get("detection_id", "<unknown>"))
    if not isinstance(value, str) or not value:
        fail(f"{detection_id} missing required path field: {field}")
    resolved = _rel_path(root, value, field, detection_id)
    if not resolved.exists():
        fail(f"{detection_id} listed file or directory is missing: {field}={value}")
    if field == "validation_package_path" and not resolved.is_dir():
        fail(f"{detection_id} validation_package_path must be a directory: {value}")
    if field != "validation_package_path" and not resolved.is_file():
        fail(f"{detection_id} {field} must be a file: {value}")


def _truthy(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return value.strip().lower() not in FALSEY_STATUSES
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    return True


def _blocked_scalar(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().casefold() in BLOCKED_SCALARS
    try:
        return value in BLOCKED_SCALARS
    except TypeError:
        return False


def _scan_authority_boundaries(
    value: Any,
    path: str = "$",
    normalized_path: tuple[str, ...] = (),
    promotion_context: bool = False,
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                fail(f"{path} contains a non-string key")
            normalized = _normalized_key(key)
            child_normalized_path = (*normalized_path, normalized)
            cumulative_keys = {normalized}
            cumulative_keys.update(
                f"{segment}{normalized}"
                for segment in normalized_path
                if segment
                in {
                    "runtime",
                    "signal",
                    "public",
                    "approval",
                    "production",
                    "customer",
                    "socaas",
                    "ai",
                    "analyst",
                    "review",
                    "final",
                    "case",
                }
            )
            child_promotion_context = promotion_context or any(
                _compositional_promotion_key(candidate)
                for candidate in cumulative_keys
            )
            if (
                not isinstance(child, (dict, list))
                and child_promotion_context
                and not _explicitly_bounded_authority_value(child)
            ):
                fail(f"{path}.{key} promotes a compositional authority state")
            if (
                not isinstance(child, (dict, list))
                and (
                    normalized in AUTHORITY_PROMOTION_KEYS
                or any(marker in normalized for marker in ("finalauthorization", "caseclosure"))
                or (
                    any(marker in normalized for marker in ("ai", "analyst"))
                    and any(marker in normalized for marker in ("authority", "approval", "approved", "disposition"))
                )
                )
            ) and not _blocked_scalar(child):
                fail(f"{path}.{key} promotes a blocked authority state")
            _scan_authority_boundaries(
                child,
                f"{path}.{key}",
                child_normalized_path,
                child_promotion_context,
            )
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _scan_authority_boundaries(
                child,
                f"{path}[{index}]",
                normalized_path,
                promotion_context,
            )
        return
    if promotion_context and not _explicitly_bounded_authority_value(value):
        fail(f"{path} promotes a compositional authority state")
    if isinstance(value, str):
        normalized = _normalize_authority_security_text(value)
        if (
            _normalized_key(path.rsplit(".", 1)[-1]).endswith("id")
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", normalized)
        ):
            return
        normalized_parent = _normalized_key(path.rsplit("[", 1)[0])
        exact_blocked_leaf = (
            path.endswith("]")
            and normalized_parent.endswith(
                ("blockedclaims", "claimsnotsupported", "notclaimedhere")
            )
            and not re.search(
                r"\b(?:is|was|has|enabled|granted|received)\b",
                normalized,
                re.IGNORECASE,
            )
        )
        for segment in AUTHORITY_STRONG_CLAUSE_SPLIT_RE.split(normalized):
            if not segment.strip():
                continue
            intro = NEGATIVE_LIST_INTRO_RE.search(segment)
            suffix = NEGATIVE_LIST_SUFFIX_RE.search(segment)
            if suffix:
                if AFFIRMATIVE_STATE_AFTER_NEGATIVE_LIST_RE.search(
                    segment[:suffix.start()]
                ):
                    fail(f"{path} contains a blocked authority claim")
                continue
            if intro:
                if (
                    AFFIRMATIVE_STATE_AFTER_NEGATIVE_LIST_RE.search(
                        segment[intro.end():]
                    )
                ):
                    fail(f"{path} contains a blocked authority claim")
                continue
            clauses = segment.split(",")
            if any(
                clause.strip()
                and (
                    _contains_unnegated_affirmative_state(clause)
                    or (
                        AFFIRMATIVE_AUTHORITY_CLAIM_RE.search(clause)
                        and not NEGATED_AUTHORITY_CONTEXT_RE.search(clause)
                    )
                )
                and not exact_blocked_leaf
                for clause in clauses
            ):
                fail(f"{path} contains a blocked authority claim")


def _scan_authority_markdown(text: str, path: str) -> None:
    """Scan Markdown by semantic block while allowing exact blocked-claim lists."""
    current_heading = ""
    block: list[tuple[int, str]] = []

    def flush() -> None:
        nonlocal block
        if not block:
            return
        bounded_heading = current_heading in {
            _normalized_key("Blocked Claims"),
            _normalized_key("Claims Not Supported"),
            _normalized_key("Not Claimed"),
            _normalized_key("Out of Scope"),
        }
        for line_number, line in block:
            stripped = line.strip()
            safe_blocked_leaf = (
                bounded_heading
                and stripped.startswith("- ")
                and not re.search(
                    r"\b(?:is|was|has|enabled|granted|received)\b",
                    stripped[2:],
                    re.IGNORECASE,
                )
            )
            if not safe_blocked_leaf:
                _scan_authority_boundaries(
                    " ".join(item for _, item in block),
                    f"{path}:line-{line_number}",
                )
                break
        block = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        heading = re.fullmatch(r"\s*#{1,6}\s+(.+?)\s*", line)
        if heading:
            flush()
            current_heading = _normalized_key(heading.group(1))
            continue
        if not line.strip():
            flush()
            continue
        block.append((line_number, line))
    flush()


def _first_int(*values: Any) -> int | None:
    for value in values:
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
    return None


def _count_case_groups(case_data: dict[str, Any]) -> tuple[int | None, int | None, int | None]:
    if isinstance(case_data.get("positives"), list) or isinstance(case_data.get("negatives"), list):
        positive = len(case_data.get("positives") or [])
        negative = len(case_data.get("negatives") or [])
        return positive + negative, positive, negative

    cases = case_data.get("cases")
    if isinstance(cases, dict):
        positive_cases = cases.get("positive")
        negative_cases = cases.get("negative")
        if isinstance(positive_cases, list) and isinstance(negative_cases, list):
            return len(positive_cases) + len(negative_cases), len(positive_cases), len(negative_cases)
    if isinstance(cases, list):
        positive = 0
        negative = 0
        unknown = 0
        for case in cases:
            if not isinstance(case, dict):
                fail("fixture cases array entries must be objects")
            expected = str(case.get("expected_result", case.get("expected_match", ""))).lower()
            if expected in {"match", "true", "1"}:
                positive += 1
            elif expected in {"no_match", "false", "0"}:
                negative += 1
            else:
                unknown += 1
        total = len(cases)
        if unknown:
            return total, None, None
        return total, positive, negative
    return None, None, None


def _report_counts(report: dict[str, Any]) -> tuple[int | None, int | None, int | None]:
    totals = report.get("totals")
    if not isinstance(totals, dict):
        totals = {}
    return (
        _first_int(report.get("total_cases"), report.get("fixture_count"), totals.get("total_cases")),
        _first_int(report.get("positive_cases"), report.get("positive_count"), totals.get("positive_cases")),
        _first_int(report.get("negative_cases"), report.get("negative_count"), totals.get("negative_cases")),
    )


def _case_ids(case_data: dict[str, Any]) -> tuple[set[str], set[str]]:
    unknown_root = sorted(set(case_data) - FIXTURE_ALLOWED_FIELDS)
    if unknown_root:
        fail(f"fixture contains unknown fields: {', '.join(unknown_root)}")
    has_grouped = "cases" in case_data
    has_split = "positives" in case_data or "negatives" in case_data
    if has_grouped and has_split:
        fail("fixture must use exactly one case shape, not both cases and positives/negatives")
    groups = case_data.get("cases")
    if not isinstance(groups, dict):
        groups = {
            "positive": case_data.get("positives"),
            "negative": case_data.get("negatives"),
        }
    result: list[set[str]] = []
    for side in ("positive", "negative"):
        values = groups.get(side)
        if not isinstance(values, list) or not values:
            fail(f"fixture {side} case list must be a non-empty array")
        ids: set[str] = set()
        for index, item in enumerate(values):
            if not isinstance(item, dict):
                fail(f"fixture {side}[{index}] must be an object")
            unknown = sorted(set(item) - FIXTURE_CASE_ALLOWED_FIELDS)
            if unknown:
                fail(f"fixture {side}[{index}] contains unknown fields: {', '.join(unknown)}")
            case_id = item.get("id")
            if not isinstance(case_id, str) or not case_id.strip():
                fail(f"fixture {side}[{index}].id must be a non-empty string")
            canonical = unicodedata.normalize("NFKC", case_id).casefold()
            if canonical in ids:
                fail(f"fixture duplicates normalized {side} case id: {case_id}")
            ids.add(canonical)
        result.append(ids)
    if result[0] & result[1]:
        fail("fixture reuses a normalized case id across positive and negative lists")
    return result[0], result[1]


def _report_case_ids(report: dict[str, Any]) -> tuple[set[str], set[str]]:
    positive = report.get("positive")
    negative = report.get("negative")
    has_grouped = "positive" in report or "negative" in report
    has_flat = "fixture_results" in report
    if has_grouped and has_flat:
        fail("report must use exactly one result shape, not both positive/negative and fixture_results")
    if has_grouped:
        if not isinstance(positive, list) or not isinstance(negative, list):
            fail("report positive and negative arrays must both be present")
        groups = (positive, negative)
    else:
        results = report.get("fixture_results")
        if not isinstance(results, list) or not results:
            fail("report must expose positive/negative arrays or fixture_results")
        positive = [
            item for item in results
            if isinstance(item, dict) and str(item.get("expected_result", "")).casefold() == "match"
        ]
        negative = [
            item for item in results
            if isinstance(item, dict) and str(item.get("expected_result", "")).casefold() == "no_match"
        ]
        if len(positive) + len(negative) != len(results):
            fail("report fixture_results contains an unknown expected_result")
        groups = (positive, negative)
    output: list[set[str]] = []
    for side, values in zip(("positive", "negative"), groups, strict=True):
        ids: set[str] = set()
        for index, item in enumerate(values):
            if not isinstance(item, dict):
                fail(f"report {side}[{index}] must be an object")
            unknown = sorted(set(item) - RESULT_ALLOWED_FIELDS)
            if unknown:
                fail(f"report {side}[{index}] contains unknown fields: {', '.join(unknown)}")
            case_id = item.get("id")
            if not isinstance(case_id, str) or not case_id.strip():
                fail(f"report {side}[{index}].id must be a non-empty string")
            canonical = unicodedata.normalize("NFKC", case_id).casefold()
            if canonical in ids:
                fail(f"report duplicates normalized {side} result id: {case_id}")
            if item.get("pass") is not True:
                fail(f"report {side}[{case_id}] is not an explicit passing result")
            if has_grouped:
                expected = side == "positive"
                if item.get("expected") is not expected:
                    fail(
                        f"report {side}[{case_id}] expected must be {expected}"
                    )
                if item.get("matched") is not expected:
                    fail(
                        f"report {side}[{case_id}] matched must be {expected}"
                    )
            else:
                expected_result = "match" if side == "positive" else "no_match"
                expected_match = side == "positive"
                if str(item.get("expected_result", "")).casefold() != expected_result:
                    fail(
                        f"report {side}[{case_id}] expected_result must be "
                        f"{expected_result}"
                    )
                if item.get("matched") is not expected_match:
                    fail(
                        f"report {side}[{case_id}] matched must be {expected_match}"
                    )
            ids.add(canonical)
        output.append(ids)
    return output[0], output[1]


def _expected_report_identity(detection_id: str, validation_kind: str) -> str:
    if validation_kind == "baseline_contract":
        return f"{detection_id}_BASELINE_VALIDATION_RESULT_V1"
    if validation_kind == "visibility_contract":
        return f"{detection_id}_VISIBILITY_CONTRACT_V1"
    return f"{detection_id}_VALIDATION_RESULT_V1"


def _expected_parity_identity(detection_id: str, validation_kind: str) -> str | None:
    if validation_kind == "baseline_contract":
        return None
    if validation_kind == "visibility_contract":
        return f"{detection_id}_VISIBILITY_PARITY_V1"
    return f"{detection_id}_RESULT_PARITY_V1"


def _validate_report_shape(
    report: dict[str, Any],
    package: dict[str, Any],
    fixture_data: dict[str, Any],
) -> None:
    detection_id = package["detection_id"]
    unknown = sorted(set(report) - REPORT_ALLOWED_FIELDS)
    if unknown:
        fail(f"{detection_id} report contains unknown fields: {', '.join(unknown)}")
    if report.get("detection_id", report.get("rule_id")) != detection_id:
        fail(f"{detection_id} report identity is missing or contradictory")
    if package["validation_kind"] == "controlled_validation":
        required_contract = {
            "validation_owner": package["validation_owner"],
            "source_owner": package["source_owner"],
            "fixture_version": package["fixture_version"],
            "expected_result": package["expected_result"],
            "actual_result": package["actual_result"],
            "report_identity": package["report_identity"],
            "parity_identity": package["parity_identity"],
            "proof_ceiling": package["proof_ceiling"],
            "human_review_required": True,
            "ai_disposition_authority": False,
        }
        for field, expected in required_contract.items():
            if field not in report:
                fail(f"{detection_id} report is missing required field: {field}")
            if report[field] != expected:
                fail(
                    f"{detection_id} report {field} disagreement: "
                    f"expected={expected!r}, actual={report[field]!r}"
                )
    if report.get("status") != "pass":
        fail(f"{detection_id} report actual result must be explicit pass")
    _scan_authority_boundaries(report, f"report[{detection_id}]")
    fixture_positive, fixture_negative = _case_ids(fixture_data)
    report_positive, report_negative = _report_case_ids(report)
    if fixture_positive != report_positive:
        fail(f"{detection_id} positive report IDs do not match fixture IDs")
    if fixture_negative != report_negative:
        fail(f"{detection_id} negative report IDs do not match fixture IDs")


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeError, OSError) as exc:
        fail(f"{label} cannot be read as UTF-8 JSON: {exc}")
    data = _load_strict_json_text(text, label)
    if not isinstance(data, dict):
        fail(f"{label} must be a JSON object")
    return data


def _verify_counts(root: Path, package: dict[str, Any]) -> None:
    detection_id = str(package["detection_id"])
    expected = (
        package.get("expected_fixture_count"),
        package.get("expected_positive_count"),
        package.get("expected_negative_count"),
    )
    if any(
        value is not None and (not isinstance(value, int) or isinstance(value, bool))
        for value in expected
    ):
        fail(f"{detection_id} expected fixture counts must be integers or null")
    if all(value is None for value in expected):
        return
    if package["validation_kind"] == "controlled_validation":
        total, positive, negative = expected
        if not all(isinstance(value, int) and value > 0 for value in (total, positive, negative)):
            fail(f"{detection_id} controlled validation requires positive integer fixture counts")
        if positive + negative != total:
            fail(f"{detection_id} expected positive and negative counts must sum to total fixtures")

    fixture_data = _load_json(_rel_path(root, package["fixture_file"], "fixture_file", detection_id), f"{detection_id} fixture file")
    fixture_counts = _count_case_groups(fixture_data)
    for label, actual, expected_value in zip(("fixture", "positive", "negative"), fixture_counts, expected, strict=True):
        if expected_value is not None and actual is not None and actual != expected_value:
            fail(f"{detection_id} {label} fixture count mismatch: expected {expected_value}, found {actual}")

    report_path = package.get("report_json")
    if report_path is None:
        return
    report = _load_json(_rel_path(root, report_path, "report_json", detection_id), f"{detection_id} report JSON")
    _validate_report_shape(report, package, fixture_data)
    report_markdown = package.get("report_markdown")
    if isinstance(report_markdown, str):
        markdown_text = _rel_path(
            root, report_markdown, "report_markdown", detection_id
        ).read_text(encoding="utf-8")
        if detection_id not in markdown_text:
            fail(f"{detection_id} report Markdown identity is missing or contradictory")
        _scan_authority_markdown(
            markdown_text, f"report_markdown[{detection_id}]"
        )
    report_detection_id = report.get("detection_id", report.get("rule_id"))
    if report_detection_id and report_detection_id != detection_id:
        fail(f"{detection_id} report JSON id mismatch: {report_detection_id}")
    if report.get("status") not in {None, "pass", "ready_for_public_pipeline_route"}:
        fail(f"{detection_id} report status is not pass")
    if report.get("public_safe_status") not in {None, "NOT_PUBLIC_SAFE"}:
        fail(f"{detection_id} report public_safe_status is not NOT_PUBLIC_SAFE")
    if _truthy(report.get("runtime_active", report.get("runtime_status", False))):
        fail(f"{detection_id} report promotes runtime status")
    if _truthy(report.get("signal_observed", report.get("signal_status", False))):
        fail(f"{detection_id} report promotes signal status")
    if package["validation_kind"] == "controlled_validation":
        if report.get("human_review_required") is not True:
            fail(f"{detection_id} report disables human review")
        if report.get("ai_disposition_authority") is not False:
            fail(f"{detection_id} report promotes AI disposition authority")
    report_ceiling = report.get("proof_ceiling")
    if report_ceiling is not None and report_ceiling != package["proof_ceiling"]:
        fail(
            f"{detection_id} report proof ceiling disagreement: "
            f"registry={package['proof_ceiling']}, report={report_ceiling}"
        )

    for label, actual, expected_value in zip(("fixture", "positive", "negative"), _report_counts(report), expected, strict=True):
        if expected_value is not None and actual is not None and actual != expected_value:
            fail(f"{detection_id} {label} report count mismatch: expected {expected_value}, found {actual}")


def _validate_bridge_records(data: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    bridges = data.get("bridge_records", [])
    if bridges is None:
        return []
    if not isinstance(bridges, list):
        fail("bridge_records must be a list when present")
    seen_artifacts: set[str] = set()
    for bridge in bridges:
        if not isinstance(bridge, dict):
            fail("each bridge_records entry must be an object")
        unknown = sorted(set(bridge) - BRIDGE_REQUIRED_FIELDS)
        if unknown:
            fail(f"bridge record contains unknown fields: {', '.join(unknown)}")
        missing = sorted(BRIDGE_REQUIRED_FIELDS - bridge.keys())
        artifact_id = str(bridge.get("bridge_record_id", bridge.get("artifact_id", "<unknown>")))
        if missing:
            fail(f"{artifact_id} bridge record missing required fields: {', '.join(missing)}")
        if artifact_id in seen_artifacts:
            fail(f"duplicate bridge artifact_id exists: {artifact_id}")
        seen_artifacts.add(artifact_id)
        if bridge["artifact_id"] != bridge["detection_id"]:
            fail(f"{artifact_id} bridge artifact_id must match detection_id")
        if bridge["detection_id"] != "HO-DET-001":
            fail(f"{artifact_id} bridge detection_id must be HO-DET-001")
        if bridge["bridge_kind"] != "hoxline_gauntlet_validation_bridge":
            fail(f"{artifact_id} bridge_kind is invalid")
        if bridge["proof_ceiling"] != "CONTROLLED_TEST_VALIDATED":
            fail(f"{artifact_id} bridge proof_ceiling must be CONTROLLED_TEST_VALIDATED")
        if bridge["public_safe_status"] not in {"BLOCKED", "NOT_PUBLIC_SAFE"}:
            fail(f"{artifact_id} bridge public_safe_status must remain blocked")
        if bridge["human_review_required"] is not True:
            fail(f"{artifact_id} bridge human_review_required must be true")
        if bridge["ai_disposition_authority"] is not False:
            fail(f"{artifact_id} bridge ai_disposition_authority must be false")
        for field in ("bridge_record_path", "bridge_markdown_path", "validator_script"):
            _require_existing_path(root, bridge, field)
        notes = str(bridge.get("notes", "")).lower()
        for term in ("runtime", "signal", "production", "customer", "socaas", "public-safe"):
            if term in notes and not any(marker in notes for marker in ("does not prove", "blocked", "not ")):
                fail(f"{artifact_id} bridge notes mention {term} without blocked context")
    return bridges


def validate_registry(data: dict[str, Any], root: Path = ROOT) -> list[dict[str, Any]]:
    unknown_root = sorted(set(data) - REGISTRY_FIELDS)
    missing_root = sorted(REGISTRY_FIELDS - set(data))
    if unknown_root:
        fail(f"registry contains unknown fields: {', '.join(unknown_root)}")
    if missing_root:
        fail(f"registry is missing required fields: {', '.join(missing_root)}")
    if data.get("schema_version") != 2:
        fail("schema_version must be 2")
    if data.get("owner_repo") != "hawkinsoperations-validation":
        fail("owner_repo must be hawkinsoperations-validation")
    if data.get("truth_surface") != "controlled_validation":
        fail("truth_surface must be controlled_validation")
    if data.get("source_authority_manifest") != "validation/SOURCE_AUTHORITY_MANIFEST.json":
        fail("source_authority_manifest must name the canonical validation handoff manifest")
    if data.get("registry_status") != "VALIDATION_CONTRACT_ENFORCED":
        fail("registry_status must be VALIDATION_CONTRACT_ENFORCED")
    if data.get("human_review_required") is not True:
        fail("human_review_required must be true")
    if data.get("ai_disposition_authority") is not False:
        fail("ai_disposition_authority must be false")
    packages = data.get("packages")
    if not isinstance(packages, list) or not packages:
        fail("packages must be a non-empty list")
    _validate_bridge_records(data, root)

    seen_ids: set[str] = set()
    path_owners: dict[str, str] = {}
    for package in packages:
        if not isinstance(package, dict):
            fail("each package entry must be an object")
        unknown = sorted(set(package) - REQUIRED_FIELDS)
        if unknown:
            fail(f"package contains unknown fields: {', '.join(unknown)}")
        missing = sorted(REQUIRED_FIELDS - package.keys())
        detection_id = str(package.get("detection_id", "<unknown>"))
        if missing:
            fail(f"{detection_id} missing required fields: {', '.join(missing)}")
        if not CANONICAL_ID.fullmatch(detection_id):
            fail(f"{detection_id} is not a canonical detection ID")
        normalized_id = unicodedata.normalize("NFKC", detection_id).casefold()
        if normalized_id in seen_ids:
            fail(f"duplicate detection_id exists: {detection_id}")
        seen_ids.add(normalized_id)

        if package["validation_owner"] != "hawkinsoperations-validation":
            fail(f"{detection_id} validation_owner is not canonical")
        expected_source_owner = (
            "hawkinsoperations-detections"
            if package["source_dependency_required"] is True
            else "hawkinsoperations-validation"
        )
        if package["source_owner"] != expected_source_owner:
            fail(f"{detection_id} source_owner is not canonical")
        source_reference = package["source_reference"]
        if not isinstance(source_reference, str):
            fail(f"{detection_id} source_reference must be a string")
        if package["source_dependency_required"] is True:
            prefix = "hawkinsoperations-detections/"
            if not source_reference.startswith(prefix):
                fail(f"{detection_id} source_reference must use the canonical detections owner")
            _canonical_relpath(source_reference.removeprefix(prefix), "source_reference", detection_id)
        elif source_reference != package["validation_package_path"]:
            fail(f"{detection_id} local source_reference must match validation_package_path")
        if not isinstance(package["fixture_version"], int) or isinstance(package["fixture_version"], bool) or package["fixture_version"] < 1:
            fail(f"{detection_id} fixture_version must be a positive integer")
        if package["expected_result"] not in {"PASS", "BLOCKED"}:
            fail(f"{detection_id} expected_result must be PASS or BLOCKED")
        if package["actual_result"] not in {"PASS", "BLOCKED"}:
            fail(f"{detection_id} actual_result must be PASS or BLOCKED")
        if package["actual_result"] != package["expected_result"]:
            fail(f"{detection_id} actual_result does not match expected_result")
        if not isinstance(package["report_identity"], str) or not package["report_identity"]:
            fail(f"{detection_id} report_identity must be explicit")
        if package["parity_identity"] is not None and (
            not isinstance(package["parity_identity"], str) or not package["parity_identity"]
        ):
            fail(f"{detection_id} parity_identity must be null or a non-empty string")
        if package["human_review_required"] is not True:
            fail(f"{detection_id} human_review_required must be true")
        if package["ai_disposition_authority"] is not False:
            fail(f"{detection_id} ai_disposition_authority must be false")

        validation_kind = package["validation_kind"]
        if validation_kind not in ALLOWED_KINDS:
            fail(f"{detection_id} unknown validation_kind: {validation_kind}")
        expected_report_identity = _expected_report_identity(detection_id, validation_kind)
        if package["report_identity"] != expected_report_identity:
            fail(
                f"{detection_id} report_identity must bind the owned report as "
                f"{expected_report_identity}"
            )
        expected_parity_identity = _expected_parity_identity(detection_id, validation_kind)
        if package["parity_identity"] != expected_parity_identity:
            fail(
                f"{detection_id} parity_identity must bind the owned parity contract as "
                f"{expected_parity_identity!r}"
            )
        if package["proof_ceiling"] not in ALLOWED_PROOF_CEILINGS:
            fail(f"{detection_id} unknown proof ceiling: {package['proof_ceiling']}")
        if package["public_safe_status"] != "NOT_PUBLIC_SAFE":
            fail(f"{detection_id} public_safe_status must be NOT_PUBLIC_SAFE")
        if package["runtime_status"] is not False:
            fail(f"{detection_id} runtime_status must be boolean false")
        if package["signal_status"] is not False:
            fail(f"{detection_id} signal_status must be boolean false")
        if not isinstance(package["notes"], str) or not package["notes"].strip():
            fail(f"{detection_id} notes must be a non-empty string")
        if not isinstance(package["source_dependency_required"], bool):
            fail(f"{detection_id} source_dependency_required must be boolean")
        if package["ci_source_dependency_mode"] not in {"none", "required"}:
            fail(f"{detection_id} ci_source_dependency_mode is invalid")
        if package["source_dependency_required"] is False and package["ci_source_dependency_mode"] != "none":
            fail(f"{detection_id} ci_source_dependency_mode must be none when source_dependency_required is false")
        if package["source_dependency_required"] is True:
            if package["ci_source_dependency_mode"] != "required":
                fail(f"{detection_id} source-backed validation must declare an enforceable source dependency mode")
            validator_path = _rel_path(root, package["validator_script"], "validator_script", detection_id)
            if validator_path.exists() and "--source-contract" not in validator_path.read_text(encoding="utf-8"):
                fail(f"{detection_id} source-backed validator does not implement --source-contract")

        required_paths = {
            "baseline_contract": BASELINE_REQUIRED_PATHS,
            "controlled_validation": CONTROLLED_REQUIRED_PATHS,
            "visibility_contract": VISIBILITY_REQUIRED_PATHS,
        }[validation_kind]
        for field in required_paths:
            _require_existing_path(root, package, field)
        for field in CONTROLLED_REQUIRED_PATHS | BASELINE_REQUIRED_PATHS | VISIBILITY_REQUIRED_PATHS:
            value = package.get(field)
            if value is not None and isinstance(value, str):
                _require_existing_path(root, package, field)
                if field in UNIQUE_OWNERSHIP_FIELDS:
                    resolved = _rel_path(root, value, field, detection_id)
                    key = unicodedata.normalize(
                        "NFKC", str(resolved).replace("\\", "/")
                    ).casefold()
                    previous = path_owners.get(key)
                    if previous is not None:
                        fail(f"{detection_id} reuses {field} already owned by {previous}: {value}")
                    path_owners[key] = detection_id

        if validation_kind == "controlled_validation":
            for field in ("validator_script", "parity_script", "claim_boundary_script", "report_json"):
                if not package.get(field):
                    fail(f"{detection_id} missing required controlled-validation field: {field}")
            if package["expected_result"] != "PASS":
                fail(f"{detection_id} controlled validation expected_result must be PASS")
            if package["parity_identity"] is None:
                fail(f"{detection_id} controlled validation parity_identity must be explicit")
            fixture_path = _rel_path(root, package["fixture_file"], "fixture_file", detection_id)
            package_path = _rel_path(
                root, package["validation_package_path"], "validation_package_path", detection_id
            )
            try:
                fixture_path.relative_to(package_path)
            except ValueError:
                fail(f"{detection_id} fixture_file is not inside validation_package_path")
            parity_text = _rel_path(
                root, package["parity_script"], "parity_script", detection_id
            ).read_text(encoding="utf-8")
            if Path(package["report_json"]).name not in parity_text:
                fail(f"{detection_id} parity script is not bound to its report JSON")
            if Path(package["fixture_file"]).name not in parity_text:
                fail(f"{detection_id} parity script is not bound to its fixture file")
        elif package["expected_result"] != "BLOCKED":
            fail(f"{detection_id} contract-only validation expected_result must be BLOCKED")
        _scan_authority_boundaries(package, f"registry.package[{detection_id}]")
        _verify_counts(root, package)

    validate_reverse_inventory(packages, root)
    return packages


def validate_reverse_inventory(packages: list[dict[str, Any]], root: Path = ROOT) -> None:
    registered_fixtures = {
        _canonical_relpath(package["fixture_file"], "fixture_file", package["detection_id"]).casefold()
        for package in packages
        if isinstance(package.get("fixture_file"), str)
        and package["validation_kind"] != "visibility_contract"
    }
    discovered_fixtures = {
        path.relative_to(root).as_posix().casefold()
        for path in root.glob("validation/**/validation-cases.json")
        if path.is_file()
    }
    missing_registry = sorted(discovered_fixtures - registered_fixtures)
    missing_files = sorted(registered_fixtures - discovered_fixtures)
    if missing_registry:
        fail(f"reverse inventory found unregistered validation fixtures: {missing_registry}")
    if missing_files:
        fail(f"reverse inventory found registry fixtures missing from disk: {missing_files}")

    registered_reports = {
        _canonical_relpath(package["report_json"], "report_json", package["detection_id"]).casefold()
        for package in packages
        if isinstance(package.get("report_json"), str)
    }
    discovered_reports = {
        path.relative_to(root).as_posix().casefold()
        for path in root.glob("reports/**/validation-result.json")
        if path.is_file()
    }
    baseline_report = root / "reports" / "hero001-validation-report.json"
    if baseline_report.is_file():
        discovered_reports.add(baseline_report.relative_to(root).as_posix().casefold())
    missing_registry = sorted(discovered_reports - registered_reports)
    missing_files = sorted(registered_reports - discovered_reports)
    if missing_registry:
        fail(f"reverse inventory found unregistered validation reports: {missing_registry}")
    if missing_files:
        fail(f"reverse inventory found registry reports missing from disk: {missing_files}")


def review_eligibility(package: dict[str, Any]) -> str:
    if package["validation_kind"] == "visibility_contract":
        return "BLOCKED"
    if package["validation_kind"] == "controlled_validation":
        return "PASS_CAPABLE"
    return "CONTRACT_ONLY"


def validate_source_parity(packages: list[dict[str, Any]], detections_root: Path) -> None:
    """Fail closed when validation registry truth disagrees with sibling source truth."""
    matrix_path = detections_root / "detections" / "DETECTION_PROMOTION_MATRIX.yml"
    if not matrix_path.is_file():
        fail(f"detection promotion matrix is missing: {matrix_path}")
    matrix = _load_strict_yaml(matrix_path, "detection promotion matrix")
    entries = matrix.get("entries") if isinstance(matrix, dict) else None
    if not isinstance(entries, list):
        fail("detection promotion matrix entries must be a list")
    by_id: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("detection_id"), str):
            fail("detection promotion matrix contains an invalid entry")
        detection_id = entry["detection_id"]
        canonical_id = unicodedata.normalize("NFKC", detection_id).casefold()
        if canonical_id in by_id:
            fail(f"detection promotion matrix duplicates detection_id: {detection_id}")
        by_id[canonical_id] = entry

    for package in packages:
        if package["source_dependency_required"] is not True:
            continue
        detection_id = package["detection_id"]
        entry = by_id.get(unicodedata.normalize("NFKC", detection_id).casefold())
        if entry is None:
            fail(f"{detection_id} validation source dependency is missing from detection matrix")
        if entry.get("validation_expected_owner") != "hawkinsoperations-validation":
            fail(f"{detection_id} detection matrix validation owner disagreement")
        expected_matrix_status = EXPECTED_MATRIX_VALIDATION_STATUS[package["proof_ceiling"]]
        if entry.get("validation_status_if_known") != expected_matrix_status:
            fail(
                f"{detection_id} source/validation status disagreement: "
                f"expected={expected_matrix_status}, matrix={entry.get('validation_status_if_known')}"
            )
        package_path = entry.get("package_path")
        if not isinstance(package_path, str) or "://" in package_path:
            fail(f"{detection_id} source-backed validation requires a local detection package")
        canonical_package_path = _canonical_relpath(
            package_path, "detection package_path", detection_id
        )
        expected_reference = f"hawkinsoperations-detections/{canonical_package_path}"
        if package["source_reference"] != expected_reference:
            fail(
                f"{detection_id} source_reference disagreement: "
                f"expected={expected_reference}, actual={package['source_reference']}"
            )
        status_path = detections_root / Path(*canonical_package_path.split("/")) / "status.yml"
        if not status_path.is_file():
            fail(f"{detection_id} source status file is missing: {package_path}/status.yml")
        status = _load_strict_yaml(status_path, f"{detection_id} source status file")
        if not isinstance(status, dict) or status.get("detection_id") != detection_id:
            fail(f"{detection_id} source status file identity disagreement")
        expected_status = expected_matrix_status.removesuffix("_IN_VALIDATION_REPO")
        if status.get("validation_status") != expected_status:
            fail(
                f"{detection_id} source status validation disagreement: "
                f"expected={expected_status}, status.yml={status.get('validation_status')}"
            )
        if status.get("public_safe_status") != "NOT_PUBLIC_SAFE":
            fail(f"{detection_id} source status promotes public-safe state")
        if _truthy(status.get("runtime_active")) or _truthy(status.get("signal_observed")):
            fail(f"{detection_id} source status promotes runtime or signal state")


def build_source_authority_manifest(
    packages: list[dict[str, Any]],
    detections_root: Path,
) -> dict[str, Any]:
    matrix_path = detections_root / "detections" / "DETECTION_PROMOTION_MATRIX.yml"
    matrix = _load_strict_yaml(matrix_path, "detection promotion matrix")
    entries = matrix.get("entries") if isinstance(matrix, dict) else None
    if not isinstance(entries, list):
        fail("detection promotion matrix entries must be a list")
    by_id: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("detection_id"), str):
            fail("detection promotion matrix contains an invalid entry")
        detection_id = entry["detection_id"]
        canonical_id = unicodedata.normalize("NFKC", detection_id).casefold()
        if canonical_id in by_id:
            fail(f"detection promotion matrix duplicates detection_id: {detection_id}")
        by_id[canonical_id] = entry
    items: list[dict[str, Any]] = []
    for package in packages:
        if package["source_dependency_required"] is not True:
            continue
        detection_id = package["detection_id"]
        entry = by_id.get(unicodedata.normalize("NFKC", detection_id).casefold())
        if entry is None:
            fail(f"{detection_id} cannot be added to source manifest because matrix entry is missing")
        package_path = _canonical_relpath(
            entry.get("package_path"), "detection package_path", detection_id
        )
        required_files = entry.get("required_files")
        if not isinstance(required_files, list) or not required_files:
            fail(f"{detection_id} matrix required_files must be a non-empty list")
        files: list[dict[str, str]] = []
        seen: set[str] = set()
        for value in required_files:
            relative_name = _canonical_relpath(value, "required_files", detection_id)
            relative_path = f"{package_path}/{relative_name}"
            normalized = relative_path.casefold()
            if normalized in seen:
                fail(f"{detection_id} required_files contains a normalized duplicate")
            seen.add(normalized)
            source_path = detections_root / Path(*relative_path.split("/"))
            if not source_path.is_file():
                fail(f"{detection_id} required source file is missing: {relative_path}")
            files.append(
                {
                    "path": relative_path,
                    "git_blob_sha": _git_blob(detections_root, relative_path),
                    "semantic_fingerprint": _semantic_fingerprint(source_path),
                    "semantic_fingerprint_method": _semantic_fingerprint_method(source_path),
                }
            )
        items.append(
            {
                "detection_id": detection_id,
                "package_path": package_path,
                "required_files": sorted(files, key=lambda item: item["path"].casefold()),
            }
        )
    matrix_relative = "detections/DETECTION_PROMOTION_MATRIX.yml"
    return {
        "schema_version": 1,
        "owner_repo": "hawkinsoperations-validation",
        "source_owner": "hawkinsoperations-detections",
        "truth_surface": "detection_to_validation_content_handoff",
        "matrix_path": matrix_relative,
        "matrix_git_blob_sha": _git_blob(detections_root, matrix_relative),
        "matrix_semantic_fingerprint": _semantic_fingerprint(matrix_path),
        "matrix_semantic_fingerprint_method": _semantic_fingerprint_method(matrix_path),
        "packages": sorted(items, key=lambda item: item["detection_id"]),
    }


def validate_source_authority_manifest(
    manifest: dict[str, Any],
    packages: list[dict[str, Any]],
    detections_root: Path,
) -> None:
    expected = build_source_authority_manifest(packages, detections_root)
    if manifest != expected:
        expected_by_id = {item["detection_id"]: item for item in expected["packages"]}
        actual_items = manifest.get("packages") if isinstance(manifest, dict) else None
        actual_by_id = {
            item.get("detection_id"): item
            for item in actual_items
            if isinstance(item, dict) and isinstance(item.get("detection_id"), str)
        } if isinstance(actual_items, list) else {}
        differing_ids = sorted(
            detection_id
            for detection_id in set(expected_by_id) | set(actual_by_id)
            if expected_by_id.get(detection_id) != actual_by_id.get(detection_id)
        )
        fail(
            "source authority manifest content identity drift: "
            f"matrix_expected_blob={expected['matrix_git_blob_sha']}, "
            f"matrix_actual_blob={manifest.get('matrix_git_blob_sha') if isinstance(manifest, dict) else None}, "
            f"differing_packages={differing_ids}; regenerate with "
            "python -B scripts/refresh_validation_source_manifest.py --write"
        )


def load_detection_source_inventory(detections_root: Path) -> dict[str, Any]:
    verifier = detections_root / "scripts" / "verify_detection_promotion_matrix.py"
    if not verifier.is_file():
        fail("detection-owned promotion-matrix verifier is missing")
    result = subprocess.run(
        [sys.executable, "-B", str(verifier), "--format", "json"],
        cwd=detections_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail(
            "detection-owned inventory verifier failed: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    value = _load_strict_json_text(result.stdout, "detection-owned source inventory")
    if not isinstance(value, dict):
        fail("detection-owned source inventory must be an object")
    return value


def validate_detection_source_inventory(
    inventory: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    if inventory.get("repository") != "hawkinsoperations-detections":
        fail("detection-owned inventory repository identity is not canonical")
    if inventory.get("authority_role") != "detection_source":
        fail("detection-owned inventory authority role is invalid")
    if inventory.get("authoritative_path") != manifest.get("matrix_path"):
        fail("detection-owned inventory authoritative path disagrees with handoff manifest")
    if inventory.get("authoritative_git_blob_sha") != manifest.get("matrix_git_blob_sha"):
        fail("detection-owned inventory matrix Git blob disagrees with handoff manifest")
    if inventory.get("authoritative_semantic_fingerprint") != manifest.get(
        "matrix_semantic_fingerprint"
    ):
        fail("detection-owned inventory matrix semantic fingerprint disagrees with handoff manifest")
    if inventory.get("current_authority") is not True or inventory.get("worktree_clean") is not True:
        fail("detection-owned inventory is not clean current authority")
    entries = inventory.get("entries")
    if not isinstance(entries, list):
        fail("detection-owned inventory entries must be a list")
    inventory_by_id = {
        entry.get("detection_id"): entry
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("detection_id"), str)
    }
    for package in manifest.get("packages", []):
        detection_id = package["detection_id"]
        entry = inventory_by_id.get(detection_id)
        if entry is None:
            fail(f"{detection_id} is missing from detection-owned inventory")
        if entry.get("package_path") != package["package_path"]:
            fail(f"{detection_id} package path disagrees with detection-owned inventory")
        if entry.get("content_matches_observed_head") is not True:
            fail(f"{detection_id} content does not match the observed detection head")
        expected_blobs = {
            item["path"].removeprefix(f"{package['package_path']}/"): item["git_blob_sha"]
            for item in package["required_files"]
        }
        expected_semantics = {
            item["path"].removeprefix(f"{package['package_path']}/"): item["semantic_fingerprint"]
            for item in package["required_files"]
        }
        if entry.get("required_file_git_blobs") != expected_blobs:
            fail(f"{detection_id} Git blob map disagrees with detection-owned inventory")
        if entry.get("required_file_semantic_fingerprints") != expected_semantics:
            fail(f"{detection_id} semantic fingerprint map disagrees with detection-owned inventory")


def build_inventory(packages: list[dict[str, Any]], root: Path = ROOT) -> dict[str, Any]:
    state = _repository_state(root)
    items: list[dict[str, Any]] = []
    fingerprint_fields = (
        "fixture_file",
        "report_json",
        "report_markdown",
        "validator_script",
        "parity_script",
        "claim_boundary_script",
    )
    for package in packages:
        fingerprints: dict[str, str] = {}
        for field in fingerprint_fields:
            value = package.get(field)
            if isinstance(value, str):
                fingerprints[field] = _sha256_file(root / value)
        eligibility = review_eligibility(package)
        items.append(
            {
                "detection_id": package["detection_id"],
                "validation_owner": package["validation_owner"],
                "source_owner": package["source_owner"],
                "source_reference": package["source_reference"],
                "fixture_version": package["fixture_version"],
                "validation_kind": package["validation_kind"],
                "proof_ceiling": package["proof_ceiling"],
                "review_eligibility": eligibility,
                "expected_fixture_review_outcome": package["expected_result"],
                "actual_fixture_review_outcome": package["actual_result"],
                "report_identity": package["report_identity"],
                "parity_identity": package["parity_identity"],
                "human_review_required": package["human_review_required"],
                "ai_disposition_authority": package["ai_disposition_authority"],
                "public_safe_status": package["public_safe_status"],
                "source_dependency_required": package["source_dependency_required"],
                "source_fingerprints": dict(sorted(fingerprints.items())),
            }
        )
    manifest_relative = "validation/SOURCE_AUTHORITY_MANIFEST.json"
    manifest_path = root / manifest_relative
    return {
        **state,
        "authoritative_path": "validation/VALIDATION_REGISTRY.yml",
        "authoritative_fingerprint": _sha256_file(root / "validation" / "VALIDATION_REGISTRY.yml"),
        "source_authority_manifest": manifest_relative,
        "source_authority_manifest_state": "CURRENT" if manifest_path.is_file() else "MISSING",
        "source_authority_manifest_fingerprint": (
            _sha256_file(manifest_path) if manifest_path.is_file() else None
        ),
        "package_count": len(items),
        "packages": items,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify validation package registry contract.")
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--detections-root", type=Path)
    parser.add_argument(
        "--detections-ref",
        help="intended checked detections ref; required for detached source checkouts",
    )
    parser.add_argument(
        "--source-manifest",
        type=Path,
        help="content-addressed detection-to-validation handoff manifest",
    )
    args = parser.parse_args()
    try:
        packages = validate_registry(load_registry(args.registry), ROOT)
        detections_root = args.detections_root
        if detections_root is None:
            sibling = ROOT.parent / "hawkinsoperations-detections"
            if sibling.is_dir():
                detections_root = sibling
        if detections_root is not None:
            detections_root = detections_root.resolve()
            source_state = _verify_source_repository(detections_root, args.detections_ref)
            validate_source_parity(packages, detections_root)
            manifest_path = args.source_manifest
            if manifest_path is None:
                manifest_path = ROOT / str(load_registry(args.registry)["source_authority_manifest"])
            manifest = _load_json(manifest_path.resolve(), "source authority manifest")
            validate_source_authority_manifest(manifest, packages, detections_root)
            validate_detection_source_inventory(
                load_detection_source_inventory(detections_root),
                manifest,
            )
        elif any(package["source_dependency_required"] for package in packages):
            fail("source-backed validation requires an explicit or sibling detections repository")
    except RegistryFailure as exc:
        print(f"VALIDATION_REGISTRY=fail: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        inventory = build_inventory(packages, ROOT)
        if detections_root is not None:
            inventory["detection_source_observation"] = source_state
        print(json.dumps(inventory, indent=2, sort_keys=True))
        return 0
    print("VALIDATION_REGISTRY=pass")
    print(f"REGISTERED_PACKAGES={len(packages)}")
    for package in packages:
        print(
            "PACKAGE={id} kind={kind} proof_ceiling={ceiling} public_safe_status={public}".format(
                id=package["detection_id"],
                kind=package["validation_kind"],
                ceiling=package["proof_ceiling"],
                public=package["public_safe_status"],
            )
        )
        print(
            f"REVIEW_ELIGIBILITY={package['detection_id']}:{review_eligibility(package)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

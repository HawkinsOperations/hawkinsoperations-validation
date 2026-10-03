#!/usr/bin/env python3
"""Cross-repo proof/claim parity scanner for HawkinsOperations.

This checker is read-only. It scans selected sibling repositories for scoped
detection IDs and claim language drift. Report-only mode always returns zero
after printing findings; enforce mode fails closed on dangerous public-claim
drift.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import unicodedata
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable

from verify_validation_registry import (
    AUTHORITY_CLAIM_SUFFIXES, AUTHORITY_PROMOTION_KEYS, CANONICAL_ID, RegistryFailure,
    _explicitly_bounded_authority_value, _load_json, _load_strict_yaml, _rel_path, _validate_package_identity,
    _validate_registry_identity, _validate_report_shape, load_registry,
)

DETECTION_IDS = [
    "HO-DET-001",
    "HO-DET-011",
    "HO-DET-012",
    "AWS-DET-001",
    "HO-NDR-001",
    "HO-PIPE-001",
]

PROMOTION_TERMS = [
    "production",
    "production-ready",
    "SOCaaS",
    "runtime-active",
    "runtime-active public proof",
    "signal-observed",
    "signal-observed public proof",
    "public-safe runtime proof",
    "autonomous SOC",
    "autonomous",
    "AI-approved",
    "AI-approved disposition",
    "analyst-approved",
    "analyst-approved disposition",
    "fleet-wide",
    "live Splunk",
    "Wazuh-routed",
    "Cribl-routed",
    "Security Onion public proof",
]

STATUS_TOKENS = {
    "SOURCE_EXISTS",
    "CONTROLLED_TEST_VALIDATED",
    "PRIVATE_RUNTIME_EVIDENCE_CAPTURED",
    "BOUNDARY_CONTRACT_ONLY",
    "NOT_PUBLIC_SAFE",
    "BLOCKED",
}

ALLOWED_PROOF_CEILING_TOKENS = {
    "SOURCE_EXISTS",
    "CONTROLLED_TEST_VALIDATED",
    "PRIVATE_RUNTIME_EVIDENCE_CAPTURED",
    "BOUNDARY_CONTRACT_ONLY",
    "NOT_PUBLIC_SAFE",
    "BLOCKED",
}

DANGEROUS_STATUS_TOKENS = {
    "PUBLIC_SAFE",
    "PUBLIC_PROOF_SAFE",
    "RUNTIME_ACTIVE",
    "SIGNAL_OBSERVED",
    "PRODUCTION_READY",
}

REQUIRED_BLOCKED_CLAIMS = [
    "production-ready",
    "SOCaaS",
    "autonomous SOC",
    "runtime-active public proof",
    "signal-observed public proof",
    "public-safe runtime proof",
    "AI-approved disposition",
    "analyst-approved disposition",
]

RENDERING_BOUNDARY_RE = re.compile(
    r"(rendering|website|github|screenshot|presentation).{0,80}(not|does\s+not|cannot).{0,80}(proof|prove)|"
    r"(not|does\s+not|cannot).{0,80}(proof|prove).{0,80}(rendering|website|github|screenshot|presentation)",
    re.IGNORECASE,
)

HUMAN_REVIEW_RE = re.compile(
    r"(human|raylee|operator|governance).{0,80}(review|approval|approved|required|authorize)|"
    r"(merge|public[-\s]?safe|proof).{0,80}(requires|required).{0,80}(human|raylee|operator|governance)",
    re.IGNORECASE,
)

PROOF_PACK_001_RE = re.compile(r"\bproof[-\s_]*pack[-\s_]*001\b", re.IGNORECASE)

STALE_SNAPSHOT_RE = re.compile(
    r"\b(stale\s+snapshot|old\s+snapshot|legacy\s+snapshot|snapshot\s+date|last\s+reviewed|reviewed_on)\b|"
    r"\b202[0-5]-\d{2}-\d{2}\b",
    re.IGNORECASE,
)

NEGATIVE_CONTEXT_RE = re.compile(
    r"(?<![A-Za-z0-9])(block|blocked|blocking|blocked[_\s-]?claims|"
    r"not|no|none|without|cannot|does\s+not|do\s+not|"
    r"must\s+not|remain(?:s)?\s+blocked|required|requires|needs|before\s+any|"
    r"pending|unsupported|not\s+proven|reject|rejects|rejected|fails?\s+closed|"
    r"stop(?:ped)?(?:\s+before)?|remain(?:s)?\s+distinct\s+from|"
    r"not\s+public[-_\s]?safe|claims_not_supported|blocked_claims|blocked_public_claims|"
    r"claim[_\s-]?boundary|not[_\s-]?approved|not[_\s-]?authorized|"
    r"does[_\s-]?not[_\s-]?support|controlled[-_\s]?test\s+scope\s+only|"
    r"fixture[-_\s]?only|support[-_\s]?only|review[-_\s]?only)(?![A-Za-z0-9])",
    re.IGNORECASE,
)

TEXT_EXTS = {".md", ".yml", ".yaml", ".json", ".html", ".ts", ".js", ".mjs"}
PUBLIC_BOUNDARY_SURFACES = {"proof", "website", "org_front_door", "platform"}


@dataclass
class DriftItem:
    severity: str
    detection_id: str
    surface: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "detection_id": self.detection_id,
            "surface": self.surface,
            "path": self.path,
            "message": self.message,
        }


class DuplicateJsonKeyError(ValueError):
    pass


def reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    seen: set[str] = set()
    for key, value in pairs:
        normalized = unicodedata.normalize("NFKC", key).casefold()
        if normalized in seen:
            raise DuplicateJsonKeyError(f"duplicate JSON key: {key}")
        seen.add(normalized)
        result[key] = value
    return result


def reject_nonfinite_json_constant(value: str) -> object:
    raise ValueError("non-finite structured values are forbidden")


def validate_structured_values(value: object, ancestors: set[int] | None = None) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite structured values are forbidden")
    if not isinstance(value, (dict, list)):
        if value is not None and not isinstance(value, (str, bool, int, float, date)):
            raise ValueError("unsupported structured scalar type")
        return
    ancestors = set() if ancestors is None else ancestors
    identity = id(value)
    if identity in ancestors:
        raise ValueError("recursive structured aliases are forbidden")
    ancestors.add(identity)
    try:
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError("structured mapping keys must be strings")
            children = value.values()
        else:
            children = value
        for child in children:
            validate_structured_values(child, ancestors)
    finally:
        ancestors.remove(identity)


def fail(message: str) -> int:
    print(f"STATUS=fail")
    print("FAIL_COUNT=1")
    print("WARNING_COUNT=0")
    print("UNKNOWN_COUNT=1")
    print(f"DRIFT_ITEMS={json.dumps([{'severity': 'fail', 'detection_id': 'GLOBAL', 'surface': 'scanner', 'path': '', 'message': message}])}")
    return 1


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def collect_files(root: Path, patterns: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for pattern in patterns:
        files.extend(root.glob(pattern))
    deduped = sorted({p.resolve() for p in files if p.is_file() and p.suffix.lower() in TEXT_EXTS})
    return deduped


def has_negative_context(line: str) -> bool:
    return bool(NEGATIVE_CONTEXT_RE.search(line))


def line_window(lines: list[str], index: int, radius: int = 2) -> str:
    start = max(0, index - radius)
    end = min(len(lines), index + radius + 1)
    return "\n".join(lines[start:end])


def has_negative_context_for_line(lines: list[str], index: int) -> bool:
    line = lines[index]
    if has_negative_context(line):
        return True
    if index == 0:
        return False

    previous = lines[index - 1]
    stripped = line.lstrip()
    continuation = stripped.startswith(("-", "*")) or line.startswith((" ", "\t"))
    parent_key = previous.rstrip().endswith(":")
    if (continuation or parent_key) and has_negative_context(previous):
        return True

    # YAML/Markdown blocked-claim lists often span several lines beneath a
    # negative parent key such as blocked_claims: or does_not_support:.
    for offset in range(1, 7):
        parent_index = index - offset
        if parent_index < 0:
            break
        candidate = lines[parent_index]
        if not candidate.strip():
            break
        if candidate.rstrip().endswith(":") and has_negative_context(candidate):
            return True
    return False


def line_is_associated_with_detection(
    lines: list[str],
    index: int,
    detection_id: str,
    detection_ids: list[str] | None = None,
) -> bool:
    governed_ids = detection_ids if detection_ids is not None else DETECTION_IDS
    scoped_ids = {
        candidate
        for line in lines
        for candidate in governed_ids
        if candidate.casefold() in line.casefold()
    }
    if scoped_ids == {detection_id}:
        return True
    current = lines[index].casefold()
    if detection_id.casefold() in current:
        return True
    for offset in range(1, 13):
        candidate_index = index - offset
        if candidate_index < 0:
            break
        candidate_line = lines[candidate_index]
        if not candidate_line.strip():
            break
        referenced = [
            candidate
            for candidate in governed_ids
            if candidate.casefold() in candidate_line.casefold()
        ]
        if referenced:
            return referenced == [detection_id]
    return False


AFFIRMATIVE_CLAIM_PREDICATE = (
    r"(?:is|are|has|have|proves|establishes|confirms|"
    r"claims|declares|enables|enabled|observed|approved|authorized|deployed)"
)


def has_negative_context_for_phrase(
    lines: list[str],
    index: int,
    phrase: str,
    phrase_start: int | None = None,
    detection_id: str | None = None,
    detection_ids: list[str] | None = None,
) -> bool:
    line = lines[index]
    folded = line.casefold()
    start = folded.find(phrase.casefold()) if phrase_start is None else phrase_start
    if start < 0:
        return False
    if re.fullmatch(rf'\s*\{{\s*label\s*:\s*["\']{re.escape(phrase)}["\']\s*,\s*value\s*:\s*["\'](?:false|0|blocked|not_approved)["\']\s*\}}\s*,?\s*', line, re.IGNORECASE):
        return True
    end = start + len(phrase)
    governed_ids = detection_ids if detection_ids is not None else DETECTION_IDS
    identities = "|".join(re.escape(identity) for identity in governed_ids)
    boundaries = re.compile(rf"[;\r\n]|(?<=[.!?])\s+|\b(?:but|however|although|(?<!not )yet|while|whereas)\b|,\s*(?=(?:{identities})\b|(?:it|this)\s+(?:is|are|has|have)\b)", re.IGNORECASE)
    prefix_boundaries = list(boundaries.finditer(line[:start]))
    clause_start = prefix_boundaries[-1].end() if prefix_boundaries else 0
    suffix_boundary = boundaries.search(line[end:])
    clause_end = end + suffix_boundary.start() if suffix_boundary else len(line)
    local = line[clause_start:clause_end]
    direct_suffix = line[end:clause_end]
    directly_negated = re.search(
        r"\b(?:not|no|never|without)(?:\s+(?:claim|claiming|prove|proving|establish|support|assert))?\s*$",
        line[clause_start:start], re.IGNORECASE,
    )
    if re.match(r"\s*(?:is|are|:|=)\s*(?:false|no|0)(?![\w.])", direct_suffix, re.IGNORECASE):
        return True
    explicit_negative_claim = re.search(
        r"\b(?:(?:does|do)\s+not\s+(?:prove|claim|authorize|support)|blocked\s+example:)",
        re.split(r"\band\b", line[clause_start:start], flags=re.IGNORECASE)[-1], re.IGNORECASE,
    )
    attached_prefix = re.search(rf"(?<![-_\w]){AFFIRMATIVE_CLAIM_PREDICATE}(?![-_\w])\s*$", line[clause_start:start], re.IGNORECASE)
    if not directly_negated and re.match(
        r"\s*(?:is|are|:|=)\s*(?:true|yes|active|approved|authorized|confirmed|enabled|live|ready|observed|[-+]?[1-9][0-9]*)\b",
        direct_suffix, re.IGNORECASE,
    ):
        return False
    if has_negative_context(local):
        if not directly_negated and not explicit_negative_claim and attached_prefix:
            return False
        return True
    direct_suffix = line[end:clause_end]
    if re.search(
        r"\b(?:remain(?:s)?|is|are|must\s+remain)\s+"
        r"(?:blocked|unsupported|not\s+(?:approved|authorized|proven|public[-_\s]?safe))\b",
        direct_suffix,
        re.IGNORECASE,
    ):
        return True
    governed_ids = detection_ids if detection_ids is not None else DETECTION_IDS
    def foreign_identity(candidate: str) -> bool:
        return detection_id is not None and any(
            identity.casefold() in candidate.casefold() and identity.casefold() != detection_id.casefold()
            for identity in governed_ids
        )
    literal = r'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`[^`]*`)'
    # A complete current-line denial field owns its literal value. Extra fields,
    # containers and affirmative text outside the literal cannot inherit it.
    if re.fullmatch(rf"\s*does(?:Not|_not_| not )Prove\s*:\s*{literal}\s*,?\s*", line, re.IGNORECASE):
        return True
    bounded_qualification = r"(?:\s+unless explicitly scoped to private controlled lab (?:evidence|signal observed)\.)?"
    quoted_item_pattern = rf"\s*(?:[-*]\s+)?{literal}{bounded_qualification}\s*[,;]?\s*"
    quoted_item = bool(re.fullmatch(quoted_item_pattern, line))
    bare_item = bool(re.fullmatch(rf"\s*[-*]\s+{re.escape(phrase)}(?:\s+(?:status|proof))?\s*[.,]?\s*", line, re.IGNORECASE))
    if quoted_item or bare_item:
        for parent_index in range(index - 1, max(-1, index - 80), -1):
            candidate = lines[parent_index]
            caption = re.sub(r"^\s*#{1,6}\s+", "", candidate).strip().rstrip(": [")
            for identity in governed_ids:
                caption = re.sub(rf"^{re.escape(identity)}\s+", "", caption, flags=re.IGNORECASE)
            if normalize_path_key(caption).replace("_", "") in {"blockedclaims", "blockedcurrentwording", "doesnotprove", "donotclaim"}:
                return not foreign_identity(candidate)
            if not candidate.strip() or re.fullmatch(quoted_item_pattern, candidate):
                continue
            if bare_item and re.fullmatch(r"\s*[-*]\s+[^.!?]+[,.]?\s*", candidate):
                continue
            break
    # These connected bullets specify inputs that a verifier rejects. They do
    # not assert the rejected state; a fresh subject or outside clause cannot
    # acquire that role merely by appearing below the conditional caption.
    criterion_pattern = r"\s*[-*]\s+(?:omits|uses|includes|promotes|claims|gives|decides)\s+[^;!?\n]+"
    def safe_rejection_criterion(candidate: str) -> bool:
        if not re.fullmatch(criterion_pattern, candidate, re.IGNORECASE) or any(
            identity.casefold() in candidate.casefold() for identity in governed_ids
        ) or re.search(r"\b(?:it|this)\s+(?:is|are|has|have)\b|[.]\s+\S", candidate, re.IGNORECASE):
            return False
        body = re.sub(r"^\s*[-*]\s+(?:omits|uses|includes|promotes|claims|gives|decides)\s+", "", candidate, flags=re.IGNORECASE)
        return not any(term_is_affirmative_claim(body, term, detection_ids=governed_ids)
                       for term in (*PROMOTION_TERMS, *DANGEROUS_STATUS_TOKENS))
    if safe_rejection_criterion(line):
        for parent_index in range(index - 1, max(-1, index - 40), -1):
            candidate = lines[parent_index]
            if candidate.strip() == "The verifier fails closed if the packet:":
                return True
            if not candidate.strip() or safe_rejection_criterion(candidate):
                continue
            break
    if attached_prefix and term_is_affirmative_claim(line, phrase, detection_ids=governed_ids):
        return False
    # A fresh subject/predicate cannot borrow even the same identity's prior
    # complete denial. Only unfinished, identity-bound denial lists wrap lines.
    if (detection_id is not None and detection_id.casefold() in line.casefold()) or re.match(
        r"\s*(?:[-*]\s+)?(?:this|it)\s+(?:is|are|has|have)\b", line, re.IGNORECASE
    ):
        return False
    for parent_index in range(index - 1, max(-1, index - 40), -1):
        candidate = lines[parent_index]
        if not candidate.strip() or foreign_identity(candidate):
            break
        if has_negative_context(candidate) and (
            candidate.rstrip().endswith((":", ","))
            or re.search(r"\b(?:does|do|must)\s+not\s+(?:prove|claim|support|authorize)\s*$", candidate, re.IGNORECASE)
        ):
            return True
        if candidate.rstrip().endswith((".", "?", "!")) or not candidate.rstrip().endswith(","):
            break
    return False


def markdown_table_cells(line: str) -> list[str] | None:
    stripped = line.strip()
    if not (stripped.startswith("|") and stripped.endswith("|")):
        return None
    return [cell.strip() for cell in stripped[1:-1].split("|")]


def markdown_table_headers(lines: list[str], index: int) -> list[str] | None:
    cells = markdown_table_cells(lines[index])
    if cells is None:
        return None
    for header_index in range(index - 1, -1, -1):
        candidate = markdown_table_cells(lines[header_index])
        if candidate is None:
            break
        if len(candidate) != len(cells):
            continue
        if all(
            re.fullmatch(r":?-{3,}:?", cell.replace(" ", ""))
            for cell in candidate
        ):
            if header_index == 0:
                return None
            header = markdown_table_cells(lines[header_index - 1])
            if header and len(header) == len(candidate):
                return header
            return None
    return None


def markdown_table_claim_cells(
    lines: list[str],
    index: int,
    phrase: str,
) -> list[tuple[str, bool, bool]] | None:
    cells = markdown_table_cells(lines[index])
    if cells is None:
        return None
    headers = markdown_table_headers(lines, index)
    row_is_negative = False
    if headers:
        for cell_index, header in enumerate(headers):
            if cell_index >= len(cells):
                continue
            if re.search(r"\b(?:truth\s+label|status|state|claim\s+class)\b", header, re.IGNORECASE):
                if has_negative_context(cells[cell_index]):
                    row_is_negative = True
                    break
    if cells and has_negative_context(cells[0]):
        row_is_negative = True
    result: list[tuple[str, bool, bool]] = []
    for cell_index, cell in enumerate(cells):
        if phrase.casefold() not in cell.casefold():
            continue
        header = headers[cell_index] if headers and cell_index < len(headers) else ""
        readiness_header = bool(re.search(r"\b(?:truth\s+label|status|state|claim\s+class)\b", header, re.IGNORECASE))
        result.append((cell, row_is_negative or has_negative_context(header), readiness_header))
    return result


def term_is_nonclaim_structure(line: str, term: str) -> bool:
    stripped = line.strip()
    if "--fixture" in stripped and "--proposed-claim" in stripped:
        return True
    if ":" not in stripped:
        return False
    key, value = stripped.split(":", 1)
    return term.casefold() in key.casefold() and not value.strip()


def term_is_affirmative_claim(line: str, term: str, readiness_cell: bool = False,
                              detection_ids: list[str] | None = None) -> bool:
    stripped = line.strip().strip('`"\'')
    stripped = re.sub(r"(?<!\w)(\*\*|__|\*|_)(?=\S)(.+?)(?<=\S)\1(?!\w)", r"\2", stripped)
    if readiness_cell and stripped.casefold() == term.casefold():
        return True
    identities = "|".join(re.escape(identity) for identity in
                          (detection_ids if detection_ids is not None else DETECTION_IDS))
    if re.fullmatch(rf"(?:#{{1,6}}\s+(?:{identities})(?:\s*[:—–-]\s*|\s+)|(?:{identities})\s*[:—–-]\s*){re.escape(term)}\s*[.!]?", stripped, re.IGNORECASE):
        return True
    folded_line = line.casefold()
    folded_term = term.casefold()
    escaped = re.escape(folded_term)
    predicate = AFFIRMATIVE_CLAIM_PREDICATE
    if re.search(rf"(?<![-_\w]){predicate}(?![-_\w]).{{0,120}}{escaped}", folded_line):
        return True
    if folded_term != "production" and re.search(
        rf"\b(?:uses|use)\b.{{0,120}}{escaped}",
        folded_line,
    ):
        return True
    if re.search(rf"{escaped}.{{0,80}}(?<![-_\w])(?:is|are|enabled|true|approved|active)(?![-_\w])", folded_line):
        return True
    key_pattern = re.escape(
        re.sub(r"[^a-z0-9]+", "_", folded_term).strip("_")
    ).replace("_", r"[-_\s]?")
    return bool(
        re.search(
            rf"[\"']?{key_pattern}[\"']?\s*[:=]\s*"
            r"(?:true|active|approved|authorized|deployed|observed|[-+]?[1-9][0-9]*)\b",
            folded_line,
        )
    )


def is_public_boundary_contract(text: str) -> bool:
    folded = text.casefold()
    return "cross_repo_claim_contract" in folded


def normalize_path_key(value: str) -> str:
    folded = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"[^a-z0-9]+", "_", folded).strip("_")


PROMOTION_AUTHORITY_KEYS = AUTHORITY_PROMOTION_KEYS | {
    normalize_path_key(term).replace("_", "") + suffix
    for term in PROMOTION_TERMS for suffix in AUTHORITY_CLAIM_SUFFIXES
}
DANGEROUS_AUTHORITY_PATHS = {
    "runtime_state",
    "runtime_status",
    "runtime_active",
    "signal_state",
    "signal_status",
    "signal_observed",
    "production_state",
    "production_status",
    "production_active",
    "approval_state",
    "approval_status",
    "ai_authority",
    "ai_disposition_authority",
    "analyst_authority",
    "analyst_disposition_authority",
    "final_authority",
    "final_authorization",
    "case_state",
    "case_status",
    "case_closure",
    "customer_state",
    "customer_status",
    "socaas_state",
    "socaas_status",
    "public_safe",
}


def assertive_authority_value(value: object) -> bool:
    if value is True:
        return True
    if value is False or value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    if not isinstance(value, str):
        return False
    numeric = re.fullmatch(r"[+-]?([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", unicodedata.normalize("NFKC", value.strip()))
    if numeric:
        # Inspect the mantissa exactly: avoid float underflow/overflow and keep
        # arbitrarily scaled mathematical zero inert.
        return any(character in "123456789" for character in numeric.group(1))
    return normalize_path_key(value) not in {"off", "no"} and not _explicitly_bounded_authority_value(value)


def rejected_contract_fixture_case_ids(repo_root: Path, rel_path: str, fixture: object) -> frozenset[str]:
    """Bind deliberately rejected contract inputs to their owning report cases."""
    canonical_path = rel_path.replace("\\", "/")
    if (not canonical_path.startswith("validation/") or not canonical_path.endswith("/validation-cases.json")
            or not isinstance(fixture, dict)):
        return frozenset()
    try:
        registry = load_registry(repo_root / "validation" / "VALIDATION_REGISTRY.yml")
        packages = _validate_registry_identity(registry)
        owners = [package for package in packages if isinstance(package, dict)
                  and package.get("fixture_file") == canonical_path
                  and package.get("detection_id") == fixture.get("detection_id")
                  and package.get("validation_kind") == "controlled_validation"]
        if len(owners) != 1:
            return frozenset()
        owner = owners[0]
        _validate_package_identity(owner)
        _rel_path(repo_root, owner["fixture_file"], "fixture_file", owner["detection_id"])
        report = _load_json(_rel_path(repo_root, owner["report_json"], "report_json", owner["detection_id"]), "fixture owner report")
        _validate_report_shape(report, owner, fixture)
        rejected_ids = {row["id"] for row in report.get("negative", [])
                        if row.get("expected") is False and row.get("matched") is False and row.get("pass") is True}
        # The exception describes direct boolean contract inputs, not containers
        # or contradictory expectation aliases that happen to share case IDs.
        return frozenset(case["id"] for case in fixture.get("cases", {}).get("negative", [])
                         if case.get("id") in rejected_ids and case.get("expected_match") is False
                         and ("expected" not in case or case["expected"] is False)
                         and ("expected_result" not in case or case["expected_result"] == "no_match")
                         and isinstance(case.get("contract"), dict)
                         and isinstance(case["contract"].get("blocked_promotion_fields"), dict)
                         and all(type(flag) is bool for flag in case["contract"]["blocked_promotion_fields"].values()))
    except (RegistryFailure, KeyError, TypeError, ValueError, OSError):
        return frozenset()


def structured_claim_items(
    value: object,
    detection_ids: list[str],
    surface: str,
    rel_path: str,
    enforce: bool,
    ancestry: tuple[str, ...] = (),
    context_ids: tuple[str, ...] = (),
    status_by_id: dict[str, set[str]] | None = None,
    schema_context: bool = False,
    list_item: bool = False,
    authority_context: bool = False,
    rejected_fixture_ids: frozenset[str] = frozenset(),
    rejected_fixture_case: bool = False,
) -> list[DriftItem]:
    items: list[DriftItem] = []
    leaf = ancestry[-1] if ancestry else ""
    authority_context = authority_context or any(
        "_".join(ancestry[offset:]) in DANGEROUS_AUTHORITY_PATHS
        or "".join(ancestry[offset:]).replace("_", "") in PROMOTION_AUTHORITY_KEYS
        for offset in range(len(ancestry))
    )
    if isinstance(value, dict):
        if ancestry == ("cases", "negative"):
            rejected_fixture_case = (
                isinstance(value.get("id"), str) and value["id"] in rejected_fixture_ids
                and value.get("expected_match") is False
                and all(value[field] is False for field in ("expected",) if field in value)
            )
        schema_context = schema_context or (
            isinstance(value.get("$schema"), str)
            and bool(re.fullmatch(r"https?://json-schema\.org/(?:draft/[0-9-]+|draft-[0-9]+)/schema#?", value["$schema"]))
        )
        schema_properties = (schema_context and leaf == "properties"
                             and all(isinstance(child, (dict, bool)) for child in value.values()))
        declared_ids = [child for key, child in value.items()
                        if normalize_path_key(str(key)) in {"detection_id", "rule_id"}
                        and not (schema_properties and isinstance(child, (dict, bool)))]
        local_ids = context_ids
        if declared_ids:
            if any(
                not isinstance(identity, str)
                or not CANONICAL_ID.fullmatch(identity.upper())
                or any(known.casefold() in identity.casefold() and known.casefold() != identity.casefold()
                       for known in detection_ids)
                for identity in declared_ids
            ) or len(
                {identity.casefold() for identity in declared_ids if isinstance(identity, str)}
            ) != 1:
                items.append(DriftItem("fail" if enforce else "warning", "GLOBAL", surface,
                                       rel_path, "structured detection identity is invalid or contradictory"))
                local_ids = ()
            else:
                local_ids = tuple(identity for identity in detection_ids
                                  if identity.casefold() == declared_ids[0].casefold())
        for key, child in value.items():
            normalized = normalize_path_key(str(key))
            items.extend(
                structured_claim_items(
                    child,
                    detection_ids,
                    surface,
                    rel_path,
                    enforce,
                    ancestry + (normalized,),
                    local_ids,
                    status_by_id,
                    schema_context,
                    False,
                    authority_context,
                    rejected_fixture_ids,
                    rejected_fixture_case,
                )
            )
        return items
    if isinstance(value, list):
        for child in value:
            items.extend(
                structured_claim_items(
                    child,
                    detection_ids,
                    surface,
                    rel_path,
                    enforce,
                    ancestry,
                    context_ids,
                    status_by_id,
                    schema_context,
                    True,
                    authority_context,
                    rejected_fixture_ids,
                    rejected_fixture_case,
                )
            )
        return items

    cumulative = "_".join(filter(None, ancestry))
    rejected_fixture_input = (
        rejected_fixture_case and len(ancestry) == 5
        and ancestry[:4] == ("cases", "negative", "contract", "blocked_promotion_fields")
        and leaf.replace("_", "") in PROMOTION_AUTHORITY_KEYS and type(value) is bool
    )
    if (
        authority_context and not rejected_fixture_input
        and not (leaf == "requires_human_approval" and value is True and not list_item
                 and "requires_human_approval" not in ancestry[:-1])
        and not (schema_context and "properties" in ancestry and "examples" not in ancestry
                 and ((leaf == "type" and value in {"object", "array", "boolean", "string", "integer", "number", "null"})
                      or (leaf == "enum" and value == "UNKNOWN")))
        and assertive_authority_value(value)
    ):
        items.append(
            DriftItem(
                severity="fail" if enforce else "warning",
                detection_id="GLOBAL",
                surface=surface,
                path=rel_path,
                message=f"assertive authority value at structured path: {cumulative}",
            )
        )

    if isinstance(value, str):
        mentioned_ids = tuple(identity for identity in detection_ids
                              if identity.casefold() in value.casefold())
        bounded_terms = (*PROMOTION_TERMS, *REQUIRED_BLOCKED_CLAIMS, *DANGEROUS_STATUS_TOKENS)
        bounded_leaf = (leaf in {
            "blocked_claims", "blocked_public_claims", "claims_not_supported",
            "does_not_support", "does_not_prove", "not_claimed_here",
        } or list_item and leaf in {
            "blocked_claim_categories", "unsupported_claims", "required_blocked_claims",
            "blocked_claim_wording", "blocked_proof_promotions", "not_supported",
        }) and value.strip().casefold() in {term.casefold() for term in bounded_terms}
        if list_item and leaf in {"not_proven", "blocked_repo_claim"}:
            # These owner fields enumerate blocked noun phrases or quoted claims,
            # never free-form summaries or nested claim-bearing records.
            identity_prefix = "|".join(re.escape(identity) for identity in detection_ids)
            bounded_leaf = any(re.fullmatch(
                rf"(?:(?:{identity_prefix})\s+(?:is|has)\s+)?{re.escape(term)}"
                r"(?:\s+(?:detection|status|proof|public proof|runtime proof))?",
                value.strip(), re.IGNORECASE,
            ) for term in bounded_terms)
        for detection_id in mentioned_ids or context_ids:
            if status_by_id is not None:
                status_by_id[detection_id].update(extract_status_tokens(value))
            text = value if detection_id.casefold() in value.casefold() else f"{detection_id}: {value}"
            if bounded_leaf:
                text = f"{detection_id}: do not claim {value}"
            items.extend(scan_promotion_terms(text, detection_id, surface, rel_path, enforce, detection_ids))
            items.extend(scan_status_tokens(text, detection_id, surface, rel_path, enforce, detection_ids))
    return items


def has_boundary(text: str, boundary_re: re.Pattern[str]) -> bool:
    compact = " ".join(text.split())
    return bool(boundary_re.search(compact))


def contains_claim(text: str, claim: str) -> bool:
    return claim.lower() in text.lower()


def extract_candidate_status_tokens(text: str) -> set[str]:
    return set(re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", text))


def scan_promotion_terms(
    text: str,
    detection_id: str,
    surface: str,
    rel_path: str,
    enforce: bool,
    detection_ids: list[str] | None = None,
) -> list[DriftItem]:
    items: list[DriftItem] = []
    lower_text = text.lower()
    if detection_id.lower() not in lower_text:
        return items

    lines = text.splitlines()
    for term in PROMOTION_TERMS:
        term_l = term.lower()
        for index, line in enumerate(lines):
            table_cells = markdown_table_claim_cells(lines, index, term)
            if table_cells is not None:
                if not line_is_associated_with_detection(lines, index, detection_id, detection_ids):
                    continue
                for cell, negative_header, readiness_cell in table_cells:
                    if (
                        not negative_header
                        and not has_negative_context(cell)
                        and term_is_affirmative_claim(cell, term, readiness_cell, detection_ids)
                    ):
                        items.append(
                            DriftItem(
                                severity="fail" if enforce else "warning",
                                detection_id=detection_id,
                                surface=surface,
                                path=f"{rel_path}:{index + 1}",
                                message=f"promotion term without blocked/negative context: {term}",
                            )
                        )
                continue
            if (
                term_l in line.lower()
                and line_is_associated_with_detection(lines, index, detection_id, detection_ids)
                and not term_is_nonclaim_structure(line, term)
                and not all(has_negative_context_for_phrase(lines, index, term, match.start(), detection_id, detection_ids)
                            for match in re.finditer(re.escape(term), line, re.IGNORECASE))
                and term_is_affirmative_claim(line, term, detection_ids=detection_ids)
            ):
                sev = "fail" if enforce else "warning"
                items.append(
                    DriftItem(
                        severity=sev,
                        detection_id=detection_id,
                        surface=surface,
                        path=f"{rel_path}:{index + 1}",
                        message=f"promotion term without blocked/negative context: {term}",
                    )
                )
    return items


def extract_status_tokens(text: str) -> set[str]:
    found: set[str] = set()
    for token in STATUS_TOKENS:
        if token in text:
            found.add(token)
    return found


def scan_status_tokens(
    text: str,
    detection_id: str,
    surface: str,
    rel_path: str,
    enforce: bool,
    detection_ids: list[str] | None = None,
) -> list[DriftItem]:
    items: list[DriftItem] = []
    if detection_id.lower() not in text.lower():
        return items

    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line_is_associated_with_detection(lines, index, detection_id, detection_ids):
            continue
        for token in extract_candidate_status_tokens(line):
            if token in ALLOWED_PROOF_CEILING_TOKENS:
                continue
            table_cells = markdown_table_claim_cells(lines, index, token)
            if table_cells is not None:
                if all(
                    negative_header or has_negative_context(cell)
                    for cell, negative_header, _ in table_cells
                ):
                    continue
            if (
                token in DANGEROUS_STATUS_TOKENS
                and not all(has_negative_context_for_phrase(lines, index, token, match.start(), detection_id, detection_ids)
                            for match in re.finditer(re.escape(token), line, re.IGNORECASE))
                and not (
                    re.fullmatch(rf"\s*#{{1,6}}\s+{re.escape(token)}\s*", line)
                    and re.fullmatch(r"\s*-?\s*Status\s*:\s*(?:NOT_SATISFIED|BLOCKED|NOT_PUBLIC_SAFE|false|0)\s*",
                                     next((candidate for candidate in lines[index + 1 : index + 4] if candidate.strip()), ""),
                                     re.IGNORECASE)
                )
            ):
                items.append(
                    DriftItem(
                        severity="fail" if enforce else "warning",
                        detection_id=detection_id,
                        surface=surface,
                        path=f"{rel_path}:{index + 1}",
                        message=f"dangerous status token without blocked/negative context: {token}",
                    )
                )
    return items


def scan_required_boundaries(
    text: str,
    detection_id: str,
    surface: str,
    rel_path: str,
    enforce: bool,
) -> list[DriftItem]:
    if detection_id.lower() not in text.lower():
        return []
    if not is_public_boundary_contract(text):
        return []

    severity = "fail" if enforce else "warning"
    items: list[DriftItem] = []
    if not has_boundary(text, RENDERING_BOUNDARY_RE):
        items.append(
            DriftItem(
                severity=severity,
                detection_id=detection_id,
                surface=surface,
                path=rel_path,
                message="missing rendering-not-proof boundary",
            )
        )
    if not has_boundary(text, HUMAN_REVIEW_RE):
        items.append(
            DriftItem(
                severity=severity,
                detection_id=detection_id,
                surface=surface,
                path=rel_path,
                message="missing human-review-required boundary",
            )
        )
    return items


def scan_required_blocked_claims(
    text: str,
    detection_id: str,
    surface: str,
    rel_path: str,
    enforce: bool,
) -> list[DriftItem]:
    if detection_id.lower() not in text.lower():
        return []
    if not is_public_boundary_contract(text):
        return []

    severity = "fail" if enforce else "warning"
    items: list[DriftItem] = []
    lines = text.splitlines()
    for claim in REQUIRED_BLOCKED_CLAIMS:
        if contains_claim(text, claim):
            claim_lines = [
                index
                for index, line in enumerate(lines)
                if claim.lower() in line.lower()
            ]
            if any(has_negative_context_for_line(lines, index) for index in claim_lines):
                continue
        items.append(
            DriftItem(
                severity=severity,
                detection_id=detection_id,
                surface=surface,
                path=rel_path,
                message=f"required blocked claim missing or not negated: {claim}",
            )
        )
    return items


def scan_release_wording(
    text: str,
    detection_id: str,
    surface: str,
    rel_path: str,
    enforce: bool,
) -> list[DriftItem]:
    if not PROOF_PACK_001_RE.search(text):
        return []

    items: list[DriftItem] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        window = line_window(lines, index)
        if PROOF_PACK_001_RE.search(window) and any(term.lower() in line.lower() for term in PROMOTION_TERMS):
            if not has_negative_context(window):
                items.append(
                    DriftItem(
                        severity="fail" if enforce else "warning",
                        detection_id=detection_id,
                        surface=surface,
                        path=f"{rel_path}:{index + 1}",
                        message="Proof Pack 001 release state contradiction",
                    )
                )
        if STALE_SNAPSHOT_RE.search(line):
            items.append(
                DriftItem(
                    severity="warning",
                    detection_id=detection_id,
                    surface=surface,
                    path=f"{rel_path}:{index + 1}",
                    message="stale release/snapshot wording requires review",
                )
            )
    return items


def scan_surface(
    surface: str,
    repo_root: Path,
    patterns: Iterable[str],
    detection_ids: list[str],
    enforce: bool,
) -> tuple[list[DriftItem], dict[str, set[str]], int]:
    drift: list[DriftItem] = []
    status_by_id: dict[str, set[str]] = {d: set() for d in detection_ids}
    if not repo_root.exists():
        drift.append(
            DriftItem("unknown", "GLOBAL", surface, str(repo_root), "missing repository")
        )
        return drift, status_by_id, 1

    files = collect_files(repo_root, patterns)
    if not files:
        drift.append(
            DriftItem("unknown", "GLOBAL", surface, str(repo_root), "no scan files found")
        )
        return drift, status_by_id, 1

    for file_path in files:
        rel_path = str(file_path.relative_to(repo_root))
        try:
            text = read_text(file_path)
        except (OSError, UnicodeError) as exc:
            drift.append(
                DriftItem(
                    severity="fail" if enforce else "warning",
                    detection_id="GLOBAL",
                    surface=surface,
                    path=rel_path,
                    message=f"declared text file is not readable strict UTF-8: {exc}",
                )
            )
            continue
        suffix = file_path.suffix.casefold()
        if suffix in {".json", ".yml", ".yaml"}:
            structured_kind = "JSON" if suffix == ".json" else "YAML"
            try:
                structured = (
                    json.loads(text, object_pairs_hook=reject_duplicate_json_keys,
                               parse_constant=reject_nonfinite_json_constant)
                    if suffix == ".json" else _load_strict_yaml(file_path, "claim surface")
                )
                validate_structured_values(structured)
            except (ValueError, TypeError, RegistryFailure, RecursionError) as exc:
                drift.append(
                    DriftItem(
                        severity="fail" if enforce else "warning",
                        detection_id="GLOBAL",
                        surface=surface,
                        path=rel_path,
                        message=f"declared {structured_kind} is malformed: {exc}",
                    )
                )
                continue
            drift.extend(
                structured_claim_items(
                    structured,
                    detection_ids,
                    surface,
                    rel_path,
                    enforce,
                    status_by_id=status_by_id,
                    rejected_fixture_ids=(rejected_contract_fixture_case_ids(repo_root, rel_path, structured)
                                          if surface == "validation" else frozenset()),
                )
            )
            continue
        lines = text.splitlines()
        prose_contract = is_public_boundary_contract(text)
        for detection_id in detection_ids:
            if detection_id.casefold() in text.casefold():
                associated_text = "\n".join(
                    line
                    for index, line in enumerate(lines)
                    if line_is_associated_with_detection(lines, index, detection_id, detection_ids)
                )
                status_by_id[detection_id].update(
                    extract_status_tokens(associated_text)
                )
                drift.extend(
                    scan_promotion_terms(
                        text=text,
                        detection_id=detection_id,
                        surface=surface,
                        rel_path=rel_path,
                        enforce=enforce,
                        detection_ids=detection_ids,
                    )
                )
                drift.extend(
                    scan_status_tokens(
                        text=text,
                        detection_id=detection_id,
                        surface=surface,
                        rel_path=rel_path,
                        enforce=enforce,
                        detection_ids=detection_ids,
                    )
                )
                if surface in PUBLIC_BOUNDARY_SURFACES and prose_contract:
                    drift.extend(
                        scan_required_boundaries(
                            text=text,
                            detection_id=detection_id,
                            surface=surface,
                            rel_path=rel_path,
                            enforce=enforce,
                        )
                    )
                    drift.extend(
                        scan_required_blocked_claims(
                            text=text,
                            detection_id=detection_id,
                            surface=surface,
                            rel_path=rel_path,
                            enforce=enforce,
                        )
                    )
                drift.extend(
                    scan_release_wording(
                        text=text,
                        detection_id=detection_id,
                        surface=surface,
                        rel_path=rel_path,
                        enforce=enforce,
                    )
                )
    return drift, status_by_id, 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify cross-repo claim parity and promotion boundaries")
    parser.add_argument("--repo-root", required=True, help="Root containing sibling HawkinsOperations repos")
    parser.add_argument("--report-only", action="store_true", help="Report drift but do not fail on warnings")
    parser.add_argument("--enforce", action="store_true", help="Fail closed on dangerous public-claim drift")
    parser.add_argument(
        "--fail-on-public-promotion",
        action="store_true",
        help="Compatibility alias for enforce-mode promotion failures",
    )
    args = parser.parse_args(argv)
    if args.report_only and args.enforce:
        parser.error("--report-only and --enforce cannot be combined")
    return args


def governed_detection_ids(validation_root: Path) -> list[str]:
    packages = _validate_registry_identity(load_registry(validation_root / "validation/VALIDATION_REGISTRY.yml"))
    identities = [_validate_package_identity(package) for package in packages]
    if len({identity.casefold() for identity in identities}) != len(identities):
        raise RegistryFailure("governed detection identities are duplicated")
    return identities


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    org_root = Path(args.repo_root).resolve()

    surface_specs = {
        "detections": (
            org_root / "hawkinsoperations-detections",
            ["detections/**/status.yml", "detections/**/rule.yml", "detections/**/event-mapping.yml"],
        ),
        "validation": (
            org_root / "hawkinsoperations-validation",
            ["reports/**/*.json", "validation/**/*.json", "validation/VALIDATION_REGISTRY.yml", "docs/**/*.md"],
        ),
        "proof": (
            org_root / "hawkinsoperations-proof",
            ["proof/records/*.md", "proof/cards/*.md", "proof/records/*.json"],
        ),
        "website": (
            org_root / "hawkinsoperations-website",
            ["src/**/*.*", "data/**/*.*", "docs/**/*.md", "README.md", "index.html"],
        ),
        "org_front_door": (
            org_root / ".github",
            ["profile/**/*.md", "governance/**/*.md", "README.md"],
        ),
        "platform": (
            org_root / "hawkinsoperations-platform",
            ["README.md", "docs/**/*.md", "contracts/**/*.json"],
        ),
    }

    enforce = args.enforce or args.fail_on_public_promotion
    drift_items: list[DriftItem] = []
    per_surface_status: dict[str, dict[str, set[str]]] = {}
    try:
        all_ids = governed_detection_ids(org_root / "hawkinsoperations-validation")
    except (RegistryFailure, KeyError, TypeError, ValueError, OSError):
        print("STATUS=fail\nFAIL_COUNT=1\nWARNING_COUNT=0\nUNKNOWN_COUNT=0")
        print('DRIFT_ITEMS=' + json.dumps([DriftItem("fail", "GLOBAL", "validation", "validation/VALIDATION_REGISTRY.yml",
              "governed detection inventory unavailable or invalid").to_dict()]))
        return 1

    for surface, (repo_path, patterns) in surface_specs.items():
        items, status_map, unknown = scan_surface(
            surface=surface,
            repo_root=repo_path,
            patterns=patterns,
            detection_ids=all_ids,
            enforce=enforce,
        )
        drift_items.extend(items)
        per_surface_status[surface] = status_map

    for detection_id in all_ids:
        seen_surfaces = [
            s
            for s, status_map in per_surface_status.items()
            if status_map.get(detection_id) and len(status_map[detection_id]) > 0
        ]
        if not seen_surfaces:
            drift_items.append(
                DriftItem(
                    severity="unknown",
                    detection_id=detection_id,
                    surface="all",
                    path="",
                    message="detection id not found in scanned surfaces",
                )
            )

    # Status drift heuristic: if a detection appears with both SOURCE_EXISTS and
    # stronger status tokens across surfaces, flag as warning for parity review.
    stronger = {"CONTROLLED_TEST_VALIDATED", "PRIVATE_RUNTIME_EVIDENCE_CAPTURED"}
    for detection_id in all_ids:
        union_tokens: set[str] = set()
        for status_map in per_surface_status.values():
            union_tokens.update(status_map.get(detection_id, set()))
        if "SOURCE_EXISTS" in union_tokens and union_tokens.intersection(stronger):
            drift_items.append(
                DriftItem(
                    severity="warning",
                    detection_id=detection_id,
                    surface="cross-repo",
                    path="",
                    message=(
                        "mixed status language detected across surfaces "
                        f"({', '.join(sorted(union_tokens))})"
                    ),
                )
            )

    deduped: list[DriftItem] = []
    seen_keys: set[tuple[str, str, str, str, str]] = set()
    for item in drift_items:
        key = (item.severity, item.detection_id, item.surface, item.path, item.message)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(item)
    drift_items = deduped

    fail_count = sum(1 for item in drift_items if item.severity == "fail")
    warning_count = sum(1 for item in drift_items if item.severity == "warning")
    unknown_count = sum(1 for item in drift_items if item.severity == "unknown")

    status = "pass"
    if fail_count > 0 or unknown_count > 0:
        status = "fail"
    if args.report_only:
        status = "pass"

    print(f"STATUS={status}")
    print(f"FAIL_COUNT={fail_count}")
    print(f"WARNING_COUNT={warning_count}")
    print(f"UNKNOWN_COUNT={unknown_count}")
    print(f"DRIFT_ITEMS={json.dumps([item.to_dict() for item in drift_items], ensure_ascii=True)}")

    if status == "fail":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

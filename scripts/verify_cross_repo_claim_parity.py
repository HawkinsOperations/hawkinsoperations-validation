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
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

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
) -> bool:
    scoped_ids = {
        candidate
        for line in lines
        for candidate in DETECTION_IDS
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
            for candidate in DETECTION_IDS
            if candidate.casefold() in candidate_line.casefold()
        ]
        if referenced:
            return referenced == [detection_id]
    return False


def has_negative_context_for_phrase(
    lines: list[str],
    index: int,
    phrase: str,
) -> bool:
    line = lines[index]
    folded = line.casefold()
    start = folded.find(phrase.casefold())
    if start < 0:
        return False
    end = start + len(phrase)
    prefix = line[:start].casefold()
    clause_start = max(
        prefix.rfind(", but "),
        prefix.rfind(" but "),
        prefix.rfind(" however "),
    )
    if clause_start >= 0:
        clause_start += 1
    else:
        clause_start = 0
    local = line[clause_start : min(len(line), end + 96)]
    if has_negative_context(local):
        return True
    suffix = line[end:]
    adversative = re.search(r"\b(?:but|however|although|yet)\b", suffix, re.IGNORECASE)
    direct_suffix = suffix if adversative is None else suffix[: adversative.start()]
    if re.search(
        r"\b(?:remain(?:s)?|is|are|must\s+remain)\s+"
        r"(?:blocked|unsupported|not\s+(?:approved|authorized|proven|public[-_\s]?safe))\b",
        direct_suffix,
        re.IGNORECASE,
    ):
        return True
    if index > 0:
        previous = lines[index - 1]
        if (
            previous.strip()
            and not previous.rstrip().endswith((".", "?", "!"))
            and has_negative_context(previous)
        ):
            return True
    stripped = line.lstrip()
    if stripped.startswith(("-", "*")) or line.startswith((" ", "\t")):
        for section_index in range(index - 1, max(-1, index - 80), -1):
            candidate = lines[section_index]
            candidate_stripped = candidate.lstrip()
            if candidate_stripped.startswith("#"):
                return has_negative_context(candidate)
            if candidate.rstrip().endswith(":") and has_negative_context(candidate):
                return True
    for parent_index in range(index - 1, -1, -1):
        candidate = lines[parent_index]
        if not candidate.strip():
            break
        if candidate.strip() and candidate.rstrip().endswith(":") and has_negative_context(candidate):
            return True
        if candidate.lstrip().startswith("#"):
            if has_negative_context(candidate):
                return True
            break
    continuation = stripped.startswith(("-", "*")) or line.startswith((" ", "\t"))
    for offset in range(1, 41):
        parent_index = index - offset
        if parent_index < 0:
            break
        candidate = lines[parent_index]
        if not candidate.strip():
            break
        if candidate.rstrip().endswith(":") and has_negative_context(candidate):
            return True
        candidate_stripped = candidate.lstrip()
        if (
            candidate_stripped
            and not candidate_stripped.startswith(("-", "*"))
            and not candidate.startswith((" ", "\t"))
            and candidate.rstrip().endswith(":")
        ):
            break
    paragraph: list[str] = []
    for parent_index in range(index - 1, -1, -1):
        candidate = lines[parent_index]
        if not candidate.strip() or candidate.rstrip().endswith((".", "?", "!")):
            break
        paragraph.append(candidate)
    if paragraph and has_negative_context(" ".join(reversed(paragraph))):
        return True
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
) -> list[tuple[str, bool]] | None:
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
    result: list[tuple[str, bool]] = []
    for cell_index, cell in enumerate(cells):
        if phrase.casefold() not in cell.casefold():
            continue
        header = headers[cell_index] if headers and cell_index < len(headers) else ""
        result.append((cell, row_is_negative or has_negative_context(header)))
    return result


def term_is_nonclaim_structure(line: str, term: str) -> bool:
    stripped = line.strip()
    if "--fixture" in stripped and "--proposed-claim" in stripped:
        return True
    if ":" not in stripped:
        return False
    key, value = stripped.split(":", 1)
    return term.casefold() in key.casefold() and not value.strip()


def term_is_affirmative_claim(line: str, term: str) -> bool:
    folded_line = line.casefold()
    folded_term = term.casefold()
    escaped = re.escape(folded_term)
    predicate = (
        r"(?:is|are|has|have|proves|establishes|confirms|"
        r"claims|declares|enables|enabled|observed|approved|authorized|deployed)"
    )
    if re.search(rf"\b{predicate}\b.{{0,120}}{escaped}", folded_line):
        return True
    if folded_term != "production" and re.search(
        rf"\b(?:uses|use)\b.{{0,120}}{escaped}",
        folded_line,
    ):
        return True
    if re.search(rf"{escaped}.{{0,80}}\b(?:is|are|enabled|true|approved|active)\b", folded_line):
        return True
    key_pattern = re.escape(
        re.sub(r"[^a-z0-9]+", "_", folded_term).strip("_")
    ).replace("_", r"[-_\s]?")
    return bool(
        re.search(
            rf"[\"']?{key_pattern}[\"']?\s*[:=]\s*"
            r"(?:true|active|approved|authorized|deployed|observed)\b",
            folded_line,
        )
    )


def is_public_boundary_contract(text: str) -> bool:
    folded = text.casefold()
    return "cross_repo_claim_contract" in folded


def normalize_path_key(value: str) -> str:
    folded = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"[^a-z0-9]+", "_", folded).strip("_")


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
    normalized = normalize_path_key(value)
    return normalized in {
        "active",
        "approved",
        "authorized",
        "closed",
        "complete",
        "customer_deployed",
        "deployed",
        "enabled",
        "final",
        "observed",
        "production",
        "production_ready",
        "public_safe",
        "granted",
        "live",
        "ready",
        "true",
        "yes",
        "runtime_active",
        "signal_observed",
        "socaas_active",
    }


def structured_claim_items(
    value: object,
    detection_ids: list[str],
    surface: str,
    rel_path: str,
    enforce: bool,
    ancestry: tuple[str, ...] = (),
) -> list[DriftItem]:
    items: list[DriftItem] = []
    leaf = ancestry[-1] if ancestry else ""
    if isinstance(value, dict):
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
                )
            )
        return items

    cumulative = "_".join(filter(None, ancestry))
    if (
        leaf in DANGEROUS_AUTHORITY_PATHS
        and not has_negative_context(leaf)
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

    if isinstance(value, str) and not has_negative_context(cumulative):
        for detection_id in detection_ids:
            if detection_id in value:
                items.extend(
                    scan_promotion_terms(
                        text=value,
                        detection_id=detection_id,
                        surface=surface,
                        rel_path=rel_path,
                        enforce=enforce,
                    )
                )
                items.extend(
                    scan_status_tokens(
                        text=value,
                        detection_id=detection_id,
                        surface=surface,
                        rel_path=rel_path,
                        enforce=enforce,
                    )
                )
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
                if not line_is_associated_with_detection(lines, index, detection_id):
                    continue
                for cell, negative_header in table_cells:
                    if (
                        not negative_header
                        and not has_negative_context(cell)
                        and term_is_affirmative_claim(cell, term)
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
                and line_is_associated_with_detection(lines, index, detection_id)
                and not term_is_nonclaim_structure(line, term)
                and not has_negative_context_for_phrase(lines, index, term)
                and term_is_affirmative_claim(line, term)
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
) -> list[DriftItem]:
    items: list[DriftItem] = []
    if detection_id.lower() not in text.lower():
        return items

    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line_is_associated_with_detection(lines, index, detection_id):
            continue
        for token in extract_candidate_status_tokens(line):
            if token in ALLOWED_PROOF_CEILING_TOKENS:
                continue
            table_cells = markdown_table_claim_cells(lines, index, token)
            if table_cells is not None:
                if all(
                    negative_header or has_negative_context(cell)
                    for cell, negative_header in table_cells
                ):
                    continue
            if (
                token in DANGEROUS_STATUS_TOKENS
                and not has_negative_context_for_phrase(lines, index, token)
                and not (
                    line.lstrip().startswith("#")
                    and any(
                        has_negative_context(candidate)
                        for candidate in lines[index + 1 : index + 4]
                    )
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
        if file_path.suffix.casefold() == ".json":
            try:
                structured = json.loads(
                    text,
                    object_pairs_hook=reject_duplicate_json_keys,
                )
            except (json.JSONDecodeError, DuplicateJsonKeyError) as exc:
                drift.append(
                    DriftItem(
                        severity="fail" if enforce else "warning",
                        detection_id="GLOBAL",
                        surface=surface,
                        path=rel_path,
                        message=f"declared JSON is malformed: {exc}",
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
                )
            )
            serialized = json.dumps(structured, ensure_ascii=True)
            for detection_id in detection_ids:
                if detection_id in serialized:
                    status_by_id[detection_id].update(
                        extract_status_tokens(serialized)
                    )
            continue
        lines = text.splitlines()
        prose_contract = is_public_boundary_contract(text)
        for detection_id in detection_ids:
            if detection_id in text:
                associated_text = "\n".join(
                    line
                    for index, line in enumerate(lines)
                    if line_is_associated_with_detection(lines, index, detection_id)
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
                    )
                )
                drift.extend(
                    scan_status_tokens(
                        text=text,
                        detection_id=detection_id,
                        surface=surface,
                        rel_path=rel_path,
                        enforce=enforce,
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
            ["reports/**/*.json", "validation/**/*.json", "docs/**/*.md"],
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
    all_ids = DETECTION_IDS.copy()

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

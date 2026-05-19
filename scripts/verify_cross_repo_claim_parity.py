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
    r"\b(block|blocked|blocking|not|no|none|without|cannot|does\s+not|do\s+not|"
    r"must\s+not|remains\s+blocked|requires|pending|unsupported|not\s+proven|"
    r"not\s+public[-_\s]?safe|claims_not_supported|blocked_claims|blocked_public_claims|"
    r"claim[_\s-]?boundary|not[_\s-]?approved|not[_\s-]?authorized)\b",
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


def fail(message: str) -> int:
    print(f"STATUS=fail")
    print("FAIL_COUNT=1")
    print("WARNING_COUNT=0")
    print("UNKNOWN_COUNT=1")
    print(f"DRIFT_ITEMS={json.dumps([{'severity': 'fail', 'detection_id': 'GLOBAL', 'surface': 'scanner', 'path': '', 'message': message}])}")
    return 1


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")


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
            if term_l in line.lower() and not has_negative_context_for_line(lines, index):
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
        for token in extract_candidate_status_tokens(line):
            if token in ALLOWED_PROOF_CEILING_TOKENS:
                continue
            if token in DANGEROUS_STATUS_TOKENS and not has_negative_context_for_line(lines, index):
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
        text = read_text(file_path)
        tokens = extract_status_tokens(text)
        for detection_id in detection_ids:
            if detection_id in text:
                status_by_id[detection_id].update(tokens)
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
                if surface in PUBLIC_BOUNDARY_SURFACES:
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
    if fail_count > 0:
        status = "fail"
    elif warning_count > 0 and not args.report_only:
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

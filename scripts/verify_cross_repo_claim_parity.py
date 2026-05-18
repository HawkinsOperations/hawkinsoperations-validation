#!/usr/bin/env python3
"""Cross-repo proof/claim parity scanner for HawkinsOperations.

This checker is read-only. It scans selected sibling repositories for scoped
detection IDs and claim language drift, and can fail closed on public-promotion
terms outside blocked/negative context.
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
    "runtime-active",
    "signal-observed",
    "public-safe runtime proof",
    "autonomous SOC",
    "AI-approved",
    "analyst-approved",
    "fleet-wide",
    "live Splunk",
    "Wazuh-routed",
    "Cribl-routed",
    "Security Onion public proof",
]

STATUS_TOKENS = {
    "SOURCE_EXISTS",
    "CONTROLLED_TEST_VALIDATED",
    "TEST_VALIDATED_SYNTHETIC_SCOPE",
    "PRIVATE_RUNTIME_EVIDENCE_CAPTURED",
    "BOUNDARY_CONTRACT_ONLY",
    "NOT_PUBLIC_SAFE",
    "BLOCKED",
}

NEGATIVE_CONTEXT_RE = re.compile(
    r"\b(block|blocked|not|no|without|does\s+not|do\s+not|remains\s+blocked|"
    r"requires|pending|unsupported|claims_not_supported|blocked_claims)\b",
    re.IGNORECASE,
)

TEXT_EXTS = {".md", ".yml", ".yaml", ".json", ".html", ".ts", ".js", ".mjs"}


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


def scan_promotion_terms(
    text: str,
    detection_id: str,
    surface: str,
    rel_path: str,
    fail_on_public_promotion: bool,
) -> list[DriftItem]:
    items: list[DriftItem] = []
    lower_text = text.lower()
    if detection_id.lower() not in lower_text:
        return items

    for term in PROMOTION_TERMS:
        term_l = term.lower()
        for line_no, line in enumerate(text.splitlines(), start=1):
            if term_l in line.lower() and not has_negative_context(line):
                sev = "fail" if fail_on_public_promotion else "warning"
                items.append(
                    DriftItem(
                        severity=sev,
                        detection_id=detection_id,
                        surface=surface,
                        path=f"{rel_path}:{line_no}",
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


def scan_surface(
    surface: str,
    repo_root: Path,
    patterns: Iterable[str],
    detection_ids: list[str],
    fail_on_public_promotion: bool,
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
                        fail_on_public_promotion=fail_on_public_promotion,
                    )
                )
    return drift, status_by_id, 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify cross-repo claim parity and promotion boundaries")
    parser.add_argument("--repo-root", required=True, help="Root containing sibling HawkinsOperations repos")
    parser.add_argument("--report-only", action="store_true", help="Report drift but do not fail on warnings")
    parser.add_argument(
        "--fail-on-public-promotion",
        action="store_true",
        help="Fail if public-promotion terms appear outside blocked/negative context",
    )
    return parser.parse_args(argv)


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

    fail_on_public_promotion = args.fail_on_public_promotion
    drift_items: list[DriftItem] = []
    per_surface_status: dict[str, dict[str, set[str]]] = {}
    all_ids = DETECTION_IDS.copy()

    for surface, (repo_path, patterns) in surface_specs.items():
        items, status_map, unknown = scan_surface(
            surface=surface,
            repo_root=repo_path,
            patterns=patterns,
            detection_ids=all_ids,
            fail_on_public_promotion=fail_on_public_promotion,
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
    stronger = {"CONTROLLED_TEST_VALIDATED", "TEST_VALIDATED_SYNTHETIC_SCOPE", "PRIVATE_RUNTIME_EVIDENCE_CAPTURED"}
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

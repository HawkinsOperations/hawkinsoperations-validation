#!/usr/bin/env python3
"""Shared helpers for HawkinsOperations validation scripts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


class ContractFailure(Exception):
    """Raised when a validation contract is inconsistent or unsafe."""


def fail(message: str) -> None:
    raise ContractFailure(message)


def ensure_check_mode(write: bool = False) -> None:
    """Guard to keep scripts in check-mode unless explicit write path is enabled."""
    if write:
        fail("write mode is blocked for this validator")


def _label_path(path: Path, root: Path | None) -> str:
    if root:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            pass
    return str(path)


def load_json(path: Path, label: str, *, root: Path | None = None) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing {label}: {_label_path(path, root)}")
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {label} ({_label_path(path, root)}): {exc}")
    if not isinstance(data, dict):
        fail(f"{label} must be a JSON object")
    return data


def iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, dict):
        for child in value.values():
            yield from iter_strings(child)
        return
    if isinstance(value, list):
        for child in value:
            yield from iter_strings(child)


def find_forbidden_terms(payload: Any, forbidden_terms: list[str]) -> list[str]:
    lowered = [(term, term.lower()) for term in forbidden_terms if term]
    found: set[str] = set()
    for text in iter_strings(payload):
        haystack = text.lower()
        for original, lowered_term in lowered:
            if lowered_term in haystack:
                found.add(original)
    return sorted(found)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_report_case_parity(case_ids: set[str], result_ids: set[str], *, side: str) -> None:
    if case_ids != result_ids:
        missing = sorted(case_ids - result_ids)
        extra = sorted(result_ids - case_ids)
        fail(
            f"{side} report IDs do not match validation cases: "
            f"missing={missing}, extra={extra}"
        )

#!/usr/bin/env python3
"""Shared helpers for HawkinsOperations validation scripts."""

from __future__ import annotations

import hashlib
import json
import unicodedata
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


def strict_json_loads(text: str, label: str = "JSON") -> Any:
    """Parse JSON while rejecting normalized duplicate object keys.

    Python's default JSON decoder silently keeps the last duplicate key. That
    behavior is unsafe for authority and claim fields because a reviewer can
    see one value while the verifier consumes another. Object keys are compared
    after NFKC normalization and case folding at every nesting depth.
    """

    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        normalized_keys: dict[str, str] = {}
        for key, value in pairs:
            if not isinstance(key, str):
                fail(f"{label} contains a non-string object key")
            normalized = unicodedata.normalize("NFKC", key).casefold()
            if normalized in normalized_keys:
                first = normalized_keys[normalized]
                fail(
                    f"{label} contains duplicate object keys after "
                    f"NFKC/casefold normalization: {first!r} and {key!r}"
                )
            normalized_keys[normalized] = key
            result[key] = value
        return result

    def reject_non_standard_constant(value: str) -> Any:
        fail(f"{label} contains non-standard JSON numeric constant: {value}")

    try:
        return json.loads(
            text,
            object_pairs_hook=strict_object,
            parse_constant=reject_non_standard_constant,
        )
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {label}: {exc}")


def strict_json_object(text: str, label: str = "JSON") -> dict[str, Any]:
    value = strict_json_loads(text, label)
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def load_json(path: Path, label: str, *, root: Path | None = None) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing {label}: {_label_path(path, root)}")
    path_label = f"{label} ({_label_path(path, root)})"
    return strict_json_object(path.read_text(encoding="utf-8"), path_label)


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

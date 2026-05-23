#!/usr/bin/env python3
"""Verify a private HO-DET-011 runtime receipt.

This verifier checks receipt structure and runtime-proof boundaries only. It
does not read raw telemetry, query runtime systems, or promote public proof.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


REQUIRED_SCHEMA = "ho-det-011-runtime-receipt-private-v1"
RUN_ID_RE = re.compile(r"^HO-DET-011-RUNTIME-\d{8}-\d{6}$")
CORRELATION_ID_RE = re.compile(r"^HO_DET_011_\d{8}_\d{6}_[0-9a-f]{8}$")
ALLOWED_PUBLIC_SAFE_STATUS = {"REVIEW_REQUIRED", "NOT_PUBLIC_SAFE"}
BLOCKED_PUBLIC_STATUSES = {"PUBLIC_SAFE", "PUBLIC_SAFE_APPROVED", "PUBLIC_PROOF_SAFE"}


def fail(message: str) -> None:
    print("HO_DET_011_RUNTIME_RECEIPT=fail")
    print("PUBLIC_SAFE_STATUS=REVIEW_REQUIRED")
    print("PROMOTION_STATUS=BLOCKED")
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing receipt: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        fail(f"invalid receipt JSON: {exc}")
    if not isinstance(value, dict):
        fail("receipt must be a JSON object")
    return value


def require_bool(data: dict[str, Any], key: str, expected: bool) -> None:
    if data.get(key) is not expected:
        fail(f"{key} must be {expected}")


def require_int_at_least(data: dict[str, Any], key: str, minimum: int) -> int:
    value = data.get(key)
    if not isinstance(value, int) or value < minimum:
        fail(f"{key} must be an integer >= {minimum}")
    return value


def require_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        fail(f"{key} must be a non-empty string")
    return value


def verify_receipt(data: dict[str, Any]) -> None:
    if data.get("schema") != REQUIRED_SCHEMA:
        fail(f"schema must be {REQUIRED_SCHEMA}")

    run_id = require_string(data, "run_id")
    if not RUN_ID_RE.match(run_id):
        fail("run_id format is invalid")

    correlation_id = require_string(data, "correlation_id")
    if not CORRELATION_ID_RE.match(correlation_id):
        fail("correlation_id format is invalid")

    service_name = require_string(data, "service_name")
    if correlation_id not in service_name:
        fail("service_name must include correlation_id")

    require_string(data, "host")
    require_string(data, "user")
    require_string(data, "benign_binary")

    create_exit = data.get("service_create_exit_code")
    if create_exit is not None and not isinstance(create_exit, int):
        fail("service_create_exit_code must be an integer or null")

    local_system = require_int_at_least(data, "local_system_7045_count", 0)
    local_security = require_int_at_least(data, "local_security_4697_count", 0)
    local_sysmon = require_int_at_least(data, "local_sysmon_1_count", 0)
    if local_system + local_security + local_sysmon < 1:
        fail("at least one local 7045, 4697, or Sysmon 1 event is required")

    require_int_at_least(data, "wazuh_query_exit_code", 0)
    if data["wazuh_query_exit_code"] != 0:
        fail("wazuh_query_exit_code must be 0")
    require_int_at_least(data, "wazuh_matching_lines", 1)

    cleanup_exit = data.get("cleanup_exit_code")
    if cleanup_exit is not None and cleanup_exit != 0:
        fail("cleanup_exit_code must be 0 or null only when cleanup was not needed")
    require_bool(data, "service_absent", True)

    if not (create_exit == 0 or local_system + local_security + local_sysmon >= 1):
        fail("service creation must succeed or be locally recorded")
    require_bool(data, "minimum_success", True)

    missing_fields = data.get("missing_fields")
    if missing_fields not in ([], None):
        fail("missing_fields must be empty for a passing runtime receipt")

    if data.get("splunk_status") != "NOT_VERIFIED":
        fail("splunk_status must remain NOT_VERIFIED")
    require_bool(data, "raw_private_evidence_public", False)
    require_bool(data, "ai_decided_disposition", False)
    require_bool(data, "human_review_required", True)
    require_bool(data, "public_safe", False)

    public_safe_status = data.get("public_safe_status")
    if public_safe_status in BLOCKED_PUBLIC_STATUSES:
        fail("receipt must not self-promote public-safe or public-proof status")
    if public_safe_status not in ALLOWED_PUBLIC_SAFE_STATUS:
        fail("public_safe_status must remain REVIEW_REQUIRED or NOT_PUBLIC_SAFE")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path, help="Private runtime receipt JSON path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    receipt = load_json(args.receipt)
    verify_receipt(receipt)
    print("HO_DET_011_RUNTIME_RECEIPT=pass")
    print(f"RUN_ID={receipt['run_id']}")
    print(f"CORRELATION_ID={receipt['correlation_id']}")
    print("PUBLIC_SAFE_STATUS=REVIEW_REQUIRED")
    print("PROMOTION_STATUS=BLOCKED_PENDING_HUMAN_REVIEW")
    print("RAW_PRIVATE_EVIDENCE_PUBLIC=false")
    print("AI_DECIDED_DISPOSITION=false")
    print("HUMAN_REVIEW_REQUIRED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Deterministic controlled-test AutoSOC triage packet generator for HO-DET-001."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from validation_lib import ContractFailure, strict_json_object


ROOT = Path(__file__).resolve().parents[1]
PACKET_PATH = ROOT / "validation" / "successor" / "ho-det-001" / "autosoc-triage-packet.json"
UNSUPPORTED_CLAIMS = [
    "live AutoSOC",
    "production triage",
    "analyst-approved disposition",
    "runtime-active",
    "signal-observed",
    "public-safe",
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing validation result: {path}")
    try:
        return strict_json_object(path.read_text(encoding="utf-8"), "validation result")
    except ContractFailure as exc:
        fail(str(exc))


def sha256_repo_text_file(path: Path) -> str:
    """Hash text as it is stored in the repo blob.

    Git normalizes these committed JSON text artifacts to LF. Windows checkouts
    can materialize them as CRLF, so provenance hashes normalize CRLF to LF to
    match the committed/GitHub blob bytes instead of local checkout bytes.
    """

    text = path.read_text(encoding="utf-8")
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def comparable_packet(packet: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(packet)
    normalized.pop("generated_at", None)
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate HO-DET-001 controlled-test AutoSOC triage packet.")
    parser.add_argument("--input", required=True, type=Path, help="Path to validation-result.json")
    parser.add_argument(
        "--write",
        action="store_true",
        help="Regenerate autosoc-triage-packet.json. Default is check-only and writes nothing.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run check-only mode. This is the default and is kept for explicit CI/readiness usage.",
    )
    args = parser.parse_args()

    result_path = args.input.resolve()
    result = load_json(result_path)
    if result.get("detection_id") != "HO-DET-001":
        fail("validation result detection_id must be HO-DET-001")
    if result.get("status") != "pass":
        fail("refusing to generate triage packet because validation status is not pass")

    matched = int(result.get("matched_positive_count", 0))
    missed = list(result.get("missed_positive_cases", []))
    false_positive = list(result.get("false_positive_negative_cases", []))
    disposition = "REVIEW_CONTROLLED_TEST_DETECTION"
    reason = (
        "Controlled-test HO-DET-001 fixtures matched expected encoded-command positives "
        "and did not match controlled negatives."
    )

    packet = {
        "packet_id": "HO-DET-001-CONTROLLED-TEST-TRIAGE-001",
        "detection_id": "HO-DET-001",
        "controlled_test_case_refs": {
            "positive_count": int(result.get("totals", {}).get("positive_cases", 0)),
            "negative_count": int(result.get("totals", {}).get("negative_cases", 0)),
        },
        "validation_result_ref": "hawkinsoperations-validation/reports/ho-det-001/validation-result.json",
        "validation_result_hash": sha256_repo_text_file(result_path),
        "disposition": disposition,
        "disposition_basis": "deterministic controlled-test validation result only",
        "reason": reason,
        "matched_positive_count": matched,
        "missed_positive_cases": missed,
        "false_positive_negative_cases": false_positive,
        "unsupported_claims": UNSUPPORTED_CLAIMS,
        "privacy_status": "Controlled-test validation output only; no live telemetry, secrets, private hostnames, or private addresses intentionally included.",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }

    if args.write:
        PACKET_PATH.parent.mkdir(parents=True, exist_ok=True)
        PACKET_PATH.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
    else:
        committed = load_json(PACKET_PATH)
        if comparable_packet(committed) != comparable_packet(packet):
            print("FAIL: committed autosoc-triage-packet.json does not match computed packet", file=sys.stderr)
            print(f"EXPECTED_VALIDATION_RESULT_HASH={packet['validation_result_hash']}", file=sys.stderr)
            print(f"COMMITTED_VALIDATION_RESULT_HASH={committed.get('validation_result_hash', '')}", file=sys.stderr)
            return 1
    print("STATUS=pass")
    print(f"MODE={'write' if args.write else 'check'}")
    print(f"PACKET_ID={packet['packet_id']}")
    print(f"DISPOSITION={packet['disposition']}")
    print(f"VALIDATION_RESULT_HASH={packet['validation_result_hash']}")
    if args.write:
        print(f"PACKET={PACKET_PATH}")
    else:
        print("WRITE_SKIPPED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

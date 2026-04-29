#!/usr/bin/env python3
"""Deterministic synthetic AutoSOC triage packet generator for HO-DET-001."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid validation result JSON: {exc}")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate HO-DET-001 synthetic AutoSOC triage packet.")
    parser.add_argument("--input", required=True, type=Path, help="Path to validation-result.json")
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
    disposition = "REVIEW_SYNTHETIC_DETECTION"
    reason = (
        "Synthetic HO-DET-001 fixtures matched expected encoded-command positives "
        "and did not match controlled negatives."
    )

    packet = {
        "packet_id": "HO-DET-001-SYNTHETIC-TRIAGE-001",
        "detection_id": "HO-DET-001",
        "synthetic_case_refs": {
            "positive_count": int(result.get("totals", {}).get("positive_cases", 0)),
            "negative_count": int(result.get("totals", {}).get("negative_cases", 0)),
        },
        "validation_result_ref": "hawkinsoperations-validation/reports/ho-det-001/validation-result.json",
        "validation_result_hash": sha256_file(result_path),
        "disposition": disposition,
        "disposition_basis": "deterministic synthetic validation result only",
        "reason": reason,
        "matched_positive_count": matched,
        "missed_positive_cases": missed,
        "false_positive_negative_cases": false_positive,
        "unsupported_claims": UNSUPPORTED_CLAIMS,
        "privacy_status": "Synthetic validation output only; no live telemetry, secrets, private hostnames, or private addresses intentionally included.",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }

    PACKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    PACKET_PATH.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
    print("STATUS=pass")
    print(f"PACKET_ID={packet['packet_id']}")
    print(f"DISPOSITION={packet['disposition']}")
    print(f"VALIDATION_RESULT_HASH={packet['validation_result_hash']}")
    print(f"PACKET={PACKET_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

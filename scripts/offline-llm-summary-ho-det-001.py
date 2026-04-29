#!/usr/bin/env python3
"""Deterministic offline LLM support stub for HO-DET-001 synthetic triage."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SUMMARY_PATH = ROOT / "validation" / "successor" / "ho-det-001" / "llm-summary.json"
UNSUPPORTED_CLAIMS = [
    "HO-GPU-01 runtime-active",
    "offline LLM validated",
    "AI decided disposition",
    "public-safe",
    "production-ready",
    "signal-observed",
    "evidence-linked",
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing triage packet: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid triage packet JSON: {exc}")


def sha256_repo_text_file(path: Path) -> str:
    """Hash text as it is stored in the repo blob.

    Git normalizes these committed JSON text artifacts to LF. Windows checkouts
    can materialize them as CRLF, so provenance hashes normalize CRLF to LF to
    match the committed/GitHub blob bytes instead of local checkout bytes.
    """

    text = path.read_text(encoding="utf-8")
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def comparable_summary(summary: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(summary)
    normalized.pop("generated_at", None)
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic HO-DET-001 offline LLM support stub.")
    parser.add_argument("--input", required=True, type=Path, help="Path to autosoc-triage-packet.json")
    parser.add_argument(
        "--write",
        action="store_true",
        help="Regenerate llm-summary.json. Default is check-only and writes nothing.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run check-only mode. This is the default and is kept for explicit CI/readiness usage.",
    )
    args = parser.parse_args()

    packet_path = args.input.resolve()
    packet = load_json(packet_path)
    if packet.get("detection_id") != "HO-DET-001":
        fail("triage packet detection_id must be HO-DET-001")

    summary = {
        "detection_id": "HO-DET-001",
        "input_packet_ref": "hawkinsoperations-validation/validation/successor/ho-det-001/autosoc-triage-packet.json",
        "input_packet_hash": sha256_repo_text_file(packet_path),
        "model_runtime_status": "BLOCKED",
        "execution_mode": "deterministic_stub_no_model_call",
        "summary_type": "hypothesis_triage_support_only",
        "hypothesis": (
            "The synthetic packet is consistent with encoded-command process creation behavior. "
            "Analyst review would focus on command intent, parent process, user context, and environment-specific allowlisting."
        ),
        "analyst_review_required": True,
        "unsupported_claims": UNSUPPORTED_CLAIMS,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "privacy_status": "Synthetic packet only; no live telemetry, secrets, private hostnames, or private addresses intentionally included.",
    }

    if args.write:
        SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
        SUMMARY_PATH.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    else:
        committed = load_json(SUMMARY_PATH)
        if comparable_summary(committed) != comparable_summary(summary):
            print("FAIL: committed llm-summary.json does not match computed summary", file=sys.stderr)
            print(f"EXPECTED_INPUT_PACKET_HASH={summary['input_packet_hash']}", file=sys.stderr)
            print(f"COMMITTED_INPUT_PACKET_HASH={committed.get('input_packet_hash', '')}", file=sys.stderr)
            return 1
    print("STATUS=pass")
    print(f"MODE={'write' if args.write else 'check'}")
    print("MODEL_RUNTIME_STATUS=BLOCKED")
    print("EXECUTION_MODE=deterministic_stub_no_model_call")
    print(f"INPUT_PACKET_HASH={summary['input_packet_hash']}")
    if args.write:
        print(f"SUMMARY={SUMMARY_PATH}")
    else:
        print("WRITE_SKIPPED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

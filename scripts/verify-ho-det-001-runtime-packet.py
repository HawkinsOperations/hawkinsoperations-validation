#!/usr/bin/env python3
"""Verify the private HO-DET-001 controlled runtime signal packet.

This verifier reads a local private packet root supplied by the operator. It
does not generate runtime events, authenticate to Splunk, publish evidence, or
promote public proof.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from validation_lib import ContractFailure, strict_json_object


PACKET_ID = "HO-DET-001_CONTROLLED_RUNTIME_SIGNAL_PACKET_001"
DETECTION_ID = "HO-DET-001"
EXPECTED_STATUS = "CONTROLLED_LAB_RUNTIME_MATCH_CAPTURED"
EXPECTED_SCOPE = "CONTROLLED_LAB_RUNTIME"
EXPECTED_PUBLIC_SAFE_STATUS = "NOT_PUBLIC_SAFE"
EXPECTED_INDEX = "ho_v2_sysmon"
EXPECTED_SOURCETYPE = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EXPECTED_SOURCE_VARIANTS = {
    "WinEventLog://Microsoft-Windows-Sysmon/Operational",
    "WinEventLog:Microsoft-Windows-Sysmon/Operational",
}
EXPECTED_MATCH_COUNT = 2
EXPECTED_VERDICT = "VERIFIED_CONTROLLED_LAB_RUNTIME_MATCH_CAPTURED"
PARTIAL_VERDICT = "PARTIAL_PACKET_NEEDS_FIX"
INVALID_VERDICT = "PACKET_INVALID"
LOCAL_WORKSPACE_MARKERS = [
    "C:" + "\\Raylee",
    "C:" + "/Raylee",
]

REQUIRED_EXACT_FILES = {
    "evidence-manifest.json": "manifest",
    "sha256-manifest.txt": "hash manifest",
    "runtime-signal-packet-summary.md": "summary",
    "sanitization-notes.md": "sanitization notes",
    "splunk-marker-search-query-v2-xml-extraction.txt": "Splunk marker query text",
    "splunk-ho-det-001-search-query-v2-xml-extraction.txt": "HO-DET-001 query text",
    "splunk-marker-search-result-v2-raw.csv": "Splunk marker raw export",
    "splunk-ho-det-001-search-result-v2-raw.csv": "HO-DET-001 raw export",
    "splunk-marker-search-result-v2-sanitized.json": "sanitized Splunk marker result JSON",
    "splunk-ho-det-001-search-result-v2-sanitized.json": "sanitized HO-DET-001 result JSON",
}
LOCAL_TELEMETRY_FILES = [
    "local-sysmon-event-raw.json",
    "local-sysmon-event-sanitized.json",
]
OPTIONAL_STATUS_FILE = "controlled-lab-runtime-match-captured.json"

SHA_LINE_RE = re.compile(r"^(?P<hash>[A-Fa-f0-9]{64})\s+(?P<name>.+?)\s*$")
MARKER_RE = re.compile(r"HO_DET_001_RUNTIME_SIGNAL_PACKET_001_[0-9]{8}-[0-9]{6}")
PRIVATE_IP_RE = re.compile(
    r"\b(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b"
)
SECRET_RE = re.compile(
    r"(?i)\b(?:splunk[_-]?(?:password|token|session|secret)|authorization:\s*bearer|"
    r"password\s*[=:]|token\s*[=:]|secret\s*[=:]|api[_-]?key\s*[=:]|"
    r"browser[_-]?cookie|set-cookie|cookie\s*[=:]|splunkd_[0-9a-f]{8,})\b"
)
BLOCKED_CLAIM_TERMS = [
    "public-safe runtime proof",
    "runtime-active",
    "production-ready",
    "fleet-wide",
    "Cribl-routed",
    "Wazuh-routed",
    "AWS-live",
    "autonomous SOC",
    "AI-approved disposition",
    "analyst-approved disposition",
]
BLOCKED_ALLOW_PATH_TERMS = [
    "blocked",
    "not_proven",
    "not_supported",
    "still_not_supported",
    "claim_boundary",
    "operator_notes",
]
BLOCKED_ALLOW_TEXT_TERMS = [
    "does not prove",
    "do not prove",
    "not prove",
    "not supported",
    "remain blocked",
    "blocked",
]


class PacketVerifier:
    def __init__(self, packet_root: Path) -> None:
        self.packet_root = packet_root
        self.failures: list[str] = []
        self.invalid_failures: list[str] = []
        self.statuses: dict[str, str] = {
            "required_files_status": "NOT_RUN",
            "hash_status": "NOT_RUN",
            "marker_correlation_status": "NOT_RUN",
            "local_telemetry_status": "NOT_RUN",
            "splunk_marker_export_status": "NOT_RUN",
            "ho_det_001_export_status": "NOT_RUN",
            "match_count_status": "NOT_RUN",
            "sanitization_status": "NOT_RUN",
            "blocked_claim_status": "NOT_RUN",
        }
        self.manifest: dict[str, Any] = {}
        self.status_doc: dict[str, Any] = {}
        self.marker = ""
        self.time_window = ""
        self.raw_hostnames: set[str] = set()
        self.raw_usernames: set[str] = set()

    def fail(self, status_key: str, message: str, *, invalid: bool = False) -> None:
        self.failures.append(message)
        if invalid:
            self.invalid_failures.append(message)
        self.statuses[status_key] = f"FAIL: {message}"

    def path(self, name: str) -> Path:
        return self.packet_root / name

    def read_text(self, name: str) -> str:
        return self.path(name).read_text(encoding="utf-8-sig")

    def load_json(self, name: str) -> Any:
        try:
            return strict_json_object(self.read_text(name), name)
        except ContractFailure as exc:
            self.fail("required_files_status", str(exc), invalid=True)
            return None

    def verify_required_files(self) -> None:
        if not self.packet_root.exists() or not self.packet_root.is_dir():
            self.fail(
                "required_files_status",
                f"packet root missing or not a directory: {self.packet_root}",
                invalid=True,
            )
            return

        missing = [name for name in REQUIRED_EXACT_FILES if not self.path(name).is_file()]
        local_present = [name for name in LOCAL_TELEMETRY_FILES if self.path(name).is_file()]
        if not local_present:
            missing.append("local telemetry raw or sanitized evidence")

        if missing:
            self.fail("required_files_status", f"missing required files: {', '.join(missing)}", invalid=True)
            return

        self.statuses["required_files_status"] = (
            f"PASS: {len(REQUIRED_EXACT_FILES)} exact files present; "
            f"local telemetry present: {', '.join(local_present)}"
        )

    def verify_hash_manifest(self) -> None:
        manifest_path = self.path("sha256-manifest.txt")
        if not manifest_path.is_file():
            self.fail("hash_status", "sha256-manifest.txt missing", invalid=True)
            return

        entries: list[tuple[str, str]] = []
        malformed: list[str] = []
        for index, line in enumerate(manifest_path.read_text(encoding="utf-8-sig").splitlines(), start=1):
            if not line.strip():
                continue
            match = SHA_LINE_RE.match(line)
            if not match:
                malformed.append(f"line {index}")
                continue
            entries.append((match.group("hash").upper(), match.group("name")))

        if malformed:
            self.fail("hash_status", f"malformed hash manifest entries: {', '.join(malformed)}", invalid=True)
            return
        if not entries:
            self.fail("hash_status", "sha256-manifest.txt has no entries", invalid=True)
            return

        mismatches: list[str] = []
        missing: list[str] = []
        for expected_hash, name in entries:
            candidate = self.path(name)
            try:
                resolved = candidate.resolve()
            except OSError:
                missing.append(name)
                continue
            if not candidate.is_file() or self.packet_root.resolve() not in [resolved.parent, *resolved.parents]:
                missing.append(name)
                continue
            actual_hash = hashlib.sha256(candidate.read_bytes()).hexdigest().upper()
            if actual_hash != expected_hash:
                mismatches.append(name)

        if missing or mismatches:
            detail = []
            if missing:
                detail.append(f"missing referenced files: {', '.join(missing)}")
            if mismatches:
                detail.append(f"hash mismatch: {', '.join(mismatches)}")
            self.fail("hash_status", "; ".join(detail), invalid=True)
            return

        self.statuses["hash_status"] = f"PASS: {len(entries)} referenced file hashes verified"

    def load_packet_documents(self) -> None:
        manifest = self.load_json("evidence-manifest.json")
        if isinstance(manifest, dict):
            self.manifest = manifest
        status_doc = self.load_json(OPTIONAL_STATUS_FILE) if self.path(OPTIONAL_STATUS_FILE).is_file() else {}
        if isinstance(status_doc, dict):
            self.status_doc = status_doc

        marker_candidates: list[str] = []
        for source in [self.manifest, self.status_doc, self.read_text("runtime-signal-packet-summary.md")]:
            marker_candidates.extend(MARKER_RE.findall(json.dumps(source) if not isinstance(source, str) else source))
        unique_markers = sorted(set(marker_candidates))
        if len(unique_markers) != 1:
            self.fail(
                "marker_correlation_status",
                f"expected exactly one packet marker, found {len(unique_markers)}",
                invalid=True,
            )
        else:
            self.marker = unique_markers[0]

        self.time_window = str(
            self.status_doc.get("selected_time_window")
            or self.manifest.get("search_time_window")
            or self._extract_time_window_from_summary()
        )

    def _extract_time_window_from_summary(self) -> str:
        text = self.read_text("runtime-signal-packet-summary.md")
        match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} -\d{2}:\d{2} to \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} -\d{2}:\d{2}", text)
        return match.group(0) if match else ""

    def verify_manifest_status(self) -> None:
        if not self.manifest:
            self.fail("required_files_status", "evidence-manifest.json did not load as an object", invalid=True)
            return
        expected_pairs = {
            "packet_id": PACKET_ID,
            "detection_id": DETECTION_ID,
            "packet_status": EXPECTED_STATUS,
            "evidence_scope": EXPECTED_SCOPE,
            "public_safe_status": EXPECTED_PUBLIC_SAFE_STATUS,
            "proposed_new_private_status": EXPECTED_STATUS,
        }
        mismatches = [
            f"{key}={self.manifest.get(key)!r}"
            for key, expected in expected_pairs.items()
            if self.manifest.get(key) != expected
        ]
        if mismatches:
            self.fail("required_files_status", f"manifest status mismatch: {', '.join(mismatches)}", invalid=True)

    def read_csv_rows(self, name: str) -> list[dict[str, str]]:
        try:
            with self.path(name).open("r", encoding="utf-8-sig", newline="") as handle:
                return [dict(row) for row in csv.DictReader(handle)]
        except csv.Error as exc:
            self.fail("required_files_status", f"{name} is invalid CSV: {exc}", invalid=True)
        return []

    def collect_raw_private_markers(self, rows: list[dict[str, str]]) -> None:
        for row in rows:
            for field in ("host", "Computer"):
                value = row.get(field, "").strip()
                if value and value.upper() not in {"UNAVAILABLE", "UNKNOWN"}:
                    self.raw_hostnames.add(value)
            user = row.get("User", "").strip()
            if "\\" in user:
                _, username = user.rsplit("\\", 1)
                if username:
                    self.raw_usernames.add(username)

    def verify_local_telemetry(self) -> None:
        if not self.marker:
            self.fail("local_telemetry_status", "marker unavailable", invalid=True)
            return
        raw_text = self.path("local-sysmon-event-raw.json").read_text(encoding="utf-8-sig") if self.path("local-sysmon-event-raw.json").is_file() else ""
        sanitized = self.load_json("local-sysmon-event-sanitized.json") if self.path("local-sysmon-event-sanitized.json").is_file() else None
        local_text = raw_text + "\n" + (json.dumps(sanitized) if sanitized is not None else "")
        if self.marker not in local_text:
            self.fail("local_telemetry_status", "marker absent from local telemetry evidence")
            return
        if not isinstance(sanitized, list) or len(sanitized) < EXPECTED_MATCH_COUNT:
            self.fail("local_telemetry_status", "sanitized local telemetry does not contain two candidate rows")
            return
        for index, row in enumerate(sanitized, start=1):
            if not isinstance(row, dict):
                self.fail("local_telemetry_status", f"local telemetry row {index} is not an object")
                return
            if row.get("event_id") != 1:
                self.fail("local_telemetry_status", f"local telemetry row {index} is not Sysmon Event ID 1")
                return
            command_line = str(row.get("CommandLine", ""))
            if self.marker not in command_line or "-EncodedCommand" not in command_line:
                self.fail("local_telemetry_status", f"local telemetry row {index} lacks marker or EncodedCommand")
                return
        self.statuses["local_telemetry_status"] = (
            f"PASS: marker present in local Sysmon telemetry with {len(sanitized)} candidate rows"
        )

    def verify_splunk_exports(self) -> tuple[list[dict[str, str]], dict[str, Any], dict[str, Any]]:
        marker_rows = self.read_csv_rows("splunk-marker-search-result-v2-raw.csv")
        ho_rows = self.read_csv_rows("splunk-ho-det-001-search-result-v2-raw.csv")
        self.collect_raw_private_markers(marker_rows)
        self.collect_raw_private_markers(ho_rows)

        marker_sanitized = self.load_json("splunk-marker-search-result-v2-sanitized.json")
        ho_sanitized = self.load_json("splunk-ho-det-001-search-result-v2-sanitized.json")
        marker_sanitized = marker_sanitized if isinstance(marker_sanitized, dict) else {}
        ho_sanitized = ho_sanitized if isinstance(ho_sanitized, dict) else {}

        if not marker_rows:
            self.fail("splunk_marker_export_status", "marker raw export has zero rows")
        elif self.marker not in self.path("splunk-marker-search-result-v2-raw.csv").read_text(encoding="utf-8-sig"):
            self.fail("splunk_marker_export_status", "marker absent from marker raw export")
        else:
            self.statuses["splunk_marker_export_status"] = f"PASS: marker raw export contains {len(marker_rows)} rows"

        if not ho_rows:
            self.fail("ho_det_001_export_status", "HO-DET-001 raw export has zero rows")
        elif self.marker not in self.path("splunk-ho-det-001-search-result-v2-raw.csv").read_text(encoding="utf-8-sig"):
            self.fail("ho_det_001_export_status", "marker absent from HO-DET-001 raw export")
        else:
            self.statuses["ho_det_001_export_status"] = f"PASS: HO-DET-001 raw export contains {len(ho_rows)} rows"

        required_columns = {
            "_time",
            "host",
            "EventID",
            "Image",
            "CommandLine",
            "ParentImage",
            "index",
            "sourcetype",
            "source",
        }
        if ho_rows:
            missing_columns = sorted(required_columns - set(ho_rows[0]))
            if missing_columns:
                self.fail("ho_det_001_export_status", f"HO-DET-001 raw export missing columns: {missing_columns}")
            command_present = any(row.get("CommandLine") for row in ho_rows)
            if not command_present:
                self.fail("ho_det_001_export_status", "CommandLine absent in HO-DET-001 raw export")

        self.verify_splunk_field_values(marker_sanitized, ho_sanitized)
        return ho_rows, marker_sanitized, ho_sanitized

    def verify_splunk_field_values(self, marker_sanitized: dict[str, Any], ho_sanitized: dict[str, Any]) -> None:
        for label, doc, rows_key in [
            ("marker", marker_sanitized, "rows"),
            ("HO-DET-001", ho_sanitized, "actual_child_encodedcommand_matches"),
        ]:
            if doc.get("marker") != self.marker:
                self.fail("marker_correlation_status", f"{label} sanitized JSON marker mismatch")
                return
            if not doc.get("search_time_window"):
                self.fail("ho_det_001_export_status", f"{label} sanitized JSON lacks search time window")
                return
            rows = doc.get(rows_key)
            if not isinstance(rows, list) or not rows:
                self.fail("ho_det_001_export_status", f"{label} sanitized JSON lacks result rows")
                return
            for index, row in enumerate(rows, start=1):
                if not isinstance(row, dict):
                    self.fail("ho_det_001_export_status", f"{label} row {index} is not an object")
                    return
                self.require_splunk_row_fields(label, index, row)
        self.statuses["marker_correlation_status"] = "PASS: marker correlates across manifest, local telemetry, and Splunk evidence"

    def require_splunk_row_fields(self, label: str, index: int, row: dict[str, Any]) -> None:
        field_checks = {
            "_time": row.get("_time"),
            "host_or_Computer": row.get("host") or row.get("Computer"),
            "EventID_or_EventCode": row.get("EventID") or row.get("EventCode"),
            "Image": row.get("Image"),
            "CommandLine": row.get("CommandLine"),
            "ParentImage": row.get("ParentImage", "UNAVAILABLE"),
            "index": row.get("index"),
            "sourcetype": row.get("sourcetype"),
            "source": row.get("source"),
        }
        missing = [name for name, value in field_checks.items() if value in (None, "")]
        if missing:
            self.fail("ho_det_001_export_status", f"{label} row {index} missing fields: {missing}")
            return
        if row.get("index") != EXPECTED_INDEX:
            self.fail("ho_det_001_export_status", f"{label} row {index} index mismatch")
            return
        if row.get("sourcetype") != EXPECTED_SOURCETYPE:
            self.fail("ho_det_001_export_status", f"{label} row {index} sourcetype mismatch")
            return
        if row.get("source") not in EXPECTED_SOURCE_VARIANTS:
            self.fail("ho_det_001_export_status", f"{label} row {index} source mismatch")
            return
        if row.get("ParentImage") in (None, ""):
            self.fail("ho_det_001_export_status", f"{label} row {index} ParentImage missing and not marked unavailable")

    def verify_match_count(self, ho_sanitized: dict[str, Any]) -> None:
        manifest_count = self.manifest.get("splunk_ho_det_001_actual_child_match_count")
        doc_count = ho_sanitized.get("actual_child_encodedcommand_match_count")
        matches = ho_sanitized.get("actual_child_encodedcommand_matches")
        search_window = self.time_window or str(ho_sanitized.get("search_time_window", ""))
        if manifest_count != EXPECTED_MATCH_COUNT or doc_count != EXPECTED_MATCH_COUNT:
            self.fail(
                "match_count_status",
                f"expected match count 2, got manifest={manifest_count!r}, sanitized={doc_count!r}",
            )
            return
        if not isinstance(matches, list) or len(matches) != EXPECTED_MATCH_COUNT:
            self.fail("match_count_status", "actual child match list length is not 2")
            return
        if not search_window:
            self.fail("match_count_status", "search time window is absent or ambiguous")
            return
        for index, row in enumerate(matches, start=1):
            command_line = str(row.get("CommandLine", ""))
            image = str(row.get("Image", "")).lower()
            event_id = str(row.get("EventID") or row.get("EventCode"))
            if row.get("actual_child_encodedcommand_candidate") is not True:
                self.fail("match_count_status", f"match {index} is not flagged as actual child candidate")
                return
            if self.marker not in command_line or "-EncodedCommand" not in command_line:
                self.fail("match_count_status", f"match {index} lacks marker or EncodedCommand")
                return
            if not image.endswith("\\windowspowershell\\v1.0\\powershell.exe"):
                self.fail("match_count_status", f"match {index} is not child Windows PowerShell")
                return
            if event_id != "1":
                self.fail("match_count_status", f"match {index} EventID/EventCode is not 1")
                return
            if not self._time_inside_window(str(row.get("_time", "")), search_window):
                self.fail("match_count_status", f"match {index} is outside search time window")
                return
        self.statuses["match_count_status"] = "PASS: match count equals 2 and rows are controlled child EncodedCommand events"

    def _time_inside_window(self, splunk_time: str, window: str) -> bool:
        try:
            event_dt = datetime.strptime(splunk_time, "%Y-%m-%dT%H:%M:%S.%f%z")
            start_text, end_text = [part.strip() for part in window.split(" to ", 1)]
            start_dt = datetime.strptime(start_text, "%Y-%m-%d %H:%M:%S %z")
            end_dt = datetime.strptime(end_text, "%Y-%m-%d %H:%M:%S %z")
        except (ValueError, TypeError):
            return False
        return start_dt <= event_dt.astimezone(start_dt.tzinfo) <= end_dt

    def verify_sanitization(self) -> None:
        sanitized_names = sorted(
            {
                "local-sysmon-event-sanitized.json",
                "splunk-marker-search-result-v2-sanitized.json",
                "splunk-ho-det-001-search-result-v2-sanitized.json",
                "runtime-signal-packet-summary.md",
                "sanitization-notes.md",
                "controlled-lab-runtime-match-captured.json",
            }
        )
        hits: list[str] = []
        raw_hostname_values = {value for value in self.raw_hostnames if value and not value.startswith("ENDPOINT_")}
        raw_username_values = {value for value in self.raw_usernames if value and value not in {"SYSTEM"}}
        for name in sanitized_names:
            if not self.path(name).is_file():
                continue
            text = self.path(name).read_text(encoding="utf-8-sig")
            for username in raw_username_values:
                if username and re.search(rf"(?i)(?<!<)\b{re.escape(username)}\b(?!>)", text):
                    hits.append(f"{name}: raw local Windows username")
            for hostname in raw_hostname_values:
                if hostname and hostname in text:
                    hits.append(f"{name}: raw endpoint hostname")
            if PRIVATE_IP_RE.search(text):
                hits.append(f"{name}: private IP address")
            if any(marker in text for marker in LOCAL_WORKSPACE_MARKERS):
                hits.append(f"{name}: local workspace path")
            if SECRET_RE.search(text):
                hits.append(f"{name}: credential/token/secret/cookie marker")
        if hits:
            self.fail("sanitization_status", "; ".join(hits))
            return
        self.statuses["sanitization_status"] = f"PASS: {len(sanitized_names)} sanitized/boundary files scanned"

    def verify_blocked_claim_boundary(self) -> None:
        files = [
            "evidence-manifest.json",
            "controlled-lab-runtime-match-captured.json",
            "runtime-signal-packet-summary.md",
            "sanitization-notes.md",
            "splunk-ho-det-001-search-result-v2-sanitized.json",
            "splunk-marker-search-result-v2-sanitized.json",
        ]
        promoted: list[str] = []
        for name in files:
            if not self.path(name).is_file():
                continue
            if name.endswith(".json"):
                value = self.load_json(name)
                promoted.extend(self._find_promoted_claims(value, name))
            else:
                promoted.extend(self._find_promoted_claims_in_markdown(self.read_text(name), name))
        if promoted:
            self.fail("blocked_claim_status", "; ".join(promoted))
            return
        self.statuses["blocked_claim_status"] = "PASS: blocked claims appear only as boundary/negative statements"

    def _find_promoted_claims(self, value: Any, path: str) -> list[str]:
        promoted: list[str] = []
        for child_path, text in self._iter_strings(value, path):
            lower_path = child_path.lower()
            lower_text = text.lower()
            allow_by_path = any(term in lower_path for term in BLOCKED_ALLOW_PATH_TERMS)
            allow_by_text = any(term in lower_text for term in BLOCKED_ALLOW_TEXT_TERMS)
            for term in BLOCKED_CLAIM_TERMS:
                if term.lower() in lower_text and not (allow_by_path or allow_by_text):
                    promoted.append(f"{child_path}: promoted blocked claim '{term}'")
        return promoted

    def _find_promoted_claims_in_markdown(self, text: str, name: str) -> list[str]:
        promoted: list[str] = []
        section = ""
        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                section = stripped.lower()
            lower_line = stripped.lower()
            allow = (
                any(term in section for term in ["still not supported", "blocked", "boundary"])
                or any(term in lower_line for term in BLOCKED_ALLOW_TEXT_TERMS)
            )
            for term in BLOCKED_CLAIM_TERMS:
                if term.lower() in lower_line and not allow:
                    promoted.append(f"{name}:{line_number}: promoted blocked claim '{term}'")
        return promoted

    def _iter_strings(self, value: Any, path: str) -> list[tuple[str, str]]:
        if isinstance(value, str):
            return [(path, value)]
        if isinstance(value, list):
            found: list[tuple[str, str]] = []
            for index, item in enumerate(value):
                found.extend(self._iter_strings(item, f"{path}[{index}]"))
            return found
        if isinstance(value, dict):
            found = []
            for key, item in value.items():
                found.extend(self._iter_strings(item, f"{path}.{key}"))
            return found
        return []

    def run(self) -> int:
        self.verify_required_files()
        if self.invalid_failures:
            return self.print_result()

        self.verify_hash_manifest()
        self.load_packet_documents()
        self.verify_manifest_status()
        self.verify_local_telemetry()
        _ho_rows, _marker_sanitized, ho_sanitized = self.verify_splunk_exports()
        self.verify_match_count(ho_sanitized)
        self.verify_sanitization()
        self.verify_blocked_claim_boundary()
        return self.print_result()

    def final_verdict(self) -> str:
        if not self.failures:
            return EXPECTED_VERDICT
        if self.invalid_failures:
            return INVALID_VERDICT
        return PARTIAL_VERDICT

    def print_result(self) -> int:
        verdict = self.final_verdict()
        print(f"packet_root={self.packet_root}")
        for key in [
            "required_files_status",
            "hash_status",
            "marker_correlation_status",
            "local_telemetry_status",
            "splunk_marker_export_status",
            "ho_det_001_export_status",
            "match_count_status",
            "sanitization_status",
            "blocked_claim_status",
        ]:
            print(f"{key}={self.statuses[key]}")
        if self.failures:
            print("failures:")
            for failure in self.failures:
                print(f"- {failure}")
        print(f"final_verdict={verdict}")
        return 0 if verdict == EXPECTED_VERDICT else 1


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-root", required=True, help="Private runtime packet root to verify")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    packet_root = Path(args.packet_root).expanduser().resolve()
    return PacketVerifier(packet_root).run()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

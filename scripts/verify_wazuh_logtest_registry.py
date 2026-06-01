#!/usr/bin/env python3
"""Verify Wazuh logtest registry shape and optional private logtest execution."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "validation" / "wazuh" / "WAZUH_LOGTEST_REGISTRY.json"

FALSEY = {False, None, "", "false", "no", "not_proven", "not_claimed", "blocked"}
ALLOWED_STATUS = "WAZUH_LOGTEST_CONTRACT_ENFORCED"
ALLOWED_PROOF_CEILING = "CONTROLLED_TEST_ONLY_NOT_RUNTIME_PROOF"
ALLOWED_EXECUTION_MODES = {
    "static_ci_optional_private_logtest",
    "planned_static_contract_only",
}


class WazuhLogtestRegistryError(Exception):
    """Wazuh logtest registry violation."""


def fail(message: str) -> None:
    raise WazuhLogtestRegistryError(message)


def truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in FALSEY
    return value not in FALSEY


def rel_path(root: Path, value: str, field: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        fail(f"{field} must be repo-relative: {value}")
    return root / path


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing {label}: {path}")
    except json.JSONDecodeError as exc:
        fail(f"invalid {label} JSON: {exc}")
    if not isinstance(data, dict):
        fail(f"{label} must be a JSON object")
    return data


def split_groups(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def require_false_boundary(data: dict[str, Any], label: str) -> None:
    for field in ("runtime_status", "signal_status"):
        if truthy(data.get(field)):
            fail(f"{label} {field} must remain false or blocked")
    if str(data.get("public_safe_status", "")).strip() != "NOT_PUBLIC_SAFE":
        fail(f"{label} public_safe_status must be NOT_PUBLIC_SAFE")


def parse_wazuh_xml(path: Path) -> list[dict[str, Any]]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        fail(f"invalid Wazuh XML parse: {path} ({exc})")
    rules = []

    def walk(node: ET.Element, inherited_groups: set[str]) -> None:
        effective_groups = set(inherited_groups)
        if node.tag == "group":
            effective_groups.update(split_groups(node.attrib.get("name")))
        if node.tag == "rule":
            rule_groups = set(effective_groups)
            for group in node.findall("group"):
                rule_groups.update(split_groups(group.text))
            rule_id = int(str(node.attrib.get("id", "")).strip())
            level = int(str(node.attrib.get("level", "0")).strip())
            mitre_ids = {
                child.text.strip()
                for child in node.findall(".//id")
                if child.text and child.text.strip().startswith("T")
            }
            rules.append({"id": rule_id, "level": level, "groups": rule_groups, "mitre_ids": mitre_ids})
            return
        for child in node:
            walk(child, effective_groups)

    walk(root, set())
    if not rules:
        fail(f"Wazuh XML has no rules: {path}")
    return rules


def verify_source_expectations(entry: dict[str, Any], detections_root: Path | None) -> None:
    source = entry.get("wazuh_rule_source")
    if not source or detections_root is None:
        return
    xml_path = rel_path(detections_root, source, "wazuh_rule_source")
    if not xml_path.exists():
        fail(f"{entry['detection_id']} missing wazuh_rule_source: {source}")
    rules = parse_wazuh_xml(xml_path)
    actual_ids = {rule["id"] for rule in rules}
    actual_levels = {rule["level"] for rule in rules}
    actual_groups = set().union(*(rule["groups"] for rule in rules))
    actual_mitre = set().union(*(rule["mitre_ids"] for rule in rules))
    for expected_id in entry.get("expected_rule_ids") or []:
        if int(expected_id) not in actual_ids:
            fail(f"{entry['detection_id']} expected Wazuh rule id missing: {expected_id}")
    for expected_level in entry.get("expected_levels") or []:
        if int(expected_level) not in actual_levels:
            fail(f"{entry['detection_id']} expected Wazuh level missing: {expected_level}")
    for expected_group in entry.get("expected_groups") or []:
        if expected_group not in actual_groups:
            fail(f"{entry['detection_id']} expected Wazuh group missing: {expected_group}")
    for expected_mitre in entry.get("expected_mitre_ids") or []:
        if expected_mitre not in actual_mitre:
            fail(f"{entry['detection_id']} expected MITRE id missing: {expected_mitre}")


def verify_sample(root: Path, entry: dict[str, Any]) -> dict[str, Any] | None:
    sample = entry.get("sample_event")
    if sample is None:
        return None
    sample_path = rel_path(root, sample, "sample_event")
    if not sample_path.exists():
        fail(f"{entry['detection_id']} missing sample_event: {sample}")
    data = load_json(sample_path, f"{entry['detection_id']} sample_event")
    if data.get("detection_id") != entry["detection_id"]:
        fail(f"{entry['detection_id']} sample detection_id mismatch")
    if data.get("sample_scope") != "controlled_synthetic_wazuh_logtest_candidate":
        fail(f"{entry['detection_id']} sample_scope must be controlled synthetic")
    require_false_boundary(data, f"{entry['detection_id']} sample")
    if not isinstance(data.get("logtest_input"), str) or not data["logtest_input"]:
        fail(f"{entry['detection_id']} sample missing logtest_input")
    return data


def run_optional_logtest(entry: dict[str, Any], sample: dict[str, Any] | None) -> None:
    if sample is None:
        return
    bin_path = os.environ.get("WAZUH_LOGTEST_BIN") or shutil.which("wazuh-logtest")
    if not bin_path:
        fail("run_logtest requested but WAZUH_LOGTEST_BIN or wazuh-logtest was not found")
    proc = subprocess.run(
        [bin_path, "-q"],
        input=sample["logtest_input"] + "\n",
        text=True,
        capture_output=True,
        timeout=30,
    )
    if proc.returncode != 0:
        fail(f"{entry['detection_id']} wazuh-logtest exited {proc.returncode}: {proc.stderr[-500:]}")
    combined = proc.stdout + proc.stderr
    for expected_id in entry.get("expected_rule_ids") or []:
        if str(expected_id) not in combined:
            fail(f"{entry['detection_id']} wazuh-logtest output missing expected rule id {expected_id}")


def verify_entry(root: Path, entry: dict[str, Any], detections_root: Path | None, run_logtest: bool) -> dict[str, Any]:
    detection_id = str(entry.get("detection_id", "")).strip()
    if not detection_id:
        fail("entry missing detection_id")
    if detection_id.startswith("ID-DET-") and entry.get("wazuh_rule_source"):
        fail("identity detections must not be forced into Wazuh logtest without identity telemetry normalization")
    if entry.get("execution_mode") not in ALLOWED_EXECUTION_MODES:
        fail(f"{detection_id} invalid execution_mode: {entry.get('execution_mode')}")
    require_false_boundary(entry, detection_id)
    planned = entry.get("execution_mode") == "planned_static_contract_only"
    if planned:
        if entry.get("sample_event") is not None or entry.get("wazuh_rule_source") is not None:
            fail(f"{detection_id} planned entries must not reference sample_event or wazuh_rule_source")
        return entry
    sample = verify_sample(root, entry)
    verify_source_expectations(entry, detections_root)
    if run_logtest:
        run_optional_logtest(entry, sample)
    return entry


def verify_registry(
    registry_path: Path = REGISTRY_PATH,
    root: Path = ROOT,
    detections_root: Path | None = None,
    run_logtest: bool = False,
    print_summary: bool = True,
) -> list[dict[str, Any]]:
    registry = load_json(registry_path, "Wazuh logtest registry")
    if registry.get("registry_status") != ALLOWED_STATUS:
        fail("registry_status must be WAZUH_LOGTEST_CONTRACT_ENFORCED")
    if registry.get("proof_ceiling") != ALLOWED_PROOF_CEILING:
        fail("proof_ceiling must preserve controlled-test-only boundary")
    require_false_boundary(registry, "registry")
    entries = registry.get("entries")
    if not isinstance(entries, list) or not entries:
        fail("entries must be a non-empty list")
    seen: set[str] = set()
    verified = []
    for entry in entries:
        if not isinstance(entry, dict):
            fail("entries must be objects")
        detection_id = str(entry.get("detection_id", "")).strip()
        if detection_id in seen:
            fail(f"duplicate detection_id: {detection_id}")
        seen.add(detection_id)
        verified.append(verify_entry(root, entry, detections_root, run_logtest))
    if print_summary:
        mode = "optional-logtest" if run_logtest else "static"
        print(f"WAZUH_LOGTEST_REGISTRY=pass mode={mode} entries={len(verified)}")
    return verified


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify HawkinsOperations Wazuh logtest registry.")
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--detections-root", type=Path)
    parser.add_argument("--run-logtest", action="store_true")
    args = parser.parse_args()
    try:
        verify_registry(args.registry, args.root, args.detections_root, args.run_logtest)
    except WazuhLogtestRegistryError as exc:
        print(f"WAZUH_LOGTEST_REGISTRY=fail: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Verify HO-LAB-WAZUH-001 static Wazuh rule contract lab."""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - exercised by environment, not unit tests
    yaml = None


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import verify_wazuh_logtest_registry as logtest_registry  # noqa: E402


MANIFEST_PATH = ROOT / "validation" / "wazuh" / "labs" / "HO-LAB-WAZUH-001.manifest.json"
DEFAULT_DETECTIONS_ROOT = ROOT.parent / "hawkinsoperations-detections"
ALLOWED_PROOF_CEILING = "SOURCE_AND_STATIC_CI_CONTRACT_ONLY"
ALLOWED_LAB_STATUS = "STATIC_CONTRACT_READY"
FALSEY = {False, None, "", "false", "no", "not_proven", "not_claimed", "blocked"}
NEGATIVE_CONTEXT_RE = re.compile(
    r"\b(block|blocked|blocked_claims|boundary|does\s+not|do\s+not|not|no|without|"
    r"gated|requires|must\s+not|remains\s+unproven|unproven|not\s+required)\b",
    re.IGNORECASE,
)
BLOCKED_TERMS = (
    "live Wazuh deployment",
    "live Wazuh manager proof",
    "Wazuh-routed runtime proof",
    "Wazuh-routed proof",
    "runtime-active proof",
    "runtime-active",
    "signal-observed proof",
    "signal-observed",
    "public-safe runtime proof",
    "production SOC",
    "SOCaaS deployment",
    "customer deployment",
    "autonomous SOC",
    "AI-approved disposition",
    "AI-decided disposition",
    "analyst-approved disposition",
    "case closure",
)


class HOLabWazuhError(Exception):
    """HO-LAB-WAZUH-001 verification failure."""


def fail(message: str) -> None:
    raise HOLabWazuhError(message)


def truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in FALSEY
    return value not in FALSEY


def repo_path(root: Path, value: str, field: str) -> Path:
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


def load_yaml(path: Path, label: str) -> dict[str, Any]:
    if yaml is None:
        fail("PyYAML is required for source registry verification")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing {label}: {path}")
    except yaml.YAMLError as exc:
        fail(f"invalid {label} YAML: {exc}")
    if not isinstance(data, dict):
        fail(f"{label} must be a mapping")
    return data


def require_false_boundary(data: dict[str, Any], label: str) -> None:
    for field in ("runtime_status", "signal_status"):
        if truthy(data.get(field)):
            fail(f"{label} {field} must remain false or blocked")
    if data.get("public_safe_status") != "NOT_PUBLIC_SAFE":
        fail(f"{label} public_safe_status must be NOT_PUBLIC_SAFE")


def manifest_entries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        fail("manifest entries must be a non-empty array")
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            fail("manifest entries must be objects")
        detection_id = str(entry.get("detection_id", "")).strip()
        if not detection_id:
            fail("manifest entry missing detection_id")
        if detection_id in seen:
            fail(f"duplicate manifest detection_id: {detection_id}")
        seen.add(detection_id)
        for field in ("source_required", "sample_required", "expected_result_reference_required"):
            if not isinstance(entry.get(field), bool):
                fail(f"{detection_id} {field} must be boolean")
    return entries


def verify_manifest(manifest: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    if manifest.get("schema_version") != 1:
        fail("manifest schema_version must be 1")
    if manifest.get("lab_id") != "HO-LAB-WAZUH-001":
        fail("manifest lab_id must be HO-LAB-WAZUH-001")
    if manifest.get("lab_status") != ALLOWED_LAB_STATUS:
        fail(f"manifest lab_status must be {ALLOWED_LAB_STATUS}")
    if manifest.get("owner_repo") != "hawkinsoperations-validation":
        fail("manifest owner_repo must be hawkinsoperations-validation")
    if manifest.get("source_registry_repo") != "hawkinsoperations-detections":
        fail("manifest source_registry_repo must be hawkinsoperations-detections")
    if manifest.get("proof_ceiling") != ALLOWED_PROOF_CEILING:
        fail(f"manifest proof_ceiling must be {ALLOWED_PROOF_CEILING}")
    require_false_boundary(manifest, "manifest")
    if repo_path(root, manifest.get("validation_registry", ""), "validation_registry") != (
        root / "validation" / "wazuh" / "WAZUH_LOGTEST_REGISTRY.json"
    ):
        fail("manifest validation_registry must point to validation/wazuh/WAZUH_LOGTEST_REGISTRY.json")
    repo_path(root, manifest.get("source_registry", ""), "source_registry")
    blocked = manifest.get("blocked_claims")
    if not isinstance(blocked, list) or not blocked:
        fail("manifest blocked_claims must be a non-empty array")
    for term in BLOCKED_TERMS:
        if term not in blocked and term not in {"Wazuh-routed proof", "runtime-active", "signal-observed"}:
            fail(f"manifest blocked_claims missing: {term}")
    return manifest_entries(manifest)


def split_groups(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def parse_wazuh_xml(path: Path) -> list[dict[str, Any]]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        fail(f"invalid Wazuh XML parse: {path} ({exc})")
    rules: list[dict[str, Any]] = []

    def walk(node: ET.Element, inherited_groups: set[str]) -> None:
        effective_groups = set(inherited_groups)
        if node.tag == "group":
            effective_groups.update(split_groups(node.attrib.get("name")))
        if node.tag == "rule":
            try:
                rule_id = int(str(node.attrib.get("id", "")).strip())
                level = int(str(node.attrib.get("level", "0")).strip())
            except ValueError:
                fail(f"Wazuh rule has invalid id or level in {path}")
            groups = set(effective_groups)
            for group in node.findall("group"):
                groups.update(split_groups(group.text))
            mitre_ids = {
                child.text.strip()
                for child in node.findall(".//id")
                if child.text and child.text.strip().startswith("T")
            }
            rules.append({"id": rule_id, "level": level, "groups": groups, "mitre_ids": mitre_ids})
            return
        for child in node:
            walk(child, effective_groups)

    walk(root, set())
    if not rules:
        fail(f"Wazuh XML has no rules: {path}")
    return rules


def verify_source_registry(source_registry: dict[str, Any], detections_root: Path) -> dict[str, dict[str, Any]]:
    entries = source_registry.get("entries")
    if not isinstance(entries, list) or not entries:
        fail("source registry entries must be a non-empty array")
    by_detection: dict[str, dict[str, Any]] = {}
    seen_rule_ids: dict[int, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            fail("source registry entries must be objects")
        detection_id = str(entry.get("detection_id", "")).strip()
        if not detection_id:
            fail("source registry entry missing detection_id")
        if detection_id in by_detection:
            fail(f"duplicate source registry detection_id: {detection_id}")
        by_detection[detection_id] = entry
        require_false_boundary(entry, f"{detection_id} source registry")
        package = entry.get("detection_package")
        if not isinstance(package, str) or not repo_path(detections_root, package, "detection_package").exists():
            fail(f"{detection_id} missing detection_package: {package}")
        xml_ref = entry.get("wazuh_rule_path")
        if not xml_ref:
            continue
        xml_path = repo_path(detections_root, xml_ref, "wazuh_rule_path")
        if not xml_path.exists():
            fail(f"{detection_id} missing wazuh_rule_path: {xml_ref}")
        rules = parse_wazuh_xml(xml_path)
        actual_ids = [rule["id"] for rule in rules]
        duplicates = sorted(rule_id for rule_id in set(actual_ids) if actual_ids.count(rule_id) > 1)
        if duplicates:
            fail(f"{detection_id} duplicate Wazuh rule id in source XML: {duplicates}")
        actual_id_set = set(actual_ids)
        actual_groups = set().union(*(rule["groups"] for rule in rules))
        actual_mitre = set().union(*(rule["mitre_ids"] for rule in rules))
        for expected_id in entry.get("expected_rule_ids") or []:
            if int(expected_id) not in actual_id_set:
                fail(f"{detection_id} expected source Wazuh rule id missing: {expected_id}")
        for expected_group in entry.get("expected_groups") or []:
            if expected_group not in actual_groups:
                fail(f"{detection_id} expected source Wazuh group missing: {expected_group}")
        for expected_mitre in entry.get("expected_mitre_ids") or []:
            if expected_mitre not in actual_mitre:
                fail(f"{detection_id} expected source MITRE id missing: {expected_mitre}")
        for rule_id in actual_id_set:
            owner = seen_rule_ids.get(rule_id)
            if owner and owner != detection_id:
                fail(f"duplicate Wazuh rule id {rule_id}: {owner} and {detection_id}")
            seen_rule_ids[rule_id] = detection_id
    return by_detection


def optional_reference_fields(entry: dict[str, Any]) -> list[tuple[str, str]]:
    references: list[tuple[str, str]] = []
    for field in ("expected_result", "expected_results", "expected_output", "expected_output_file", "expected_result_file"):
        value = entry.get(field)
        if isinstance(value, str) and value:
            references.append((field, value))
        elif isinstance(value, list):
            references.extend((field, item) for item in value if isinstance(item, str) and item)
    return references


def verify_validation_registry(
    manifest_entries_: list[dict[str, Any]],
    validation_entries: list[dict[str, Any]],
    root: Path,
) -> dict[str, dict[str, Any]]:
    by_detection: dict[str, dict[str, Any]] = {}
    for entry in validation_entries:
        detection_id = entry["detection_id"]
        by_detection[detection_id] = entry
        for field, value in optional_reference_fields(entry):
            if not repo_path(root, value, field).exists():
                fail(f"{detection_id} missing {field}: {value}")
    manifest_ids = {entry["detection_id"] for entry in manifest_entries_}
    validation_ids = set(by_detection)
    if manifest_ids != validation_ids:
        fail(f"manifest/logtest detection_id mismatch: manifest={sorted(manifest_ids)} logtest={sorted(validation_ids)}")
    for lab_entry in manifest_entries_:
        detection_id = lab_entry["detection_id"]
        validation_entry = by_detection[detection_id]
        if validation_entry.get("status") != lab_entry.get("validation_registry_status"):
            fail(f"{detection_id} validation_registry_status mismatch")
        if lab_entry["sample_required"] and not validation_entry.get("sample_event"):
            fail(f"{detection_id} sample_event is required by manifest")
        if not lab_entry["sample_required"] and validation_entry.get("sample_event") is not None:
            fail(f"{detection_id} sample_event must stay null until sample wiring exists")
        if lab_entry["expected_result_reference_required"] and not optional_reference_fields(validation_entry):
            fail(f"{detection_id} expected result reference is required by manifest")
    return by_detection


def verify_cross_registry_mapping(
    manifest_entries_: list[dict[str, Any]],
    validation_by_detection: dict[str, dict[str, Any]],
    source_by_detection: dict[str, dict[str, Any]],
) -> None:
    for lab_entry in manifest_entries_:
        detection_id = lab_entry["detection_id"]
        source_entry = source_by_detection.get(detection_id)
        if source_entry is None:
            fail(f"{detection_id} missing source registry entry")
        if source_entry.get("status") != lab_entry.get("source_registry_status"):
            fail(f"{detection_id} source_registry_status mismatch")
        validation_entry = validation_by_detection[detection_id]
        source_path = source_entry.get("wazuh_rule_path")
        validation_source = validation_entry.get("wazuh_rule_source")
        if lab_entry["source_required"]:
            if not source_path:
                fail(f"{detection_id} source_required but source registry has no wazuh_rule_path")
            if validation_source != source_path:
                fail(f"{detection_id} validation/source Wazuh path mismatch: {validation_source} != {source_path}")
        else:
            if validation_source is not None:
                fail(f"{detection_id} validation source must stay null until source exists")


def line_has_negative_context(lines: list[str], index: int) -> bool:
    start = max(0, index - 20)
    context = " ".join(lines[start : index + 1])
    return bool(NEGATIVE_CONTEXT_RE.search(context))


def scan_claim_boundaries(root: Path, manifest: dict[str, Any]) -> None:
    paths = manifest.get("claim_boundary_files")
    if not isinstance(paths, list) or not paths:
        fail("manifest claim_boundary_files must be a non-empty array")
    for value in paths:
        if not isinstance(value, str) or not value:
            fail("claim_boundary_files entries must be non-empty strings")
        path = repo_path(root, value, "claim_boundary_files")
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            fail(f"missing claim boundary file: {value}")
        lines = text.splitlines()
        for index, line in enumerate(lines):
            for term in BLOCKED_TERMS:
                if term.lower() in line.lower() and not line_has_negative_context(lines, index):
                    fail(f"{value}:{index + 1} blocked claim without negative context: {term}")


def verify_lab(
    root: Path = ROOT,
    manifest_path: Path = MANIFEST_PATH,
    detections_root: Path | None = DEFAULT_DETECTIONS_ROOT,
    source_contract: str = "skip-if-missing",
    print_summary: bool = True,
) -> dict[str, Any]:
    manifest = load_json(manifest_path, "HO-LAB-WAZUH-001 manifest")
    lab_entries = verify_manifest(manifest, root)
    registry_path = repo_path(root, manifest["validation_registry"], "validation_registry")
    source_root = detections_root if detections_root and detections_root.exists() else None
    if source_root is None and source_contract == "required":
        fail(f"detections source root missing: {detections_root}")
    validation_entries = logtest_registry.verify_registry(
        registry_path=registry_path,
        root=root,
        detections_root=source_root,
        run_logtest=False,
        print_summary=False,
    )
    validation_by_detection = verify_validation_registry(lab_entries, validation_entries, root)
    source_checked = False
    if source_root is not None:
        source_registry_path = repo_path(source_root, manifest["source_registry"], "source_registry")
        source_by_detection = verify_source_registry(load_yaml(source_registry_path, "Wazuh source registry"), source_root)
        verify_cross_registry_mapping(lab_entries, validation_by_detection, source_by_detection)
        source_checked = True
    scan_claim_boundaries(root, manifest)
    result = {
        "lab_id": manifest["lab_id"],
        "entries": len(lab_entries),
        "source_contract": "checked" if source_checked else "skipped",
        "proof_ceiling": manifest["proof_ceiling"],
    }
    if print_summary:
        print(
            "HO_LAB_WAZUH_001=pass entries={entries} source_contract={source_contract} proof_ceiling={proof_ceiling}".format(
                **result
            )
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify HO-LAB-WAZUH-001 static Wazuh rule contract lab.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--detections-root", type=Path, default=DEFAULT_DETECTIONS_ROOT)
    parser.add_argument(
        "--source-contract",
        choices=("required", "skip-if-missing"),
        default="skip-if-missing",
        help="Require adjacent detections source registry or skip it when absent.",
    )
    args = parser.parse_args()
    try:
        verify_lab(args.root, args.manifest, args.detections_root, args.source_contract)
    except (HOLabWazuhError, logtest_registry.WazuhLogtestRegistryError) as exc:
        print(f"HO_LAB_WAZUH_001=fail: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

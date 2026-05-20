#!/usr/bin/env python3
"""Run every registry-listed validation package check."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any

from verify_validation_registry import REGISTRY_PATH, ROOT, RegistryFailure, load_registry, validate_registry


CHECK_FIELDS = (
    ("validator", "validator_script"),
    ("parity", "parity_script"),
    ("claim-boundary", "claim_boundary_script"),
)


def _script_command(script_path: str) -> list[str]:
    path = Path(script_path)
    if path.suffix.lower() == ".py":
        return [sys.executable, "-B", script_path]
    return [script_path]


def build_commands(package: dict[str, Any]) -> list[tuple[str, list[str]]]:
    commands: list[tuple[str, list[str]]] = []
    for label, field in CHECK_FIELDS:
        script_path = package.get(field)
        if not script_path:
            continue
        command = _script_command(script_path)
        if (
            field == "validator_script"
            and package.get("source_dependency_required") is True
            and package.get("ci_source_dependency_mode") == "skip-if-missing"
        ):
            command.extend(["--source-contract", "skip-if-missing"])
        commands.append((label, command))
    return commands


def run_package_commands(packages: list[dict[str, Any]], root: Path = ROOT) -> int:
    rows: list[tuple[str, str, str]] = []
    failed = False

    for package in packages:
        detection_id = package["detection_id"]
        for label, command in build_commands(package):
            result = subprocess.run(command, cwd=root, text=True, capture_output=True)
            status = "pass" if result.returncode == 0 else "fail"
            rows.append((detection_id, label, status))
            if result.stdout:
                print(result.stdout.rstrip())
            if result.stderr:
                print(result.stderr.rstrip(), file=sys.stderr)
            if result.returncode != 0:
                failed = True

    print("VALIDATION_PACKAGE_CHECKS")
    print("detection_id | check | status")
    print("-------------|-------|-------")
    for detection_id, label, status in rows:
        print(f"{detection_id} | {label} | {status}")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run every registry-listed validation package check.")
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    args = parser.parse_args()
    try:
        packages = validate_registry(load_registry(args.registry), ROOT)
    except RegistryFailure as exc:
        print(f"VALIDATION_REGISTRY=fail: {exc}", file=sys.stderr)
        return 1
    return run_package_commands(packages, ROOT)


if __name__ == "__main__":
    raise SystemExit(main())

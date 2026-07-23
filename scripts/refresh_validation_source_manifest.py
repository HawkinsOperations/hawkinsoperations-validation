#!/usr/bin/env python3
"""Generate or verify the content-addressed detection-to-validation handoff."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from verify_validation_registry import (
    REGISTRY_PATH,
    ROOT,
    RegistryFailure,
    _verify_source_repository,
    build_source_authority_manifest,
    load_detection_source_inventory,
    load_registry,
    validate_detection_source_inventory,
    validate_registry,
)


OUTPUT_PATH = ROOT / "validation" / "SOURCE_AUTHORITY_MANIFEST.json"


def render(payload: dict[str, object]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refresh or verify the immutable content identity handoff from detections."
    )
    parser.add_argument(
        "--detections-root",
        type=Path,
        default=ROOT.parent / "hawkinsoperations-detections",
    )
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--detections-ref")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        packages = validate_registry(load_registry(args.registry), ROOT)
        detections_root = args.detections_root.resolve()
        _verify_source_repository(detections_root, args.detections_ref)
        payload = build_source_authority_manifest(packages, detections_root)
        validate_detection_source_inventory(
            load_detection_source_inventory(detections_root),
            payload,
        )
        expected = render(payload)
        if args.write:
            OUTPUT_PATH.write_text(expected, encoding="utf-8", newline="\n")
            print(f"SOURCE_AUTHORITY_MANIFEST=written:{OUTPUT_PATH.relative_to(ROOT).as_posix()}")
            return 0
        if not OUTPUT_PATH.is_file():
            raise RegistryFailure(
                "source authority manifest is missing; run with --write to create it"
            )
        actual = OUTPUT_PATH.read_text(encoding="utf-8")
        if actual != expected:
            raise RegistryFailure(
                "source authority manifest is stale; run with --write to refresh it"
            )
    except (RegistryFailure, OSError) as exc:
        print(f"SOURCE_AUTHORITY_MANIFEST=fail: {exc}", file=sys.stderr)
        return 1
    print("SOURCE_AUTHORITY_MANIFEST=pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

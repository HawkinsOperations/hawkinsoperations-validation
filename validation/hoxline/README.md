# Hoxline Validation Bridges

This directory contains validation-owned bridge records for Hoxline reviewer paths. These records point at Hoxline outputs and validation-owned behavior records, but they do not make Hoxline, ProofCards, websites, or demos the validation authority.

Current bridge:

| Detection | Bridge | Status | Public-safe |
|---|---|---|---|
| HO-DET-001 | `HO-DET-001_HOXLINE_GAUNTLET_VALIDATION_BRIDGE_V1.md` | `VALIDATION_BRIDGE_REVIEWER_PATH_RECORDED` | `BLOCKED` |

Primary Hoxline source route for HO-DET-001 is `HawkinsOperations/hoxline/examples/gauntlet/ho-det-001-gauntlet-v1-source-manifest.json`, with `examples/gauntlet/ho-det-001-gauntlet-run-v1.json` and `schemas/gauntlet-run-v1.schema.json` as the bounded Gauntlet v1 run and schema. The local checkout may still be named `aevumguard`; the GitHub source repo remains `HawkinsOperations/hoxline`. The v0 Gauntlet route remains compatibility-only.

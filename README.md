# HawkinsOperations Validation

Validation framework and execution evidence for HawkinsOps V2 detections.

## Purpose

This repository verifies that detection logic behaves as intended against controlled test inputs and replay scenarios.

## Scope

- Detection test cases and replay packs
- Validation harnesses and pipelines
- Pass/fail reports and regression tracking

## Out of Scope

- Primary detection authoring (lives in `hawkinsoperations-detections`)
- Production infrastructure ownership (lives in `hawkinsoperations-platform`)
- Sensitive runtime logs from live environments

## Repository Contract

- Every detection promoted to production should have validation coverage.
- Validation outputs must be reproducible and traceable to specific detection versions.
- Failures are treated as engineering defects, not documentation notes.

## Public-Safe Proof

- Sanitized validation summaries
- Reproducible test methodology
- Versioned pass/fail snapshots

## Related Repositories

- Detections: `hawkinsoperations-detections`
- Platform: `hawkinsoperations-platform`
- Proof: `hawkinsoperations-proof`
- Website: `hawkinsoperations-website`


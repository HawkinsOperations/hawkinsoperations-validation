# Governance

Repository: `hawkinsoperations-validation`

## Rules

1. Validation must be reproducible from committed inputs.
2. Result claims must map to evidence entries.
3. No host-local paths, credentials, or secret material in tracked files.
4. Regression-impacting changes require clear pass/fail criteria updates.

## Evidence Contract

- Evidence ledger files:
  - `evidence/EVIDENCE_LEDGER_SCHEMA.json`
  - `evidence/evidence-ledger.json`
- Entries include validation artifact references and checksums.

## Promotion Gate

- Required governance files must exist.
- CI gate must pass before merge.
- Public-safe output only; internal control-plane data stays out.


# ID-DET-003 Controlled-Test Validation

## Purpose

This fixture set validates ID-DET-003 privileged role assignment or admin group change behavior against controlled identity administration cases.

## Scope

- Privileged role assignment.
- Admin group membership change.
- Sensitive entitlement grant.
- Approved-change suppressions for just-in-time, ticketed, break-glass, and maintenance contexts.

## Positive Fixtures

- `pos-001-privileged-role-assignment`: successful privileged role assignment.
- `pos-002-admin-group-change`: successful admin group addition.
- `pos-003-sensitive-entitlement-grant`: successful sensitive entitlement grant.

## Negative Fixtures

- `neg-001-approved-jit-role`: approved just-in-time privileged role assignment.
- `neg-002-ticketed-admin-group-change`: ticketed admin group change.
- `neg-003-breakglass-exercise`: break-glass exercise.
- `neg-004-maintenance-expected-admin`: maintenance window with expected administrative actor.

## Validation Boundary

This validates controlled identity administration fixture behavior only. It does not inspect runtime systems, live IdP telemetry, live Splunk, Wazuh routing, Cribl routing, Security Onion observation, production deployment, public-safe status, or evidence-linked public proof.

## Current Scope

This validation lane establishes controlled-test validation for ID-DET-003 only. The fixture cases are deterministic validation cases built from controlled identity administration fixtures.

## Not Claimed Here

This validation lane does not claim live IdP proof, live SIEM/NDR observation, production identity coverage, complete identity-attack coverage, autonomous SOC operation, disposition authority, proof promotion, public-safe status, or website/public-surface publication.

## Reproduction

From the validation repository root:

```powershell
python -B scripts/validate-id-det-003.py
python -B scripts/verify-id-det-003-result-parity.py
python -B scripts/scan-id-det-003-claim-boundaries.py
```

Use `--write` only when intentionally regenerating `reports/id-det-003/validation-result.json` and `reports/id-det-003/validation-result.md`.

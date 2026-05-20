# ID-DET-002 Controlled-Test Validation

## Purpose

This fixture set validates ID-DET-002 suspicious MFA fatigue or repeated MFA failure behavior against controlled identity-event cases.

## Scope

- Repeated MFA push attempts in a short controlled window.
- Repeated MFA denial outcomes in a short controlled window.
- Successful authentication after repeated MFA failures.
- Privileged identity under repeated MFA pressure.

## Positive Fixtures

- `pos-001-mfa-push-fatigue-volume`: repeated MFA push attempts inside the threshold window.
- `pos-002-repeated-mfa-denial`: repeated MFA denials inside the threshold window.
- `pos-003-success-after-mfa-failures`: successful login after repeated MFA failures.
- `pos-004-privileged-identity-pressure`: privileged identity under repeated MFA pressure.

## Negative Fixtures

- `neg-001-single-mfa-failure`: single MFA failure below threshold.
- `neg-002-approved-mfa-reset`: repeated MFA activity during an approved reset.
- `neg-003-enrollment-workflow`: repeated MFA activity during enrollment.
- `neg-004-expected-health-check`: repeated MFA activity from expected health-check behavior.

## Validation Boundary

This validates controlled identity-event fixture behavior only. It does not inspect runtime systems, live IdP telemetry, live Splunk, Wazuh routing, Cribl routing, Security Onion observation, production deployment, public-safe status, or evidence-linked public proof.

## Current Scope

This validation lane establishes controlled-test validation for ID-DET-002 only. The fixture cases are deterministic validation cases built from controlled identity-event fixtures.

## Not Claimed Here

This validation lane does not claim live IdP proof, live SIEM/NDR observation, production identity coverage, complete identity-attack coverage, autonomous SOC operation, disposition authority, proof promotion, public-safe status, or website/public-surface publication.

## Reproduction

From the validation repository root:

```powershell
python -B scripts/validate-id-det-002.py
python -B scripts/verify-id-det-002-result-parity.py
python -B scripts/scan-id-det-002-claim-boundaries.py
```

Use `--write` only when intentionally regenerating `reports/id-det-002/validation-result.json` and `reports/id-det-002/validation-result.md`.

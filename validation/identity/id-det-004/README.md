# ID-DET-004 Controlled-Test Validation

## Purpose

This fixture set validates ID-DET-004 impossible travel or anomalous session context behavior against controlled identity-event cases.

## Scope

- Impossible travel on successful login.
- High location velocity.
- New country with new device context.
- Session reuse after ASN and user-agent context shift.
- Approved travel, VPN, corporate proxy, and maintenance suppressions.

## Positive Fixtures

- `pos-001-impossible-travel-success`: impossible travel on successful login.
- `pos-002-high-location-velocity`: high controlled location velocity.
- `pos-003-new-country-new-device`: new country with unknown device.
- `pos-004-session-context-shift`: session reuse after ASN and user-agent shift.

## Negative Fixtures

- `neg-001-approved-travel`: approved travel context.
- `neg-002-expected-vpn`: expected VPN egress.
- `neg-003-known-corporate-proxy`: known corporate proxy context.
- `neg-004-maintenance-window`: maintenance or test session.

## Validation Boundary

This validates controlled identity-event fixture behavior only. It does not inspect runtime systems, live IdP telemetry, live Splunk, Wazuh routing, Cribl routing, Security Onion observation, production deployment, public-safe status, or evidence-linked public proof.

## Current Scope

This validation lane establishes controlled-test validation for ID-DET-004 only. The fixture cases are deterministic validation cases built from controlled identity-event fixtures.

## Not Claimed Here

This validation lane does not claim live IdP proof, live SIEM/NDR observation, production identity coverage, complete identity-attack coverage, impossible-travel completeness, session hijacking completeness, autonomous SOC operation, disposition authority, proof promotion, public-safe status, or website/public-surface publication.

## Reproduction

From the validation repository root:

```powershell
python -B scripts/validate-id-det-004.py
python -B scripts/verify-id-det-004-result-parity.py
python -B scripts/scan-id-det-004-claim-boundaries.py
```

Use `--write` only when intentionally regenerating `reports/id-det-004/validation-result.json` and `reports/id-det-004/validation-result.md`.

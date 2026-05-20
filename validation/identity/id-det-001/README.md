# ID-DET-001 Controlled-Test Validation

## Purpose

This fixture set validates ID-DET-001 suspicious identity session context behavior against controlled identity-event cases.

## Scope

- Successful login with impossible travel.
- Successful login from a new device plus new ASN category.
- Interactive service-account use.
- AI or agent privileged action outside approved tool scope.
- Session reuse after user-agent and ASN category shift.

## Positive Fixtures

- `pos-001-impossible-travel-success`: impossible travel successful login.
- `pos-002-new-device-new-asn`: successful login from new device plus new ASN category.
- `pos-003-service-account-interactive`: service account used interactively.
- `pos-004-ai-agent-privileged-out-of-scope`: AI or agent identity performs privileged action outside approved tool scope.
- `pos-005-session-reuse-context-shift`: session reuse after user-agent and ASN shift.

## Negative Fixtures

- `neg-001-normal-known-device`: normal successful login from known device.
- `neg-002-vpn-known-device-expected-asn`: VPN country change with known device and expected ASN category.
- `neg-003-service-account-expected-automation`: service account used by expected automation.
- `neg-004-ai-agent-approved-tool-scope`: AI or agent identity uses approved tool within scope.
- `neg-005-privileged-maintenance-window`: privileged user performs expected action during maintenance window.

## Validation Boundary

This validates controlled identity-event fixture behavior only. It does not inspect runtime systems, live IdP telemetry, live Splunk, Wazuh routing, Cribl routing, Security Onion observation, production deployment, public-safe status, or evidence-linked public proof.

## Reproduction

From the validation repository root:

```powershell
python -B scripts/validate-id-det-001.py
python -B scripts/verify-id-det-001-result-parity.py
python -B scripts/scan-id-det-001-claim-boundaries.py
```

Use `--write` only when intentionally regenerating `reports/id-det-001/validation-result.json` and `reports/id-det-001/validation-result.md`.

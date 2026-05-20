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

## Current Scope

This validation lane establishes controlled-test validation for ID-DET-001 only. The 10 fixture cases are deterministic validation cases built from controlled identity-event fixtures.

## Future Gated Phases

Future live or runtime work requires separate gates:

- `ID-RUNTIME-001`: Proxmox and Windows private runtime identity receipt using Windows identity/auth metadata, Wazuh count-only receipt, Splunk count-only receipt, and platform private ledger review.
- `ID-CLOUD-001`: IdP export/log review lane for approved Entra-style or Okta-style identity log exports.
- `ID-AGENT-001`: AI or machine identity tool-scope validation lane for actions outside approved tool or resource scope.
- `ID-ROUTE-001`: SIEM/NDR route receipt lane for count-only Wazuh, Splunk, Cribl, and Security Onion route checks.

## Not Claimed Here

This validation lane does not claim live IdP proof, live SIEM/NDR observation, production identity coverage, complete identity-attack coverage, autonomous SOC operation, disposition authority, proof promotion, public-safe status, or website/public-surface publication.

## Reproduction

From the validation repository root:

```powershell
python -B scripts/validate-id-det-001.py
python -B scripts/verify-id-det-001-result-parity.py
python -B scripts/scan-id-det-001-claim-boundaries.py
```

Use `--write` only when intentionally regenerating `reports/id-det-001/validation-result.json` and `reports/id-det-001/validation-result.md`.

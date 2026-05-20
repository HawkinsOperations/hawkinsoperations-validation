# ID-DET-001 Validation Result

- Status: `pass`
- Detection ID: `ID-DET-001`
- Validation scope: `controlled identity-event fixtures only`
- Claim ceiling: `CONTROLLED_TEST_VALIDATED`
- Fixture count: `10`
- Positive count: `5`
- Negative count: `5`
- Matched positives: `5`
- Missed positives: `0`
- False-positive negatives: `0`

## Supported Claim

ID-DET-001 passed controlled-test validation against 10 controlled identity-event fixtures for suspicious identity session context.

## Current Scope

This validation result establishes controlled-test validation for ID-DET-001 only.

## Future Gated Phases

- `ID-RUNTIME-001`: Proxmox and Windows private runtime identity receipt. Claim ceiling: `PRIVATE_RUNTIME_METADATA_CAPTURED`. Boundary: Not public proof. Not production coverage. Not public-safe.
- `ID-CLOUD-001`: IdP export/log review lane. Claim ceiling: `CONTROLLED_TEST_VALIDATED first, then PRIVATE_RUNTIME_METADATA_CAPTURED only if approved sanitized export review exists.`. Boundary: No live IdP proof in this PR. No production tenant claim.
- `ID-AGENT-001`: AI or machine identity tool-scope validation lane. Claim ceiling: `CONTROLLED_TEST_VALIDATED`. Boundary: No autonomous SOC claim. No AI disposition authority.
- `ID-ROUTE-001`: SIEM/NDR route receipt lane. Claim ceiling: `PRIVATE_RUNTIME_METADATA_CAPTURED if receipt exists.`. Boundary: No live SIEM/NDR public proof in this PR. No full route proof unless later separately captured and reviewed.

## Not Claimed Here

- live IdP proof
- live SIEM/NDR observation
- production identity coverage
- complete identity-attack coverage
- autonomous SOC operation
- disposition authority
- proof promotion
- public-safe status
- website/public-surface publication

## Boundary

Controlled identity-event fixture validation only. This does not prove runtime, signal, public-safe proof, live IdP, live Splunk, Wazuh routing, Cribl routing, Security Onion observation, production identity coverage, AI or agent production governance, autonomous SOC behavior, AI-approved disposition, or analyst-approved disposition.

## Blocked Claims

- runtime-active
- signal-observed
- public-safe
- evidence-linked public proof
- live Okta proof
- live Entra proof
- live IdP proof
- live Splunk proof
- Wazuh-routed proof
- Cribl-routed proof
- Security Onion observed proof
- production-ready
- fleet-wide
- production identity coverage
- machine identity production governance
- AI agent production governance
- full identity attack coverage
- impossible-travel completeness
- session hijacking completeness
- autonomous SOC
- AI-approved disposition
- analyst-approved disposition
- proof promotion
- website/public-surface promotion

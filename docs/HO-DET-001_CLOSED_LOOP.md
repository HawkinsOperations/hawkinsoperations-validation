# HO-DET-001 Closed-Loop Detection Walkthrough

## Status

- Detection ID: HO-DET-001
- Current public repo proof label: CONTROLLED_TEST_VALIDATED
- Runtime-active: BLOCKED
- Signal-observed: BLOCKED
- Public-safe: NOT_PUBLIC_SAFE
- Cribl-routed: NOT_PROVEN
- Wazuh-routed: NOT_PROVEN

## What This Detects

Suspicious PowerShell or pwsh execution using encoded-command style flags or encoded payload indicators in process-creation telemetry.

## Detection Loop

1. Source logic exists in `hawkinsoperations-detections/detections/successor/ho-det-001/rule.yml`.
2. Splunk SPL exists in `hawkinsoperations-detections/detections/successor/ho-det-001/splunk.spl`.
3. Controlled test cases exist in `hawkinsoperations-validation/validation/successor/ho-det-001/validation-cases.json`.
4. Validation output exists in `hawkinsoperations-validation/reports/ho-det-001/validation-result.json`.
5. Proof status is recorded in `hawkinsoperations-proof/proof/records/HO-DET-001.md`.

## What Passed

- 14 total controlled process-creation test cases
- 7 positive cases matched
- 7 negative cases did not match
- 0 missed positive cases
- 0 false-positive negative cases

## Supported Claim

HO-DET-001 is CONTROLLED_TEST_VALIDATED through controlled positive and negative process-creation test cases.

## SOCaaS Pilot Receipt Fit

This existing loop can support a SOCaaS-style reviewer receipt at controlled-test scope only:

- Alert shape: PARTIAL. The fixture and case packet expose endpoint process fields such as host, user, process image, command line, parent process, detection ID, and ATT&CK technique. Vendor, raw alert name, rule version, and timestamp still need a normalized receipt wrapper.
- Robustness/decomposition record: PARTIAL. The detection source records the observable, ATT&CK mapping, data source, false-positive context, and source assumptions; it does not yet provide a first-class evasion and blind-spot record.
- Deterministic validation: PRESENT. Positive and negative controlled fixtures passed with deterministic output.
- Receipt record: PARTIAL. The validation result, case packet, AutoSOC triage packet, proof record, and proof card form the receipt chain, but there is not yet one unified SOCaaS receipt object.
- Triage-support output: PRESENT at controlled-test support-only scope. Human review remains required, and AI cannot decide disposition.
- Customer-safe summary: PARTIAL. Existing proof and website routes can explain the boundary, but the customer-safe summary still needs one explicit view.

## Blocked Claims

This does not prove:

- runtime-active deployment
- signal-observed status
- public-safe status
- production readiness
- live Splunk firing
- Cribl-routed telemetry
- Wazuh live collection
- fleet-wide coverage
- attack detection in production

## Reviewer Summary

This artifact closes the public repo validation loop for HO-DET-001 at controlled-test scope only. It explains what exists, what passed, and what remains blocked.

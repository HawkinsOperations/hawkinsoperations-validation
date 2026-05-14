# HO-DET-001 Public Pipeline Proof Pack

## Public Label

CONTROLLED_TEST_VALIDATED

## Allowed Public Claim

HO-DET-001 is CONTROLLED_TEST_VALIDATED through a public proof-loop workflow with controlled positive and negative test cases, deterministic pass/fail output, and blocked-claim enforcement.

## Public Proof Loop

| Field | Value |
|---|---:|
| Public proof-loop workflow count | 1 |
| Repositories checked out by workflow | 3 |
| Verifier/check run-step count | 13 |
| Referenced Python scripts | 11 |
| Missing referenced scripts | 0 |

Workflow route: `.github/workflows/ho-det-001-proof-loop.yml`

## Controlled Test Results

| Field | Value |
|---|---:|
| Controlled test case count | 14 |
| Positive case count | 7 |
| Negative case count | 7 |
| Matched positive count | 7 |
| Missed positives | 0 |
| False-positive negatives | 0 |
| Passed case count | 14 |
| Failed case count | 0 |

Validation report route: `reports/ho-det-001/validation-result.md`

## Public Routes

- Validation report: <https://github.com/HawkinsOperations/hawkinsoperations-validation/blob/main/reports/ho-det-001/validation-result.md>
- Proof-loop workflow: <https://github.com/HawkinsOperations/hawkinsoperations-validation/blob/main/.github/workflows/ho-det-001-proof-loop.yml>
- Detection source: <https://github.com/HawkinsOperations/hawkinsoperations-detections/blob/main/detections/successor/ho-det-001/rule.yml>
- Splunk source: <https://github.com/HawkinsOperations/hawkinsoperations-detections/blob/main/detections/successor/ho-det-001/splunk.spl>
- Proof record: <https://github.com/HawkinsOperations/hawkinsoperations-proof/blob/main/proof/records/HO-DET-001.md>

## Blocked Claims

This public packet does not claim:

- runtime-active
- production-ready
- fleet-wide
- public-safe runtime evidence
- live Splunk firing
- Cribl-routed telemetry
- Wazuh live collection
- autonomous disposition
- analyst-approved disposition
- evidence-linked public runtime proof

## Boundary

This packet is a public route into controlled-test validation and proof-loop enforcement. It does not publish private runtime evidence, does not convert private/internal lab evidence into public-safe evidence, and does not promote HO-DET-001 beyond CONTROLLED_TEST_VALIDATED.

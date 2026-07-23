# HawkinsOperations Validation

Behavior-truth layer for HawkinsOperations detections, case packets, validation contracts, and AI-support boundaries.

This repository answers one narrow question:

> Did the detection or workflow behave correctly against controlled inputs inside the stated validation scope?

It does not answer whether a detection is running in production, whether a live signal was observed, whether runtime evidence is public-safe, or whether AI or an analyst approved a final disposition.

## 10-Second Reviewer Path

| Start here | What it shows | Command or route | Boundary |
| --- | --- | --- | --- |
| Single-repo validation package sweep | Clone-runnable registry, validation package, parity, claim-boundary, and contract checks | `python -B scripts/verify_all_validation_packages.py` | Public fixtures and skip-if-missing source contracts only |
| HO-DET-001 source-contract pipeline | Full local pipeline for public fixtures, case packet structure, AI authority boundary, claim scan, and result parity | `python -B scripts/run-ho-det-001-local-case-pipeline.py --check` | Requires adjacent HawkinsOperations source checkout for source-contract validation |
| Validation registry | Detection package inventory, fixture counts, proof ceilings, public-safe status, and verifier routes | [`validation/VALIDATION_REGISTRY.yml`](validation/VALIDATION_REGISTRY.yml) | Registry truth, not runtime truth |
| Activity ledger | Reviewer-facing controlled validation activity totals | [`activity/detection-activity-ledger-v1.md`](activity/detection-activity-ledger-v1.md) | Counts controlled validation activity, not governed case closure |
| HO-LAB-WAZUH-001 static contract lab | Wazuh source/static registry consistency, controlled sample wiring, and proof-boundary checks | `python -B scripts/verify_ho_lab_wazuh_001.py` | Source/static CI contract only |
| HO-DET-001 validation result | Positive/negative controlled fixture result with missed-positive and false-positive tracking | [`reports/ho-det-001/validation-result.md`](reports/ho-det-001/validation-result.md) | Validation truth only |
| CI validation gates | Public PR checks for registry, contracts, parity, claim boundaries, and trusted-runner separation | [`.github/workflows`](.github/workflows) | CI checks do not prove live deployment or public-safe runtime proof |

## Strongest Current Receipts

- **HO-DET-001 controlled validation route**: 14 controlled process-creation cases, 7 positive cases, 7 negative cases, 0 missed positives, and 0 false-positive negatives in [`reports/ho-det-001/validation-result.md`](reports/ho-det-001/validation-result.md).
- **Public clone-runnable package sweep**: `scripts/verify_all_validation_packages.py` runs every registry-listed validation package and uses the registry's skip-if-missing source-contract mode where sibling source repositories are not present.
- **Full HO-DET-001 source-contract pipeline**: `scripts/run-ho-det-001-local-case-pipeline.py --check` composes the backend adapter verifier, AI-support contract verifier, controlled validator, claim-boundary scanner, result parity verifier, deterministic case-packet check, and case-packet contract verifier when the adjacent HawkinsOperations source checkout is available.
- **Case-packet and AI authority checks**: the HO-DET-001 route validates deterministic triage/case-packet structure while keeping AI output support-only and requiring human review before any disposition or action claim.
- **Validation registry**: [`validation/VALIDATION_REGISTRY.yml`](validation/VALIDATION_REGISTRY.yml) ties each validation package to fixture counts, validator scripts, parity scripts, claim-boundary scanners, proof ceilings, and public-safe status.
- **Reviewer Metrics Pipeline v1**: [`activity/detection-activity-ledger-v1.md`](activity/detection-activity-ledger-v1.md) records 49 controlled positive fixture matches, 57 controlled negative checks, and 106 total validation cases, while keeping runtime-public-safe and public-safe counts at 0.
- **Result parity and claim-boundary enforcement**: scripts such as `verify-ho-det-001-result-parity.py`, `verify-aws-det-001-result-parity.py`, `verify-id-det-001-result-parity.py`, and `scan-ho-det-001-claim-boundaries.py` keep reports, source expectations, and public wording boundaries aligned.
- **Contract validation beyond one detection**: the repo includes controlled validation or contract lanes for HO-DET-001, HO-DET-011, HO-DET-012, AWS-DET-001, ID-DET-001 through ID-DET-004, HO-PIPE-001, HO-NDR-001 Security Onion visibility samples, and Wazuh logtest registry contracts.
- **HO-LAB-WAZUH-001 static Wazuh rule contract lab**: [`validation/wazuh/labs/HO-LAB-WAZUH-001.md`](validation/wazuh/labs/HO-LAB-WAZUH-001.md) gives reviewers a deterministic source/static Wazuh registry and sample-wiring check without requiring live Wazuh manager access.

## What This Repo Owns

- Controlled positive and negative validation cases.
- Deterministic validation harnesses and replay/check pipelines.
- Validation reports with missed-positive and false-positive negative tracking.
- Case-packet validation and deterministic triage packet checks.
- AI authority boundary checks: AI may support reasoning, but it does not decide disposition.
- Result parity checks between fixtures, reports, proof records, and expected boundaries.
- Claim-boundary scanners that keep blocked claims negative, boundary-only, not-proven, or future-gated.
- Validation registry and detection activity ledger maintenance.
- Public clone-runnable checks that do not require private lab access.
- CI-backed validation workflows for reviewer-visible checks.

## What This Repo Does Not Own

This repo does not claim or prove:

- runtime-active deployment
- signal-observed public proof
- public-safe runtime proof
- live Splunk, Wazuh, Cribl, AWS, or Security Onion proof
- FortiSIEM integration proven
- production SOC or SOCaaS deployment
- customer deployment
- fleet-wide coverage
- autonomous SOC authority
- AI-decided disposition
- AI-approved disposition
- analyst-approved disposition

Those claims require separate runtime evidence, proof records, public-safe review, and human approval gates outside this validation surface.

## Flagship Route: HO-DET-001

HO-DET-001 is the clearest validation-to-reviewer path in this repository.

| Layer | Route | What it verifies | What it does not prove |
| --- | --- | --- | --- |
| Controlled fixtures | [`validation/successor/ho-det-001/validation-cases.json`](validation/successor/ho-det-001/validation-cases.json) | Positive and negative process-creation cases | Live telemetry |
| Single-repo validator | `python -B scripts/validate-ho-det-001.py --source-contract skip-if-missing` | Detection behavior against controlled fixtures when sibling source checkout is absent | Deployment or signal observation |
| Source-contract validator | `python -B scripts/validate-ho-det-001.py` | Detection behavior plus required adjacent detections source contract | Runtime or signal observation |
| Result parity | `python -B scripts/verify-ho-det-001-result-parity.py` | Reported result matches expected fixture outcome | Public-safe runtime proof |
| Claim scan | `python -B scripts/scan-ho-det-001-claim-boundaries.py` | Blocked claims remain blocked or boundary-only | Public approval |
| Case packet | `python -B scripts/build-ho-det-001-case-packet.py --check` | Deterministic case-packet output remains stable | Case closure |
| AI boundary | `python -B scripts/verify-ho-det-001-ai-triage-contract.py` | AI-support artifacts preserve human-review authority | AI disposition authority |
| Local pipeline | `python -B scripts/run-ho-det-001-local-case-pipeline.py --check` | End-to-end controlled public fixture route with required adjacent source checkout | Runtime, signal, or production truth |

Detailed route notes live in [`validation/successor/ho-det-001/README.md`](validation/successor/ho-det-001/README.md) and [`docs/HO-DET-001_CLOSED_LOOP.md`](docs/HO-DET-001_CLOSED_LOOP.md).

## Validation Expansion Routes

| Route | Scope | Primary verifier | Boundary |
| --- | --- | --- | --- |
| HO-DET-011 | Windows service-creation controlled fixtures | `python -B scripts/validate-ho-det-011.py` | Controlled validation only |
| HO-DET-012 | Scheduled-task / service-account misuse controlled fixtures | `python -B scripts/validate-ho-det-012.py` | Controlled validation only |
| AWS-DET-001 | CloudTrail-style controlled fixtures | `python -B scripts/validate-aws-det-001.py` | No live AWS or IdP proof |
| ID-DET-001..004 | Identity-event controlled fixtures | `python -B scripts/validate-id-det-001.py` through `validate-id-det-004.py` | No live IdP or SIEM proof |
| HO-PIPE-001 | Pipeline route integrity contract fixtures | `python -B scripts/validate-ho-pipe-001.py` | No live Cribl/Wazuh/Splunk route proof |
| HO-NDR-001 | Security Onion visibility and corroboration samples | `python -B scripts/verify-security-onion-visibility-rollup.py` | Contract samples only |
| Wazuh logtest | Registry and controlled-test sample contract | `python -B scripts/verify_wazuh_logtest_registry.py` | Static CI contract, not live Wazuh routing |
| HO-LAB-WAZUH-001 | Source/static Wazuh registry lab | `python -B scripts/verify_ho_lab_wazuh_001.py` | Source/static CI contract only |

Run every registry-listed validation package check:

```powershell
python -B scripts/verify_validation_registry.py
python -B scripts/verify_all_validation_packages.py
```

## Reviewer Commands

### Single-repo public clone path

These commands are the safest first path when a reviewer clones only `hawkinsoperations-validation`:

```powershell
python -B scripts/verify_validation_registry.py
python -B scripts/verify_all_validation_packages.py
python -B scripts/verify_validation_contract.py
python -B scripts/verify_wazuh_logtest_registry.py
python -B scripts/verify_ho_lab_wazuh_001.py
python -B -m unittest discover -s tests
```

For HO-DET-001 alone in a single-repo clone:

```powershell
python -B scripts/validate-ho-det-001.py --source-contract skip-if-missing
python -B scripts/verify-ho-det-001-result-parity.py
python -B scripts/scan-ho-det-001-claim-boundaries.py
python -B scripts/build-ho-det-001-case-packet.py --check
python -B scripts/verify_case_packet_contract.py
```

### Full source-contract path

Use this path when the adjacent HawkinsOperations source repositories are available, especially `../hawkinsoperations-detections` for HO-DET-001 source-contract validation:

```powershell
python -B scripts/validate-ho-det-001.py
python -B scripts/run-ho-det-001-local-case-pipeline.py --check
python -B scripts/verify-ho-det-001-result-parity.py
python -B scripts/scan-ho-det-001-claim-boundaries.py
python -B scripts/build-ho-det-001-case-packet.py --check
python -B scripts/verify_case_packet_contract.py
python -B scripts/verify_ho_lab_wazuh_001.py --source-contract required
```

## CI And Workflow Boundaries

CI workflows make validation repeatable and reviewer-visible:

- [`baseline-validation-contract.yml`](.github/workflows/baseline-validation-contract.yml) checks the validation registry, package verifiers, baseline contract, Wazuh logtest registry, HO-LAB-WAZUH-001 static contract lab, and unit tests.
- [`ho-det-001-proof-loop.yml`](.github/workflows/ho-det-001-proof-loop.yml) runs deterministic HO-DET-001 validation, AI boundary checks, claim scans, result parity, case-packet checks, proof-record parity, and reproducible proof-pack checks.
- [`cross-repo-claim-parity.yml`](.github/workflows/cross-repo-claim-parity.yml) keeps claim surfaces aligned across repositories.
- [`governance-gate.yml`](.github/workflows/governance-gate.yml) verifies required files and trusted-runner public PR boundaries.

Passing CI means the checked validation contracts passed within their configured scope. It does not prove runtime deployment, signal observation, production readiness, public-safe runtime proof, or human disposition approval.

## Related Repositories

- [`hawkinsoperations-detections`](https://github.com/HawkinsOperations/hawkinsoperations-detections): source detection logic and detection metadata.
- [`hawkinsoperations-proof`](https://github.com/HawkinsOperations/hawkinsoperations-proof): proof records, cards, and reviewer navigation. Proof records do not expand validation claims unless separately approved.
- [`hawkinsoperations-platform`](https://github.com/HawkinsOperations/hawkinsoperations-platform): platform and runtime contracts. Runtime truth remains separate from validation truth.
- [`hawkinsoperations-website`](https://github.com/HawkinsOperations/hawkinsoperations-website): public presentation. Website rendering is not proof.

## Public Claim Ceiling

Current validation language may say that controlled validation passed for the exact public fixtures and verifier scope checked here.

It must not say or imply runtime-active, signal-observed, production-ready, customer-deployed, fleet-wide, SOCaaS-deployed, autonomous-SOC, AI-approved, analyst-approved, live-SIEM-proven, live-cloud-proven, or public-safe runtime proof unless separate evidence and approval gates explicitly promote that claim.

AI can accelerate detection drafting, triage reasoning, documentation, and automation planning. Validation decides what behavior was actually checked. Human review and proof records decide what may be claimed.

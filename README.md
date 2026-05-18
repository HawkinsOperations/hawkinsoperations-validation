# HawkinsOperations Validation

Validation framework and execution evidence for HawkinsOperations detections.

Owner identity: Raylee Hawkins, Detection Engineer | SOC Automation | Detection-as-Code | Security Automation.

Official links: [Raylee Hawkins on LinkedIn](https://www.linkedin.com/in/raylee-hawkins) · [Raylee Hawkins on GitHub](https://github.com/raylee-hawkins) · [HawkinsOps detection engineering portfolio](https://hawkinsops.com) · [HawkinsOperations GitHub organization](https://github.com/HawkinsOperations) · [RayleeOps public operating journal](https://rayleeops.com)

## Purpose

This repository verifies that detection logic behaves as intended against controlled test inputs and replay scenarios.

## HO-DET-001 Enforcement Boundary

- Current HO-DET-001 public label: CONTROLLED_TEST_VALIDATED.
- Current HO-DET-001 runner scope: CONTROLLED_TEST_ONLY.
- Validation enforcement status: CI_ENFORCED_FOR_CONTROLLED_TEST_SCOPE.
- Validation enforcement PR: `HawkinsOperations/hawkinsoperations-validation#10`.
- Validation enforcement merge commit: `8b48500d2ebbaacd93ac88e77a31dccf1d3b4e25`.
- Proof-loop workflow: `.github/workflows/ho-det-001-proof-loop.yml`.
- Local public clone-runner: `python -B scripts/run-ho-det-001-local-case-pipeline.py --check`.
- Clone boundary: the command runs from this validation repository using committed public test fixtures; sibling repository checkouts are not required for the controlled test fixture receipt.
- Supported claim: HawkinsOperations provides a clone-runnable controlled HO-DET-001 test-fixture proof runner that validates public test fixtures, verifies the controlled case packet, enforces AI authority boundaries, scans blocked claims, verifies result parity, and emits a bounded receipt without requiring private lab access or private runtime evidence.
- Truth surface: validation truth. This repository verifies controlled test fixture inputs, harnesses, validation methodology, validation checks, and recorded validation outputs only.
- Control boundary: the controlled validation loop is a real control only for the exact checked public test fixtures and controlled-test validation scope.
- Surface boundary: website rendering is not proof; proof records, public surfaces, and private runtime evidence remain separate from this validation truth surface.

This repository does not claim runtime-active public proof, signal-observed public proof, public-safe runtime proof, live Splunk proof, live Wazuh proof, Cribl-routed proof, model execution in CI, Ollama prompt execution in CI, production readiness, autonomous SOC, AI-approved disposition, analyst-approved disposition, AI-decided disposition, or production AutoSOC triage status.

## Scope

- Detection test cases and replay packs
- Validation harnesses and pipelines
- Pass/fail reports and regression tracking

## Out of Scope

- Primary detection authoring (lives in `hawkinsoperations-detections`)
- Production infrastructure ownership (internal platform route; not a public validation surface)
- Sensitive runtime logs from live environments

## Repository Contract

- Every detection promoted to production should have validation coverage.
- Validation outputs must be reproducible and traceable to specific detection versions.
- Failures are treated as engineering defects, not documentation notes.

## Reviewed External Proof Candidates

- Sanitized validation summaries
- Reproducible test methodology
- Versioned pass/fail snapshots

## Current Validation Work

- Hero Rule `001-powershell-encoded-command`
  - Cases: `validation/hero/001-powershell-encoded-command/validation-cases.json`
  - Harness: `scripts/validate-hero001.ps1`
  - Report output: `reports/hero001-validation-report.json`

## Related Repositories

- Detections: `hawkinsoperations-detections`
- Platform/runtime contracts: internal platform route, not public validation proof
- Proof: `hawkinsoperations-proof`
- Website: `hawkinsoperations-website`

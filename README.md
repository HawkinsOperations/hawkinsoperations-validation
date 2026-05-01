# HawkinsOperations Validation

Validation framework and execution evidence for HawkinsOperations detections.

Owner identity: Raylee Hawkins, Detection Engineer | SOC Automation | Detection-as-Code | Security Automation.

Official links: [Raylee Hawkins on LinkedIn](https://www.linkedin.com/in/raylee-hawkins) · [Raylee Hawkins on GitHub](https://github.com/raylee-hawkins) · [HawkinsOps detection engineering portfolio](https://hawkinsops.com) · [HawkinsOperations GitHub organization](https://github.com/HawkinsOperations) · [RayleeOps public operating journal](https://rayleeops.com)

## Purpose

This repository verifies that detection logic behaves as intended against controlled test inputs and replay scenarios.

## HO-DET-001 Enforcement Boundary

- Current HO-DET-001 ceiling: TEST_VALIDATED_SYNTHETIC_SCOPE.
- Validation enforcement status: CI_ENFORCED_FOR_SYNTHETIC_SCOPE.
- Validation enforcement PR: `HawkinsOperations/hawkinsoperations-validation#10`.
- Validation enforcement merge commit: `8b48500d2ebbaacd93ac88e77a31dccf1d3b4e25`.
- Proof-loop workflow: `.github/workflows/ho-det-001-proof-loop.yml`.
- Truth surface: validation truth. This repository proves test inputs, harnesses, validation methodology, validation checks, and recorded validation outputs only.
- Control boundary: proof-loop CI is a real control only for the exact checked synthetic validation scope.

This repository does not claim runtime-active, signal-observed, evidence-linked public proof, public-safe, live Splunk fired as public proof, production-ready, fleet-wide, enterprise deployed, Cribl-routed, Wazuh-routed, AWS-live, HO-GPU-01 runtime-active, autonomous SOC, AI-approved disposition, AI-decided disposition, analyst-approved disposition, or production AutoSOC triage status.

## Scope

- Detection test cases and replay packs
- Validation harnesses and pipelines
- Pass/fail reports and regression tracking

## Out of Scope

- Primary detection authoring (lives in `hawkinsoperations-detections`)
- Production infrastructure ownership (lives in `hawkinsoperations-platform`)
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
- Platform: `hawkinsoperations-platform`
- Proof: `hawkinsoperations-proof`
- Website: `hawkinsoperations-website`

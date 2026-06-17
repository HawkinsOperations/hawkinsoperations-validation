# HO-DET-001 Hoxline Gauntlet Validation Bridge v1

## Header

| Field | Value |
|---|---|
| Artifact ID | `HO-DET-001` |
| Bridge record ID | `HO-DET-001_HOXLINE_GAUNTLET_VALIDATION_BRIDGE_V1` |
| Detection ID | `HO-DET-001` |
| Owner | `hawkinsoperations-validation` |
| Status | `VALIDATION_BRIDGE_REVIEWER_PATH_RECORDED` |
| Public-safe | `false` / `BLOCKED` |
| Human review required | `true` |
| Proof ceiling | `CONTROLLED_TEST_VALIDATED` |

## Scope

This validation bridge records the Hoxline Gauntlet v1 reviewer path for HO-DET-001 under controlled scope. It links Hoxline Gauntlet v1 output to validation-owned behavior records and keeps proof promotion authority in `hawkinsoperations-proof`.

Hoxline v1, Claim Authority, and ProofCard material are reviewer-path references here. They do not replace validation records, proof records, human review, or evidence gates.

## Hoxline Source Manifest

- Hoxline source repo: `HawkinsOperations/hoxline`
- Remote: `https://github.com/HawkinsOperations/hoxline.git`
- Branch: `feature/hoxline-gauntlet-v1-engine`
- Primary source manifest: `HawkinsOperations/hoxline/examples/gauntlet/ho-det-001-gauntlet-v1-source-manifest.json`
- Local checkout compatibility name: `aevumguard`
- Repo-relative manifest path: `examples/gauntlet/ho-det-001-gauntlet-v1-source-manifest.json`
- Manifest status: present and primary for this bridge.

## Primary Hoxline v1 Source Paths

- Gauntlet v1 run: `examples/gauntlet/ho-det-001-gauntlet-run-v1.json`
- Gauntlet v1 schema: `schemas/gauntlet-run-v1.schema.json`
- Overclaim fail-closed fixture: `examples/gauntlet/ho-det-001-gauntlet-run-v1-overclaim.json`
- Evidence Graph v1: `examples/gauntlet/ho-det-001-evidence-graph-v1.json`
- Evidence Graph v1 schema: `schemas/evidence-graph-v1.schema.json`
- ProofCard v1: `examples/gauntlet/ho-det-001-proofcard-v1.json`
- ProofCard v1 schema: `schemas/proofcard-v1.schema.json`
- Claim Authority decision v1: `examples/gauntlet/ho-det-001-claim-decision-v1.json`
- Claim Authority decision v1 schema: `schemas/claim-authority-decision-v1.schema.json`
- Gauntlet v1 doc: `docs/gauntlet/HOXLINE_GAUNTLET_V1.md`
- ProofCard v1 doc: `docs/proofcards/PROOFCARD_V1.md`
- Claim Authority v1 doc: `docs/claim-authority/CLAIM_AUTHORITY_V1.md`

## Compatibility v0 Paths

These paths are compatibility-only and are not the primary source route:

- Gauntlet v0 run: `examples/gauntlet/ho-det-001-full-loop-run-v0.json`
- Gauntlet v0 schema: `schemas/gauntlet-full-loop-run-v0.schema.json`
- ProofCard v0 example: `examples/gauntlet/ho-det-001-proofcard-v0.json`
- Evidence Graph v0 example: `examples/gauntlet/ho-det-001-evidence-graph-v0.json`
- Promotion-state v0 example: `examples/gauntlet/ho-det-001-promotion-state-v0.json`

## Validation Authority References

- `validation/successor/ho-det-001/validation-cases.json`
- `reports/ho-det-001/validation-result.json`
- `reports/ho-det-001/validation-result.md`
- `scripts/validate-ho-det-001.py`
- `scripts/scan-ho-det-001-claim-boundaries.py`
- `scripts/verify-ho-det-001-result-parity.py`

## Supported Claim

"HO-DET-001 has Hoxline Gauntlet v1 reviewer-path validation under controlled scope."

## Positive Expectations

- Gauntlet v1 output names artifact_id `HO-DET-001`.
- Gauntlet v1 output preserves proof_ceiling `CONTROLLED_TEST_VALIDATED`.
- Gauntlet v1 output keeps public_safe `false`.
- Gauntlet v1 output keeps human_review_required `true`.
- Gauntlet v1 output carries structured blocked-claim decisions and controlled-validation allowed wording only.

## Blocked Claims

- runtime proven
- signal observed
- production ready
- customer deployed
- SOCaaS deployed
- public-safe runtime proof
- AI approved
- analyst approved
- final authorization
- case closure

## Telemetry Requirements

- runtime_evidence: missing
- signal_observation_evidence: missing
- public_safe_authorization: missing
- human_review_gate_complete: missing

## Missing Evidence

- analyst_review_record
- case_closure_record
- customer_deployment_evidence
- deployment_evidence
- final_authorization_record
- human_review_gate_complete
- public_safe_authorization
- runtime_evidence
- service_deployment_evidence
- signal_observation_evidence

## Reproduction

From `hawkinsoperations-validation`:

```powershell
python -B scripts/verify_hoxline_gauntlet_validation_bridge.py --format json
python -B scripts/verify_hoxline_gauntlet_validation_bridge.py --format json --hoxline-root ..\aevumguard
python -B scripts/verify_validation_registry.py
python -B scripts/verify_all_validation_packages.py
python -B -m unittest discover -s tests
```

From sibling checkout `aevumguard`:

```powershell
python -B -m hoxline gauntlet verify --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json --schema schemas/gauntlet-run-v1.schema.json
python -B -m hoxline gauntlet summarize --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json
python -B -m hoxline claim-authority decide --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json
python -B -m hoxline proofcard render --input examples/gauntlet/ho-det-001-gauntlet-run-v1.json
python -B -m hoxline gauntlet verify --input examples/gauntlet/ho-det-001-gauntlet-run-v1-overclaim.json --schema schemas/gauntlet-run-v1.schema.json
python -B -m hoxline gauntlet verify --input examples/gauntlet/ho-det-001-full-loop-run-v0.json --schema schemas/gauntlet-full-loop-run-v0.schema.json
```

The overclaim fixture is expected to fail closed with a nonzero verifier result.

## Website Boundary

Website rendering is not validation authority. No website edit is required for this bridge.

## Proof Ceiling

This follow-up reconciles validation/proof bridge records to Hoxline Gauntlet v1 only. It does not create runtime truth, signal truth, public-safe status, customer deployment, SOCaaS deployment, production readiness, AI-approved disposition, analyst-approved disposition, final authorization, or case closure.

## Next Gate

`human_review_gate`

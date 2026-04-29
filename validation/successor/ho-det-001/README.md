# HO-DET-001 Closed-Loop Synthetic Validation

## Scope

This directory owns the HawkinsOperations V2 synthetic validation slice for HO-DET-001. It validates controlled process-creation fixtures against the HO-DET-001 source semantics and produces deterministic downstream artifacts for triage and offline LLM-support review.

This is synthetic validation only. It does not query live systems, deploy detections, observe signals, link evidence, approve public wording, or prove production behavior.

## Reproduction Commands

From the validation repository root:

```powershell
python scripts/validate-ho-det-001.py
python scripts/autosoc-triage-ho-det-001.py --input reports/ho-det-001/validation-result.json
python scripts/offline-llm-summary-ho-det-001.py --input validation/successor/ho-det-001/autosoc-triage-packet.json
```

The default mode is check-only and does not rewrite committed artifacts. Use `--write` only when intentionally regenerating the JSON and Markdown artifacts:

```powershell
python scripts/validate-ho-det-001.py --write
python scripts/autosoc-triage-ho-det-001.py --input reports/ho-det-001/validation-result.json --write
python scripts/offline-llm-summary-ho-det-001.py --input validation/successor/ho-det-001/autosoc-triage-packet.json --write
```

## Artifact Map

| Artifact | Purpose |
|---|---|
| `validation/successor/ho-det-001/validation-cases.json` | Controlled positive and negative process-creation fixtures |
| `scripts/validate-ho-det-001.py` | Source contract and synthetic fixture validator |
| `reports/ho-det-001/validation-result.json` | Machine-readable synthetic validation result |
| `reports/ho-det-001/validation-result.md` | Human-readable synthetic validation result |
| `scripts/autosoc-triage-ho-det-001.py` | Deterministic triage packet generator from the validation result |
| `validation/successor/ho-det-001/autosoc-triage-packet.json` | Synthetic triage packet |
| `scripts/offline-llm-summary-ho-det-001.py` | Deterministic offline LLM-support stub |
| `validation/successor/ho-det-001/llm-summary.json` | Hypothesis support summary or blocked local-runtime stub |

## Claim Boundaries

Supported after all commands pass:

- HO-DET-001 passed synthetic validation against controlled positive and negative process-creation fixtures.
- A deterministic triage packet was generated from the HO-DET-001 synthetic validation result.
- An offline LLM-support summary artifact or blocked local-runtime stub was generated from a known synthetic triage packet.

Blocked:

- Not supported: runtime-active.
- Not supported: signal-observed.
- Not supported: evidence-linked.
- Not supported: public-safe.
- Not supported: production-ready.
- Not supported: live Splunk firing.
- Not supported: Cribl-routed telemetry.
- Not supported: Wazuh live collection.
- Not supported: live AutoSOC.
- Not supported: production triage.
- Not supported: analyst-approved disposition.
- Not supported: AI-decided disposition.

## Proof Levels

| Phase | Result if passing | Boundary |
|---|---|---|
| Phase 1 | `TEST_VALIDATED_SYNTHETIC_SCOPE` | Synthetic process-creation fixtures only |
| Phase 2 | Deterministic triage packet generated | Derived from synthetic validation output only |
| Phase 3 | LLM-support stub generated | Hypothesis support only; local model runtime remains blocked unless separately approved and proven |

## What Is Supported

The controlled validator can show that the current HO-DET-001 source semantics match expected encoded-command positive fixtures and reject controlled negative fixtures.

## What Is Blocked

Runtime deployment, signal observation, evidence linkage, public approval, production readiness, live Splunk firing, Cribl route proof, Wazuh live collection, and analyst-approved triage remain blocked until separate evidence and promotion gates exist.

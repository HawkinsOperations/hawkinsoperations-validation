# HO-DET-001 Private Runtime Evidence Index

## Status

- Detection ID: HO-DET-001
- Private truth label: CONTROLLED_LOCAL_LLM_SUPPORT_ONLY_PRIVATE_RECEIPT
- Public-safe status: NOT_PUBLIC_SAFE
- Promotion status: BLOCKED
- Evidence scope: PRIVATE_LLM_RUNTIME_RECEIPT_SCOPED
- Verification scope: STRUCTURE_AND_BOUNDARY_ONLY
- Public proof ceiling: CONTROLLED_LOCAL_LLM_RUNTIME_RECEIPT_PACKET_SCOPE
- Evidence ID: gpu-runtime-receipt-001
- Evidence store: PRIVATE_EVIDENCE_STORE
- Evidence location public: REDACTED_PRIVATE
- Storage class: PRIVATE_LAB_EVIDENCE
- Trust label: CONTROLLED_LOCAL_LLM_SUPPORT_ONLY_PRIVATE_RECEIPT
- Model: qwen2.5:14b
- Verifier status: PASS
- Required artifacts present: 14/14

## Boundary Fields

- AI_DECIDED_DISPOSITION=false
- AI_MAY_APPROVE=false
- AI_MAY_PROMOTE=false
- AI_MAY_CLOSE=false
- HUMAN_REVIEW_REQUIRED=true
- SUPPORT_ONLY=true
- PUBLIC_SAFE_STATUS=NOT_PUBLIC_SAFE
- PROOF_CEILING=CONTROLLED_LOCAL_LLM_RUNTIME_RECEIPT_PACKET_SCOPE

## Runtime Truth Spine

| Truth plane | State | Public/runtime claim status | Evidence refs |
| --- | --- | --- | --- |
| source_truth | SOURCE_EXISTS | not a runtime claim | `hawkinsoperations-detections/detections/successor/ho-det-001/rule.yml`; `hawkinsoperations-detections/detections/successor/ho-det-001/splunk.spl` |
| validation_truth | CONTROLLED_TEST_VALIDATED | not a runtime claim | `reports/ho-det-001/validation-result.json`; `reports/ho-det-001/pipeline-proof.json` |
| runtime_truth | RUNTIME_EVIDENCE_VERIFIED_PRIVATE | PUBLIC_RUNTIME_BLOCKED | `HawkinsOperations/hawkinsoperations-validation#22`; `scripts/verify-ho-det-001-runtime-packet.py` |
| signal_truth | SIGNAL_OBSERVED_PRIVATE | PUBLIC_RUNTIME_BLOCKED | `HawkinsOperations/hawkinsoperations-validation#22`; `proof/records/HO-DET-001.md#controlled-runtime-signal-packet-001` |
| evidence_truth | RUNTIME_EVIDENCE_VERIFIED_PRIVATE | raw private evidence remains NOT_PUBLIC_SAFE | hash-only private refs; repo contains no raw private evidence |
| ai_triage_truth | AI_SUPPORT_ONLY / AI_TRIAGE_OUTPUT_PRIVATE / AI_NOT_AUTHORITY | AI is not disposition authority | AI_DECIDED_DISPOSITION=false; HUMAN_REVIEW_REQUIRED=true |
| public_proof_truth | PUBLIC_RUNTIME_BLOCKED | proof ceiling remains CONTROLLED_TEST_VALIDATED | public-safe status remains NOT_PUBLIC_SAFE |
| human_review_truth | HUMAN_REVIEW_REQUIRED | PUBLIC_RUNTIME_BLOCKED until approval | approval required for any public runtime summary |

## Public Boundary

- private GPU local LLM runtime receipt exists
- raw evidence remains private
- repo verifier checks structure and boundary only
- repo index records hash-only receipt references

## Proven Private

- controlled local Ollama invocation completed
- qwen2.5:14b generated support-only triage output
- sanitized controlled-test HO-DET-001 case packet hash matched across transfer
- private receipt artifacts and hashes exist
- private verifier status is PASS

## Not Proven

- runtime-active detection
- signal-observed public proof
- live telemetry routing
- public-safe runtime proof
- production-ready
- fleet-wide
- autonomous SOC
- AI-approved disposition
- analyst-approved disposition

## Receipt Hashes

| Artifact | SHA256 |
| --- | --- |
| case_packet_input | `b258feca9515aa643937929f148f87bf6ae9e9b71e4af9e45420bcc8cbcbb41e` |
| linux_case_packet_input | `b258feca9515aa643937929f148f87bf6ae9e9b71e4af9e45420bcc8cbcbb41e` |
| llm_output_raw | `cec879ef8827d2a0f984b553d08c91782942d4403560f92bc8a45a197db383eb` |
| evidence_manifest | `fe2d767d69e936132dabcf12fc1b6f9a8fc24c2d22559e43f0a2ef0a31ca95e6` |
| verifier_result | `28d0166781035523cdaa6551a12355a705930c842afeb3a09184b4f8ad61dc5f` |

## Allowed Repo Claim

- Private support-only local LLM runtime receipt exists for HO-DET-001 and remains blocked from public promotion.

## Blocked Repo Claims

- HO-DET-001 is runtime-active
- HO-DET-001 is signal-observed public proof
- HO-DET-001 is public-safe
- HO-DET-001 is production-ready
- HO-DET-001 is fleet-wide
- HO-DET-001 has live Splunk proof
- HO-DET-001 is Cribl-routed
- HO-DET-001 is Wazuh-routed
- HO-DET-001 has AI-approved disposition
- HO-DET-001 has analyst-approved disposition

## Boundary

This index records private evidence existence only. It does not copy private evidence into the repository, does not expose local evidence paths, does not include raw model output, does not prove public-safe runtime status, and does not promote HO-DET-001 beyond CONTROLLED_LOCAL_LLM_RUNTIME_RECEIPT_PACKET_SCOPE.

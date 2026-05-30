# HO-DET-001 SOCaaS Pilot Receipt

## Receipt

- Receipt ID: `HO-DET-001-SOCAAS-PILOT-RECEIPT-001`
- Detection: `HO-DET-001` - Encoded PowerShell process creation
- Proof ceiling: `CONTROLLED_TEST_VALIDATED`
- Validation scope: controlled process-creation fixtures
- Human review required: yes
- AI authority: support only

## Controlled Validation Result

| Measure | Result |
|---|---:|
| Total cases | 14 |
| Positive cases | 7 |
| Negative cases | 7 |
| Matched positives | 7 |
| Missed positives | 0 |
| False-positive negative matches | 0 |

Supported claim:

`HO-DET-001 passed controlled-test validation against controlled positive and negative process-creation fixtures.`

## Alert Shape

The controlled fixture shape is a Sysmon process-creation style event with:

- `EventID` equal to `1`.
- PowerShell or pwsh process identity from `Image` or `OriginalFileName`.
- Encoded-command behavior in `CommandLine`, including `-enc`, `-encodedcommand`, `/encodedcommand:`, or `FromBase64String(`.

Required fields:

- `EventID`
- `CommandLine`
- `Image` or `OriginalFileName`

Partial or missing field behavior:

- `OriginalFileName` may supply PowerShell or pwsh identity when `Image` is generic.
- Missing both `Image` and `OriginalFileName` is a negative control.
- Missing `CommandLine` is a negative control.
- Non-PowerShell processes with encoded-looking text are negative controls.

## References

Case packet references:

- `validation/successor/ho-det-001/case-packet.json`
- `validation/successor/ho-det-001/autosoc-triage-packet.json`
- `validation/successor/ho-det-001/validation-cases.json`

Proof and validation references:

- `reports/ho-det-001/validation-result.json`
- `reports/ho-det-001/validation-result.md`
- `reports/ho-det-001/pipeline-proof.json`
- `hawkinsoperations-proof/proof/records/HO-DET-001.md`

## Blocked Claims

This receipt does not support:

- runtime-active
- signal-observed
- evidence-linked public proof
- public-safe
- production-ready
- production or customer SOCaaS deployment
- SOCaaS availability
- live Splunk firing
- Cribl-routed telemetry
- Wazuh live collection
- FortiSIEM integration proven
- production triage
- analyst-approved disposition
- AI-decided or AI-approved disposition
- autonomous SOC response
- fleet-wide deployment

## Next Promotion Gate

Next promotion requires human review plus separately approved runtime, signal, evidence, and proof/publication promotion before any runtime-active, signal-observed, evidence-linked, public-safe, production, customer, or SOCaaS availability claim.

This receipt is reviewer-readable validation truth. It is not runtime proof, signal proof, public proof, public-safe approval, or a production SOCaaS service claim.

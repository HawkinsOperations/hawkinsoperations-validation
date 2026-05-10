# HO-DET-011 Synthetic Validation Result

## Summary
- Status: pass
- Detection ID: HO-DET-011
- Proof ceiling: TEST_VALIDATED_SYNTHETIC_SCOPE
- Total cases: 6
- Matched positive count: 3
- Missed positives: none
- False-positive negatives: none

## Telemetry Boundary
- Event ID 7045: Windows System / Service Control Manager
- Event ID 4697: Windows Security service installation auditing where available
- Event ID 1: Sysmon process creation context
- ServiceFileName coverage: Windows Security 4697 ServiceFileName is evaluated as a service path alias.

## Supported Claim
- HO-DET-011 passed synthetic validation against controlled Windows service creation fixtures.

## Blocked Claims
- Not supported: runtime-active
- Not supported: signal-observed
- Not supported: public-safe
- Not supported: production-ready
- Not supported: Wazuh-routed
- Not supported: live Splunk fired
- Not supported: fleet-wide
- Not supported: validation-passed as runtime proof
- Not supported: evidence-linked public proof

## Boundary
Synthetic Windows event fixture validation only. This is not runtime, signal, public-safe, production, routing, fleet, live Splunk, or evidence-linked public proof.

## Reproduction Command
- From the validation repository root, run: `python scripts/validate-ho-det-011.py`

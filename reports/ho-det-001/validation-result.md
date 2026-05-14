# HO-DET-001 Controlled-test Validation Result

## Summary
- Status: pass
- Detection ID: HO-DET-001
- Executed at: 2026-04-29T15:00:21Z
- Matched positive count: 7
- Missed positives: none
- False-positive negatives: none

## Inputs
- Source file: hawkinsoperations-detections/detections/successor/ho-det-001/rule.yml
- Splunk source file: hawkinsoperations-detections/detections/successor/ho-det-001/splunk.spl
- Validation cases file: hawkinsoperations-validation/validation/successor/ho-det-001/validation-cases.json

## Results
- Total cases: 14
- Positive cases: 7
- Negative cases: 7
- Passed cases: 14
- Failed cases: 0

## Supported Claim
- HO-DET-001 passed controlled-test validation against controlled positive and negative process-creation fixtures.

## Blocked Claims
- Not supported: runtime-active
- Not supported: signal-observed
- Not supported: evidence-linked
- Not supported: public-safe
- Not supported: production-ready
- Not supported: live Splunk firing
- Not supported: Cribl-routed telemetry
- Not supported: Wazuh live collection
- Not supported: production triage
- Not supported: analyst-approved disposition

## What This Does Not Prove
This does not prove deployment, live telemetry collection, live Splunk alerting, Cribl routing, signal observation, evidence linkage, public approval, production readiness, or analyst-approved triage.

## Reproduction Command
- From the validation repository root, run: `python scripts/validate-ho-det-001.py`

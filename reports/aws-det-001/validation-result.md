# AWS-DET-001 Fixture Validation Result

## Summary
- Status: pass
- Detection ID: AWS-DET-001
- Proof ceiling: TEST_VALIDATED_SYNTHETIC_SCOPE
- AWS live status: BLOCKED
- Public-safe status: NOT_PUBLIC_SAFE
- Total cases: 6
- Matched positive count: 3
- Missed positives: none
- False-positive negatives: none

## Supported Claim
- AWS-DET-001 passed fixture-only validation against controlled CloudTrail-style IAM denial fixtures.

## Blocked Claims
- Not supported: AWS-live proof
- Not supported: AWS CloudTrail live proof
- Not supported: cloud runtime-active proof
- Not supported: production proof
- Not supported: public-safe runtime proof
- Not supported: signal-observed public proof

## Boundary
Fixture-only CloudTrail-style validation. This is not AWS-live, CloudTrail live, cloud runtime-active, production, signal-observed, or public-safe proof.

## Reproduction Command
- From the validation repository root, run: `python scripts/validate-aws-det-001.py`

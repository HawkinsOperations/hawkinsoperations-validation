# Detection Activity Ledger v1

This ledger gives reviewers the activity number that the Lifetime Case Ledger intentionally does not count.

The Lifetime Case Ledger remains strict and platform-owned. This validation-owned ledger counts controlled validation positive fixture matches as detection activity and keeps the broader validation case total separate.

| Metric | Count | Basis |
| --- | ---: | --- |
| Detection Activity Count | 49 | Sum of `expected_positive_count` values in `validation/VALIDATION_REGISTRY.yml`. |
| Controlled Validation Fire Count | 49 | Same source as Detection Activity Count for v1. |
| Controlled Negative Test Count | 57 | Sum of `expected_negative_count` values in `validation/VALIDATION_REGISTRY.yml`. |
| Validation Case Count | 106 | Sum of all expected controlled validation fixture counts. |
| Runtime Public-Safe Count | 0 | No runtime-public-safe fire is approved here. |
| Public-Safe Count | 0 | All activity remains `NOT_PUBLIC_SAFE`. |

## Boundary

This ledger does not prove runtime activity, signal observation, public-safe runtime proof, production deployment, case closure, autonomous SOC authority, AI-approved disposition, or analyst-approved disposition.

It also does not append or reinterpret governed cases. `GOVERNED_CASE_APPEND` remains a reserved activity scope for cross-surface modeling only; it is not used by this validation ledger.

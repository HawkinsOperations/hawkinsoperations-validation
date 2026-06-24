# HO-DET-010 Controlled-test Validation

This package validates controlled, synthetic fixtures for Windows local Administrators group membership change source logic. It does not use live endpoint logs, raw private telemetry, runtime evidence, public proof, or production claims.

## Scope

- Positive fixtures cover Windows Security Event IDs 4732/4733 and process context for `net localgroup`, `Add-LocalGroupMember`, and `Remove-LocalGroupMember`.
- Negative fixtures cover approved admin workflows, non-admin group membership changes, account changes that are not group membership, and query-only commands.

## Boundary

The supported claim is limited to controlled-test validation for the included fixture set. Runtime-active, signal-observed, public-safe, live Wazuh, live Splunk, production, fleet-wide, autonomous SOC, AI-approved, analyst-approved, and case-closure claims remain blocked.

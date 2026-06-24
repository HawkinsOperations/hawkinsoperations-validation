# HO-DET-009 Controlled-test Validation

This package validates controlled, synthetic fixtures for Windows local user creation source logic. It does not use live endpoint logs, raw private telemetry, runtime evidence, public proof, or production claims.

## Scope

- Positive fixtures cover Windows Security Event ID 4720 and process context for `net user /add` and `New-LocalUser`.
- Negative fixtures cover approved onboarding/lab reset context, account changes that are not creation, and query-only account commands.

## Boundary

The supported claim is limited to controlled-test validation for the included fixture set. Runtime-active, signal-observed, public-safe, live Wazuh, live Splunk, production, fleet-wide, autonomous SOC, AI-approved, analyst-approved, and case-closure claims remain blocked.

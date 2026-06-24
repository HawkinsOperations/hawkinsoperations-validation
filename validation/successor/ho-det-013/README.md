# HO-DET-013 Controlled-test Validation

This package validates controlled, synthetic fixtures for defense tool and telemetry tamper source logic. It does not use live endpoint logs, raw private telemetry, runtime evidence, public proof, or production claims.

## Scope

- Positive fixtures cover telemetry/security-control service stop or disable patterns, Security Event ID 1102 style log-clear context, Defender preference tamper strings, and audit policy disable strings.
- Negative fixtures cover approved maintenance, service query/status-only behavior, non-security service restart context, approved Defender policy application, and log query behavior without clearing.

## Boundary

The supported claim is limited to controlled-test validation for the included fixture set. Runtime-active, signal-observed, public-safe, live Wazuh, live Splunk, live Defender, production, fleet-wide, autonomous SOC, AI-approved, analyst-approved, and case-closure claims remain blocked.

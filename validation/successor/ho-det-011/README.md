# HO-DET-011 Synthetic Validation

## Purpose

This fixture set validates HO-DET-011 service creation source behavior against controlled synthetic Windows event shapes.

## Scope

- Windows System Event ID 7045 from Service Control Manager service install telemetry.
- Windows Security Event ID 4697 where service installation auditing is available.
- Sysmon Event ID 1 process creation context for service creation tooling.

## Fixtures

- `pos-001-system-7045-suspicious-image-path`: suspicious service `ImagePath` in Windows System 7045 telemetry.
- `pos-002-security-4697-servicefilename`: suspicious `ServiceFileName` in Windows Security 4697 telemetry.
- `pos-003-sysmon-1-service-creation-tooling`: `sc.exe create` process context with suspicious service binary path.
- `neg-001-benign-agent-service-install`: standard agent installation path.
- `neg-002-benign-admin-service-creation`: benign administrative service creation without suspicious path context.
- `neg-003-unrelated-sysmon-process`: unrelated Sysmon process creation.

## Validation Boundary

This validates synthetic fixture behavior only. It does not inspect runtime systems, live telemetry, live Splunk, Wazuh routing, production deployment, fleet status, public-safe status, or evidence-linked public proof.

## Reproduction

From the validation repository root:

```powershell
python scripts/validate-ho-det-011.py
```

Use `--write` only when intentionally regenerating `reports/ho-det-011/validation-result.json` and `reports/ho-det-011/validation-result.md`.

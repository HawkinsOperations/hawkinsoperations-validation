# HO-DET-011 Controlled-test Validation

## Purpose

This fixture set validates HO-DET-011 service creation source behavior against controlled controlled-test Windows event shapes.

## Scope

- Windows System Event ID 7045 from Service Control Manager service install telemetry.
- Windows Security Event ID 4697 where service installation auditing is available.
- Sysmon Event ID 1 process creation context for service creation tooling.

## Positive Fixtures

- `pos-001-system-7045-appdata-imagepath`: Windows System 7045 service install with suspicious `ImagePath` under AppData.
- `pos-002-system-7045-servicefilename-windows-temp`: Windows System 7045 service install with suspicious `ServiceFileName` under Windows Temp.
- `pos-003-security-4697-servicefilename-users-public`: Windows Security 4697 service install with suspicious `ServiceFileName` under Users Public.
- `pos-004-sysmon-sc-create-binpath-public`: Sysmon Event ID 1 process context using `sc.exe create` with `binPath` pointing to a suspicious path.
- `pos-005-sysmon-powershell-new-service-programdata`: Sysmon Event ID 1 process context using PowerShell `New-Service` with a suspicious service path.
- `pos-006-system-7045-interpreter-backed-rundll32`: Windows System 7045 service install with interpreter-backed service target.
- `pos-007-system-7045-script-like-ps1-target`: Windows System 7045 service install with script-like service target.

## Negative Fixtures

- `neg-001-benign-signed-vendor-installer-program-files`: benign signed vendor installer service under Program Files.
- `neg-002-benign-updater-program-files-x86`: benign updater service under Program Files (x86).
- `neg-003-benign-driver-system32-drivers`: benign driver service under Windows System32 drivers.
- `neg-004-benign-backup-monitor-security-agent`: benign backup, monitoring, or security agent service.
- `neg-005-benign-maintenance-window-service`: benign service creation during approved maintenance window context.
- `neg-006-system-7045-without-suspicious-path`: Windows System 7045 without suspicious `ImagePath` or `ServiceFileName`.
- `neg-007-sysmon-sc-query-no-create`: Sysmon Event ID 1 service tooling without suspicious service creation command line.
- `neg-008-suspicious-keyword-benign-service-name`: suspicious-looking keyword in benign service name without suspicious path.
- `neg-009-managed-application-directory`: service path with managed application directory and benign service naming.
- `neg-010-service-adjacent-command-no-create-pattern`: PowerShell service-adjacent command line without create, `binPath`, or `New-Service` pattern.

## Validation Boundary

This validates controlled-test fixture behavior only. It does not inspect runtime systems, live telemetry, live Splunk, Wazuh routing, Cribl routing, Security Onion observation, production deployment, fleet status, public-safe status, or evidence-linked public proof.

## Reproduction

From the validation repository root:

```powershell
python scripts/validate-ho-det-011.py
python scripts/verify-ho-det-011-result-parity.py
python scripts/scan-ho-det-011-claim-boundaries.py
```

Use `--write` only when intentionally regenerating `reports/ho-det-011/validation-result.json` and `reports/ho-det-011/validation-result.md`.

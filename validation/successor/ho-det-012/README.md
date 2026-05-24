# HO-DET-012 Controlled-test Validation

## Purpose

This fixture set validates HO-DET-012 scheduled-task source behavior against controlled-test Windows event shapes.

## Scope

- Windows Security Event ID 4698 for scheduled task creation where audit policy and collection support it.
- Windows Security Event ID 4702 for scheduled task update where audit policy and collection support it.
- Microsoft-Windows-TaskScheduler/Operational Event IDs 106 and 140 where the operational log is enabled and collected.
- Sysmon Event ID 1 process context for scheduled-task creation tooling where available.

## Positive Fixtures

- `pos-001-security-4698-appdata-action`: Windows Security 4698 task creation with suspicious task action under AppData.
- `pos-002-taskscheduler-106-interpreter-action`: TaskScheduler Operational 106 task registration with an interpreter-backed action.
- `pos-003-sysmon-schtasks-create-public-target`: Sysmon Event ID 1 process context using `schtasks.exe /create` with a suspicious `/tr` target.
- `pos-004-sysmon-powershell-register-task`: Sysmon Event ID 1 process context using PowerShell scheduled-task registration with a suspicious action.

## Negative Fixtures

- `neg-001-benign-vendor-updater-program-files`: benign vendor updater task under Program Files.
- `neg-002-benign-endpoint-management-task`: benign endpoint management task.
- `neg-003-approved-maintenance-window-task`: approved maintenance-window task creation.
- `neg-004-suspicious-name-without-suspicious-action`: suspicious-looking task name without suspicious action, path, or tooling evidence.

## Validation Boundary

This validates controlled-test fixture behavior only. It does not inspect runtime systems, live telemetry, live Splunk, Wazuh routing, Cribl routing, Security Onion observation, production deployment, fleet status, public-safe status, or evidence-linked public proof.

## Reproduction

From the validation repository root:

```powershell
python scripts/validate-ho-det-012.py
python scripts/verify-ho-det-012-result-parity.py
python scripts/scan-ho-det-012-claim-boundaries.py
```

Use `--write` only when intentionally regenerating `reports/ho-det-012/validation-result.json` and `reports/ho-det-012/validation-result.md`.

## Private Runtime Receipt Verifier

The runtime receipt verifier validates a private HO-DET-012 scheduled-task runtime receipt without reading raw telemetry or querying runtime systems:

```powershell
python scripts/verify-ho-det-012-runtime-receipt.py --receipt <PRIVATE_RUNTIME_RECEIPT>
```

The verifier requires the receipt to remain private-bound:

- `detection_id` is `HO-DET-012`.
- The task name includes the receipt correlation ID.
- Local scheduled-task or Sysmon telemetry is present.
- Private Wazuh observation is present.
- Cleanup confirms the task is absent.
- `splunk_status` remains `NOT_VERIFIED`.
- `raw_private_evidence_public` is `false`.
- `ai_decided_disposition` is `false`.
- `human_review_required` is `true`.
- `public_safe` is `false`.
- `public_safe_status` remains `REVIEW_REQUIRED` or `NOT_PUBLIC_SAFE`.

This verifier keeps the private runtime receipt bounded to deterministic receipt validation and does not raise the existing controlled-test ceiling.

# HO-DET-011 Controlled-test Validation Result

## Summary
- Status: pass
- Detection ID: HO-DET-011
- Validation scope: controlled-test fixtures only
- Proof ceiling: CONTROLLED_TEST_VALIDATED
- Total cases: 17
- Positive cases: 7
- Negative cases: 10
- Matched positive count: 7
- Missed positives: none
- False-positive negatives: none

## Source Reference
- hawkinsoperations-detections/detections/successor/ho-det-011

## Positive Coverage
- pos-001-system-7045-appdata-imagepath: suspicious ImagePath under user profile application data path (Windows System 7045)
- pos-002-system-7045-servicefilename-windows-temp: suspicious ServiceFileName under temporary operating system path (Windows System 7045)
- pos-003-security-4697-servicefilename-users-public: Security event ServiceFileName alias coverage (Windows Security 4697)
- pos-004-sysmon-sc-create-binpath-public: sc.exe create command with binPath service target (Sysmon Event ID 1)
- pos-005-sysmon-powershell-new-service-programdata: PowerShell New-Service command with suspicious binary path (Sysmon Event ID 1)
- pos-006-system-7045-interpreter-backed-rundll32: interpreter-backed service image path (Windows System 7045)
- pos-007-system-7045-script-like-ps1-target: script-like service target (Windows System 7045)

## Negative Coverage
- neg-001-benign-signed-vendor-installer-program-files: benign installer service path (Windows System 7045)
- neg-002-benign-updater-program-files-x86: benign updater service path (Windows System 7045)
- neg-003-benign-driver-system32-drivers: benign driver service path (Windows System 7045)
- neg-004-benign-backup-monitor-security-agent: benign operations agent path (Windows System 7045)
- neg-005-benign-maintenance-window-service: approved maintenance service path (Windows Security 4697)
- neg-006-system-7045-without-suspicious-path: service install without suspicious path (Windows System 7045)
- neg-007-sysmon-sc-query-no-create: service tooling without create or binPath behavior (Sysmon Event ID 1)
- neg-008-suspicious-keyword-benign-service-name: keyword in service name should not match without suspicious service path (Windows System 7045)
- neg-009-managed-application-directory: managed application service path (Windows Security 4697)
- neg-010-service-adjacent-command-no-create-pattern: service-adjacent command without creation behavior (Sysmon Event ID 1)

## Supported Claim
- HO-DET-011 passed controlled-test validation against controlled Windows service creation fixtures.

## Blocked Claims
- Not supported: runtime-active
- Not supported: signal-observed
- Not supported: public-safe
- Not supported: evidence-linked public proof
- Not supported: public-safe runtime proof
- Not supported: Splunk-fired
- Not supported: live Splunk fired
- Not supported: Wazuh-routed
- Not supported: Cribl-routed
- Not supported: Security Onion observed
- Not supported: Suricata observed
- Not supported: Zeek observed
- Not supported: production-ready
- Not supported: production triage
- Not supported: fleet-wide
- Not supported: autonomous SOC
- Not supported: AI-approved disposition
- Not supported: analyst-approved disposition
- Not supported: attack coverage completeness
- Not supported: service-creation coverage completeness

## Boundary
Controlled-test Windows service creation fixture validation only. This does not prove runtime, signal, public-safe proof, live Splunk, Wazuh routing, Cribl routing, Security Onion observation, production readiness, fleet-wide deployment, autonomous SOC behavior, AI-approved disposition, or analyst-approved disposition.

## Reproduction Command
- From the validation repository root, run: `python scripts/validate-ho-det-011.py`

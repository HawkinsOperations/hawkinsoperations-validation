# HO-LAB-WAZUH-001 Static Wazuh Rule Contract Lab

HO-LAB-WAZUH-001 is a validation-owned static Wazuh rule contract lab. It gives reviewers a deterministic path to inspect the Wazuh source registry, the Wazuh logtest/static validation registry, controlled synthetic sample wiring, and proof-boundary metadata without requiring a live Wazuh manager.

## Reviewer Path

From `hawkinsoperations-validation`:

```powershell
python -B scripts/verify_ho_lab_wazuh_001.py
```

When the adjacent `../hawkinsoperations-detections` checkout is present, run the stricter source-contract path:

```powershell
python -B scripts/verify_ho_lab_wazuh_001.py --source-contract required
```

Optional private `wazuh-logtest` execution remains gated by the Wazuh registry verifier and is not required for this public static lab:

```powershell
python -B scripts/verify_wazuh_logtest_registry.py --detections-root ..\hawkinsoperations-detections --run-logtest
```

## What This Lab Proves

- Wazuh source registry entries exist in the adjacent detections checkout when the source contract is required.
- Wazuh logtest/static validation registry entries exist in this validation repo.
- HO-DET-011 and HO-DET-012 validation entries map to Wazuh source entries and controlled synthetic samples.
- HO-DET-001 is tracked as planned until Wazuh source and controlled sample wiring exist.
- Expected rule IDs, groups, MITRE IDs, and levels are statically checked where rule XML is available.
- Referenced sample files exist where the registry says they exist.
- Static CI commands return pass/fail output that a reviewer can rerun.

## What This Lab Does Not Prove

- No live Wazuh deployment.
- No live Wazuh manager proof.
- No Wazuh-routed runtime proof.
- No runtime-active proof.
- No signal-observed proof.
- No public-safe runtime proof.
- No production SOC.
- No SOCaaS deployment.
- No customer deployment.
- No autonomous SOC.
- No AI-approved disposition.
- No AI-decided disposition.
- No analyst-approved disposition.
- No case closure.

## Proof Ceiling

`SOURCE_AND_STATIC_CI_CONTRACT_ONLY`

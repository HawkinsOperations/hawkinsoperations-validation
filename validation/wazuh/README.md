# Wazuh Logtest Contracts

This folder contains static CI contracts and controlled synthetic sample events for future Wazuh `wazuh-logtest` validation.

These files do not prove live Wazuh routing, runtime activity, signal observation, public-safe status, production deployment, or dashboard authority. Live Wazuh manager deployment and private runtime validation require a separate approved implementation gate.

The CI-safe verifier checks registry shape, sample availability, blocked claim boundaries, and optional sibling Wazuh XML expectations. If a private runner later provides `wazuh-logtest`, the same registry can be used with the optional execution mode.

## HO-LAB-WAZUH-001 Reviewer Path

[`labs/HO-LAB-WAZUH-001.md`](labs/HO-LAB-WAZUH-001.md) is the reviewer-facing static Wazuh rule contract lab. The lab manifest lives at [`labs/HO-LAB-WAZUH-001.manifest.json`](labs/HO-LAB-WAZUH-001.manifest.json).

Single-repo static check:

```powershell
python -B scripts/verify_ho_lab_wazuh_001.py
```

Full source/static contract check with adjacent detections checkout:

```powershell
python -B scripts/verify_ho_lab_wazuh_001.py --source-contract required
```

The lab proves source/static registry consistency and controlled sample wiring only. It does not prove live Wazuh deployment, Wazuh-routed runtime proof, signal-observed proof, public-safe runtime proof, production SOC, SOCaaS deployment, customer deployment, autonomous SOC, AI-approved disposition, AI-decided disposition, analyst-approved disposition, or case closure.

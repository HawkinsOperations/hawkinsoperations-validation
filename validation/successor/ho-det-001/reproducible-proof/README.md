# HO-DET-001 Reproducible Proof Pack

Clone and verify the validation/proof boundary locally.

## Run

```powershell
python -B scripts\verify-ho-det-001-reproducible-proof-pack.py
```

## What This Proves

- HO-DET-001 validation artifacts are structured and verifier-checkable.
- Public-safe boundary remains NOT_PUBLIC_SAFE.
- Promotion status remains BLOCKED.
- Runtime-active, signal-observed, production, fleet-wide, Cribl-routed, Wazuh-routed, AWS-live, autonomous SOC, AI-approved disposition, and analyst-approved disposition claims are blocked.

## What This Does Not Prove

- live runtime signal
- public-safe runtime evidence
- production deployment
- fleet-wide coverage
- Cribl-routed telemetry
- Wazuh-routed public proof
- live Splunk fired

## Relationship To Private Runtime Evidence

- private lab runtime receipts may exist outside the repo
- public clone-run does not require or expose them
- public promotion requires separate review

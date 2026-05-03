# HO-DET-001 Private Runtime Evidence Index

## Status

- Detection ID: HO-DET-001
- Private truth label: LOCAL_SYSMON_AND_WAZUH_EVENT_CORRELATED_PRIVATE_LAB_SPLUNK_NOT_PROVEN
- Public-safe status: NOT_PUBLIC_SAFE
- Promotion status: BLOCKED
- Evidence scope: PRIVATE_LAB_ENDPOINT_SCOPED
- Public proof ceiling: TEST_VALIDATED_SYNTHETIC_SCOPE

## Proven Private

- controlled benign event generated
- local Sysmon captured event
- HO-DET-001 local match observed
- Wazuh event identifiers correlated
- private receipt files and hashes exist

## Not Proven

- original event-specific Splunk proof
- Cribl-routed telemetry
- public-safe runtime proof
- runtime-active public proof
- signal-observed public proof
- production-ready
- fleet-wide
- AWS-live
- autonomous SOC
- AI-approved disposition
- analyst-approved disposition

## Evidence Files

| Label | Path | SHA256 |
| --- | --- | --- |
| private_receipt_md | `C:\Raylee\Data\evidence-staging\HO-DET-001\runtime-signal-001\HO-DET-001_RUNTIME_SIGNAL_001_PRIVATE_RECEIPT.md` | `2BF41780DAAEB8628CE8E4A3AFCC8A9450327FD9F9F9E4D4775D37C49370744A` |
| private_receipt_json | `C:\Raylee\Data\evidence-staging\HO-DET-001\runtime-signal-001\HO-DET-001_RUNTIME_SIGNAL_001_PRIVATE_RECEIPT.json` | `D1B6ED8FF8A048DFEFFECD623962F63BBAA808AD3330CAE2195BDE2C4AB82882` |
| private_receipt_hash_manifest | `C:\Raylee\Data\evidence-staging\HO-DET-001\runtime-signal-001\HO-DET-001_RUNTIME_SIGNAL_001_PRIVATE_RECEIPT_HASHES.txt` | `064316D73A07C88CC0F42ED9437105A1338DFF6F3851117E3B88A928C0217706` |

## Allowed Repo Claim

- Private runtime receipt exists for HO-DET-001 and remains blocked from public promotion.

## Blocked Repo Claims

- HO-DET-001 is runtime-active
- HO-DET-001 is signal-observed public proof
- HO-DET-001 is public-safe
- HO-DET-001 is production-ready
- HO-DET-001 is fleet-wide
- HO-DET-001 is Splunk-proven for Runtime Signal 001
- HO-DET-001 is Cribl-routed
- HO-DET-001 is Wazuh-routed public proof
- HO-DET-001 is AWS-live
- HO-DET-001 has AI-approved disposition
- HO-DET-001 has analyst-approved disposition

## Boundary

This index records private evidence existence only. It does not copy private evidence into the repository, does not prove public-safe runtime status, and does not promote HO-DET-001 beyond TEST_VALIDATED_SYNTHETIC_SCOPE.

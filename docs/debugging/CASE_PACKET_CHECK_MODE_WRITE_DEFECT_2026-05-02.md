# HO-DET-001 case packet check-mode write defect - 2026-05-02

## 1. Title

HO-DET-001 case packet builder wrote tracked output during `--check` mode before the May 2, 2026 guard was added.

## 2. Public-safe control summary

This note documents a bounded validation-control defect: a verifier command that looked like a read-only `--check` path could still reach the case-packet write path before the guard was added.

Safe public summary:

> Found and documented a verifier check-mode write defect in the controlled case-packet builder.

This is a validation/control story only. It does not claim a production incident, live SOC impact, runtime execution, signal observation, autonomous response, or public-safe runtime proof.

## 3. Discovery source

- Operator-scoped May 2026 debugging/log context identified the control defect to preserve as a repo debugging artifact.
- Static repo inspection confirmed the current builder path is `scripts/build-ho-det-001-case-packet.py`.
- Read-only history inspection confirmed commit `10a60ae` added explicit `argparse` handling, `--check` comparison semantics, and `WRITE_SKIPPED=true`.
- Read-only history inspection of the prior builder version confirmed `main()` always reached `CASE_PACKET.write_text(...)` and had no `--check` branch.
- Current static inspection confirms the current builder returns from the `--check` branch before the write path.

## 4. Expected behavior of `--check`

`--check` must be a read-only verification mode.

Expected behavior:

- build the expected packet in memory from committed controlled-test validation inputs;
- read the existing `validation/successor/ho-det-001/case-packet.json`;
- fail if the existing packet is missing or out of date;
- pass if the existing packet exactly matches the deterministic builder output;
- avoid creating directories, rewriting JSON, touching tracked outputs, changing mtimes, or self-healing the working tree;
- print an explicit write-skipped marker when the check passes.

## 5. Observed defect

The pre-guard builder accepted a `--check` invocation as an unused command-line argument because it did not parse arguments. The script then built the deterministic packet and executed the normal write path:

- `CASE_PACKET.parent.mkdir(parents=True, exist_ok=True)`
- `CASE_PACKET.write_text(stable_json(packet), encoding="utf-8")`

That meant a command shaped like a check could still rewrite `case-packet.json`.

## 6. Why this violates read-only/check-mode semantics

A check command must observe state and report pass/fail. It must not repair, regenerate, normalize, or rewrite the state it is checking.

When a `--check` command writes tracked output, it changes the condition under review. That creates a false sense of control because the command can make stale or drifted output look current by rewriting it during the check path.

## 7. Governance/control impact

Verifier behavior is part of the governance boundary for controlled validation. A verifier that mutates the thing it is checking can blur the line between:

- source truth: the committed case packet already matches the builder;
- validation truth: the check confirmed that committed state;
- generated output: the command rewrote the packet during the run.

For claim-boundary work, that distinction matters. The control must prove the committed packet was already current inside the controlled-test scope, not silently make it current during verification.

## 8. Packaging impact

The defect could contaminate packaging or reviewer-prep work by creating unexpected tracked-output dirt while the operator expected a read-only check.

The specific package risk is that a verification pass could silently regenerate the case packet and leave `validation/successor/ho-det-001/case-packet.json` changed. That makes it harder to tell whether a package contains intentional source changes, generated output churn, or self-healed validation output.

## 9. Risk to CI/control trust

CI and local control checks are only trustworthy when check mode is non-mutating.

If a check command writes outputs, the control is weaker than it appears:

- local runs can hide stale generated artifacts by rewriting them;
- CI can pass after mutation instead of proving the committed file was already current;
- reviewers may confuse generated churn with intentional claim-boundary changes;
- a future proof-loop package could carry output produced by the check itself rather than output intentionally generated in a write phase.

## 10. Current validation guardrail

The current guardrail is the separated check/write path in `scripts/build-ho-det-001-case-packet.py`:

- `--check` builds the expected packet in memory;
- `--check` reads and compares the committed packet;
- `--check` prints `WRITE_SKIPPED=true` on success;
- `--check` returns before `CASE_PACKET.parent.mkdir(...)` or `CASE_PACKET.write_text(...)`;
- the write path remains reachable only when the builder is run without `--check`.

The local controlled validation runner also calls the builder in check mode through `scripts/run-ho-det-001-local-case-pipeline.py --check`, and the case-packet contract verifier remains separate in `scripts/verify_case_packet_contract.py`.

This proves only that the current controlled validation tooling separates check-mode verification from the case-packet write path. It does not prove runtime activity, signal observation, live deployment, production triage, public-safe runtime proof, or autonomous response.

## 11. Recommended fix

Keep the current separation between check mode and write mode:

- parse `--check` before any output write;
- compute `expected = stable_json(packet)` in memory;
- in `--check`, read the existing packet, compare it to `expected`, print `WRITE_SKIPPED=true` on success, and return before any write call;
- leave `CASE_PACKET.parent.mkdir(...)` and `CASE_PACKET.write_text(...)` reachable only in the non-check write phase.

The current builder already shows this shape after commit `10a60ae`; this artifact records the defect and the control expectation so future changes do not regress it.

## 12. Recommended regression test

Add a regression test that proves `--check` is non-mutating.

Recommended test behavior:

- record the hash and mtime of `validation/successor/ho-det-001/case-packet.json`;
- run `python scripts/build-ho-det-001-case-packet.py --check`;
- assert the command exits successfully;
- assert stdout contains `WRITE_SKIPPED=true`;
- assert the hash and mtime are unchanged;
- assert `git diff --exit-code -- validation/successor/ho-det-001/case-packet.json` remains clean in a clean test checkout.

The test should fail if `--check` creates, rewrites, normalizes, or self-heals the case packet.

## 13. Claim boundary impact

This defect record does not promote HO-DET-001.

Claim boundary remains:

- current ceiling: `CONTROLLED_TEST_VALIDATED`;
- public safe status remains `NO`;
- this artifact does not prove runtime-active status;
- this artifact does not prove signal-observed status;
- this artifact does not prove evidence-linked public proof;
- this artifact does not prove public-safe status;
- this artifact does not prove Cribl-routed, Wazuh-routed, AWS-live, fleet-wide deployment, production triage, autonomous SOC, or AI-approved disposition claims.

The artifact only documents a check-mode write defect and the expected read-only control behavior for the case-packet builder.

## 14. Next implementation approval phrase

`APPROVE_IMPLEMENT_CASE_PACKET_CHECK_MODE_REGRESSION_TEST`

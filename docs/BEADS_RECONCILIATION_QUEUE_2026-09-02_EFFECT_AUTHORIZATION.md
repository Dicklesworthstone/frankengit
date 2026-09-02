# Beads reconciliation queue: effect-time authorization

**Status:** non-authoritative operator handoff  
**Date:** 2026-09-02  
**Repository:** `Dicklesworthstone/frankengit`  
**Owning subsystem:** Agent Control Plane / capability and effect authorization  
**Implementation and documentation boundary to verify:** `6cf78b57a83edb9e3be6ad0fc0d66d73e6ef58f0`  
**Tracker mutation:** none; `.beads/issues.jsonl` was not edited

The commit containing this final anchor is a handoff-only descendant of the boundary above and is also acceptable for testing. Neither the boundary nor its metadata-only descendant changes the evidence class by existing: formatter, compiler, test, Clippy, repository lanes, and independent verification remain separate required results.

## Why this file exists

The execution environment used for this implementation wave had authenticated GitHub repository write access but did not provide:

- a local FrankenGit checkout;
- Cargo, rustc, rustfmt, or Clippy;
- the repository's `br` or `bv` binaries;
- a safe transactional interface to the approximately multi-megabyte Beads ledger.

The live repository search did not identify one unambiguous indexed Bead for effect-time revocation. Guessing an owner or hand-editing tracker storage would violate `AGENTS.md`.

This document preserves the exact reconciliation work for an operator or independent verifier with the real worktree and tracker tools. It is not Beads state and does not authorize a lifecycle transition.

## Source wave

The wave began from:

```text
1c96a1596d7361ecdfe12226d01981b70dc59111
```

The implementation and documentation commits through the dated change record include, in first-parent order:

```text
9f8cb181122879f033f60cd9fdc42ecc2cfb9ed0  feat(agent-control): add effect-time revocation gate
7d11aaa0b569df0014e3bd93ab80867e1180ff0a  feat(agent-control): expose effect-time revocation gate
04d56ff40a2057c7772fb0539310cea79327fe0a  test(agent-control): pin effect-time revocation invariants
cba85177ccd90da55c226a00d94e0cc0de3954b5  fix(agent-control): bind effect records to complete runs
3804ec7ead956430e3358c690084e2b6db40030a  fix(agent-control): reconcile complete run identities
0daced69648c1dcc9c632ca217520274904cc6ec  test(agent-control): bind handoff effect fixtures to complete runs
ad06c32a0a39e4ac3110fcd31100554abcb8cbd9  test(agent-control): bind cancellation effects to complete runs
355c42f224e957a1bfbe800fa2e6e42dc64ab8f0  test(agent-control): bind receiver handoff debt to complete runs
110a171bbfefdb664a5f9319212303c8fd23e303  test(agent-control): pin complete-run effect reconciliation
7d51971d280a2e74fcf1ac615eb3691c24d8f374  fix(agent-control): bind public cancellation to complete runs
0edfba4af78520eef56c703d88bde32dfd645c1e  fix(agent-control): expose complete-run cancellation refusals
69299f4f9080b196cf2285f7160483f393e99a26  feat(agent-control): require fresh revocation proof at outbox dispatch
84daac4104f026a655f05a9bb0611a036ea6ecc8  fix(agent-control): retain outbox reservations on dispatch refusal
a01186d12c78a51231b784be63168ba50d86f5cd  feat(agent-control): expose dispatch-time revocation gate
0ec11aa403be9b650623fd51eb7adbcd5e8391be  test(agent-control): pin revocation checks at external dispatch
3c7c2212fc44abb94698104fb8d003f4168557da  test(agent-control): pin cancellation report run identity
d003fbdedaddcdde1347a3882785ba309b32db15  test(agent-control): reject mixed complete runs during journal replay
43e21ce353a9a5cb9abec95d04ed3fe908760b76  docs(agent-control): define effect-time revocation and dispatch gating
9a9151788f6ff24bec9d1d5c93b4b44f1112b061  docs(protocol): require complete-run and dispatch-time effect identity
0e46beb848b46ada37b7816ecf83555ed38ca93b  docs(changes): record effect-time revocation wave
```

The exact pinned boundary additionally includes the implementation-status, changelog, lifecycle-continuity, focused security, and focused verification documents.

## Implemented boundary

The source now provides:

- bounded exact-position revocation read requests and receipts;
- explicit half-open freshness with a caller-selected bounded maximum age;
- complete root-first capability-chain authentication and canonical identity;
- duplicate capability-identity refusal;
- ancestor revocation checks, not leaf-only checks;
- exact effect authorization binding run, authority, chain, leaf, request, cost, input, and time;
- a production-facing checked broker that rejects high-value use through its low-risk path;
- proof-carrying outbox reservations with no raw dispatch method;
- a new authorization at the irreversible dispatch instant;
- exact chain/leaf continuity between request acceptance and dispatch;
- reservation recovery after every pre-dispatch refusal;
- deferred-obligation recovery after post-commit journal refusal;
- abort and reconciliation after later revocation;
- complete `IntentRunCommitment` in every effect record;
- journal refusal for mixed numeric or complete runs;
- v2 complete-run-bound reconciliation reports;
- v2 complete-run-bound public cancellation request and completion.

## Focused source tests

The current source tree includes or strengthens tests for:

- deterministic revocation and authorization identity;
- stale receipt use at the exclusive deadline;
- ancestor revocation;
- complete-run substitution;
- low-risk/high-value path separation;
- malformed adapter profile, row limit, duplicate revocation, and empty key;
- request-time proof expiry before external dispatch;
- revocation between reservation and dispatch;
- reservation recovery and abort after refusal;
- fresh dispatch and stable-key acknowledgement reconciliation;
- effect-record complete-run identity;
- same-ID/different-commitment journal replay refusal;
- same-ID/different-commitment reconciliation refusal;
- cancellation request and final-report substitution refusal.

Test source is not a test result.

## Required local verification

Resolve the live Bead first, then test the pinned boundary or this handoff-only descendant with the repository's pinned toolchain:

```bash
cargo fmt --all --check
cargo test -p fgit-agent --all-targets --no-fail-fast
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check --no-fail-fast
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

Record:

- exact source SHA;
- `rustc -Vv` and pinned nightly;
- `Cargo.lock` identity;
- each complete command and exit status;
- first load-bearing failure output;
- whether failures are introduced, pre-existing, or indeterminate;
- every source edit made after the run.

GitHub-hosted Actions are not required and are not substitute evidence.

## Suggested live-graph procedure

```bash
br ready --json
br list --json
bv --robot-triage
```

Search the live graph for work covering at least:

```text
Agent Protocol §6.3
effect-time capability revocation
revocation freshness
external-effect dispatch
EffectRecord complete-run identity
run reconciliation
```

If no existing task owns the complete slice, create or split one through `br` under the appropriate Agent Control Plane parent. Do not infer ownership from this document.

## Suggested progress-comment substance

```text
Implemented the library-level Agent Control Plane effect-time revocation slice. Added exact authenticated-position revocation receipts with bounded half-open freshness, complete root-first capability-chain verification, ancestor-revocation refusal, exact complete-run/effect authorization, and a public checked broker that separates low-risk from revocation-gated work. External effects now carry a proof-bearing outbox reservation and obtain a fresh authorization at the actual dispatch boundary; stale or newly revoked ancestry returns the live reservation, while post-commit cleanup remains available. EffectRecord, journal replay, RunReconciliationReport v2, and public cancellation v2 now retain IntentRunCommitment and refuse same-RunId/different-scope substitution. Added focused adversarial source tests and reconciled the Agent Protocol, status, changelog, lifecycle, threat, and verification documents. Mechanical and independent verification remain pending for the exact pinned descendant revision.
```

## Stop conditions

Do not mark the owning task `verified` or `closed` merely because:

- the source exists;
- the tests exist;
- the changelog or status document says it landed;
- a hosted workflow is green or unavailable;
- one local focused test passed;
- the request-time authorization path works while dispatch bypass remains;
- a revocation reader is represented only by an in-memory test adapter.

Stop and leave the task in progress or verification-pending when:

- any required local command fails;
- the source SHA tested differs from the final delivered SHA;
- a concrete high-value host path bypasses the checked service integration;
- exact-position revocation cannot be reconstructed from durable canonical policy state;
- a pre-dispatch refusal loses its reservation;
- a post-commit failure loses the deferred obligation;
- same-ID/different-commitment effects can enter one replay or reconciliation report;
- required evidence is unavailable.

## Remaining production work

This wave deliberately leaves:

- canonical revocation event/body schema;
- concrete authority-selected revocation reader;
- durable revocation index/cache and invalidation stream;
- durable codecs and migrations;
- mandatory checked-broker integration for network, secret, runner, forge, publication, and external-integration hosts;
- process/workspace/credential/tunnel/upload/VM cleanup;
- complete action-packet execution;
- later-head ancestry witnesses;
- stable robot/native/MCP surfaces;
- ECC-backed publication and independent batch closure.

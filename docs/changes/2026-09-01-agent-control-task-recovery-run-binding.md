# 2026-09-01: Task recovery complete-run binding correction

## Context

The initial restart-recovery slice correctly bound:

- the exact collection;
- durable lease history;
- the original `TaskClaimReceipt`;
- a fresh activating situation;
- the exact authenticated authority read event.

Its persisted-release API still accepted an ordinary `RecoveredActiveTaskClaim` plus a separately supplied `IntentRun`.

That left one gap: `ActiveTaskClaim` and the older semantic task lease carry numeric `RunId`, not the complete machine-enforced run commitment. A caller could recover under one run and later supply another run with the same ID and exact authority read but different operation scope, resource budget, or expiry.

## Correction

The final public cleanup path now requires:

```text
recover_task_claim_for_cleanup(
    reconstruction,
    original claim,
    fresh situation,
    complete run,
)
    -> RunBoundRecoveredTaskClaim
```

The constructor performs ordinary claim recovery and `IntentRun::commitment()` in the same API call. `RunBoundRecoveredTaskClaim` has no public field constructor.

Its identity commits:

```text
ordinary RecoveredActiveTaskClaimId
+ IntentRunCommitment
```

The run commitment covers:

- `RunId`;
- exact `AuthorityReadReceiptId`;
- operation classes;
- resource budget;
- expiry.

`persist_recovered_task_release` now accepts only `RunBoundRecoveredTaskClaim`. Before semantic mutation or store I/O it re-computes the supplied run commitment and returns a typed `RunCommitmentMismatch` on any difference.

## Cleanup after expiry

The correction does not make cleanup depend on run liveness.

A recovered claim may be released after both claim and run expiry because release reduces responsibility. The original expired run's commitment remains the required identity. A caller cannot construct a same-ID run with a later expiry to make cleanup appear authorized by a different run.

## Terminal evidence

Confirmed release now commits:

```text
RunBoundRecoveredTaskClaimId
RecoveredActiveTaskClaimId
TaskLeaseReconstructionReceiptId
TaskProjectionPersistenceReceiptId
```

Conflict and `NeedsReconciliation` outcomes retain the run-bound recovery ID, ordinary recovery ID, reconstruction ID, complete mutation envelope, and store execution result.

## Focused source oracle

The recovery integration test now proves:

- durable release succeeds after the original run expires;
- a same-ID run using the same exact authority read but different scope, budget, and expiry is structurally valid;
- its commitment differs from the recovery-bound commitment;
- persisted cleanup refuses it before any store read, CAS, or flush;
- confirmed and ambiguous outcomes retain the run-bound recovery identity.

## Exact source revisions

```text
cd6d92434e0b4f4e8e8c9c67bedfdfaef857c2f7
    bind restart cleanup to the complete run

fa7f09bfe7e08f309d4511642722176a25b61d29
    expose the run-bound public API

4334255e65320e1f2fb4364941efd02d8bec8860
    pin expiry cleanup and same-ID substitution refusal
```

Documentation descendants reconcile the focused recovery contract and Beads handoff.

## Remaining boundary

The older general-purpose task claim and semantic lease vocabulary still carries numeric `RunId` rather than `IntentRunCommitment`. The restart-cleanup facade is now safe because it adds an opaque run-bound recovery layer, but a future hardening wave should propagate complete commitments through the generic claim/release/transfer tower.

The concrete Beads transport, durable codecs, process/workspace cleanup, action execution, ECC closure, and repository publication also remain outside this correction.

## Verification state

The implementation environment did not provide a local FrankenGit checkout or Rust toolchain. No formatter, compiler, test, Clippy, repository-lane, or independent batch result is claimed for these revisions.

The designated verifier must test the final descendant, including the source revisions above, with the repository-owned local gates.
# Agent Control Plane Task Recovery

**Status:** companion implementation contract; not repository authority  
**Owning architecture:** [`AGENT_CONTROL_PLANE_ARCHITECTURE.md`](AGENT_CONTROL_PLANE_ARCHITECTURE.md)  
**Task coordination contract:** [`AGENT_CONTROL_PLANE_TASK_COORDINATION.md`](AGENT_CONTROL_PLANE_TASK_COORDINATION.md)  
**Implementation ledger:** [`AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`](AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md)  
**Owning crate:** `crates/fgit-agent`

## 1. Problem

A process restart does not erase a durable task claim. It also does not make the task row alone sufficient evidence for continuing or cleaning up that claim.

The multi-row task projection retains the current fields needed for frontier construction:

```text
task ID
phase
assignee
plan ID
claim expiry
reservation surface
current projection generation
```

The v1 row does not retain two historical facts needed to reconstruct the active lease exactly:

```text
predecessor projection generation
original claim instant
```

Inventing either value would create a plausible local object that never existed in the durable task system. Ignoring them would let a current assignment impersonate the original claim transition.

A second gap appears after reconstruction. [`crate::RunId`] is only a coordination identifier; it does not commit the authority read, operation scope, resource budget, or expiry that recovery validated. A cleanup API accepting only a numeric run ID could therefore validate one run during recovery and execute under a different same-ID run later.

The recovery slice treats both problems as evidence-binding problems. It neither mints missing history nor allows a complete run identity to be detached from recovery before a durable cleanup effect.

## 2. Recovery tower

The implemented recovery path is:

```text
AuthorityReadReceipt + IntentRun
    -> TaskProjectionCollectionReceipt
    -> collected claimed TaskProjectionRow
    + TaskLeaseHistoryObservation
    -> TaskLeaseReconstructionReceipt
    + original TaskClaimReceipt
    + fresh AgentSituationReceipt
    + complete IntentRun
    -> RunBoundRecoveredTaskClaim
    -> semantic release application
    -> TaskProjectionMutationEnvelope
    -> one-shot read / CAS / flush / reread
    -> PersistedRecoveredTaskRelease
       | Conflict
       | NeedsReconciliation
```

`RunBoundRecoveredTaskClaim` contains the ordinary `RecoveredActiveTaskClaim` plus the exact `IntentRunCommitment` captured by the same constructor that performs activation. There is no public constructor that can attach a different commitment afterward.

Each arrow validates an exact predecessor. No stage infers that an earlier stage succeeded merely because a later-looking object exists.

## 3. Collection bridge activation

`task_collection_bridge` is part of the owning crate's compiled public surface.

For an unassigned row, `collected_unclaimed_task` converts the row directly into an `AuthorityBoundTaskProjectionSnapshot` because the row already contains all state needed for a claim basis.

For a claimed or assigned row, that direct path returns:

```text
LeaseReconstructionRequired { task_id }
```

It never silently drops assignment, plan, expiry, or reservation state to make the task appear unclaimed.

## 4. Durable lease history

`TaskLeaseHistoryObservation` supplies only the facts absent from the collected row:

```text
collection receipt ID
task ID
current claimed generation
previous generation
original claimed_at
history-reader profile
evidence root
```

Repeating the collection, task, and current generation in the history observation prevents a valid history record from being replayed against another collection or later generation.

`reconstruct_collected_task_lease` then reuses the current fields from the validated collection:

```text
assignee
plan ID
expiry
reservation surface
phase
current generation
```

It refuses:

- another exact authenticated read event;
- another collection, task, or current generation;
- an unclaimed row;
- missing plan, expiry, or reservation state;
- a conflict state that does not reserve the task for its assignee;
- a claim instant later than the collection that already reflects it;
- zero adapter identity;
- zero, unchanged, or otherwise invalid lease generations;
- duplicate, empty, or excessive reservation surfaces.

The result is a `TaskLeaseReconstructionReceipt` containing:

- the exact collection receipt;
- the exact authenticated read event;
- the reconstructed semantic snapshot;
- predecessor generation and claim time;
- history-reader profile and evidence commitment;
- a stable domain-separated receipt identity.

## 5. Semantic identity versus recovery evidence

The reconstructed task snapshot keeps the same semantic identity it would have had if observed without a restart.

History adapter identity and evidence do not perturb:

```text
semantic task generation
semantic snapshot identity
```

They do perturb:

```text
TaskLeaseReconstructionReceiptId
```

Two independently evidenced reconstructions may therefore agree on task state while remaining distinguishable audit events.

That separation is required for deterministic task state and honest recovery evidence.

## 6. Original claim revalidation

A reconstructed lease is not yet an active claim.

`activate_reconstructed_task_claim` requires the original `TaskClaimReceipt` and checks that it matches the reconstructed lease exactly across:

- task;
- plan;
- assignee and supplied run ID;
- predecessor generation;
- current claimed generation;
- reservation surface;
- original claim instant;
- exclusive expiry.

It then requires the reconstructed snapshot, supplied run, and fresh situation to use the same exact authenticated read event before invoking ordinary claim activation.

This exact-read requirement is stricter than comparing repository and authority-head identities. A later read of the same head is a different event and cannot be substituted without a future explicit ancestry/freshness proof.

The resulting `RecoveredActiveTaskClaim` commits:

```text
lease reconstruction receipt ID
original task claim receipt ID
fresh active-claim activation ID
```

Recovery evidence therefore cannot be validated and then omitted from the recovery identity.

## 7. Complete-run binding

Ordinary active-claim recovery still carries a numeric assignee because the older claim vocabulary predates complete-run commitments. Persisted restart cleanup adds the missing stronger boundary.

`recover_task_claim_for_cleanup` performs these operations in one API call:

1. validates and activates the reconstructed claim;
2. computes the complete `IntentRunCommitment` from the same supplied run;
3. produces `RunBoundRecoveredTaskClaim`;
4. commits ordinary recovery identity and complete run commitment into `RunBoundRecoveredTaskClaimId`.

The complete commitment binds:

```text
RunId
exact AuthorityReadReceiptId
allowed operation classes
resource budget
expiry
```

`RunBoundRecoveredTaskClaim` has no public field constructor. A caller cannot activate under one run, then attach a same-ID run commitment with different bytes.

`persist_recovered_task_release` re-computes the supplied run commitment before semantic mutation or store I/O. Any difference returns:

```text
RunCommitmentMismatch { expected, observed }
```

This refusal occurs even when repository, authority head, exact read event, and numeric `RunId` all match.

## 8. Cleanup after expiry

Expiry prevents additional work. It does not erase durable ownership or make cleanup impossible.

`persist_recovered_task_release` permits an expired run-bound recovered claim to release its exact lease. The original run may be past its exclusive expiry at `resolved_at`; cleanup does not require widening or renewing it.

The function still refuses:

- another lease reconstruction;
- another original claim receipt;
- another complete run commitment;
- another task, plan, assignee, generation, surface, or exact read;
- observation-time rollback;
- an invalid store profile;
- every ordinary semantic release refusal.

Expiry is part of the captured run commitment. A caller cannot replace the expired run with a same-ID copy carrying a later expiry to obtain the cleanup path.

The invoked store profile becomes the transition adapter identity. The caller cannot prepare the release under one adapter identity and execute it under another.

The release disposition remains explicit:

```text
ReturnToOpen
RequireRework
```

## 9. Durable execution and uncertainty

Recovered cleanup reuses the ordinary task-store protocol:

```text
authenticated initial read
-> at most one exact-predecessor compare-and-replace
-> explicit flush or no-op decision
-> authenticated confirming reread
-> complete semantic-state reconciliation
```

A successful result becomes `PersistedRecoveredTaskRelease`, whose identity commits:

- the complete-run-bound recovery identity;
- the underlying recovery identity;
- the lease-reconstruction identity;
- the ordinary confirmed task-persistence receipt.

Conflict and uncertain outcomes also retain all three recovery identities alongside the complete mutation envelope and store execution record.

A timed-out write followed by the predecessor is **not** labelled retry-safe. The operation may still be in flight. The outcome remains `NeedsReconciliation` until a backend-specific request-ID or envelope-ID probe proves quiescence or the exact successor is observed.

## 10. Authority boundary

Every object in this document is derived task-coordination evidence.

It does not:

- move a ref;
- modify canonical forge state;
- publish a repository commit record;
- replace the `RepositoryAuthorityHead` CAS;
- mint capability;
- authorize action execution;
- prove that a Beads command or database write occurred merely by existing.

Only the concrete backend effect plus authenticated reread can produce a task-persistence receipt. Repository publication remains a separate authority path.

## 11. Concrete Beads adapter obligations

A production Beads adapter must provide, without hand-editing `issues.jsonl`:

1. one authenticated collection read with a stable projection generation;
2. complete structured rows for frontier construction;
3. exact durable lease history for claimed rows;
4. stable task, run, plan, phase, expiry, and reservation encoding;
5. exact-predecessor compare-and-replace or an owned equivalent transaction;
6. an idempotency key derived from the mutation envelope;
7. explicit collaborative/read-projection flush semantics;
8. authenticated reread of complete task state and transition metadata;
9. a probe that can resolve ambiguous envelope outcomes after restart;
10. durable preservation of the mutation evidence contract and lease history.

A human-readable command response or zero exit code is evidence input, not proof of persistence.

## 12. Refused shortcuts

The implementation explicitly rejects:

- treating assignment as an active claim;
- reconstructing a claimed row as unclaimed;
- guessing predecessor generation or claim time;
- constructing opaque plan IDs solely for fixtures;
- using a plan built against the already-claimed generation as the historical claim plan;
- accepting another collection or generation's lease history;
- accepting a later same-head read as the same authenticated event;
- treating numeric `RunId` as complete run identity;
- validating one run during recovery and supplying another same-ID run during persistence;
- renewing or changing run expiry to perform cleanup;
- preventing release because the claim or run expired;
- retrying an ambiguous write because the predecessor was seen once;
- exposing a cancellation projection before the release successor is confirmed;
- dropping recovery or complete-run evidence after validation;
- treating task persistence as repository publication.

## 13. Focused source tests

The public-path source tests cover:

- exact unassigned-row conversion;
- refusal of same-head authenticated-read substitution;
- missing-task refusal;
- deterministic active-lease reconstruction from a real predecessor-bound plan;
- plan, assignee, predecessor/current generations, reservation surface, claim time, and expiry retention;
- history-generation replay refusal;
- claim-time rollback refusal;
- recovery of the original active claim;
- same-head read substitution refusal during recovery;
- atomic complete-run capture during recovery;
- durable release after both claim and run expiry;
- refusal of a same-ID run with changed scope, budget, or expiry before store I/O;
- explicit rework successor state;
- run-bound recovery, ordinary recovery, and reconstruction identity retention on success;
- reconstruction substitution refusal before store I/O;
- ambiguous release preserving run-bound recovery identity as reconciliation debt.

Test source is not a revision-bound test result.

## 14. Remaining boundary

This slice still does not provide:

- concrete `br`/Beads transport or database integration;
- durable codecs and migrations for collection, reconstruction, run-bound recovery, or persisted-release receipts;
- a backend envelope-ID probe that proves an ambiguous write is quiescent;
- complete-run commitment fields in the older general-purpose task lease/claim vocabulary outside this restart-cleanup facade;
- multi-task atomic task transactions;
- distributed reservation arbitration;
- automatic process, workspace, credential, or external-effect cleanup;
- action-packet execution;
- robot CLI, native API, or MCP transport;
- ECC-backed verification and closure publication;
- later-head authority ancestry witnesses;
- independent batch verification or Bead closure.

The next production step is the concrete Beads transport implementing the read/history/CAS/flush/reread/probe contract above, followed by durable codecs and process-restart replay. A later hardening wave should propagate complete `IntentRunCommitment` into the older generic claim and lease objects so the same protection applies outside restart cleanup.
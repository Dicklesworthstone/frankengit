# Agent Control Plane Task Coordination

**Status:** companion implementation contract; not repository authority  
**Owning architecture:** [`AGENT_CONTROL_PLANE_ARCHITECTURE.md`](AGENT_CONTROL_PLANE_ARCHITECTURE.md)  
**Recovery companion:** [`AGENT_CONTROL_PLANE_TASK_RECOVERY.md`](AGENT_CONTROL_PLANE_TASK_RECOVERY.md)  
**Implementation ledger:** [`AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`](AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md)  
**Owning crate:** `crates/fgit-agent`

## 1. Purpose

Task coordination connects five different kinds of fact that must not be conflated:

```text
current task-system state
control-plane selection and plan
semantic task transition
backend persistence evidence
repository authority
```

The implemented slice supplies a coherent typed path across the first four while preserving the fifth as a separate authority system.

It does not create a second repository truth source. A task claim can be durable, auditable, and load-bearing for collaboration without moving a Git ref or publishing a repository commit record.

## 2. End-to-end task tower

The current path is:

```text
exact AuthorityReadReceipt + complete IntentRun
    -> TaskProjectionCollectionRequest
    -> TaskProjectionCollectionReceipt
       -> canonical multi-row TaskProjectionSnapshot
       -> TaskProjection SituationComponent
    -> AgentSituationReceipt
    -> WorkFrontier
    -> AgentControlPulse
    -> AgentChangePlan
    -> authority-bound single-task predecessor
    -> semantic claim/release/transfer application
    -> TaskProjectionMutationEnvelope
    -> one-shot store read/CAS/flush/reread
    -> TaskProjectionPersistenceReceipt
    -> TaskClaimReceipt or TaskClaimCancellationProjection
```

Restart recovery extends this tower through:

```text
collected claimed row
+ exact durable lease history
    -> TaskLeaseReconstructionReceipt
+ original TaskClaimReceipt
+ fresh situation
    -> RecoveredActiveTaskClaim
    -> persistence-gated release
```

## 3. Authority and derived state

Repository authority remains the conditionally replaced `RepositoryAuthorityHead`.

Task projections, assignments, leases, persistence receipts, recovery receipts, and cancellation projections are derived coordination records. They cannot:

- move refs;
- alter canonical forge state;
- mint capability;
- authorize a publication merely by existing;
- substitute for authority-head authentication;
- convert a tracker response into repository truth.

Every production task mutation still needs a concrete backend effect and authenticated post-state read.

## 4. Pre-situation collection

The first task generation cannot be discovered by a reader whose request already requires an `AgentSituationReceipt` naming that generation.

`task_collection` resolves this bootstrap ordering with one bounded request containing:

- the exact authenticated read event;
- repository and authority-head identity;
- complete Intent Run identity;
- logical request time;
- hard row ceiling.

A collector returns:

- current nonzero task generation;
- complete structured task rows;
- observation time;
- adapter profile;
- collection-evidence root.

The validated `TaskProjectionCollectionReceipt` supplies both the canonical rows for `WorkFrontier` and the task-projection `SituationComponent` for building the first situation.

The collection trait is a storage-neutral boundary, not a concrete Beads adapter.

## 5. Exact-generation reread

`task_projection_read` remains a separate operation for a situation that already names one immutable generation.

It refuses a backend that silently substitutes its current generation. A backend that no longer retains the requested generation returns a typed unavailable-history result.

Collection and exact-generation reread are therefore complementary:

```text
collection = discover current generation before situation construction
reread     = materialize one generation already named by a situation
```

## 6. Multi-row projection

The canonical multi-row `TaskProjectionSnapshot` binds:

- exact authenticated-read identity;
- one nonzero task generation;
- observation time;
- bounded, sorted, unique task rows.

Each row preserves:

- task and phase;
- ranking inputs;
- blocker count;
- assignee;
- independent-verifier exclusion;
- capability eligibility;
- conflict state;
- current plan and expiry, when claimed;
- complete reservation surface.

The projection can feed frontier construction. It is not sufficient by itself to reconstruct historical lease facts omitted from the row format.

## 7. Collection bridge

`task_collection_bridge` converts collected rows into authority-bound single-task state.

### Unassigned row

An unassigned row contains all state needed for an exact claim basis. `collected_unclaimed_task` therefore produces an `AuthorityBoundTaskProjectionSnapshot` while checking the exact authenticated read event and task identity.

### Claimed row

A claimed row cannot use the unassigned path. It returns `LeaseReconstructionRequired` rather than discarding assignment or claim metadata.

Claimed-row recovery is specified fully in [`AGENT_CONTROL_PLANE_TASK_RECOVERY.md`](AGENT_CONTROL_PLANE_TASK_RECOVERY.md).

## 8. Semantic transition kernel

The crate-private `task_projection_adapter` module owns deterministic single-task transitions:

```text
claim
release
transfer
```

It validates the exact predecessor, task, phase, pulse, plan, action, run, assignment, lease, reservation surface, lifetime, claim receipt, active claim, and successor relationship.

The raw kernel remains crate-private so an external caller cannot omit repository or exact-read scope.

### Claim

Claim requires:

- pulse task, phase, action, and generation equal to the predecessor;
- plan bound to the pulse and complete run;
- no conflicting assignment or active lease;
- claim time no earlier than the pulse;
- live run at claim time;
- nonempty interval no longer than run lifetime;
- nonzero adapter identity;
- exact plan conflict surface as the lease reservation surface.

### Release

Release validates the lease against the original claim receipt and active claim. It remains available after claim or run expiry because expiry prevents new work rather than cleanup.

The caller chooses:

```text
ReturnToOpen
RequireRework
```

### Transfer

Transfer removes the source lease and records a successor assignment in one semantic transition.

It does not transfer the source plan, active claim, capability, workspace, or publication authority. The successor must construct a fresh situation, frontier, pulse, plan, claim receipt, and activation.

## 9. Semantic identity and audit identity

Semantic task state is independent from backend implementation and evidence bytes.

The same exact logical mutation produces:

```text
same semantic successor generation
same semantic successor snapshot identity
```

Adapter profile, evidence contract, exact read, and transition time remain in the audit transition and persistence records. Different conforming adapters may therefore produce distinct audit identities without changing logical task state.

Observation freshness is also separate from semantic state identity. A later authenticated reread of the same row keeps the same semantic snapshot ID.

## 10. Authority-bound public facade

`task_coordination` adds the production-facing scope omitted by the pure kernel:

- repository namespace;
- complete authenticated read event;
- stable semantic snapshot identity;
- monotone observation time;
- exact predecessor and successor snapshots;
- scoped transition identity.

A run from another repository or another exact read event is refused even when it reuses the same numeric `RunId` or names the same authority head.

The facade still computes an application. It does not persist it.

## 11. Exact-predecessor mutation envelope

`TaskProjectionMutationEnvelope` freezes the complete backend request:

```text
repository and task
exact authenticated mutation basis
complete predecessor snapshot
complete desired successor snapshot
scoped transition identity
inner transition identity
transition kind and time
adapter profile
mutation-evidence contract
```

The envelope is the idempotency and recovery identity for a concrete store.

## 12. Complete-state reconciliation

A backend reread is represented by `TaskProjectionPersistedState`, which contains a structurally validated authority-bound snapshot rather than caller-supplied identity strings.

Reconciliation compares:

- repository and task;
- authority position;
- complete semantic predecessor or successor state;
- phase, assignment, lease, generation, and surface;
- transition and inner-transition metadata;
- mutation-evidence contract;
- monotone observation time.

The result is:

```text
Confirmed(TaskProjectionPersistenceReceipt)
RetrySafe { exact predecessor remains }
Conflict { another semantic state is current }
typed refusal { mixed, missing, or substituted metadata }
```

An exact predecessor decorated with the attempted successor's transition metadata is a partial-write contradiction, not a safe retry.

## 13. One-shot store orchestration

`task_store` owns the storage-neutral effect protocol:

1. authenticated initial read;
2. at most one exact-predecessor compare-and-replace;
3. explicit projection flush or no-op decision;
4. authenticated confirming reread;
5. complete-state reconciliation.

Definite precondition failure can become a conflict. Failures after possible persistence become reconciliation debt.

An ambiguous write followed by the predecessor remains unresolved because the original operation may still be in flight. A future concrete backend may use an envelope-ID probe to prove quiescence; the generic protocol does not guess.

## 14. Persistence gates

`task_persistence_gate` prevents semantically valid but control-stale applications from reaching store I/O.

For claim it rechecks:

- pulse-selected task and generation;
- plan, pulse, task, and complete run;
- exact authority and observation basis.

For release or transfer it accepts a complete authority-bound resolution application and exposes the `TaskClaimCancellationProjection` only after the exact successor is confirmed.

Conflict and uncertainty retain the complete mutation envelope.

## 15. Restart recovery and cleanup

The restart recovery path is implemented by `task_collection_bridge` and `task_recovery`.

It:

- reconstructs the current lease from collection-bound durable history;
- validates the original claim receipt across task, plan, assignee, generations, surface, claim time, and expiry;
- recovers a fresh active claim under the same exact read event;
- releases the recovered claim through the ordinary persistence gate;
- retains recovery and reconstruction identities on success, conflict, and uncertainty.

A successful `PersistedRecoveredTaskRelease` commits the recovery identity, reconstruction identity, and ordinary confirmed persistence receipt.

## 16. Concrete Beads adapter obligations

A Beads-backed implementation must use `br` or an owned stable library/API boundary. It must not hand-edit `.beads/issues.jsonl` as its mutation protocol.

It must implement:

- current-generation collection;
- complete task-row mapping;
- durable lease-history lookup;
- exact task/run/plan/phase/surface encoding;
- exact-predecessor mutation;
- request/envelope idempotency;
- flush semantics;
- authenticated complete-state reread;
- envelope-ID probing after ambiguity;
- durable transition and evidence metadata.

Tracker output is evidence input, not self-authenticating truth. Success exists only after reconciled post-state evidence.

## 17. Refused shortcuts

The current design rejects:

- an in-memory map described as production task storage;
- a current-row assignment treated as a historical active claim;
- guessing predecessor generation or claim time;
- a later same-head read substituted for the exact mutation basis;
- adapter/evidence bytes changing semantic task state;
- a pulse from another task generation;
- preventing release because a lease expired;
- transferring source plan or capability to a successor;
- reporting success from command exit status alone;
- treating object or row presence as proof of a specific transition;
- retrying an ambiguous write without quiescence evidence;
- exposing claim or cancellation projections before durable confirmation;
- treating task persistence as repository publication.

## 18. Focused source tests

The current source covers:

- bounded pre-situation collection and situation-component construction;
- exact-generation reread and unavailable history;
- deterministic task state and transition identity;
- stale generation, assignment, lifetime, surface, repository, and exact-read refusal;
- release after expiry;
- fresh successor planning and claiming after transfer;
- complete-state predecessor/successor/conflict reconciliation;
- missing or substituted transition/evidence metadata;
- one-shot applied, retry, conflict, timeout, flush, and reread paths;
- persistence-gated projection release;
- unassigned collection bridging;
- claimed-row lease reconstruction;
- history replay and temporal inversion refusal;
- restart active-claim recovery;
- durable recovered release and explicit rework;
- recovery identity retention on ambiguity;
- reconstruction substitution refusal before store I/O.

Test source is not revision-bound verification evidence.

## 19. Remaining implementation boundary

This contract still does not provide:

- concrete Beads transport, database, or command mapping;
- durable codecs and migrations for task-control records;
- a backend envelope-ID quiescence probe;
- multi-task transactions;
- distributed reservations;
- automatic process/workspace/effect cleanup;
- action-packet execution;
- robot, native API, or MCP task commands;
- ECC-backed verification and closure;
- repository publication;
- independent batch verification or Bead closure.

The next production slice is the concrete Beads adapter followed by durable codecs and restart replay.
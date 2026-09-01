# Agent Control Plane Task Coordination

**Status:** companion implementation contract; not repository authority  
**Owning architecture:** [`AGENT_CONTROL_PLANE_ARCHITECTURE.md`](AGENT_CONTROL_PLANE_ARCHITECTURE.md)  
**Implementation ledger:** [`AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`](AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md)  
**Owning crate:** `crates/fgit-agent`

## 1. Purpose

The Agent Control Plane already had typed inputs and outputs around task mutation:

- `WorkFrontier` and `AgentControlPulse` select one exact task generation;
- `AgentChangePlan` fixes the intended and conflict surfaces;
- `TaskClaimProjection` records what a task backend says it changed;
- `TaskClaimReceipt` validates that observation;
- `ActiveTaskClaim` becomes usable only after a fresh situation sees the post-claim generation;
- `TaskClaimCancellationProjection` records release or transfer during cancellation and handoff.

What was missing was the transition kernel between those objects. Without one, every future Beads, API, or scheduler adapter would have to invent generation advancement, assignment semantics, lease retention, retry identity, and stale-basis behavior independently.

The landed task-coordination slice supplies that kernel without creating a second task database or pretending an in-memory value is durable.

## 2. Ownership and authority

Task coordination is **derived metadata**. It does not publish repository state, move refs, modify forge state, mint capabilities, or prove that code changed.

Repository authority remains the CAS-selected `RepositoryAuthorityHead`. A task mutation may be auditable and important while remaining outside repository authority.

The public production-facing snapshot binds:

```text
AuthorityBoundTaskProjectionSnapshot {
  snapshot_id,
  repository_id,
  observed_at,
  task_id,
  task_projection_generation,
  task_phase,
  assignment,
  active_lease?,
}
```

The repository namespace prevents one task row or transition from being replayed into another repository merely because a task ID or generation bytes collide. The observation time is monotone and prevents a later projection from being used to manufacture an earlier pulse.

## 3. Pure transition kernel

`task_projection_adapter` is the deterministic, storage-agnostic state machine. Given one exact predecessor snapshot, it implements:

```text
claim
release
transfer
```

For every accepted operation it returns:

```text
successor snapshot
+ stable transition receipt
+ existing protocol projection
```

The existing protocol projection is either:

- `TaskClaimProjection`, consumed by `TaskClaimReceipt::admit`; or
- `TaskClaimCancellationProjection`, consumed by cancellation completion or transfer handling.

The kernel does not write a file, mutate Beads, hold a process-local lock, or claim that its returned value is durable.

## 4. Repository- and time-bound facade

`task_coordination` wraps the pure kernel with the scope a production adapter must not leave implicit:

- one `RepositoryId`;
- one logical observation instant;
- monotone mutation time;
- a pulse from the same repository;
- source and successor runs from the same repository namespace;
- identities that commit both the scoped snapshot and the inner deterministic transition.

The facade refuses:

- a run from another repository;
- a pulse from another repository;
- a pulse or mutation observed before the current task snapshot;
- every stale-basis, lease, assignment, generation, surface, lifetime, or identity refusal of the pure kernel.

It still does not claim persistence. Repository scope and logical time are necessary for production use, not sufficient to prove a backend write.

## 5. Claim transition

A claim requires all of the following:

- the pulse selected the same task and phase;
- the pulse used the snapshot's exact task-projection generation;
- the plan belongs to that pulse, task, phase, action, and run;
- the snapshot is unassigned or already assigned to the same run;
- no active lease exists;
- claim time is not before the pulse observation;
- the run is live at claim time;
- claim expiry is strictly after claim time and no later than run expiry;
- adapter identity is nonzero;
- the exact plan conflict surface becomes the lease reservation surface.

The transition computes one deterministic successor generation from the predecessor generation and canonical mutation inputs. It returns a `TaskClaimProjection` using exactly those values.

The backend must persist the successor before treating the claim as applied. The caller must then pass the projection through `TaskClaimReceipt::admit` and observe the new generation in a fresh `AgentSituationReceipt` before the claim becomes active.

## 6. Release transition

Release validates:

- the snapshot carries an active lease;
- claim receipt task, plan, assignee, generation, and reservation surface match that lease;
- the active claim names the same receipt, plan, task, and run;
- resolution time is not before claim activation;
- adapter identity is nonzero.

Release remains available after claim or run expiry. Expiry prevents new work; it cannot prevent responsibility cleanup.

A release chooses one explicit result:

```text
ReturnToOpen
RequireRework
```

The successor snapshot is unassigned, carries no lease, and advances to a new generation. The returned `TaskClaimCancellationProjection` names `Released`.

## 7. Transfer transition

Transfer atomically:

1. validates and removes the source lease;
2. advances the task generation once;
3. records the successor as the projected assignment;
4. returns a `Transferred { successor_run_id }` cancellation projection.

Transfer does **not** transfer the source plan, active claim, capability, or publication authority. The successor assignment is a coordination preference. Before continuing work, the successor must obtain:

```text
new situation
-> new frontier/pulse
-> new plan bound to the successor run
-> new claim projection and receipt
-> fresh activation observation
```

Source and successor runs must use the same authenticated authority receipt in the pure kernel and the same repository namespace in the production-facing facade. Self-transfer is refused.

## 8. Exact-predecessor persistence

A production backend must persist transitions using exact-predecessor compare-and-replace:

```text
expected repository_id
expected task_id
expected snapshot_id
expected task_projection_generation
proposed successor snapshot
proposed transition_id
adapter evidence root
```

Only one writer may replace an exact predecessor. A loser re-reads and either:

- recognizes an identical retry by transition identity and exact successor bytes;
- rebuilds from the newly observed generation;
- returns a typed conflict or stale-basis refusal.

The backend must not report success merely because a human-readable command returned zero or because a JSONL append appears somewhere on disk.

## 9. Ambiguous-write recovery

A timeout, process crash, lost response, or disconnected client does not prove that a task mutation failed.

After an ambiguous result, the adapter must re-read the task row and compare:

- repository and task identity;
- predecessor and successor generation;
- transition identity;
- assignment and lease state;
- plan and run identity where applicable;
- reservation surface;
- adapter evidence root.

Exact match is an idempotent retry. A different successor is a conflict. Absence of the transition permits a safe retry only against the still-current exact predecessor.

## 10. Beads adapter obligations

A Beads-backed implementation must use `br` or a stable owned library/API boundary. It must not hand-edit `.beads/issues.jsonl` as its production mutation protocol.

The adapter must map typed task semantics to the live Beads policy while preserving:

- dependency readiness and blocker counts;
- assignment and claim ownership;
- implementation versus verification phases;
- source and successor run identities;
- conflict/reservation surfaces;
- exact pre/post projection generations;
- mutation evidence and retry identity;
- release versus rework versus transfer;
- independent verification requirements.

A tracker response is evidence input, not self-authenticating truth. The adapter returns a projection only after it has reconciled the persisted post-state.

## 11. Refused shortcuts

The following are explicitly rejected:

- an in-memory `HashMap` described as the production task database;
- generation advancement based on wall-clock time or random bytes;
- accepting a pulse from another task generation;
- transferring the source plan or capability to the successor;
- treating assignment as an active task claim;
- preventing release because the claim expired;
- allowing a cross-repository task mutation because task IDs happen to match;
- reporting success before exact post-state reconciliation;
- rewriting the Beads JSONL ledger directly from an agent;
- treating task mutation as repository publication.

## 12. Focused source tests

The current source includes focused cases for:

- deterministic claim generation and transition identity;
- stale predecessor refusal;
- exact conflict-surface retention;
- release after expiry into explicit rework or open state;
- atomic source transfer followed by a fresh successor plan and claim;
- cross-authority transfer refusal in the pure kernel;
- repository-scoped identity and observation time;
- observation rollback refusal;
- cross-repository claim refusal;
- cross-repository successor refusal;
- compatibility with existing claim admission and activation.

Test source is not revision-bound verification evidence.

## 13. Remaining implementation boundary

This slice still does not provide:

- a durable Beads or scheduler backend;
- exact-predecessor storage and ambiguous-write recovery implementation;
- task projection collectors for `AgentSituationReceipt`;
- multi-task transaction semantics;
- a distributed reservation service;
- automatic task release from process cancellation;
- durable codecs, migration, replay, or crash recovery;
- robot/CLI/native/MCP task commands;
- task verification or closure from ECC evidence;
- repository authority or publication.

The next production step is an adapter that implements the persistence contract above against the current `br`/Beads policy and returns revision-bound mutation evidence.
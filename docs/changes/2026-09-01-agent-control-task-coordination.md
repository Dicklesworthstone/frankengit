# 2026-09-01: Agent Control Plane task coordination and persistence

## Scope

This wave closes the value-layer gap between `AgentChangePlan` and the existing task claim/release projections.

It adds three linked final-abstraction slices:

1. a deterministic claim/release/transfer transition kernel;
2. a repository- and time-scoped public coordination facade;
3. a storage-neutral exact-predecessor mutation and ambiguous-write reconciliation protocol.

The wave does **not** claim to be a concrete durable Beads backend. Task state remains derived coordination metadata rather than repository authority.

## Starting basis

The wave begins after the lifecycle-continuity head recorded in the preceding change documents:

```text
d869294636727ea35ab13148b1d54f2925b6edf8
```

Subsequent commits were deliberately incremental. Their exact SHAs are authoritative in `git log`; the commit subjects are:

```text
feat(agent-control): add deterministic task-projection transitions
test(agent-control): pin task projection claim release transfer
feat(agent-control): expose task-projection adapter kernel
feat(agent-control): bind task transitions to repository and time
feat(agent-control): expose repository-scoped task coordination
test(agent-control): pin repository-scoped task coordination
fix(agent-control): restore complete task transition kernel
fix(agent-control): remove unused adapter fixture state
docs(agent-control): define task coordination persistence contract
docs(agent-control): reconcile task coordination implementation
fix(agent-control): seal task coordination behind scoped receipts
fix(agent-control): remove raw task transition bypass
test(agent-control): connect task release and transfer to cancellation
fix(agent-control): separate task state identity from adapter evidence
fix(agent-control): use exact-width task kernel profile
feat(agent-control): reconcile task projection CAS outcomes
feat(agent-control): expose task mutation persistence receipts
test(agent-control): pin task CAS reread reconciliation
fix(agent-control): isolate task state identity oracle
fix(agent-control): make task snapshot identity reread-stable
test(agent-control): pin reread-stable task snapshot identity
docs(agent-control): reconcile task CAS and identity semantics
docs(agent-control): finalize task coordination status
docs(changelog): record task coordination and CAS recovery
```

One connector write returned ambiguously while updating the raw transition module. The complete module was immediately restored in a separate commit before the public facade and documentation were finalized. The resulting current file, not the ambiguous intermediate response, is the implementation basis.

## Deterministic semantic transition kernel

The crate-private `task_projection_adapter` module owns the pure transition algebra for:

```text
claim
release
transfer
```

It consumes one exact predecessor state and emits:

```text
successor semantic task state
+ semantic transition commitment
+ compatibility projection
```

The kernel validates:

- task identity;
- task phase;
- exact pulse generation;
- plan, action, and run identity;
- assignment and active-lease state;
- claim lifetime;
- exact conflict/reservation surface;
- claim receipt and activation identity during release/transfer;
- successor authority and liveness during transfer;
- monotone generation advancement.

The kernel is crate-private. External callers cannot use it to omit repository namespace or observation freshness.

## Repository-scoped public coordination

`AuthorityBoundTaskProjectionSnapshot` is the public task-state value. It binds:

- `RepositoryId`;
- task ID;
- semantic generation;
- phase;
- assignment;
- active lease, when present;
- separate logical observation time.

The public facade refuses:

- a pulse from another repository;
- a run or successor from another repository;
- observation rollback;
- every stale-basis, assignment, lease, surface, lifetime, and identity error from the semantic kernel.

### State-stable identity

The snapshot identity commits repository namespace and semantic task state. It deliberately excludes `observed_at`.

A later reread of the same persisted row therefore retains the same snapshot identity while carrying newer freshness metadata. This is required for stable exact-predecessor retry and recovery.

### Adapter/evidence separation

A logical successor generation must not change because another conforming backend implementation performed the same mutation or because its audit evidence differs.

The facade therefore invokes the semantic kernel with a fixed internal profile and a semantic plan/claim root. The actual adapter profile and mutation-evidence contract are committed into the repository-scoped transition and public task projection instead of the successor state.

The same logical mutation produces:

```text
same successor generation
same successor snapshot identity
possibly different scoped transition identity and evidence
```

## Claim

Claim construction requires an exact pulse, plan, run, repository, phase, generation, and conflict surface.

The successor task state contains:

- assigned run;
- action-relative active phase;
- one lease bound to the plan, run, predecessor/result generation, complete conflict surface, claim time, and expiry.

The returned `TaskClaimProjection` still passes through `TaskClaimReceipt::admit`. The task becomes actionable only after a fresh situation observes the persisted post-claim generation.

## Release

Release validates the active lease against the exact claim receipt and activated claim.

It returns either:

```text
ReturnToOpen
RequireRework
```

The successor state is unassigned and has no lease.

Release remains permitted after claim or run expiry. Expiry prevents new work; it does not excuse cleanup or make responsibility impossible to discharge.

A focused integration path uses the generated release projection to complete `RunCancellationIntent` cleanly after explicit task release.

## Transfer

Transfer removes the source lease and records a successor assignment in one generation transition.

It does not transfer:

- the source plan;
- active claim;
- capability;
- workspace authority;
- repository publication authority.

The successor must build a new situation, frontier, pulse, plan, claim receipt, and activation against the transferred generation before continuing work.

Cross-repository and self-transfer attempts are refused.

## Exact-predecessor mutation envelope

`TaskProjectionMutationEnvelope` freezes:

- repository and task;
- exact predecessor snapshot and generation;
- exact successor snapshot and generation;
- repository-scoped transition identity;
- semantic inner-transition commitment;
- transition kind and time;
- adapter profile;
- mutation-evidence contract.

The envelope is the stable retry key for a future backend CAS operation.

## Ambiguous-write reconciliation

`TaskProjectionPersistedState` is the storage-neutral result of a backend reread after success, timeout, crash, or lost response.

Reconciliation yields:

```text
Confirmed(TaskProjectionPersistenceReceipt)
RetrySafe { exact predecessor remains }
Conflict { another state is current }
typed refusal { exact successor metadata is absent or substituted }
```

Confirmation requires exact successor state plus:

- scoped transition ID;
- semantic inner-transition ID;
- mutation-evidence contract.

Successor presence alone is not enough.

`TaskProjectionPersistenceReceipt` commits the mutation envelope and confirming reread. It is post-write evidence; it does not alter task-state identity.

## Evidence contract and circularity avoidance

The evidence root supplied before mutation is a commitment to the expected operation and post-state evidence contract. It can be embedded in a tracker command, durable row, or adjacent transition record.

It is not a claim that persistence already succeeded.

The persistence receipt proves that the reread retained that contract beside the exact successor. This avoids the impossible design in which the successor generation depends on a receipt that can be created only after the successor exists.

## Public API hardening

Fresh review found that exposing the raw transition engine would allow callers to produce unscoped task projections.

The raw module is now crate-private. The crate root exports only:

- repository-scoped snapshots, transitions, applications, and IDs;
- mutation envelopes and persistence receipts;
- assignment, lease, transition-kind, release-disposition, and typed refusal vocabulary.

The public scoped transition does not expose the raw transition object. It carries the semantic inner commitment and all durable-adapter fields directly.

## Focused source tests

The current source covers:

- deterministic semantic claim state;
- exact conflict-surface lease retention;
- stale generation and assignment refusal;
- release after expiry;
- explicit open/rework release;
- atomic transfer;
- fresh successor plan and claim;
- cross-authority and cross-repository refusal;
- repository-scoped identity;
- monotone observation time;
- reread-stable snapshot identity;
- adapter/evidence-independent logical successor identity;
- different transition identity for different adapter/evidence facts;
- exact predecessor as safe retry;
- exact successor as confirmed persistence;
- another successor as conflict;
- missing transition metadata as typed ambiguity;
- substituted evidence as refusal;
- release projection completing cancellation cleanly.

Test source is not a revision-bound test result.

## Verification state

The implementation environment did not expose usable revision-bound Rust command output. No result is claimed for:

```text
cargo fmt --all --check
cargo test -p fgit-agent --all-targets
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

GitHub-hosted Actions availability or status was not used as evidence.

The designated verifier must test the current descendant containing all task-coordination commits, not the preceding lifecycle-only head.

## Explicit non-claims

This wave does not implement:

- concrete `br`/Beads read, mutation, lock, CAS, flush, or reread I/O;
- durable active-lease reconstruction after process restart;
- task projection collection into `AgentSituationReceipt`;
- multi-task atomic transactions;
- distributed reservations;
- automatic release from process cancellation;
- robot/CLI/native/MCP task commands;
- automatic ECC-backed verification or closure;
- repository authority or publication;
- independent batch verification or Bead closure.

## Next production slice

The next final-abstraction slice is a concrete Beads adapter that:

1. reads the exact task row and current projection generation through `br` or an owned stable library boundary;
2. builds the scoped transition and mutation envelope;
3. performs exact-predecessor mutation;
4. flushes/persists according to the tracker contract;
5. rereads and reconciles success, safe retry, conflict, or ambiguity;
6. returns a `TaskProjectionPersistenceReceipt`;
7. exposes the reconciled generation to the situation collector;
8. reconstructs active leases durably after restart.

It must not hand-edit `.beads/issues.jsonl` or infer mutation success from command exit status alone.
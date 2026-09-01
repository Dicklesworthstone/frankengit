# Agent Control Plane Implementation Status

**Status:** implementation ledger, not an authority source  
**Normative architecture:** [`AGENT_CONTROL_PLANE_ARCHITECTURE.md`](AGENT_CONTROL_PLANE_ARCHITECTURE.md)  
**Task coordination contract:** [`AGENT_CONTROL_PLANE_TASK_COORDINATION.md`](AGENT_CONTROL_PLANE_TASK_COORDINATION.md)  
**Task recovery contract:** [`AGENT_CONTROL_PLANE_TASK_RECOVERY.md`](AGENT_CONTROL_PLANE_TASK_RECOVERY.md)  
**Owning crate:** `crates/fgit-agent`  
**Last reconciled:** 2026-09-01  
**Verification state:** implementation and focused source-level tests are present; the current execution environment has no local FrankenGit checkout or Rust toolchain, so no revision-bound formatter, compiler, test, Clippy, repository-lane, or independent batch result is claimed for the latest revisions

## Current executable tower

The owning crate now contains this authority-bound control tower:

```text
AuthorityReadReceipt + IntentRun
    -> TaskProjectionCollectionReceipt
       -> TaskProjection SituationComponent
       -> AgentSituationReceipt
       -> WorkFrontier
       -> AgentControlPulse
       -> AgentChangePlan

    -> collected unassigned row
       -> AuthorityBoundTaskProjectionSnapshot
       -> semantic claim application
       -> TaskProjectionMutationEnvelope
       -> one-shot store read/CAS/flush/reread
       -> TaskProjectionPersistenceReceipt
       -> TaskClaimReceipt
       -> ActiveTaskClaim

    -> collected claimed row
       + TaskLeaseHistoryObservation
       -> TaskLeaseReconstructionReceipt
       + original TaskClaimReceipt
       + fresh AgentSituationReceipt
       -> RecoveredActiveTaskClaim
       -> persistence-gated recovered release
       -> PersistedRecoveredTaskRelease
          | Conflict
          | NeedsReconciliation

    -> ActiveTaskClaim
       -> AgentActionPacket
          -> ActiveClaimContinuityReceipt
          -> AgentActionPacketContinuation
       -> RunReconciliationReport
          -> AgentHandoffCapsule -> AgentHandoffAcceptance
          -> RunCancellationIntent -> RunCancellationCompletion
       -> OutcomeLearningRecord
```

Every object above is inert unless its module explicitly owns a store or effect boundary. A recommendation, collection, projection, plan, receipt, packet, capsule, cancellation record, recovery record, or learning record does not become repository authority, mint capability, mutate Beads, execute a tool, settle an obligation, or publish canonical state merely because it exists.

## Landed modules and exact boundaries

| Module | Landed final-abstraction slice | Explicit boundary |
|---|---|---|
| `protocol` | complete authenticated `AuthorityReadReceipt`; bounded `ContextPacket`; `WorkspaceBinding`; ordinary sealed-ref proposal bridge | no authority-head write; no automatic ECC assembly |
| `authority_identity`, `run_identity` | exact authenticated-read identity; complete `IntentRun` commitment; same-ID equivocation guard | identity does not grant authority or prove revocation state |
| `intent`, `capability`, `classes` | authenticated Intent Runs; attenuation-only capabilities and operation classes | freshness is not revocation; no ambient authority |
| `situation` | closed ten-component `AgentSituationReceipt`; explicit omissions; deterministic identity; anti-rollback `SituationDelta` | only the task component has a concrete collector in this crate; the other production collectors remain absent |
| `task_collection` | one bounded pre-situation read request tied to exact authority and complete run; complete canonical rows; current generation; adapter/evidence receipt; task `SituationComponent` | trait is storage-neutral; no concrete Beads transport or durability claim |
| `task_projection_read` | exact-generation reread after a situation already names the generation | cannot discover the first generation and does not replace `task_collection` |
| `task_collection_bridge` | exact unassigned-row claim basis; collection-bound durable lease-history reconstruction; stable reconstruction evidence; original-claim revalidation; restart-safe active-claim recovery | does not invent missing predecessor history; later same-head read events are not interchangeable; no backend history reader is implemented |
| private `task_projection_adapter` | deterministic single-task claim/release/transfer state machine; lease validation and reconstruction; semantic generation derivation | storage-agnostic; inaccessible as an unscoped public mutation path |
| `task_coordination` | public repository- and exact-read-bound semantic task snapshot; monotone freshness; claim/release/transfer applications retaining exact predecessor and successor | application is derived intent/evidence, not persistence |
| `task_persistence` | complete exact-predecessor mutation envelope; full-state authenticated reread; confirmed/retry-safe/conflict interpretation; persistence receipt binding authorizing and confirming reads | defines no store and does not retry effects |
| `task_store` | storage-neutral authenticated read → at-most-one CAS → flush/no-op → authenticated reread orchestration; typed pre-effect refusal and post-effect debt | no concrete Beads or scheduler implementation; an ambiguous write is never blindly retried |
| `task_persistence_gate` | validates exact pulse/plan/run/task basis before store I/O; exposes claim/cancellation projections only after exact durable successor confirmation | conflict and uncertainty retain the envelope; no tracker transport |
| `task_recovery` | recovered active-claim release through the ordinary store protocol; uses invoked store profile; retains reconstruction and recovery identities on success, conflict, and uncertainty | currently supports conservative release, not recovered continuation or transfer; no process/workspace cleanup |
| legacy `task_projection`, `task_mutation`, `task_adapter` | multi-row backend-neutral snapshot/mutation request and observation vocabulary; one-call post-commit-aware adapter boundary; strict claim/release integration | coexists explicitly with the newer single-task semantic kernel; neither is a concrete durable backend |
| `frontier`, `frontier_policy` | bounded deterministic eligibility, typed exclusions, advisory ordering, action-scoped verifier independence | no scheduler; scores and ordering grant no authority |
| `pulse` | compact Level-0 per-turn view binding one situation and frontier; exact live-run recheck; visible exclusion counts | advisory selection only |
| `plan` | inert acceptance contract binding context, intended/conflict surfaces, checkpoints, evidence, effects, budget, stop conditions, rejected shortcuts, non-claims, and approval | no task claim or execution |
| `claim` | claim observation bound to plan, complete run, pre/post generations, conflict surface, adapter evidence, and expiry; activation only after refreshed observation | claim evidence is derived coordination state; legacy activation alone is not the restart-recovery proof |
| `action_packet` | bounded Level-1 packet with exact claim-activation situation, complete plan-approved context, ordered plan-contained steps, evidence obligations, aggregate budget, peer roots, mandatory preconditions, and result/refusal/continuation contracts | no executor; no effect authority; later situations require explicit continuity |
| `claim_continuity` | proof that only logical observation time advanced while authority, run, workspace, and every situation component stayed unchanged; packet continuation with fresh precondition-recheck commitment | deliberately refuses every component change; no plan-relative invalidation analysis |
| `broker` | effect acceptance, typed obligation binding, append-only in-process journal, external-effect reconciliation evidence | journal is not durable storage by itself |
| `reconcile` | deterministic inventory of every accepted effect in one complete run; parent graph, lifecycle, and conserved-spend validation; one typed remaining action per effect | report performs no abort, probe, settlement, escalation resolution, or containment |
| private `handoff` engine + public handoff facade | canonical debt-preserving capsule; exact-activation constructor; later-observation constructor requiring and committing full-context continuity; attenuation ceiling and complete debt retention | capsule grants no authority and does not mutate task assignment |
| `handoff_acceptance` | receiver-side exact-head, complete-run, operation, budget, expiry, target-resolution, and inherited-effect verification | no later-head ancestry witness and no task transfer effect |
| private `cancellation` engine + public cancellation facade | request → drain → finalize over frozen effects and active claim; immutable effect identity; monotone evidence; explicit task release/transfer; clean/debt-transferred/contained states | cancellation deliberately remains available after context change; performs no process, workspace, task, or effect mutation itself |
| `ecc`, `refresh` | evidence classes, requirement dispositions, machine-classified verifier independence, typed refresh relations | partial ECC body only; no complete assembly or publication service |
| `learning`, `outcome_learning` | immutable retrieval-only learning record with complete requirement outcomes, exact plan-required evidence classes, machine-classified independence, ownership findings, failed hypotheses, measured resources, reusable patterns, applicability, invalidation, and negative evidence | no durable learning index; artifact identities are not resolved here; learning grants no authority |

## Task collection, persistence, and recovery semantics

### First observation

A task generation must be collected before an `AgentSituationReceipt` can name it. `TaskProjectionCollectionReceipt` therefore supplies both:

- the canonical multi-row snapshot used by `WorkFrontier`; and
- the exact task-projection `SituationComponent` used to construct the situation.

The older exact-generation reader remains useful for rereads but is not used to bootstrap the first situation.

### Semantic state versus audit evidence

Task generation and semantic snapshot identity are independent from adapter implementation and evidence bytes. The same logical transition produces the same semantic successor state across conforming adapters.

Adapter profile, mutation-evidence contract, exact read basis, and persistence confirmation remain in scoped transition and persistence identities. This prevents backend choice from changing task state while keeping audits distinguishable.

### Claimed-row restart

A claimed collected row cannot be converted through the unassigned path. Recovery requires exact durable history for the predecessor generation and original claim instant.

The reconstruction process reuses assignee, plan, expiry, reservation surface, phase, and current generation from the validated collection. It then revalidates the original `TaskClaimReceipt` and fresh situation before producing `RecoveredActiveTaskClaim`.

### Cleanup after expiry

Claim and run expiry stop new work but do not erase responsibility. A recovered expired claim may still be released through `task_recovery`.

The terminal success identity commits the recovery, reconstruction, and confirmed persistence receipt. Conflict and uncertain outcomes retain the same recovery identities alongside the mutation envelope.

### Ambiguous effects

A timeout, lost response, crash, or disconnect does not prove non-commit. The task-store protocol performs at most one compare-and-replace call.

Seeing the exact predecessor after an ambiguous write is not sufficient for a blind retry because the original operation may still be in flight. The result remains reconciliation debt until an exact successor or a future backend-specific quiescence probe resolves the envelope.

## Continuation, handoff, and cancellation semantics

The control plane preserves the lifecycle asymmetry:

- **Action packets and handoff continue work.** They require the exact claim-activation situation or a full-context continuity receipt proving that only logical time advanced.
- **Cancellation and task release reduce work.** They remain available after ordinary context change or claim expiry, but they still bind exact task ownership, effect inventory, and persistence evidence.
- **Recovery does not widen authority.** Reconstructing a durable lease proves task ownership state; it does not mint a new plan, capability, workspace, or publication right.

Comparing only task generation remains rejected for continuation, handoff, or restart recovery. An unchanged generation does not prove unchanged context, original lease history, or the same exact authenticated read event.

## Focused source tests present

The current tree contains public-path source tests for:

- authenticated situation identities, omissions, forks, rollback, and deltas;
- pre-situation task collection, complete rows, generation, evidence, and component construction;
- exact-generation task rereads and typed unavailable-history results;
- collected unassigned-row conversion and same-head exact-read substitution refusal;
- deterministic claimed-row lease reconstruction using a real predecessor-bound plan;
- history replay, missing state, temporal inversion, and conflict-state refusals;
- original-claim revalidation and restart active-claim recovery;
- deterministic task claim, release, and transfer semantics;
- repository namespace and exact-read task binding;
- complete-state persistence reconciliation, partial-write detection, and stable reread identity;
- one-shot store success, identical retry, conflict, timeout, flush, and confirming-read paths;
- persistence-gated claim and resolution projection release;
- recovered release after expiry, evidence retention, pre-I/O reconstruction substitution refusal, and ambiguous-write debt;
- frontier eligibility, exclusions, action-scoped independence, and deterministic ranking;
- Level-0 pulse identity and exclusion accounting;
- plan canonicalization, conflict coverage, budget attenuation, evidence, and authority boundaries;
- action-packet context completeness, exact activation continuity, same-ID run-scope revalidation, target containment, and budget bounds;
- time-only claim continuity and component-change refusal;
- complete run-effect reconciliation and conserved spend;
- proof-carrying handoff, receiver verification, and inherited debt;
- changed-context-safe cancellation and explicit task release/transfer evidence;
- learning determinism, evidence requirements, ownership containment, resource bounds, and machine-classified independence.

Test source is not a test result. No command outcome is attached to the latest recovery revisions by this ledger.

## Deliberately absent product surfaces

The landed library slices do not implement or imply:

- concrete `br`/Beads collection, lease-history, CAS, flush, reread, or envelope-probe I/O;
- production collectors for the nine non-task situation components;
- multi-task atomic transactions or a distributed reservation service;
- durable codecs, migrations, replay, or restart storage for the new control-plane records;
- a production action-packet executor connecting steps to TreeFS, sandboxing, capabilities, the effect broker, and evidence services;
- process, child-task, workspace, credential, tunnel, upload, or external-effect reaping;
- effect-time capability revocation against a named canonical position;
- authenticated ancestry proof allowing handoff acceptance at a later head;
- plan-relative invalidation across changed situation components;
- a stable `fg agent` CLI, JSON/NDJSON robot protocol, native API, or MCP surface;
- automatic requirement-to-artifact resolution, complete ECC assembly, task verification/closure transition, or canonical publication;
- a durable authorization-filtered learning and negative-evidence index;
- a complete human review renderer;
- independent batch verification or Bead closure for this tower.

## Verification evidence still required

Before the current control-plane tower may be represented as verified, a revision-bound local or designated batch gate must record at least:

```text
cargo fmt --all --check
cargo test -p fgit-agent --all-targets
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

The evidence must retain:

- exact tested revision;
- pinned Rust toolchain identity;
- dependency constellation identity;
- complete command outcomes;
- whether each failure is introduced, pre-existing, or indeterminate;
- every source edit made after the result.

GitHub-hosted Actions availability or status is not required and is not a substitute for the repository-owned commands.

## Next coherent implementation order

1. obtain a real local checkout and repair formatter/compiler/test/Clippy failures, if any, for the newly activated collection, recovery, persistence, and store modules;
2. implement the concrete Beads transport for collection, lease history, exact-predecessor mutation, flush, authenticated reread, and envelope-ID probing;
3. add registered durable codecs, migrations, and restart replay for collection, reconstruction, recovery, envelope, and persistence receipts;
4. connect confirmed recovered release directly into cancellation completion and host process/workspace cleanup orchestration;
5. build the action-packet executor over real capabilities, TreeFS, sandboxing, the effect broker, obligations, and evidence outputs;
6. expose stable bounded robot-mode results through `fg agent`, native API, and MCP adapters generated from the same typed results;
7. assemble complete ECCs and task verification/closure transitions through ordinary publication authority;
8. add authenticated authority-history witnesses and plan-relative invalidation witnesses;
9. add the authorization-filtered learning index and measure repeated retrieval/check cost avoided;
10. submit the exact revision to the independent batch verifier and update Beads only through `br`.

The active repository priority outside this slice remains the live Beads dependency graph and authenticated repository state, not this status document.
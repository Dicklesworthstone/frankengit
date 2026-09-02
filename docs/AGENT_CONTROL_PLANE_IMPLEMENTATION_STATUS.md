# Agent Control Plane Implementation Status

**Status:** implementation ledger, not an authority source  
**Normative architecture:** [`AGENT_CONTROL_PLANE_ARCHITECTURE.md`](AGENT_CONTROL_PLANE_ARCHITECTURE.md)  
**Agent protocol:** [`AGENT_PROTOCOL.md`](AGENT_PROTOCOL.md)  
**Task coordination:** [`AGENT_CONTROL_PLANE_TASK_COORDINATION.md`](AGENT_CONTROL_PLANE_TASK_COORDINATION.md)  
**Task recovery:** [`AGENT_CONTROL_PLANE_TASK_RECOVERY.md`](AGENT_CONTROL_PLANE_TASK_RECOVERY.md)  
**Effect authorization:** [`AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md`](AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md)  
**Owning crate:** `crates/fgit-agent`  
**Last reconciled:** 2026-09-02  
**Verification state:** implementation and focused source tests are present; the current execution environment has no local FrankenGit checkout or Rust toolchain, so no formatter, compiler, test, Clippy, repository-lane, or independent batch result is claimed for the latest revisions

## 1. Current executable tower

The owning crate contains this authority-bound control tower:

```text
AuthorityReadReceipt
    + IntentRun / IntentRunCommitment
    -> TaskProjectionCollectionReceipt
       -> task SituationComponent
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
       + exact complete IntentRun
       -> RunBoundRecoveredTaskClaim
       -> persistence-gated recovered release
       -> PersistedRecoveredTaskRelease
          | Conflict
          | NeedsReconciliation

ActiveTaskClaim
    -> AgentActionPacket
       -> ActiveClaimContinuityReceipt
       -> AgentActionPacketContinuation

sealed capability chain
    -> VerifiedCapabilityChain
exact authority read + complete run
    -> CapabilityRevocationReadRequest
    -> CapabilityRevocationReceipt
verified chain + fresh receipt + exact EffectRequest
    -> CapabilityEffectAuthorization
    -> RevocationAuthorizedEffectGrant
    -> RevocationAuthorizedOutboxEffect
    -> fresh dispatch-time authorization
    -> RevocationAuthorizedDeferredOutboxEffect

EffectBroker records
    -> RunReconciliationReport
       -> AgentHandoffCapsule
          -> AgentHandoffAcceptance
       -> RunCancellationIntent
          -> RunCancellationCompletion

AgentActionPacket + evidence
    -> OutcomeLearningRecord
```

Every object above is inert unless its module explicitly owns a store, budget reservation, typed obligation, or effect transition. A recommendation, projection, plan, receipt, authorization, packet, capsule, cancellation record, recovery record, or learning record does not become repository authority, mint capability, mutate Beads, execute a host tool, or publish canonical state merely because it exists.

## 2. Landed modules and exact boundaries

| Module | Landed final-abstraction slice | Explicit boundary |
|---|---|---|
| `protocol` | complete authenticated `AuthorityReadReceipt`; bounded `ContextPacket`; `WorkspaceBinding`; ordinary sealed-ref proposal bridge | no authority-head write; no automatic ECC assembly |
| `authority_identity`, `run_identity` | exact authenticated-read identity; complete `IntentRunCommitment`; same-ID equivocation guard | identity does not grant authority or prove current revocation state |
| `intent`, `capability`, `classes` | authenticated and legacy Intent Runs; attenuation-only capability construction; authenticated sealed ancestry; stable operation classes | capability authentication proves issuance, not absence of later revocation; legacy runs are unsuitable for high-value authorization |
| `situation` | closed ten-component `AgentSituationReceipt`; explicit omissions; complete-run identity; deterministic deltas and rollback refusal | only the task component has a concrete collector in this crate; nine production collectors remain absent |
| `task_collection` | bounded pre-situation task read tied to exact authority and complete run; canonical rows; current generation; adapter/evidence receipt; task `SituationComponent` | storage-neutral trait; no concrete Beads transport or durability claim |
| `task_projection_read` | exact-generation reread after a situation already names the generation | does not discover the first generation and does not replace collection |
| `task_collection_bridge` | exact unassigned-row claim basis; collection-bound lease-history reconstruction; original-claim revalidation; restart-safe claim recovery | does not invent missing predecessor history; no backend history reader |
| private `task_projection_adapter` | deterministic single-task claim/release/transfer kernel; complete assignment identity; lease validation and semantic generation derivation | storage-agnostic and inaccessible as an unscoped public mutation path |
| `task_coordination` | repository- and exact-read-bound semantic task state; monotone freshness; claim/release/transfer applications | application is derived intent/evidence, not durable persistence |
| `task_persistence` | exact-predecessor mutation envelope; complete authenticated reread reconciliation; confirmed/retry-safe/conflict result; persistence receipt | defines no store and never retries effects |
| `task_store` | authenticated read → at-most-one CAS → flush/no-op → authenticated reread orchestration; typed pre-effect refusal and post-effect debt | no concrete Beads or scheduler implementation; ambiguous writes are never blindly retried |
| `task_persistence_gate` | validates pulse/plan/run/task basis before I/O; exposes claim/cancellation projections only after exact durable successor confirmation | no tracker transport or multi-task atomic transaction |
| `task_recovery` | complete-run-bound restart recovery and conservative persisted release after claim/run expiry; retains evidence through success, conflict, and uncertainty | recovered continuation/transfer and host cleanup remain absent |
| legacy `task_projection`, `task_mutation`, `task_adapter` | multi-row snapshot/mutation vocabulary; post-commit-aware one-call adapter; strict claim/release integration | backend-neutral compatibility surface; not a concrete durable backend |
| `frontier`, `frontier_policy` | bounded deterministic eligibility, typed exclusions, advisory ordering, action-scoped verifier independence | no scheduler; scores grant no authority |
| `pulse` | compact Level-0 view binding one situation, frontier, and complete live run; visible exclusion counts | advisory selection only |
| `plan` | inert acceptance contract binding context, intended/conflict surfaces, checkpoints, evidence, effects, budget, stop conditions, rejected shortcuts, non-claims, and approval | no task mutation or execution |
| `claim` | claim observation bound to plan, complete run, pre/post generations, conflict surface, adapter evidence, and expiry; activation after refreshed observation | claim evidence is derived coordination state; restart recovery needs the stronger recovery path |
| `action_packet` | bounded Level-1 packet with exact claim-activation situation, complete context, ordered plan-contained steps, evidence obligations, aggregate budget, mandatory preconditions, and typed continuation contracts | no production executor; packet grants no effect authority |
| `claim_continuity` | proof that only logical time advanced while authority, complete run, workspace, and every situation component stayed unchanged | deliberately refuses component changes; no plan-relative invalidation witness |
| `broker` | typed budget reservation, obligation binding, external reconciliation, complete-run-bound `EffectRecord`, append-only replayable journal, mixed-run refusal | in-process journal is not durable; low-level `EffectBroker` remains a library primitive and concrete services must adopt the checked authorization facade for high-value work |
| private `effect_authorization` | bounded exact-position revocation requests/receipts; half-open freshness; complete verified capability-chain identity; exact effect authorization; ancestor-revocation checks | reader is storage-neutral; no canonical revocation schema, durable cache, or production transport |
| `effect_dispatch` | production-facing checked broker; low-risk/high-value separation; proof-carrying outbox reservation; fresh exact-request authorization at irreversible dispatch; reservation/deferred-obligation recovery | no network/secret/runner/forge/publication host adapter is wired yet; service adoption is still required |
| `reconcile` | v2 complete-run effect inventory; authority, operation, parent graph, lifecycle, evidence, and conserved-spend validation; one typed remaining action per effect | performs no abort, probe, settlement, escalation resolution, or containment |
| private `handoff` + public facade | canonical debt-preserving capsule; exact activation or full-context continuity; attenuation ceiling; complete effect-debt retention | capsule grants no authority and does not mutate task assignment |
| `handoff_acceptance` | exact-head receiver verification; complete receiver run; operation, budget, expiry, target-resolution, and inherited-effect checks | no later-head ancestry witness and no task-transfer effect |
| private `cancellation` + public facade | v2 request → drain → finalize; complete-run-bound situation, claim, initial/final report; frozen effect membership; monotone evidence; explicit release/transfer; clean/debt-transferred/contained outcomes | cancellation performs no task, process, workspace, or effect mutation itself; remains available after context change |
| `ecc`, `refresh` | evidence classes, requirement dispositions, machine-classified verifier independence, typed refresh relations | partial ECC body; no complete assembly or publication service |
| `learning`, `outcome_learning` | immutable retrieval-only outcome record with exact plan-required evidence classes, independence, ownership, hypotheses, measured resources, patterns, applicability, invalidation, and negative evidence | no durable authorized learning index; learning grants no authority |

## 3. Effect-time authorization semantics

### 3.1 Authentication and revocation are separate

A valid sealed chain proves that each link was authenticated and no child widened its parent. It does not prove that the root or another ancestor remains unrevoked.

`VerifiedCapabilityChain` authenticates and commits the complete root-first ancestry. `CapabilityRevocationReceipt` independently binds current revocation evidence to one exact authenticated read and complete run.

### 3.2 Freshness is half-open

The implemented interval is:

```text
revocation_observed_at <= effect_time < valid_until
```

Use at `valid_until` is stale. The deadline is bounded by the requested maximum age and the run expiry.

### 3.3 Every ancestor is checked

The authorization path refuses when any capability ID in the verified ancestry appears in the revocation receipt. A non-revoked leaf cannot conceal a revoked root.

### 3.4 Request acceptance is not dispatch

For external effects:

```text
high-value request authorization
-> run-budget reservation
-> typed outbox reservation
-> fresh dispatch authorization
-> downstream-visible effect
-> reconciliation
```

The checked broker never returns a raw outbox reservation. `RevocationAuthorizedOutboxEffect` may abort, but dispatch requires a newly constructed authorization for the retained exact request at the actual dispatch time. The chain and leaf must equal those used at initial acceptance.

### 3.5 Cleanup remains available

Revocation blocks new consequential work. It does not block abort, reconciliation, acknowledgement, terminal failure, escalation resolution, cancellation, or containment.

Every pre-dispatch refusal returns the live reservation. A failure after obligation commit retains the deferred effect for reconciliation.

## 4. Complete-run effect identity

`EffectRecord` carries both:

```text
RunId
IntentRunCommitment
```

The broker computes the complete commitment before any budget movement. Journal replay establishes both values from the first accepted effect and refuses mixed numeric or complete runs.

`RunReconciliationReport` uses its v2 identity and commits the complete run in the report header and every effect row. A same-ID record from another authority read, operation set, budget, or expiry is refused before lifecycle or resource interpretation.

The public cancellation facade also uses v2 identities. Request construction verifies situation, active claim, initial report, and supplied run. Completion verifies the final report uses the same complete run.

## 5. Task and lifecycle asymmetry

The control plane preserves four distinct rules:

- **Action execution and handoff continue work.** They require exact activation or a full-context continuity receipt.
- **High-value effects create new responsibility.** They require fresh named-position revocation evidence at the consequential boundary.
- **Cancellation and task release reduce work.** They remain available after context change or expiry while retaining exact ownership and effect evidence.
- **Abort and reconciliation resolve responsibility.** Later revocation cannot disable them.

Comparing only task generation, authority-head generation, capability leaf, or numeric `RunId` remains rejected.

## 6. Focused source tests present

The source tree contains public-path tests for:

- authenticated situation identity, omissions, rollback, and deltas;
- task collection, exact-generation reread, mutation, persistence, and restart recovery;
- frontier eligibility, typed exclusions, deterministic ordering, and verifier independence;
- pulse, plan, claim, activation, action packet, and time-only continuity;
- deterministic claim/release/transfer and complete-run assignment;
- one-shot store success, conflict, timeout, flush, reread, and post-effect debt;
- complete-run-bound recovered cleanup after expiry;
- capability attenuation, sealing, ancestry, and tamper refusal;
- exact-position revocation request and receipt identity;
- stale revocation refusal at the exclusive deadline;
- revoked ancestor refusal;
- complete-run substitution refusal in authorization;
- request-time proof expiry before external dispatch;
- ancestor revocation between reservation and dispatch;
- reservation recovery and abort after dispatch refusal;
- fresh dispatch authorization followed by acknowledgement reconciliation;
- effect-record complete-run retention;
- journal replay refusal across same-ID/different-commitment runs;
- complete-run reconciliation refusal;
- handoff and receiver preservation of complete effect debt;
- cancellation request and final-report complete-run substitution refusal;
- outcome-learning evidence and independence invariants.

Test source is not a test result.

## 7. Identity revisions

This wave deliberately changed identity domains rather than silently reinterpreting existing bytes:

```text
RunReconciliationReport          v1 -> v2
public RunCancellationIntent     v1 -> v2
public RunCancellationCompletion v1 -> v2
```

New v1 identities exist for:

```text
CapabilityRevocationReadRequest
CapabilityRevocationReceipt
VerifiedCapabilityChain
CapabilityEffectAuthorization
```

No registered durable codec currently exists for these values or the expanded `EffectRecord`. Future persistence must provide explicit schemas and migration/refusal rules.

## 8. Deliberately absent product surfaces

The landed library slices do not implement or imply:

- a canonical capability-revocation event/body schema selected by repository authority;
- concrete revocation reads from policy state;
- a durable revocation index, cache, invalidation stream, or backend adapter;
- mandatory adoption of the checked broker by every network, secret, runner, forge, or publication service;
- concrete `br`/Beads collection, history, mutation, flush, reread, or envelope-probe I/O;
- production collectors for the nine non-task situation components;
- multi-task atomic transactions or distributed reservations;
- durable codecs, migrations, storage, and replay for the control-plane objects;
- a production action-packet executor connecting TreeFS, runner, capabilities, effects, and evidence;
- process, child-task, workspace, credential, tunnel, upload, secret, VM, or external-resource reaping;
- authenticated ancestry proof for handoff acceptance at a later authority head;
- plan-relative invalidation after selected component changes;
- stable `fg agent`, JSON/NDJSON, native API, or MCP surfaces;
- automatic requirement-to-artifact resolution, complete ECC assembly, task closure, or canonical publication;
- a durable authorization-filtered learning and negative-evidence index;
- complete human review rendering;
- independent batch verification or Bead closure.

## 9. Verification evidence required

Before the latest control-plane tower is represented as mechanically verified, a revision-bound local or designated batch gate must record at least:

```text
cargo fmt --all --check
cargo test -p fgit-agent --all-targets --no-fail-fast
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check --no-fail-fast
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

The evidence must retain:

- exact tested source revision;
- pinned Rust toolchain identity;
- dependency and `Cargo.lock` identity;
- complete command outcomes;
- first load-bearing failure output;
- whether each failure is introduced, pre-existing, or indeterminate;
- every source edit after the result.

The current implementation environment did not provide a local checkout, Cargo, rustc, rustfmt, Clippy, `br`, or `bv`; none of these commands is claimed for the latest revisions. GitHub-hosted Actions were not consulted and are not substitute evidence.

## 10. Next coherent implementation order

1. obtain an exact local checkout and repair formatter/compiler/test/Clippy failures for the revocation, dispatch, effect-record, reconciliation, and cancellation changes;
2. define a canonical revocation event/body schema and authority-selected revocation root or policy projection;
3. implement a concrete durable revocation reader/cache with invalidation and exact-read replay;
4. wire the checked broker into network, secret, runner, forge-mutation, publication, and external-integration hosts so high-value service paths cannot select the raw broker;
5. add registered durable codecs and migrations for revocation receipts, chain identities, authorizations, effect records, reconciliation reports, and cancellation records;
6. implement the complete action-packet executor over TreeFS, sandboxing, effect brokerage, obligations, and evidence;
7. add host process/workspace/credential/tunnel/upload/VM cleanup and cancellation orchestration;
8. expose bounded robot/native/MCP representations from the same typed results;
9. assemble complete ECC-backed verification and publication transitions;
10. run the independent batch gate and update the owning Bead only through `br`.

The active repository priority remains the live Beads dependency graph and authenticated repository state, not this ledger.

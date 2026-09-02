# Agent Control Plane Implementation Status

**Status:** implementation ledger, not an authority source  
**Normative architecture:** [`AGENT_CONTROL_PLANE_ARCHITECTURE.md`](AGENT_CONTROL_PLANE_ARCHITECTURE.md)  
**Agent protocol:** [`AGENT_PROTOCOL.md`](AGENT_PROTOCOL.md)  
**Task coordination:** [`AGENT_CONTROL_PLANE_TASK_COORDINATION.md`](AGENT_CONTROL_PLANE_TASK_COORDINATION.md)  
**Task recovery:** [`AGENT_CONTROL_PLANE_TASK_RECOVERY.md`](AGENT_CONTROL_PLANE_TASK_RECOVERY.md)  
**Effect authorization:** [`AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md`](AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md)  
**Lifecycle continuity:** [`AGENT_CONTROL_PLANE_LIFECYCLE_CONTINUITY.md`](AGENT_CONTROL_PLANE_LIFECYCLE_CONTINUITY.md)  
**Handoff ancestry:** [`AGENT_CONTROL_PLANE_HANDOFF_ANCESTRY.md`](AGENT_CONTROL_PLANE_HANDOFF_ANCESTRY.md)  
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

canonical repository configuration
    -> authority-selected capability revocation generation
    -> canonical exact-head revocation receipt
    -> bounded current-head ancestry proof when authority advanced

sealed capability chain
    -> VerifiedCapabilityChain
exact authority read + complete run
    -> CapabilityRevocationReceipt
verified chain + fresh receipt + exact EffectRequest
    -> CapabilityEffectAuthorization
    -> CurrentAuthorityRevocationAuthorizedEffectGrant
    -> typed reservation / irreversible-start authorization
    -> proof-carrying deferred responsibility

EffectBroker records
    -> RunReconciliationReport
       -> AgentHandoffCapsule
          + same authenticated receiver head
          | AuthorityHeadAncestryReceipt
          -> AgentHandoffAcceptance v2
          -> accept_handoff_at_current_authority[_async]
       -> RunCancellationIntent
          -> RunCancellationCompletion

AgentActionPacket + evidence
    -> OutcomeLearningRecord
```

Every object above is inert unless its module explicitly owns a store, budget reservation, typed obligation, or effect transition. A recommendation, projection, plan, receipt, authorization, packet, capsule, acceptance, cancellation record, recovery record, or learning record does not become repository authority, mint capability, mutate Beads, execute a host tool, transfer task ownership, or publish canonical state merely because it exists.

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
| private `task_projection_adapter` | deterministic single-task claim/release/transfer kernel; complete assignment identity; lease validation and semantic generation derivation | same-read transfer only; storage-agnostic and inaccessible as an unscoped public mutation path |
| `task_coordination` | repository- and exact-read-bound semantic task state; monotone freshness; claim/release/transfer applications | application is derived intent/evidence, not durable persistence; no two-authority-basis cross-head transfer |
| `task_persistence` | exact-predecessor mutation envelope; complete authenticated reread reconciliation; confirmed/retry-safe/conflict result; persistence receipt | one authenticated-read basis governs predecessor and successor; defines no store and never retries effects |
| `task_store` | authenticated read → at-most-one CAS → flush/no-op → authenticated reread orchestration; typed pre-effect refusal and post-effect debt | no concrete Beads or scheduler implementation; ambiguous writes are never blindly retried |
| `task_persistence_gate` | validates pulse/plan/run/task basis before I/O; exposes claim/cancellation projections only after exact durable successor confirmation | no tracker transport, cross-head transfer envelope, or multi-task atomic transaction |
| `task_recovery` | complete-run-bound restart recovery and conservative persisted release after claim/run expiry; retains evidence through success, conflict, and uncertainty | recovered continuation/transfer and host cleanup remain absent |
| legacy `task_projection`, `task_mutation`, `task_adapter` | multi-row snapshot/mutation vocabulary; post-commit-aware one-call adapter; strict claim/release integration | backend-neutral compatibility surface; not a concrete durable backend |
| `frontier`, `frontier_policy` | bounded deterministic eligibility, typed exclusions, advisory ordering, action-scoped verifier independence | no scheduler; scores grant no authority |
| `pulse` | compact Level-0 view binding one situation, frontier, and complete live run; visible exclusion counts | advisory selection only |
| `plan` | inert acceptance contract binding context, intended/conflict surfaces, checkpoints, evidence, effects, budget, stop conditions, rejected shortcuts, non-claims, and approval | no task mutation or execution |
| `claim` | claim observation bound to plan, complete run, pre/post generations, conflict surface, adapter evidence, and expiry; activation after refreshed observation | claim evidence is derived coordination state; restart recovery needs the stronger recovery path |
| `action_packet` | bounded Level-1 packet with exact claim-activation situation, complete context, ordered plan-contained steps, evidence obligations, aggregate budget, mandatory preconditions, and typed continuation contracts | no production executor; packet grants no effect authority |
| `claim_continuity` | proof that only logical time advanced while authority, complete run, workspace, and every situation component stayed unchanged | deliberately refuses component changes; no plan-relative invalidation witness |
| `broker` | typed budget reservation, obligation binding, external reconciliation, complete-run-bound `EffectRecord`, append-only replayable journal, mixed-run refusal | in-process journal is not durable; low-level broker remains an internal/conformance primitive beneath checked high-value facades |
| private `effect_authorization` | bounded exact-position revocation requests/receipts; half-open freshness; complete verified capability-chain identity; exact effect authorization; ancestor-revocation checks | generic reader contract remains storage-neutral |
| `authority_revocation` | exact-head canonical revocation reader selected by authenticated repository configuration; sync/async parity | no product host adoption or durable agent-control codec implied |
| `descendant_revocation` | current-head authenticated ancestry walk plus current authority-selected revocation state and exact effect authorization | bounded proof does not itself execute an effect or migrate historical control records |
| `effect_dispatch`, `current_effect_dispatch` | checked high-value broker; low-risk/high-value separation; proof-carrying reservation; fresh irreversible-start authorization; reservation/deferred-obligation recovery and proof-preserving reconciliation | concrete network, runner, secret, forge, and publication hosts must still select these facades; no raw high-value bypass is permitted in first-party hosts |
| `reconcile` | v2 complete-run effect inventory; authority, operation, parent graph, lifecycle, authorization evidence, and conserved-spend validation; one typed remaining action per effect | performs no abort, probe, settlement, escalation resolution, or containment |
| private `handoff` + public facade | canonical debt-preserving capsule; exact activation or full-context source continuity; attenuation ceiling; complete effect-debt retention | capsule grants no authority and does not mutate task assignment |
| `handoff_acceptance` | v2 same-head or exact bounded descendant-head receiver verification; complete receiver run; retained ancestry receipt; operation, budget, expiry, target-resolution, and inherited-effect checks | acceptance grants no capability or task ownership; cross-head task transfer remains absent |
| `handoff_ancestry` | sync/async host driver that authenticates the current authority slot, proves bounded ancestry from the capsule source, requires the receiver's exact current head token, and immediately consumes the proof | no persistence or task mutation; a descendant proof is not plan-validity proof |
| private `cancellation` + public facade | v2 request → drain → finalize; complete-run-bound situation, claim, initial/final report; frozen effect membership; monotone evidence; explicit release/transfer; clean/debt-transferred/contained outcomes | cancellation performs no task, process, workspace, or effect mutation itself; remains available after context change |
| `ecc`, `refresh` | evidence classes, requirement dispositions, machine-classified verifier independence, typed refresh relations | partial ECC body; no complete assembly or publication service |
| `learning`, `outcome_learning` | immutable retrieval-only outcome record with exact plan-required evidence classes, independence, ownership, hypotheses, measured resources, patterns, applicability, invalidation, and negative evidence | no durable authorized learning index; learning grants no authority |

## 3. Handoff authority semantics

### 3.1 Source continuity and receiver ancestry are separate

Source capsule construction requires the exact claim-activation situation or a full-context continuity receipt proving only logical time advanced.

Receiver acceptance asks a different question: whether the receiver's authenticated head is the same source head or a proven descendant. The two proofs are not interchangeable.

### 3.2 Generation comparison is not ancestry

A receiver at a later generation must present an `AuthorityHeadAncestryReceipt` whose repository, ancestor head/generation, descendant head/generation, exact descendant version token, and hop count match the capsule and receiver.

The receipt comes from the authority layer's bounded predecessor walk. A later number, a same-looking body from another store, or a proof for another ancestor is refused.

### 3.3 The receiver is a complete run

Acceptance recomputes `IntentRunCommitment` and compares it with the receiver situation before scope, budget, expiry, or inherited-effect interpretation. Same numeric `RunId` with another authority read, operation set, budget, or lifetime is identity substitution.

### 3.4 Proof acquisition and consumption are atomic at the host boundary

The recommended host surface is:

```text
accept_handoff_at_current_authority(...)
accept_handoff_at_current_authority_async(...)
```

It reads and authenticates the current slot, walks to the source head, compares the exact current head/generation/token with the receiver run, and immediately consumes the proof. This prevents a proof from one slot or store being paired with a receiver from another.

### 3.5 Acceptance is not task transfer

The current task mutation envelope assumes one exact authenticated-read basis for predecessor and successor. Removing that check after descendant acceptance would create an unprovable durable transition.

A future cross-head transfer must use a two-authority-basis envelope retaining source and receiver reads, ancestry, capsule/acceptance, exact task states, one-shot persistence evidence, source cancellation projection, and receiver activation.

## 4. Effect-time authorization semantics

### 4.1 Authentication and revocation are separate

A valid sealed chain proves that each link was authenticated and no child widened its parent. It does not prove that the root or another ancestor remains unrevoked.

`VerifiedCapabilityChain` authenticates and commits the complete root-first ancestry. Canonical revocation readers bind authority-selected revocation state to an exact authenticated read and complete run.

### 4.2 Freshness is half-open

The implemented interval is:

```text
revocation_observed_at <= effect_time < valid_until
```

Use at `valid_until` is stale. The deadline is bounded by policy maximum age, run expiry, and capability expiry.

### 4.3 Every ancestor is checked

The authorization path refuses when any capability ID in the verified ancestry appears in the revocation receipt. A non-revoked leaf cannot conceal a revoked root.

### 4.4 Request acceptance is not irreversible start

For external effects:

```text
high-value request authorization
-> run-budget reservation
-> typed outbox reservation
-> fresh dispatch authorization
-> downstream-visible effect
-> reconciliation
```

Equivalent proof-carrying start gates exist for landed checked sandbox and secret lifecycles. Cleanup remains available after revocation.

## 5. Complete-run effect identity

`EffectRecord` carries both:

```text
RunId
IntentRunCommitment
```

The broker computes the complete commitment before budget movement. Journal replay establishes both values and refuses mixed numeric or complete runs.

`RunReconciliationReport` uses its v2 identity and commits the complete run in the report header and every effect row. Same-ID records from another authority read, operation set, budget, or expiry are refused before lifecycle or resource interpretation.

The public cancellation facade also uses v2 identities. Request construction verifies situation, active claim, initial report, and supplied run. Completion verifies the final report uses the same complete run.

## 6. Task and lifecycle asymmetry

The control plane preserves five distinct rules:

- **Action execution and source handoff construction continue work.** They require exact activation or full-context source continuity.
- **Receiver handoff acceptance at a later head requires exact authority ancestry.** Generation comparison alone is insufficient.
- **High-value effects create new responsibility.** They require fresh named-position revocation evidence at the consequential boundary.
- **Cancellation and task release reduce work.** They remain available after context change or expiry while retaining exact ownership and effect evidence.
- **Abort and reconciliation resolve responsibility.** Later revocation cannot disable them.

Comparing only task generation, authority-head generation, capability leaf, or numeric `RunId` remains rejected.

## 7. Focused source tests present

The source tree contains public-path tests for:

- authenticated situation identity, omissions, rollback, and deltas;
- task collection, exact-generation reread, mutation, persistence, and restart recovery;
- frontier eligibility, typed exclusions, deterministic ordering, and verifier independence;
- pulse, plan, claim, activation, action packet, and time-only continuity;
- deterministic claim/release/transfer and complete-run assignment;
- one-shot store success, conflict, timeout, flush, reread, and post-effect debt;
- complete-run-bound recovered cleanup after expiry;
- capability attenuation, sealing, ancestry, and tamper refusal;
- authority-selected revocation reads, stale evidence, and revoked ancestors;
- request-time proof expiry before irreversible dispatch;
- reservation recovery, abort, and proof-preserving reconciliation;
- effect-record complete-run retention and mixed-run journal refusal;
- complete-run reconciliation and cancellation refusal;
- exact-activation and proof-carrying source handoff construction;
- same-head receiver acceptance;
- later-head refusal without ancestry;
- deterministic descendant-head acceptance with retained proof;
- wrong-ancestor and cross-store token substitution refusal;
- same-ID/different-commitment receiver refusal;
- synchronous/asynchronous current-authority driver parity;
- outcome-learning evidence and independence invariants.

Test source is not a test result.

## 8. Identity revisions

Deliberate identity changes include:

```text
RunReconciliationReport          v1 -> v2
public RunCancellationIntent     v1 -> v2
public RunCancellationCompletion v1 -> v2
AgentHandoffAcceptance           v1 -> v2
```

The v2 handoff acceptance adds the complete receiver run commitment, closed authority relation, and optional exact ancestry receipt ID.

New identity families also exist for authority-selected revocation reads, verified capability chains, exact effect authorizations, task persistence/recovery records, and authority-head ancestry receipts.

Registered durable codecs and migrations remain incomplete for much of the Agent Control Plane. An old v1 acceptance must never be reinterpreted as a v2 value carrying ancestry evidence.

## 9. Deliberately absent product surfaces

The landed library slices do not implement or imply:

- concrete `br`/Beads collection, history, mutation, flush, reread, or envelope-probe I/O;
- production collectors for the nine non-task situation components;
- multi-task atomic transactions or distributed reservations;
- a cross-head, two-authority-basis task-transfer envelope and persistence path;
- automatic receiver plan adoption after descendant acceptance;
- plan-relative invalidation after selected component changes;
- durable codecs, migrations, storage, and replay for all control-plane objects, including `AgentHandoffAcceptance` v2;
- a production action-packet executor connecting TreeFS, runner, capabilities, effects, and evidence;
- complete process, child-task, workspace, credential, tunnel, upload, VM, and external-resource reaping;
- mandatory adoption of every checked high-value host facade by all product services;
- stable `fg agent`, JSON/NDJSON, native API, or MCP surfaces;
- automatic requirement-to-artifact resolution, complete ECC assembly, task closure, or canonical publication;
- a durable authorization-filtered learning and negative-evidence index;
- complete human review rendering;
- independent batch verification or Bead closure.

## 10. Verification evidence required

Before the latest control-plane tower is represented as mechanically verified, a revision-bound local or designated batch gate must record at least:

```text
cargo fmt --all --check
cargo test -p fgit-agent --all-targets --no-fail-fast
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-authority --all-targets --no-fail-fast
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

## 11. Next coherent implementation order

1. obtain an exact local checkout and repair formatter/compiler/test/Clippy failures for the new handoff-acceptance and current-authority driver plus the surrounding Agent Control Plane;
2. design the two-authority-basis task-transfer envelope and persistence/reconciliation protocol rather than weakening the existing same-read transition;
3. implement the concrete Beads collection, history, mutation, flush, reread, and request/envelope probe transport;
4. add registered durable codecs and migrations for handoff acceptance v2, ancestry-linked transfer, authorization, effect, reconciliation, cancellation, and task-control records;
5. wire checked high-value host lifecycles into all product services and prove no raw-broker bypass;
6. implement the complete action-packet executor over TreeFS, sandboxing, effect brokerage, obligations, and evidence;
7. add complete host cleanup and cancellation orchestration;
8. expose bounded robot/native/MCP representations from the same typed results;
9. assemble complete ECC-backed verification and publication transitions;
10. run the independent batch gate and update the owning Bead only through `br`.

The active repository priority remains the live Beads dependency graph and authenticated repository state, not this ledger.

# Changelog

All notable FrankenGit changes are recorded here. This file is a summary, not a source of authority or verification. Exact behavior is governed by executable code, [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md), the constitutions and registries, and revision-bound evidence.

FrankenGit has moved beyond its original architecture-only phase into active implementation and pre-release integration. It is still not a general-purpose Git server, production-ready forge, or GitHub replacement.

## [Unreleased] — 2026-09-02

### Added — network push over the raw git-daemon transport (frankengit-hh37)

`fg serve` now serves `git-receive-pack` when the operator names a publishing
principal with `--receive-principal <principal-id-hex>`; without the flag the
compatibility default stands and the service is refused. The session
advertises through the canonical hidden-ref filter, finds the exact pack end
with a new incremental `fgit-pack::PackBoundaryScanner` (over a new framed
mode of the streaming inflater), and admits the verbatim captured request
through the existing authenticated durable receive boundary — quarantine,
validation, policy, and exact-predecessor head CAS unchanged, with
`report-status` derived only from authenticated terminal outcomes. An
identical retried push resolves to the same sealed transaction. The
`first_push.sh` e2e suite passes 21/21 with a stock `git` client, including
the refusal twin, a byte-identical re-clone, an idempotent retry, and an
incremental push.

### Fixed — serving closure now unions the verified decision history

Closure selection returned only the latest committed record's closure, so a
clone after an incremental push was missing every earlier decision's objects.
The materializer now unions closure roots along the verified head chain as a
derived serving projection (`ClosureSelectionSource::CumulativeHistory`);
canonical per-decision closures are unchanged and single-closure histories
behave byte-identically.

### Fixed — the 2026-08-31..09-02 agent-control stream builds and tests again

The toolchain-less implementation wave left the workspace unbuildable (an
oversized refusal enum failing its 128-byte const bound, missing derives,
shadowed test helpers, never-imported traits, a dead duplicate of the
incarnation-configuration family, and a non-exhaustive verified-read match
for the new V2_2 configuration schema, which now serves a typed refusal).
All repaired with the workspace green: 4,513 tests / 0 failures at
`66de074e`. The constitution lane still refuses fgit-agent's 23
`too_many_arguments` allows, tracked as the lint-debt drain bead.

### Added — descendant-head handoff acceptance

The Agent Control Plane can now accept one proof-carrying handoff at either the same authenticated repository head or a strictly later head proven to descend from the capsule's source head.

- Added `AgentHandoffCapsule::accept_at_descendant_head`, consuming the authority layer's bounded `AuthorityHeadAncestryReceipt`.
- Required exact agreement on repository, source head/generation, receiver head/generation, receiver backend version token, and full generation-distance hop count.
- Added `DescendantAuthenticatedHead` as a closed authority relation distinct from same-head acceptance.
- Bound receiver acceptance to the complete `IntentRunCommitment` retained by the receiver situation, refusing same-ID runs with changed authority read, scope, budget, or expiry before attenuation checks.
- Retained the exact ancestry receipt in the accepted value and its identity rather than validating the proof and dropping it.
- Added synchronous and asynchronous `accept_handoff_at_current_authority` drivers that authenticate the current `HeadKey`, prove ancestry, require the receiver to carry that exact current slot token, and immediately consume the proof.
- Versioned `AgentHandoffAcceptance` from v1 to v2 to commit the complete receiver run, authority relation, and optional ancestry receipt identity.

Focused source tests cover later-head refusal without ancestry, deterministic descendant acceptance, wrong-ancestor refusal, same-body cross-store token substitution, same-ID receiver-run substitution, atomic current-slot proof consumption, and synchronous/asynchronous parity.

Receiver acceptance remains distinct from durable task ownership transfer. The current task-persistence envelope has one authenticated-read basis for predecessor and successor; a cross-head transfer requires a future two-authority-basis envelope rather than removal of the existing exact-read check.

The focused contract is [`docs/AGENT_CONTROL_PLANE_HANDOFF_ANCESTRY.md`](docs/AGENT_CONTROL_PLANE_HANDOFF_ANCESTRY.md).

### Added — effect-time capability revocation and irreversible-dispatch gating

The `fgit-agent` effect boundary now includes:

- `CapabilityRevocationReadRequest` and `CapabilityRevocationReceipt`: bounded revocation evidence tied to one exact authenticated authority read, complete `IntentRunCommitment`, explicit maximum age, hard row limit, reader profile, generation commitment, and evidence root;
- `VerifiedCapabilityChain`: complete root-first capability ancestry authenticated through the existing MAC and attenuation verifier, with hard depth bounds and duplicate-identity refusal;
- `CapabilityEffectAuthorization`: one exact high-value effect authorization binding the run, authority read, chain, leaf, revocation receipt and generation, effect/parent IDs, operation, full resource cost, canonical input, authorization time, and exclusive deadline;
- `RevocationCheckedEffectBroker`: a public checked surface separating low-risk effects from operations that require current revocation evidence;
- `RevocationAuthorizedOutboxEffect`: a proof-carrying external-effect reservation that permits abort but exposes no raw dispatch method;
- `dispatch_authorized_outbox`: a second fresh authorization at the actual downstream-visible dispatch boundary, requiring the same verified chain and leaf used at request acceptance;
- `RevocationAuthorizedDeferredOutboxEffect`: a committed external obligation retaining both request-time and dispatch-time authorizations before ordinary reconciliation.

Revocation freshness uses the half-open interval:

```text
revocation_observed_at <= effect_time < valid_until
```

Use exactly at `valid_until` is stale. Revocation of any ancestor invalidates the leaf for a new high-value effect.

The checked external-effect path deliberately distinguishes request acceptance, typed outbox reservation, irreversible dispatch, and reconciliation. Every pre-dispatch refusal returns the live reservation; a post-commit journal failure retains the deferred obligation. Abort and reconciliation remain available after later revocation because they reduce outstanding responsibility.

The focused contract is [`docs/AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md`](docs/AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md).

### Fixed — complete-run effect identity

- Added `IntentRunCommitment` to every `EffectRecord`; the broker computes it before budget movement.
- Made effect-journal replay establish both numeric `RunId` and complete run commitment from its first accepted row, refusing mixed numeric or same-ID/different-commitment effects.
- Versioned `RunReconciliationReport` to v2 and committed the complete run in both the report header and every effect row.
- Refused same-ID effects from another authority read, operation scope, budget, or expiry before authority, lifecycle, operation, or resource interpretation.
- Versioned the public cancellation request/completion identities to v2 and required latest situation, active claim, initial report, final report, and supplied run to agree on one complete run commitment.
- Migrated handoff, receiver-acceptance, cancellation, and reconciliation fixtures to complete-run effect records.

### Added — effect-authorization source tests

Focused public-path source tests now cover:

- deterministic revocation receipt, chain, and exact-effect authorization identity;
- malformed reader profiles, row limits, duplicate revocations, and empty issuer keys;
- stale receipt use at the exclusive freshness deadline;
- revoked root or intermediate ancestry;
- same numeric run ID with changed machine scope;
- low-risk/high-value checked-broker separation;
- request-time proof expiry before external dispatch;
- revocation between reservation and dispatch;
- reservation recovery and abort after a dispatch refusal;
- successful fresh dispatch followed by stable-key acknowledgement reconciliation;
- complete-run identity in effect records;
- journal replay refusal across same-ID/different-commitment runs;
- complete-run reconciliation refusal;
- cancellation request and final-report substitution refusal.

Source-level test presence is not a test result.

### Identity revisions — effect authorization and handoff

The following identities changed deliberately rather than silently reinterpreting old bytes:

```text
RunReconciliationReport          v1 -> v2
public RunCancellationIntent     v1 -> v2
public RunCancellationCompletion v1 -> v2
AgentHandoffAcceptance           v1 -> v2
```

New identity families were added for revocation read requests/receipts, verified capability chains, exact effect authorizations, and authority-head ancestry receipts. Registered durable codecs and migrations remain future work. In particular, an old v1 handoff acceptance must never be interpreted as though it carried complete receiver-run or descendant-ancestry evidence.

### Added — task collection, persistence, and restart recovery

The `fgit-agent` task coordination tower now includes:

- `TaskProjectionCollectionRequest` and `TaskProjectionCollectionReceipt`: one bounded pre-situation read binding the exact authenticated authority event, complete Intent Run, current immutable task generation, canonical rows, adapter profile, and collection evidence;
- a task-projection `SituationComponent` produced from the same validated collection used by `WorkFrontier`, removing the former first-generation bootstrap circularity;
- `TaskProjectionMutationEnvelope`, complete semantic predecessor/successor reread reconciliation, and `TaskProjectionPersistenceReceipt`;
- the storage-neutral one-shot task-store protocol: authenticated read, at most one exact-predecessor CAS, explicit flush/no-op, authenticated reread, and typed success/conflict/reconciliation debt;
- persistence gates that validate the pulse/plan/run/task basis before store I/O and expose claim or cancellation projections only after the exact durable successor is confirmed;
- the compiled `task_collection_bridge` public surface for exact collected unassigned-row claim bases;
- `TaskLeaseHistoryObservation` and `TaskLeaseReconstructionReceipt` for reconstructing a claimed row only from collection-bound durable predecessor history;
- `RecoveredActiveTaskClaim`, which binds the reconstruction, original task claim receipt, and fresh activation under the same exact authenticated read event;
- `PersistedRecoveredTaskRelease`, which releases a recovered claim through the ordinary one-shot store protocol while retaining recovery and reconstruction identities through success, conflict, or ambiguity.

Claim and run expiry continue to prevent new work but do not prevent conservative responsibility cleanup. Recovered releases may return the task explicitly to `Open` or `Rework`.

The focused contracts are maintained in:

- [`docs/AGENT_CONTROL_PLANE_TASK_COORDINATION.md`](docs/AGENT_CONTROL_PLANE_TASK_COORDINATION.md);
- [`docs/AGENT_CONTROL_PLANE_TASK_RECOVERY.md`](docs/AGENT_CONTROL_PLANE_TASK_RECOVERY.md).

### Fixed — task recovery correctness and API boundaries

- Activated the already-landed collection bridge in `fgit-agent::lib`; its source and public-path test no longer sit outside the crate's compiled module graph.
- Refused conversion of a claimed collected row through the unassigned path instead of silently discarding assignment, plan, expiry, or reservation state.
- Required lease history to bind the exact collection receipt, task, and current generation before supplying the predecessor generation and original claim time omitted from the collected row.
- Revalidated collected assignee, plan, expiry, complete reservation surface, and `ReservedBy(assignee)` conflict state before reconstructing an active lease.
- Kept semantic task state independent from lease-history adapter/evidence identity while giving each evidenced reconstruction a distinct stable receipt.
- Required the original `TaskClaimReceipt` to match the reconstructed lease across task, plan, assignee, predecessor/current generations, reservation surface, claim time, and expiry.
- Required the reconstruction, refreshed situation, and supplied run to use the same exact authenticated read event; a later read of the same head and same numeric `RunId` is not interchangeable.
- Committed reconstruction and claim identities into restart-recovered active-claim identity rather than validating recovery evidence and then dropping it.
- Used the invoked task-store profile as the recovered release's adapter identity so the transition cannot be prepared under one backend profile and executed under another.
- Retained recovery identity in conflict and uncertain store outcomes instead of collapsing restart cleanup into an ordinary anonymous mutation envelope.
- Corrected a test-only attempt to forge `AgentChangePlanId` bytes; recovery fixtures now build a real situation, frontier, pulse, and plan.
- Corrected the recovery fixture's history so the plan is built against the predecessor generation before the claim, not against the already-claimed generation.
- Corrected the scripted store's initial reread time to occur after the cleanup request, matching the store protocol's anti-rollback rule.

### Added — authority-bound Agent Control Plane

The `fgit-agent` crate now contains a linked observe → plan → claim → act → reconcile → hand off/cancel → learn tower over the existing repository authority, capability, TreeFS, obligation, and evidence contracts.

Landed final-abstraction slices include:

- `AgentSituationReceipt`: one complete authenticated authority read, exact optional `IntentRun` and TreeFS workspace, a closed ten-component observed-or-omitted profile, deterministic identity, and anti-rollback `SituationDelta`;
- `WorkFrontier`: bounded deterministic task eligibility, typed exclusions, advisory ordering, and action-scoped verifier independence;
- `AgentControlPulse`: compact Level-0 per-turn state with exact situation/frontier/run binding and visible exclusion counts;
- `AgentChangePlan`: acceptance, context, intended/conflict surface, checkpoint, evidence, effect, budget, stop-condition, rejected-shortcut, non-claim, and approval contract;
- `TaskClaimReceipt` and `ActiveTaskClaim`: task-adapter mutation evidence bound to exact pre/post projection generations, plan, run, conflict surface, evidence, and expiry;
- `AgentActionPacket`: bounded Level-1 ordered steps with complete plan-approved context, plan-contained targets, evidence obligations, aggregate resource attenuation, peer-change commitments, mandatory preconditions, and result/refusal/continuation contracts;
- `ActiveClaimContinuityReceipt` and `AgentActionPacketContinuation`: proof that only logical time advanced while authority, run, workspace, and every situation component stayed unchanged, without mutating the original packet;
- `RunReconciliationReport`: complete run-level effect inventory, parent-graph and lifecycle validation, conserved consumable spend, and one typed remaining action per effect;
- public `AgentHandoffCapsule` and receiver-side `AgentHandoffAcceptance`: debt-preserving source handoff with attenuation, target-resolution evidence, exact activation or source continuity, same-head or proven-descendant receiver authority, complete receiver run, and inherited-effect responsibility;
- `accept_handoff_at_current_authority` and its async twin: one host operation that authenticates the current authority slot, proves bounded ancestry, checks the receiver's exact current token, and immediately consumes the proof;
- public `RunCancellationIntent` and `RunCancellationCompletion`: request → drain → finalize over a frozen effect set and active claim, with immutable effect identity, monotone evidence, explicit task release/transfer, escalation transfer, and leak containment; cancellation remains available after context change and may optionally retain a continuity receipt when only time advanced;
- `OutcomeLearningRecord`: immutable retrieval-only requirement, evidence, verifier-independence, ownership, failed-hypothesis, resource, reusable-pattern, applicability, invalidation, and negative-evidence record.

The exact current implementation boundary and module map are maintained in [`docs/AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`](docs/AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md).

### Fixed — Agent Control Plane correctness and API boundaries

- Removed the provisional duplicate `fgit-agent-control` package after the work-frontier implementation moved into its owning `fgit-agent` crate.
- Activated the deterministic frontier, Level-0 pulse, change plan, task claim, reconciliation, handoff, cancellation, Level-1 action packet, learning, and continuity modules only after their complete source/test slices were present.
- Scoped `independent_from` to verification work so a future independent verification gate cannot prevent the implementation run from implementing or reworking its own task.
- Required action packets to use the exact claim-activation situation unless an explicit continuity receipt proves that every context component is unchanged.
- Required action packets to retain every context packet admitted by the plan rather than silently execute from a partial subset.
- Revalidated the complete same-ID `IntentRun` machine scope and budget instead of trusting run identity alone.
- Bound action-packet identity to task ID and task-projection generation.
- Made the generic learning constructor crate-private and exposed only a plan-strict wrapper.
- Required every satisfied or partially satisfied plan line to carry at least one evidence record of the exact class named by the plan; `Observed` or `Inferred` evidence cannot substitute for required `Executed` evidence.
- Computed verifier independence from recorded workspace, credential, model/harness, context, oracle, sponsor, and human facts; no public self-declared independence flag exists.
- Required completed learning outcomes to retain complete requirement dispositions and refused hidden unsatisfied requirements.
- Kept learning ownership findings inside the plan surface and measured resource totals inside the plan budget.
- Preserved every accepted effect through reconciliation, handoff, and cancellation rather than reducing outstanding responsibility to prose or a count.
- Made the raw handoff capsule engine crate-private. The public facade now refuses a later source situation without a full-context continuity receipt and commits either exact activation or the receipt ID into the public capsule identity, which receiver acceptance inherits.
- Required later-head receiver acceptance to carry a bounded exact authority ancestry receipt rather than trusting generation comparison.
- Bound receiver acceptance to the complete `IntentRunCommitment` retained by its situation and exact current slot token when using the atomic host driver.
- Kept receiver acceptance separate from task ownership transfer; cross-head transfer remains blocked until a two-authority-basis persistence envelope exists.
- Made the raw cancellation engine crate-private behind a public identity-preserving facade. Cancellation completion commits the public request identity, so optional continuity evidence cannot be checked and then lost.
- Corrected an overstrict provisional cancellation rule during fresh review: handoff continues work and needs continuity, but cancellation is a conservative stop operation and must remain available after context change. Continuity is optional audit evidence for cancellation, never permission to stop.

### Added — focused source-level tests

Public-path tests now cover:

- situation identity, omissions, forks, rollback, and deltas;
- pre-situation task collection and exact-generation reread;
- frontier eligibility, exclusions, deterministic ordering, and action-scoped independence;
- pulse determinism, exclusion accounting, expiry, and substitution refusal;
- plan canonicalization, conflict coverage, budget attenuation, evidence, and authority boundaries;
- task-claim admission, activation, stale basis, conflict surface, lifetime, and overlap;
- deterministic task claim/release/transfer transitions and exact-read scope;
- complete-state mutation envelopes, store reconciliation, one-shot persistence, and post-effect debt;
- task collection bridging, lease-history reconstruction, claim recovery, and persisted restart cleanup;
- action-packet context completeness, exact activation continuity, same-ID scope revalidation, target containment, and budget bounds;
- time-only claim continuity, context-change refusal, claim expiry, and packet continuation;
- complete run-effect reconciliation, terminal markers, parent cycles, authority, and conserved spend;
- handoff exact-activation refusal, proof-carrying source construction, same-head and descendant receiver acceptance, ancestry retention, complete receiver-run binding, wrong-ancestor refusal, cross-store token refusal, and sync/async current-head parity;
- cancellation after changed context, optional continuity evidence, effect-set preservation, immutable effect identity, claim release, escalation transfer, and containment;
- learning determinism, evidence requirements, ownership containment, resource bounds, completed-outcome completeness, and machine-classified verifier independence.

Source-level test presence is not a test result.

### Documentation

- Reconciled [`docs/AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`](docs/AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md) with the actual owning modules and current non-claims.
- Reconciled [`docs/AGENT_CONTROL_PLANE_TASK_COORDINATION.md`](docs/AGENT_CONTROL_PLANE_TASK_COORDINATION.md) through collection, persistence, and restart recovery.
- Added [`docs/AGENT_CONTROL_PLANE_TASK_RECOVERY.md`](docs/AGENT_CONTROL_PLANE_TASK_RECOVERY.md).
- Added [`docs/AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md`](docs/AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md).
- Added [`docs/AGENT_CONTROL_PLANE_HANDOFF_ANCESTRY.md`](docs/AGENT_CONTROL_PLANE_HANDOFF_ANCESTRY.md).
- Added dated change records under `docs/changes/` for the Agent Control Plane evolution.
- Retained explicit Beads reconciliation handoffs instead of hand-editing the multi-megabyte `.beads/issues.jsonl` ledger from an environment without `br`.

### Verification state

The environment used for the latest handoff-ancestry commits did not contain a local FrankenGit checkout, Cargo, rustc, rustfmt, Clippy, `br`, or `bv`. No formatter, compiler, test, Clippy, repository verification, or independent batch result is claimed for these revisions.

Required local evidence remains at least:

```text
cargo fmt --all --check
cargo test -p fgit-authority --all-targets --no-fail-fast
cargo test -p fgit-agent --all-targets --no-fail-fast
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check --no-fail-fast
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

GitHub-hosted Actions availability or status is neither required nor used as evidence.

### Explicit non-claims

This wave does not claim:

- a cross-head two-authority-basis task-transfer mutation or persistence envelope;
- automatic receiver plan adoption or task ownership after descendant acceptance;
- concrete `br`/Beads collection, lease-history, mutation, flush, reread, or envelope-probe I/O;
- production collectors for the nine non-task situation components;
- multi-task transactions or distributed reservations;
- a production action-packet executor;
- automatic process, workspace, credential, secret, tunnel, upload, VM, or external-resource cleanup;
- plan-relative invalidation when a situation component changes;
- durable codecs, migrations, storage, or replay for all new control-plane values, including `AgentHandoffAcceptance` v2;
- an `fg agent` CLI, stable robot API, native API, or MCP surface;
- automatic ECC assembly, task verification/closure transition, or canonical publication;
- a durable authorization-filtered learning index;
- independent batch verification or Bead closure.

## 2026-08-24 through 2026-08-31 — implementation and one-node integration waves

FrankenGit advanced from specification into substantial safe-Rust vertical slices, including:

- canonical object and identity types for SHA-1/SHA-256 repositories;
- canonical bodies, transaction seals, intent/effect folding, decision batches, terminal outcomes, authenticated authority heads, and exact-predecessor CAS publication;
- bounded clean-room Git object, DEFLATE, pack/delta, pkt-line, upload-pack, receive-pack parsing, quarantine, admission, and authority-selected pack materialization;
- a narrow `fgit-cli`/`fg` one-node boundary for initialization, import, doctor, export, raw git-daemon upload-pack serving, and decision-addressed forge projection;
- TreeFS, object fabric, ATP-Git, RaptorQ repair, verified reads, forge events and merge computation, graph algorithms, evidence protocols, hostile-runner policy, recovery, and release-attempt slices;
- local and differential test campaigns recorded at their exact historical revisions.

These waves did not complete the full Git compatibility matrix, network push, smart HTTP, SSH, hosted API, projections, search, web UI, TUI, MCP, hostile-execution isolation, or release publication path.

## v3 — 2026-08-20 — FrankenSuite deep-synthesis architecture

The v3 architecture replaced the mutable repository/database split with one immutable repository decision stream plus one authenticated `RepositoryAuthorityHead` selected by conditional compare-and-swap.

It established the normative ATP-Git, TreeFS, CALM/obligation, graph, object-store, dependency/memory-safety, local-verification, repair, negative-evidence, and machine-validated registry framework that current implementation slices follow.

Architecture anchor: [`f3fe619`](https://github.com/Dicklesworthstone/frankengit/commit/f3fe619).

## v2 — 2026-08-19 — audited first-cut architecture

The exploratory plan was replaced with an audited architecture, normative protocol contracts, verification specification, threat model, RaptorQ constraints, agent protocol, licensing decision, and documentation-integrity machinery.

Representative anchors:

- [`5cb517c`](https://github.com/Dicklesworthstone/frankengit/commit/5cb517c) — audited architecture v2;
- [`78e4878`](https://github.com/Dicklesworthstone/frankengit/commit/78e4878) — normative protocol contracts;
- [`50d3b8b`](https://github.com/Dicklesworthstone/frankengit/commit/50d3b8b) — agent-native protocol with attenuated authority;
- [`41876cc`](https://github.com/Dicklesworthstone/frankengit/commit/41876cc) — source-available licensing text.

## v1 — 2026-08-19 — initial publication

The initial FrankenGit architecture and execution plan was published at [`1c05cf0`](https://github.com/Dicklesworthstone/frankengit/commit/1c05cf0) and superseded the same day by v2.

## Notes for agents

- Truth order when sources disagree: executable evidence → normative contracts → constitutions/registries → ADRs → comprehensive plan → summaries.
- Read `AGENTS.md` before a material change.
- Use the repository-owned local verification commands; do not encode unique correctness logic in hosted workflows.
- Update Beads through `br`; do not replace `.beads/issues.jsonl` by hand.
- Preserve rejected ideas and failed experiments in the negative-evidence ledger and registry.
- A source file, test case, closed Bead, local scenario, or confident summary is not by itself proof of a public claim.

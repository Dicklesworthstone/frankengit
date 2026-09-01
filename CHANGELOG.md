# Changelog

All notable FrankenGit changes are recorded here. This file is a summary, not a source of authority or verification. Exact behavior is governed by executable code, [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md), the constitutions and registries, and revision-bound evidence.

FrankenGit has moved beyond its original architecture-only phase into active implementation and pre-release integration. It is still not a general-purpose Git server, production-ready forge, or GitHub replacement.

## [Unreleased] — 2026-09-01

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
- public `AgentHandoffCapsule` and receiver-side `AgentHandoffAcceptance`: debt-preserving handoff with attenuation, target-resolution evidence, exact-head validation, and inherited-effect responsibility; exact-activation construction needs no extra proof, while a later observation requires and commits a specific `ActiveClaimContinuityReceipt`;
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
- Made the raw handoff capsule engine crate-private. The public facade now refuses a later situation without a full-context continuity receipt and commits either exact activation or the receipt ID into the public capsule identity, which receiver acceptance inherits.
- Made the raw cancellation engine crate-private behind a public identity-preserving facade. Cancellation completion commits the public request identity, so optional continuity evidence cannot be checked and then lost.
- Corrected an overstrict provisional cancellation rule during fresh review: handoff continues work and needs continuity, but cancellation is a conservative stop operation and must remain available after context change. Continuity is optional audit evidence for cancellation, never permission to stop.

### Added — focused source-level tests

Public-path tests now cover:

- situation identity, omissions, forks, rollback, and deltas;
- frontier eligibility, exclusions, deterministic ordering, and action-scoped independence;
- pulse determinism, exclusion accounting, expiry, and substitution refusal;
- plan canonicalization, conflict coverage, budget attenuation, evidence, and authority boundaries;
- task-claim admission, activation, stale basis, conflict surface, lifetime, and overlap;
- action-packet context completeness, exact activation continuity, same-ID scope revalidation, target containment, and budget bounds;
- time-only claim continuity, context-change refusal, claim expiry, and packet continuation;
- complete run-effect reconciliation, terminal markers, parent cycles, authority, and conserved spend;
- handoff exact-activation refusal, proof-carrying later construction, proof identity retention, attenuation, receiver verification, target resolution, and inherited effect debt;
- cancellation after changed context, optional continuity evidence, effect-set preservation, immutable effect identity, claim release, escalation transfer, and containment;
- learning determinism, evidence requirements, ownership containment, resource bounds, completed-outcome completeness, and machine-classified verifier independence.

Source-level test presence is not a test result.

### Documentation

- Reconciled [`docs/AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`](docs/AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md) with the actual owning modules and current non-claims.
- Added dated change records under `docs/changes/` for the Agent Control Plane evolution.
- Retained an explicit Beads reconciliation handoff instead of hand-editing the multi-megabyte `.beads/issues.jsonl` ledger from an environment without `br`.

### Verification state

The environment used for the latest Agent Control Plane commits did not contain a Rust toolchain or a locally accessible repository clone. No `cargo fmt`, build, test, clippy, repository verification, or independent batch result is claimed for these revisions.

Required local evidence remains at least:

```text
cargo fmt --all --check
cargo test -p fgit-agent --all-targets
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

GitHub-hosted Actions availability or status is neither required nor used as evidence.

### Explicit non-claims

This wave does not claim:

- production collectors for every situation component;
- a production Beads/task claim, release, transfer, or reservation adapter;
- a scheduler or action-packet executor;
- effect-time capability revocation against a named canonical position;
- plan-relative invalidation when a situation component changes;
- handoff acceptance at a later authority head without an authenticated ancestry witness;
- durable codecs, storage, replay, migration, or recovery for the new control-plane objects;
- an `fg agent` CLI, stable robot API, native API, or MCP surface;
- automatic ECC assembly, task verification transition, or canonical publication;
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
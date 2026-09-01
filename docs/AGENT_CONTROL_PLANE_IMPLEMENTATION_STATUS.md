# Agent Control Plane Implementation Status

**Status:** implementation ledger, not an authority source  
**Normative architecture:** [`AGENT_CONTROL_PLANE_ARCHITECTURE.md`](AGENT_CONTROL_PLANE_ARCHITECTURE.md)  
**Owning crate:** `crates/fgit-agent`  
**Last reconciled:** 2026-09-01  
**Verification state:** implementation and focused source-level tests are present; the environment used for the latest commits had no Rust toolchain or repository clone, so no revision-bound `cargo fmt`, build, test, clippy, or batch result is claimed

## Current executable tower

The owning crate now contains an authority-bound, retrieval- and effect-aware control tower:

```text
AuthorityReadReceipt + IntentRun
    -> AgentSituationReceipt
    -> WorkFrontier
    -> AgentControlPulse
    -> AgentChangePlan
    -> TaskClaimReceipt -> ActiveTaskClaim
    -> AgentActionPacket
       -> ActiveClaimContinuityReceipt
       -> AgentActionPacketContinuation
    -> RunReconciliationReport
       -> AgentHandoffCapsule -> AgentHandoffAcceptance
       -> RunCancellationIntent -> RunCancellationCompletion
    -> OutcomeLearningRecord
```

Every object above is inert unless its documentation says otherwise. Recommendations, packets, receipts, capsules, cancellation records, and learning records do not become repository authority, mint capability, mutate Beads, execute a tool, settle an obligation, or publish canonical state merely because they exist.

## Landed modules and boundaries

| Module | Landed final-abstraction slice | Explicit boundary |
|---|---|---|
| `protocol` | complete authenticated `AuthorityReadReceipt`; bounded `ContextPacket`; `WorkspaceBinding`; ordinary sealed-ref proposal bridge | no authority-head write, no automatic ECC assembly |
| `intent`, `capability`, `classes` | authenticated `IntentRun`; attenuation-only capabilities and operation classes | freshness is not revocation; no ambient authority |
| `broker` | effect acceptance, typed obligation binding, append-only in-process journal, external-effect reconciliation evidence | effect journal is not durable storage by itself |
| `ecc`, `refresh` | evidence classes, requirement dispositions, machine-classified verifier independence, typed refresh relations | partial ECC bundle only; no publication service |
| `situation` | closed ten-component `AgentSituationReceipt`; explicit omissions; deterministic identity; anti-rollback `SituationDelta` | no production collectors for the ten components |
| `frontier`, `frontier_policy` | bounded deterministic eligibility, typed exclusions, advisory ordering, action-scoped verifier independence | no scheduler, claim mutation, or reservation adapter |
| `pulse` | compact Level-0 per-turn view binding one situation and frontier; exact live-run recheck; visible exclusion counts | advisory selection only |
| `plan` | inert acceptance contract binding context, intended/conflict surfaces, checkpoints, evidence, effects, budget, stop conditions, rejected shortcuts, non-claims, and approval | no task claim or execution |
| `claim` | task-system mutation receipt bound to the exact plan, run, pre/post task generations, conflict surface, adapter identity, evidence, and expiry; activation only after refreshed observation | the adapter result is derived coordination evidence, not repository authority |
| `action_packet` | bounded Level-1 packet with exact claim-activation situation, complete plan-approved context, ordered plan-contained steps, evidence obligations, aggregate budget, peer roots, mandatory preconditions, and result/refusal/continuation contracts | no executor; no effect authority; later situations require an explicit continuity receipt |
| `claim_continuity` | proof that only logical observation time advanced while exact authority, run, workspace, and every situation component remained unchanged; packet-continuation binding with a precondition-recheck commitment | deliberately refuses every component change; no plan-relative invalidation analysis yet |
| `reconcile` | deterministic inventory of every effect in one run, typed remaining action, parent-graph validation, lifecycle checks, and conserved consumable spend | report is inert and performs no abort, probe, settlement, escalation resolution, or containment |
| private `handoff` engine + public handoff facade | canonical debt-preserving capsule body; public exact-activation constructor; later-observation constructor requiring and committing `ActiveClaimContinuityReceipt`; attenuation ceiling; complete evidence/non-claim/debt retention | capsule grants no authority; task transfer is not inferred |
| `handoff_acceptance` | receiver-side exact-head, operation, budget, expiry, target-resolution, and inherited-effect verification against the proof-carrying public capsule identity | no authority-history witness for acceptance at a later head |
| private `cancellation` engine + public cancellation facade | request → drain → finalize over the frozen effect set and active claim; immutable effect identity; monotone evidence; explicit task release/transfer; clean/debt-transferred/contained states; public identity retains optional continuity evidence | cancellation deliberately does not require context continuity, because changed context must not block a conservative stop; performs no task/process/workspace/effect mutation itself |
| `learning`, `outcome_learning` | immutable retrieval-only learning record with complete requirement outcomes, exact plan-required evidence classes, machine-classified verifier independence, ownership findings, failed hypotheses, measured resources, reusable patterns, applicability, invalidation, and negative evidence | no durable learning index; artifact identities are not resolved by this crate; learning grants no authority |

## Continuation and cancellation semantics

The control plane now makes the lifecycle asymmetry explicit:

- **Action packets and handoff continue work.** A packet is bound to the exact claim-activation situation. A handoff created at that situation needs no extra proof; a handoff at a later observation requires a validated `ActiveClaimContinuityReceipt`. The public capsule identity commits the receipt ID. The older raw capsule builder is crate-private, so callers cannot validate continuity and then discard it or call around it.
- **Cancellation stops work.** A cancellation request binds the exact latest `AgentSituationReceipt`, active claim when present, and complete `RunReconciliationReport`. It remains available after peer, search, conflict, evidence, capability, obligation, registry, graph, or other context change. When only logical time advanced, callers may attach a continuity receipt as stronger audit evidence; its ID is committed into the public cancellation request and therefore into completion. Absence of continuity never blocks draining responsibility.

Comparing only task generation remains rejected for plan continuation or handoff. An unchanged task row does not prove that the rest of the plan context remained applicable.

## Focused source tests present

The current tree contains public-path tests for:

- authenticated situation identities, omissions, forks, rollback, and deltas;
- frontier eligibility, exclusions, action-scoped independence, and deterministic ranking;
- Level-0 pulse identity, exclusion accounting, expired/substituted runs, and cross-situation substitution;
- plan canonicalization, conflict-surface coverage, budget attenuation, independent evidence, and mixed-authority context;
- task-claim admission, activation, stale generation, conflict surface, lifetime, and overlap;
- Level-1 action packets, complete context retention, exact activation-situation continuity, same-ID run-scope revalidation, target containment, and aggregate budgets;
- time-only active-claim continuity, component-change refusal, expiry, and action-packet continuation;
- complete run-effect reconciliation, terminal markers, parent cycles, authority, and consumable-budget conservation;
- exact-activation and proof-carrying later handoff, proof identity retention, debt preservation, attenuation, receiver acceptance, target resolution, and inherited effect scope;
- cancellation after changed context, optional continuity evidence, effect-set preservation, immutable effect identity, explicit claim release, escalation transfer, and containment requirements;
- outcome-learning determinism, evidence requirements, completed-outcome completeness, ownership containment, resource bounds, and computed verifier independence.

Test source is not a test result. No command outcome is attached to the latest revisions by this ledger.

## Deliberately absent product surfaces

The landed library slices do not implement or imply:

- production collectors for all ten situation components;
- a Beads/task adapter that claims, releases, transfers, reserves, or updates task state;
- a scheduler or multi-agent reservation service;
- a production action-packet executor connecting steps to TreeFS, sandboxing, capabilities, the effect broker, and evidence services;
- effect-time capability revocation against a named canonical position;
- an authenticated authority-history witness allowing handoff acceptance on a later head;
- plan-relative invalidation across changed situation components;
- registered durable codecs, migrations, storage, replay, or recovery for the new control-plane objects;
- a stable robot JSON/NDJSON command, `fg agent` CLI, native API, or MCP surface;
- automatic requirement-to-artifact resolution, ECC assembly, task verification transition, or canonical publication;
- a durable, authorization-filtered learning and negative-evidence index;
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

1. run and repair the local formatter/compiler/test/clippy gates for every newly activated module;
2. implement the production task-projection and claim/release/transfer adapter through typed receipts;
3. build the action-packet executor over real capabilities, TreeFS, the effect broker, obligations, sandboxing, and evidence outputs;
4. define registered canonical codecs plus durable append/recovery for control-plane records;
5. expose stable bounded robot-mode results through `fg agent`, native API, and MCP adapters generated from the same typed results;
6. assemble complete ECCs and task-verification transitions through ordinary publication authority;
7. add the authorization-filtered learning index and measure repeated retrieval/check cost avoided;
8. add authenticated authority-history witnesses for later-head handoff acceptance and plan-relative invalidation witnesses for selected component changes;
9. submit the exact revision to the independent batch verifier and update Beads only through `br`.

The active repository priority outside this slice remains the current Beads dependency graph and authenticated repository state, not this status document.
# 2026-09-01: Agent Control Plane act, learn, and lifecycle continuity

## Scope

This change wave extends the authority-bound Agent Control Plane from observation, selection, planning, and task activation into five linked final-abstraction slices:

1. a bounded Level-1 action packet;
2. evidence-grounded outcome learning;
3. explicit time-only active-claim and packet continuity;
4. proof-carrying handoff construction;
5. cancellation that remains available after context invalidation while retaining optional continuity evidence.

All five remain derived control evidence. None is repository authority, a capability grant, a task-system mutation, an effect executor, or canonical publication.

## Revision sequence

| Revision | Change |
|---|---|
| `72a9160d` | close action-packet continuity, context-completeness, run-scope, task, and generation gaps |
| `2378bb34` | add public-path action-packet success and refusal tests |
| `b5933a65` | activate and re-export the Level-1 action-packet surface |
| `a23125a0` | add the evidence-grounded learning core |
| `78ac0bc9` | add public-path learning success and epistemic-refusal tests |
| `5997e8d2` | activate the initial learning surface |
| `4dc1d58d` | add the public plan-strict learning wrapper |
| `477408af` | simplify and pin the exact evidence-class guard |
| `16b51ce3` | make the strict wrapper the only public learning constructor |
| `c8a29a12` | add active-claim and packet-continuity receipts |
| `207bbb67` | add public-path continuity success, component-change, time, and expiry tests |
| `c3ac9e32` | activate the continuity surfaces |
| `884e7475` | reconcile the implementation-status ledger |
| `ec0c74a9` | replace the obsolete architecture-only changelog framing |
| `4b083d09` | add the first revision-linked change record |
| `63e9489f` | add the non-authoritative Beads verification handoff |
| `bc5cfc41` | preserve deterministic structural refusals before strict evidence-class enforcement |
| `36e64f71` | add the proof-carrying public handoff facade |
| `990016ce` | add the first proof-carrying public cancellation facade |
| `5ac024eb` | make raw handoff/cancellation engines crate-private and expose only strict facades |
| `65a69399` | add public lifecycle-continuity integration tests |
| `b9ffc200` | remove an unused integration-test import under warnings-as-errors policy |
| `82fd0c9d` | correct cancellation so changed context never blocks a conservative stop |
| `a91ab980` | update lifecycle tests for changed-context cancellation and optional continuity |
| `9d5ab061` | reconcile crate-level continuation-versus-cancellation semantics |
| `d6b8cdc6` | pin the exact changed-component refusal in tests |
| `f6c8e2c7` | reconcile the implementation-status ledger through lifecycle continuity |
| `a5f56a48` | reconcile the changelog through lifecycle continuity |
| `cf9ad1f5` | add the focused lifecycle-continuity design contract |

The full commit IDs remain in git history. Short IDs above are navigation aids, not verification evidence.

## Level-1 action packet

`crates/fgit-agent/src/action_packet.rs` binds one concrete action sequence to:

- the exact situation that activated the task claim;
- the exact task-projection generation and task ID;
- the complete live `IntentRun`, not only its ID;
- the complete context-packet set admitted by the plan;
- ordered nonzero step identities;
- operation classes contained by both plan and run;
- exact targets inside the plan's intended change surface;
- input and expected-output commitments;
- per-step and aggregate resource ceilings;
- plan evidence requirement identities;
- canonical peer-change commitments;
- all mandatory action preconditions;
- expected result, typed refusal, continuation, and executor-profile commitments.

The packet performs no work. The future executor must acquire ordinary capability/effect grants, reserve typed obligations, and record outcomes through the existing broker.

### Rejected shortcut: “any observed task projection is current enough”

The first provisional packet accepted a later situation whenever its task component was merely present. That was unsound: a changed peer, conflict, capability, obligation, evidence, registry, graph, or search generation could invalidate the plan while the task row remained present.

The public packet therefore accepts only the exact claim-activation situation. Later use requires a separate continuity proof.

### Rejected shortcut: partial planned context

The packet refuses omission of any `ContextPacketId` admitted by the plan. A plan cannot be justified using one context set and executed using a quietly smaller one.

### Rejected shortcut: Run ID as scope

A caller may reconstruct an `IntentRun` using the same `RunId`. The packet revalidates the complete operation set, resource budget, authority receipt, and expiry; identity alone does not authorize the plan.

## Evidence-grounded outcome learning

`crates/fgit-agent/src/learning.rs` owns canonicalization and the immutable record body. `crates/fgit-agent/src/outcome_learning.rs` is the only public construction boundary.

A record binds:

- exact situation, action packet, plan, run, and task identities;
- a typed terminal outcome;
- complete plan-requirement dispositions;
- claim-supporting evidence records;
- verifier identities and recorded independence facts;
- evidence-backed ownership findings inside the plan surface;
- failed hypotheses with discriminating evidence, applicability, and invalidation conditions;
- measured phase resource observations conserved under the plan budget;
- reusable patterns with applicability, invalidation, expected savings, and evidence;
- explicit negative-evidence references.

### Exact evidence-class enforcement

A satisfied or partially satisfied requirement must carry at least one evidence record of the exact class named by `PlanEvidenceRequirement`.

```text
required = Executed
supplied = Observed
result   = typed refusal
```

Other supporting classes may accompany the required record, but cannot replace it. The generic internal constructor is crate-private so callers cannot bypass this plan-relative check through a raw module path.

The public wrapper first runs the internal builder's fixed structural refusal order and canonicalization. Exact-class enforcement runs only on that canonical requirement matrix. Duplicate, mismatched, or incomplete requirement rows therefore retain the same core refusal regardless of caller row order; a structurally valid record still cannot become public with a weaker evidence class.

### Completed outcomes

`Completed` is refused when any applicable plan requirement remains partially satisfied, blocked, or unsatisfied. `NotApplicable` remains representable because a complete requirement matrix must distinguish inapplicability from disappearance.

### Verifier independence

No self-declared independence field exists. Independence is recomputed from recorded workspace, credential, model/harness, context, oracle, sponsor, and human identities. Missing facts fail closed.

### Retrieval-only boundary

A learning record may improve retrieval or planning only when its applicability and invalidation conditions match. It cannot grant capability, change task status, suppress a required check, authorize publication, become repository truth, or prove that a referenced artifact exists without the future evidence resolver.

## Active-claim continuity

`ActiveClaimContinuityReceipt` proves the narrow case in which only logical observation time advances after task activation.

The receipt requires:

- the exact activation situation named by `ActiveTaskClaim`;
- the same complete authenticated authority receipt;
- the same `IntentRun`;
- the same workspace binding;
- no change to any of the ten situation components;
- strictly advancing logical time;
- a live claim and run at the later observation;
- an observed, unchanged task-projection generation.

Any component change is a typed refusal. The receipt deliberately does not attempt plan-relative invalidation analysis.

`AgentActionPacketContinuation` binds this proof to the immutable original packet and carries the original packet identity, continuity identity, source/later situations, plan, claim, task, run, task generation, original continuation contract, and a fresh commitment proving mandatory packet preconditions were rechecked. It does not rewrite or clone the packet body.

## Proof-carrying handoff

Handoff continues the plan attempt. The public API therefore exposes:

```text
AgentHandoffCapsule::build(activation_situation, ...)
AgentHandoffCapsule::build_with_continuity(later_situation, continuity, ...)
```

The first constructor refuses a situation other than the one retained by `ActiveTaskClaim`. The second revalidates the full-context receipt against the claim, later situation, and complete run.

The public capsule identity commits the crate-private canonical capsule identity plus the exact-activation/continuity choice and continuity receipt ID when present. Receiver acceptance binds this public identity, so source continuity evidence cannot be checked and then discarded before transfer.

The raw capsule engine is crate-private. A caller cannot bypass the strict facade through a parallel public constructor.

## Cancellation remains a stop path

The first provisional facade copied handoff's exact-activation-or-continuity rule onto cancellation. Fresh review rejected that model.

Handoff and action execution continue work, so changed context invalidates permission to proceed. Cancellation reduces work and must remain available precisely when peer, conflict, capability, obligation, evidence, registry, graph, search, or other context changed.

The final public API therefore exposes:

```text
RunCancellationIntent::request(latest_situation, ...)
RunCancellationIntent::request_with_continuity(later_situation, continuity, ...)
```

`request` binds the exact latest situation, active claim when present, and complete reconciliation report observed at the same logical time. It does not require context equivalence.

`request_with_continuity` optionally retains stronger evidence when only logical time advanced. The public request identity commits the continuity receipt ID. Completion commits the public request ID, so optional evidence survives into terminal identity.

The crate-private engine continues to enforce frozen effect membership, immutable accepted-effect identity, legal lifecycle progress, monotone evidence and charged resources, explicit task release/transfer, no unresolved automatic work at completion, named escalation transfer, and explicit leak containment.

## Focused test source added

Public-path tests cover:

- deterministic action-packet identity and complete bindings;
- later action use refusal without continuity;
- missing planned context;
- same-ID run-scope substitution;
- operation and budget amplification;
- deterministic outcome-learning canonicalization;
- unsupported completion without evidence;
- completed outcomes with unmet requirements;
- ownership and resource containment;
- computed verifier independence;
- deterministic time-only claim continuity;
- non-task component-change refusal;
- non-advancing time and claim expiry;
- packet-continuation binding;
- later handoff refusal without continuity;
- deterministic proof-carrying handoff identity;
- changed-context cancellation remaining available;
- optional cancellation continuity producing a distinct proof-bearing identity;
- clean completion with explicit task release.

## Verification state

The implementation environment did not contain a Rust toolchain or a locally accessible repository clone. No formatter, compiler, test, clippy, repository verification, or batch result is claimed for these revisions.

Source and tests require revision-bound execution of at least:

```text
cargo fmt --all --check
cargo test -p fgit-agent --all-targets
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

GitHub-hosted Actions status is not required and was not used.

## Additional non-claims

This wave does not implement:

- production situation collectors;
- a Beads claim/release/transfer/reservation adapter;
- a scheduler or executor;
- effect-time revocation;
- authority-history proofs for handoff acceptance at a later head;
- plan-relative invalidation across selected component changes;
- durable codecs, storage, replay, or migration;
- stable robot JSON/NDJSON, CLI, native API, or MCP transport;
- automatic ECC assembly or canonical publication;
- a durable learning index;
- independent batch verification or Bead closure.

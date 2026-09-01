# Agent Control Plane Lifecycle Continuity

**Status:** companion design and implementation rationale; not repository authority  
**Owning architecture:** [`AGENT_CONTROL_PLANE_ARCHITECTURE.md`](AGENT_CONTROL_PLANE_ARCHITECTURE.md)  
**Implementation ledger:** [`AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`](AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md)  
**Owning crate:** `crates/fgit-agent`

## 1. Purpose

The Agent Control Plane has three superficially similar operations after a task claim becomes active:

1. continue executing the same plan;
2. hand the plan and its unresolved responsibility to another run;
3. stop the run and drain or transfer every responsibility.

They must not share one vague “latest situation is close enough” predicate. The safety direction is different:

- execution and handoff **continue** work, so stale context can authorize the wrong action;
- cancellation **reduces** work, so context change must not make the stop path unavailable.

This document fixes that distinction as a reusable contract for public APIs, codecs, adapters, recovery, and review surfaces.

## 2. Objects

```text
TaskClaimReceipt
    -> ActiveTaskClaim
       -> exact activation AgentSituationReceipt
       -> ActiveClaimContinuityReceipt?

AgentActionPacket
    -> AgentActionPacketContinuation

AgentHandoffCapsule
    -> AgentHandoffAcceptance

RunCancellationIntent
    -> RunCancellationCompletion
```

`ActiveTaskClaim` retains the situation identity at which its post-claim task generation was observed. `ActiveClaimContinuityReceipt` may relate that activation situation to a later situation only when the complete context is unchanged and logical time strictly advances.

## 3. Full-context continuity

A valid `ActiveClaimContinuityReceipt` requires:

- the receipt's source situation is the situation retained by `ActiveTaskClaim`;
- source and later situations use the same complete authenticated authority receipt;
- both situations name the same `IntentRun`;
- workspace identity and manifest commitment are unchanged;
- every one of the ten closed situation components is unchanged;
- observation time strictly advances;
- the claim remains live at the later observation;
- the run remains live at the later observation;
- the task projection remains observed and names the same generation.

The component comparison is deliberately complete. An unchanged task row does not prove that peer reservations, conflict state, capabilities, obligations, evidence, policy registries, graph/search generations, workspace state, or another control input stayed applicable.

## 4. Continuing an action packet

`AgentActionPacket` is built only from the exact claim-activation situation. A later observation does not rewrite the packet.

`AgentActionPacketContinuation` instead commits:

- the immutable original packet identity;
- the exact continuity-receipt identity;
- source and later situation identities;
- plan, claim, task, run, and task-generation identities;
- the packet's original continuation contract;
- a fresh commitment that all mandatory effect-time preconditions were rechecked.

The continuation receipt grants no authority. The executor must still acquire ordinary capabilities, reserve obligations, and pass the effect broker at execution time.

## 5. Handoff continues work

Handoff preserves the plan attempt, unresolved questions, failed approaches, evidence state, workspace state, outstanding effect debt, proposed receiver attenuation, and requested next actions. It is therefore a continuation operation.

The public `AgentHandoffCapsule` API exposes exactly two constructors:

```text
build(activation_situation, ...)
build_with_continuity(later_situation, continuity_receipt, ...)
```

`build` refuses any situation other than the one retained by `ActiveTaskClaim`.

`build_with_continuity` revalidates the receipt against the claim, later situation, and complete run. The public capsule identity commits:

```text
canonical_inner_capsule_id
+ exact_activation_or_continuity_tag
+ continuity_receipt_id?
```

The lower-level canonicalization engine is crate-private. External callers cannot validate continuity, discard the receipt, and then call a raw builder whose identity omits the proof.

Receiver acceptance binds the public capsule identity. It therefore inherits the source continuity commitment while independently verifying repository identity, authenticated head, receiver run, operation scope, budget, expiry, target resolution, and every carried effect responsibility.

## 6. Cancellation stops work

Cancellation is not plan continuation. It freezes the latest known situation, active claim when present, and complete run-level effect inventory so the system can:

```text
request stop
    -> cease new work
    -> abort reservations
    -> reconcile committed/deferred effects
    -> release or transfer the task claim
    -> transfer named escalation debt
    -> contain recorded leaks
    -> finalize
```

Requiring context equivalence before requesting cancellation would be unsafe. A conflict, peer change, capability change, obligation change, evidence failure, policy change, or other invalidation can be the reason to stop. The stop path must remain available under those conditions.

The public `RunCancellationIntent` API therefore provides:

```text
request(latest_situation, ...)
request_with_continuity(later_situation, continuity_receipt, ...)
```

`request` requires the exact latest authority-bound situation and a reconciliation report observed at the same logical time. It does not require continuity.

`request_with_continuity` is optional stronger audit evidence for the case in which only logical time advanced. The public request identity commits the continuity receipt ID, and the public completion identity commits the public request ID. Optional evidence cannot be checked and then disappear from the terminal record.

The lower-level cancellation engine is crate-private. It still enforces:

- exact run and authority basis;
- frozen effect membership;
- immutable accepted-effect identity;
- legal obligation-state progress;
- monotone output and reconciliation evidence;
- nondecreasing consumed-resource accounting;
- explicit task release or transfer;
- no unresolved reservation or committed-effect automation at completion;
- named transfer evidence for escalated debt;
- explicit containment evidence for leaks;
- distinct `Clean`, `DebtTransferred`, and `Contained` outcomes.

## 7. Identity and replay rules

The proof-carrying public IDs are separate domains from their private canonicalization engines:

```text
public_handoff_id = H(domain, inner_capsule_id, continuity_id?)
public_cancel_id  = H(domain, inner_cancel_id, continuity_id?)
public_done_id    = H(domain, public_cancel_id, inner_completion_id)
```

Consequences:

- the same canonical body with and without continuity evidence has different public identity;
- retry with identical inputs is deterministic;
- a receiver or auditor can require the exact evidence-bearing identity;
- completion cannot erase which cancellation request it finalized;
- private engine IDs remain useful internal canonicalization facts but are not public lifecycle identities.

Durable codecs must preserve these domain separations and reject unknown or duplicated proof fields. Migration must never reinterpret a private engine ID as a public proof-carrying ID.

## 8. Refused shortcuts

The following are explicitly rejected:

- treating an unchanged task generation as full plan continuity;
- accepting a later handoff because the claim is merely unexpired;
- validating a continuity receipt and omitting its identity from the capsule;
- exposing the raw handoff builder beside the strict facade;
- requiring continuity before cancellation can begin;
- treating disconnect, task unassignment, or process exit as completed cancellation;
- summarizing outstanding effects as a count without retaining complete effect identities and required actions;
- reporting escalation as clean settlement without a named transfer receipt;
- reporting a leak as contained without explicit containment evidence.

## 9. Product-adapter obligations

A production task adapter must return typed claim, release, and transfer projections whose generation transition and evidence can be checked against these objects. It must not infer success from a human-readable tracker response.

A production executor must:

- recheck action-packet preconditions before each consequential step;
- stop admission immediately after cancellation request;
- preserve ambiguous external outcomes until reconciliation resolves them;
- keep cancellation available even when plan continuation fails;
- attach the exact public handoff/cancellation identity to logs, evidence, and recovery records;
- never mint receiver capability from a handoff capsule.

A robot/API/MCP surface must render exact IDs and typed refusal variants. Prose may explain the state but cannot replace the machine contract.

## 10. Verification obligations

Source-level tests should cover at least:

- exact-activation handoff success;
- later handoff refusal without continuity;
- deterministic later handoff with continuity;
- continuity identity retained by receiver acceptance;
- changed non-task component refusing continuity;
- changed context still permitting cancellation request;
- optional cancellation continuity producing a distinct public identity;
- completion binding the public request identity;
- frozen effect-set and immutable-effect checks;
- explicit task release/transfer;
- escalation transfer and leak containment evidence.

Revision-bound verification still requires the repository-owned formatter, test, clippy, registry, docs, constitution, and fast lanes. Test source, this document, a Bead transition, or hosted workflow state is not verification evidence.

## 11. Remaining boundaries

This slice does not provide:

- production situation collectors;
- the Beads/task mutation adapter;
- the action-packet executor;
- effect-time capability revocation;
- an authenticated authority-history witness for receiver acceptance at a later head;
- plan-relative continuation after selected component changes;
- durable codecs, storage, replay, migration, or crash recovery;
- stable robot/CLI/native/MCP transport;
- automatic ECC assembly or canonical publication;
- independent batch-verifier closure.

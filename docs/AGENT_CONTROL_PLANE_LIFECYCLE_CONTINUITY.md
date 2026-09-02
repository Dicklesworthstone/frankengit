# Agent Control Plane Lifecycle Continuity

**Status:** companion design and implementation rationale; not repository authority  
**Owning architecture:** [`AGENT_CONTROL_PLANE_ARCHITECTURE.md`](AGENT_CONTROL_PLANE_ARCHITECTURE.md)  
**Implementation ledger:** [`AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`](AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md)  
**Effect authorization:** [`AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md`](AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md)  
**Handoff ancestry:** [`AGENT_CONTROL_PLANE_HANDOFF_ANCESTRY.md`](AGENT_CONTROL_PLANE_HANDOFF_ANCESTRY.md)  
**Owning crate:** `crates/fgit-agent`

## 1. Purpose

The Agent Control Plane has four related but directionally different operations after a task claim becomes active:

1. continue executing the same plan;
2. hand the plan and unresolved responsibility to another run;
3. start a new high-value effect or irreversible external dispatch;
4. stop the run and drain, reconcile, or transfer every responsibility.

They must not share one vague “latest situation is close enough” predicate. The safety direction differs:

- execution and handoff **continue** plan work, so stale context can authorize the wrong action;
- a high-value effect creates new consequential responsibility, so capability revocation must be current at the effect boundary;
- cancellation, abort, and reconciliation **reduce** responsibility, so invalidation must not make cleanup unavailable.

Handoff also contains two independent continuity questions:

```text
source continuity
    -> did the source capsule preserve one still-applicable plan attempt?

receiver authority ancestry
    -> does the receiver's current authenticated head descend from the
       historical head named by that capsule?
```

One proof cannot substitute for the other. Full-context continuity does not prove a later authority head descends from the source, and an authority ancestry proof does not prove that every source-plan assumption remains unchanged.

This document fixes those distinctions as reusable contracts for public APIs, codecs, adapters, recovery, and review surfaces.

## 2. Objects

```text
TaskClaimReceipt
    -> ActiveTaskClaim
       -> exact activation AgentSituationReceipt
       -> ActiveClaimContinuityReceipt?

AgentActionPacket
    -> AgentActionPacketContinuation

VerifiedCapabilityChain
    + CapabilityRevocationReceipt
    + exact EffectRequest
    -> CapabilityEffectAuthorization
    -> RevocationAuthorizedOutboxEffect
    -> fresh dispatch-time authorization

AgentHandoffCapsule
    + receiver AgentSituationReceipt / IntentRun
    + AuthorityHeadAncestryReceipt?
    -> AgentHandoffAcceptance v2

current authority HeadKey
    -> bounded exact predecessor walk
    -> accept_handoff_at_current_authority[_async]
    -> AgentHandoffAcceptance v2

RunCancellationIntent
    -> RunCancellationCompletion
```

`ActiveTaskClaim` retains the situation identity and complete run identity at which its post-claim generation was observed. `ActiveClaimContinuityReceipt` may relate that activation situation to a later source situation only when the complete context is unchanged and logical time strictly advances.

`AuthorityHeadAncestryReceipt` answers a different question. It binds an exact historical source head to the exact current descendant slot, including repository, identities, generations, complete predecessor-path commitment, hop count, and current backend version token.

Capability-effect authorization is separate again. An unchanged situation or valid head path does not prove that a capability remains unrevoked throughout a later effect or dispatch window. The service performing the effect requires exact-position revocation evidence at the actual consequential boundary.

## 3. Full-context source continuity

A valid `ActiveClaimContinuityReceipt` requires:

- the receipt's source situation is the situation retained by `ActiveTaskClaim`;
- source and later situations use the same complete authenticated authority receipt;
- both situations name the same complete `IntentRunCommitment`, not merely the same `RunId`;
- workspace identity and manifest commitment are unchanged;
- every one of the ten closed situation components is unchanged;
- observation time strictly advances;
- the claim remains live at the later observation;
- the run remains live at the later observation;
- the task projection remains observed and names the same generation.

The component comparison is deliberately complete. An unchanged task row does not prove that peer reservations, conflicts, capabilities, obligations, evidence, policy registries, graph/search generations, workspace state, or another control input stayed applicable.

## 4. Continuing an action packet

`AgentActionPacket` is built only from the exact claim-activation situation. A later observation does not rewrite the packet.

`AgentActionPacketContinuation` instead commits:

- the immutable original packet identity;
- the exact continuity-receipt identity;
- source and later situation identities;
- plan, claim, task, complete run, and task-generation identities;
- the packet's original continuation contract;
- a fresh commitment that all mandatory effect-time preconditions were rechecked.

The continuation receipt grants no authority. The executor must still acquire ordinary capabilities, reserve obligations, and pass current effect authorization when the selected operation requires revocation freshness.

## 5. Handoff continues work

Handoff preserves the plan attempt, unresolved questions, failed approaches, evidence state, workspace state, outstanding effect debt, proposed receiver attenuation, and requested next actions. It is therefore a continuation operation at the source boundary.

### 5.1 Source capsule construction

The public `AgentHandoffCapsule` API exposes exactly two constructors:

```text
build(activation_situation, ...)
build_with_continuity(later_source_situation, continuity_receipt, ...)
```

`build` refuses any source situation other than the one retained by `ActiveTaskClaim`.

`build_with_continuity` revalidates the receipt against the claim, later source situation, and complete source run. The public capsule identity commits:

```text
canonical_inner_capsule_id
+ exact_activation_or_continuity_tag
+ continuity_receipt_id?
```

The lower-level canonicalization engine is crate-private. External callers cannot validate continuity, discard the receipt, and then call a raw builder whose identity omits the proof.

### 5.2 Receiver authority relationship

Receiver acceptance now recognizes two closed authority relationships:

```text
SameAuthenticatedHead
DescendantAuthenticatedHead
```

Same-head acceptance requires source and receiver to name the same repository head identity and generation.

Descendant acceptance requires an `AuthorityHeadAncestryReceipt` produced by the bounded authority walk. The receipt must match:

- source repository, head identity, and generation from the capsule;
- receiver repository, head identity, and generation from the receiver run;
- the receiver's exact backend version token;
- the complete generation distance as its hop count.

A numerically later generation is not ancestry. A proof for another ancestor, descendant, slot, store, repository, or token is refused.

### 5.3 Complete receiver run

Acceptance recomputes the receiver's `IntentRunCommitment` and requires the receiver situation to retain the same value. Numeric `RunId` equality is insufficient.

The accepted value retains:

```text
receiver RunId
receiver IntentRunCommitment
authority relation
optional AuthorityHeadAncestryReceipt
```

It independently verifies operation scope, resource budget, expiry, target-resolution evidence, and every inherited effect responsibility.

### 5.4 Atomic current-head host driver

A host should not separately prove ancestry against one current slot and later pair that proof with a receiver read from another slot or store.

The sync and async drivers instead perform:

```text
read + authenticate current HeadKey
    -> bounded predecessor walk to capsule source
    -> require receiver head/generation/token == exact current read
    -> immediately consume same-head or descendant proof
```

The public functions are:

```text
accept_handoff_at_current_authority(...)
accept_handoff_at_current_authority_async(...)
```

A byte-identical current head obtained from another store still has another version token and is refused before acceptance.

Handoff acceptance does not itself authorize a new effect. The receiver still needs its own current capability chain and revocation evidence at each high-value effect boundary.

### 5.5 Acceptance is not cross-head task transfer

The current task mutation and persistence envelope uses one authenticated-read basis for both predecessor and successor. Simply deleting that equality check after proving ancestry would create a durable write that cannot prove which authority basis governed each side.

A future descendant-head task-transfer protocol must carry both source and receiver authority receipts, the accepted ancestry receipt, exact predecessor and successor task states, one-shot CAS/flush/reread evidence, source cancellation evidence, and receiver post-transfer activation. Until then, descendant acceptance validates review, responsibility, and receiver scope without pretending durable task assignment moved.

## 6. High-value effects need current revocation evidence

Full-context continuity, authority ancestry, and capability revocation answer different questions:

```text
continuity receipt
    -> is this source plan context unchanged?

authority ancestry receipt
    -> does this exact current receiver head descend from the capsule head?

revocation receipt
    -> is this authenticated capability ancestry currently usable
       at this named repository position and logical instant?
```

`CapabilityEffectAuthorization` requires:

- one complete verified capability chain;
- one exact authenticated-position revocation receipt;
- one complete Intent Run;
- one exact effect request;
- an effect instant inside the run, leaf capability, and revocation freshness windows;
- no revoked capability ID anywhere in the ancestry.

Freshness is half-open:

```text
revocation_observed_at <= effect_time < valid_until
```

Use at `valid_until` is stale.

### 6.1 Request and dispatch are distinct

For an external effect:

```text
request accepted
-> budget reserved
-> outbox obligation reserved
-> downstream-visible dispatch
-> reconciliation
```

A request-time proof may expire before dispatch. The checked broker therefore returns a proof-carrying outbox reservation with no raw dispatch method. Actual dispatch constructs a new authorization for the retained exact request at the dispatch instant and requires the same chain and leaf used at acceptance.

A stale or newly revoked proof returns the still-live reservation. A post-commit journal failure retains the deferred obligation.

## 7. Cancellation stops work

Cancellation is not plan continuation. It freezes the latest known situation, active claim when present, complete run identity, and complete run-level effect inventory so the system can:

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

Requiring context equivalence before requesting cancellation would be unsafe. A conflict, peer change, capability revocation, obligation change, evidence failure, policy change, or other invalidation can be the reason to stop. The stop path must remain available under those conditions.

The public `RunCancellationIntent` API therefore provides:

```text
request(latest_situation, ...)
request_with_continuity(later_situation, continuity_receipt, ...)
```

`request` requires the exact latest authority-bound situation and a reconciliation report observed at the same logical time. It does not require continuity.

`request_with_continuity` is optional stronger audit evidence for the case in which only logical time advanced. The public request identity commits the continuity receipt ID, and the public completion identity commits the public request ID. Optional evidence cannot be checked and then disappear from the terminal record.

The v2 public facade also requires situation, active claim, initial report, supplied run, and final report to retain one exact `IntentRunCommitment`. Numeric `RunId` equality is insufficient.

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

## 8. Cleanup remains available after invalidation

The control plane deliberately distinguishes permission to create new responsibility from permission to remove or settle it.

After expiry, context invalidation, capability revocation, or authority advancement:

- a pre-dispatch outbox reservation may be aborted;
- committed/deferred effects may be probed and reconciled by stable identity;
- acknowledgement and terminal failure may be recorded;
- named escalation debt may be resolved or transferred;
- task claims may be released under their exact ownership evidence;
- cancellation may begin and finish;
- leaks may be contained and reported.

None of these operations is allowed to mint a new plan, capability, effect request, or publication authority.

## 9. Identity and replay rules

The proof-carrying public IDs remain separate domains from private canonicalization engines:

```text
public_handoff_id = H(domain, inner_capsule_id, source_continuity_id?)

AgentHandoffAcceptance v2 = H(
  domain,
  capsule_id,
  receiver_situation_id,
  receiver_run_id,
  receiver_run_commitment,
  authority_relation,
  authority_ancestry_receipt_id?,
  attenuation and responsibility fields,
  ...
)

public_cancel_id  = H(domain, run_commitment, inner_cancel_id, continuity_id?)
public_done_id    = H(domain, public_cancel_id, inner_completion_id)
```

Effect records and reconciliation additionally retain complete run identity:

```text
EffectRecord {
  run_id,
  run_commitment,
  ...
}

RunReconciliationReport v2 {
  run_id,
  run_commitment,
  effects[] each carrying the same commitment,
  ...
}
```

Consequences:

- same-ID runs with different authority, scope, budget, or expiry cannot share effect history;
- journal replay refuses a mixed complete run;
- handoff debt remains tied to the exact source run;
- receiver acceptance cannot drop a descendant ancestry proof after validating it;
- same-head and descendant-head acceptances have distinct identities;
- final cancellation reports cannot be substituted from another complete run;
- the same canonical handoff/cancellation body with and without continuity evidence has different public identity;
- completion cannot erase which cancellation request it finalized.

Durable codecs must preserve these domain separations and reject unknown or duplicated proof fields. Migration must never reinterpret an old v1 handoff acceptance as a v2 acceptance carrying complete-run and ancestry evidence.

## 10. Refused shortcuts

The following are explicitly rejected:

- treating an unchanged task generation as full plan continuity;
- treating a larger authority generation as proof of ancestry;
- accepting an ancestry receipt for another ancestor, descendant, repository, slot, store, or current version token;
- proving ancestry against one current slot and accepting a receiver from another;
- validating descendant ancestry and omitting its receipt identity from the acceptance;
- treating a valid capability authenticator as proof of current non-revocation;
- checking only the leaf capability and ignoring revoked ancestry;
- reusing request-time revocation evidence at a later external dispatch;
- returning a raw dispatch handle from the checked broker;
- accepting a later source handoff because the claim is merely unexpired;
- validating a source continuity receipt and omitting its identity from the capsule;
- removing task-transition exact-read checks without a two-basis persistence envelope;
- treating handoff acceptance as task assignment or receiver plan authority;
- requiring continuity before cancellation can begin;
- allowing revocation to prevent abort or reconciliation;
- treating disconnect, task unassignment, or process exit as completed cancellation;
- summarizing outstanding effects without complete identities and required actions;
- merging same-ID/different-commitment effects during replay or reconciliation;
- reporting escalation as clean settlement without a named transfer receipt;
- reporting a leak as contained without explicit containment evidence.

## 11. Product-adapter obligations

A production task adapter must return typed claim, release, and transfer projections whose generation transition and evidence can be checked against these objects. It must not infer success from a human-readable tracker response.

A future cross-head task-transfer adapter must use a two-authority-basis envelope. It must not reuse the current single-basis envelope by weakening its equality checks.

A production revocation adapter must:

- read from authority-selected policy state;
- bind one exact authenticated read event;
- return bounded canonical revocation identities and a generation commitment;
- preserve an explicit maximum age and invalidation path;
- refuse partial, stale, mixed-position, or unauthenticated state;
- never become a second repository authority.

A production handoff host should use the atomic current-authority sync/async driver rather than separately obtaining and later consuming an ancestry receipt.

A production executor or host service must:

- recheck action-packet preconditions before each consequential step;
- use the checked broker for operations requiring effect-time revocation;
- perform a new check at an irreversible external dispatch;
- stop admission immediately after cancellation request;
- preserve ambiguous external outcomes until reconciliation resolves them;
- keep cancellation, abort, and reconciliation available when continuation fails;
- attach exact authorization, run, handoff, ancestry, and cancellation identities to evidence and recovery;
- never mint receiver capability or task ownership from a handoff capsule or acceptance.

A robot/API/MCP surface must render exact IDs and typed refusal variants. Prose may explain the state but cannot replace the machine contract.

## 12. Verification obligations

Source-level tests should cover at least:

- exact-activation handoff success;
- later source handoff refusal without continuity;
- deterministic later source handoff with continuity;
- source continuity identity retained by receiver acceptance;
- changed non-task component refusing source continuity;
- same-head receiver acceptance;
- later receiver-head refusal without ancestry;
- deterministic descendant-head acceptance with retained proof;
- wrong-ancestor, wrong-descendant, wrong-repository, and wrong-hop refusal;
- same-body cross-store current-token substitution refusal;
- same-ID/different-commitment receiver refusal;
- sync/async current-authority driver parity;
- exact-position revocation receipt identity;
- stale use at the exclusive freshness deadline;
- revoked ancestor refusal;
- request-time proof expiry before external dispatch;
- revocation between reservation and dispatch;
- reservation recovery and abort after refusal;
- committed-effect reconciliation after dispatch;
- changed context still permitting cancellation request;
- same-ID/different-commitment effect replay and reconciliation refusal;
- optional cancellation continuity producing a distinct public identity;
- final report complete-run substitution refusal;
- frozen effect-set and immutable-effect checks;
- explicit task release/transfer;
- escalation transfer and leak containment evidence.

Revision-bound verification still requires the repository-owned formatter, test, Clippy, registry, docs, constitution, and fast lanes. Test source, this document, a Bead transition, or hosted workflow state is not verification evidence.

## 13. Remaining boundaries

This slice does not provide:

- production situation collectors for the nine non-task components;
- a concrete Beads task transport;
- a cross-head, two-authority-basis task-transfer envelope and persistence path;
- automatic receiver plan adoption after descendant acceptance;
- plan-relative continuation after selected component changes;
- mandatory checked-host adoption for every high-value operation;
- the complete action-packet executor;
- process, workspace, credential, tunnel, upload, secret, VM, or external-resource reaping;
- durable codecs, storage, replay, migration, or crash recovery for `AgentHandoffAcceptance` v2 and related control records;
- stable robot/CLI/native/MCP transport;
- automatic ECC assembly or canonical publication;
- independent batch-verifier closure.

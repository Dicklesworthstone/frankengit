# Merge Forge-Event Delivery Contract

**Status:** native implementation present; revision-bound production verification remains required  
**Primary path:** `crates/fgit-admission/src/merge/native.rs`; legacy compatibility facade in `merge.rs`
**Existing models to reuse:** forge event/merge types in `fgit-forge`; canonical effect/outbox transition machinery in `fgit-reference`; authority-head and RCR publication in `fgit-authority`/`fgit-admission`  
**Beads relationship:** this document defines the remaining verification scope of the merge task; it is not evidence that the task is verified or closed

## 1. Problem statement

The incomplete merge path that motivated this contract could stage the immutable forge event batch and commit its root into the Repository Commit Record. That proved which event body the decision intended. It did not make the event durably observable by a forge stream consumer or create a durable delivery obligation. Section 13 records the current implementation boundaries; section 11 defines the evidence required to complete this contract.

A complete merge transition must publish, through the same exact-predecessor authority-head CAS:

1. the merged ref state;
2. the forge aggregate position after applying the merge event;
3. the canonical outbox state containing the corresponding delivery effect;
4. the decision/RCR identities that bind all three;
5. every immutable body needed to re-read and verify those roots.

Carrying forward `forge_position_root` or `outbox_root` while only changing `forge_event_batch_root` is an incomplete transition.

## 2. Authority rule

There is one publication point: the Repository Authority Head CAS.

No event listener, worker row, database transaction, filesystem rename, callback, or post-CAS hook may independently make merge delivery canonical. Before CAS, every new body and effect is staged and invisible. After one successful CAS, ref state, forge position, outbox obligation, decision, and RCR become visible together.

If the CAS loses, none of the staged successor roots is canonical. The attempt must re-read authority and either:

- recognize the already-committed identical result;
- replan against the new predecessor;
- or refuse with the existing typed stale/conflict outcome.

It must not replay a stale outbox transition against the winner's head.

## 3. Required immutable state bodies

The implementation must persist canonical bodies sufficient to verify these authenticated maps without process-local memory:

### 3.1 Forge-position state

For every affected aggregate/stream, the body records the canonical post-transition position required by the existing forge event model, including the aggregate identity, exact predecessor position, successor position, and event-batch identity or equivalent existing commitment.

The authenticated `forge_position_root` is computed from these canonical entries. A reader starting only from the authority head and body store must be able to recover and verify the post-merge stream position.

### 3.2 Outbox state

The body records the canonical effect state produced by the existing effect/outbox transition model. It must bind at least:

- stable effect/idempotency identity;
- effect class and destination/audience;
- immutable event payload or payload identity;
- repository and decision/RCR basis;
- delivery obligation state;
- attempt/reconciliation state already defined by the canonical model;
- any predecessor state required to prove a legal transition.

The authenticated `outbox_root` is computed from canonical entries, not from an unordered process map or a merge-specific serialization.

### 3.3 No merge-private encoding

Merge admission must reuse the existing canonical forge/effect transition types and byte encodings. A new helper may compose them, but it may not create a second event identity, position counter, outbox state machine, retry vocabulary, or hash domain.

If the current production store cannot read and stage the existing reference bodies, the missing store/body bridge is the first implementation slice. Hashing a summary of the intended update is not a substitute.

## 4. Stable effect identity

The delivery effect must have a deterministic idempotency identity derived from immutable semantic inputs. It must not depend on wall-clock time, process identity, retry count, allocation order, random bytes, or the winning head generation when that generation is not part of the effect's semantic identity.

An identical retry of the same sealed merge intent against the same canonical predecessor must stage the same event, position transition, effect, and successor roots.

A distinct merge decision, repository, aggregate, event payload, or destination must not collide.

The implementation must document which fields define semantic sameness and cover every field with change-sensitivity tests.

## 5. Transaction sequence

The final merge path follows this order:

```text
1. authenticate and read the exact authority predecessor
2. resolve the current ref state, forge-position state, and outbox state
3. verify the sealed merge request and policy/evidence prerequisites
4. compute the merged tree/ref result
5. build the canonical forge event batch
6. apply the canonical forge-position transition in memory
7. build the canonical outbox effect with stable idempotency
8. apply the canonical outbox transition in memory
9. compute all successor bodies and roots
10. build decision batch and RCR binding those exact roots
11. stage every immutable body
12. flush staged bodies to the durability boundary required by the store
13. perform one exact-predecessor authority-head CAS
14. on success, return the committed outcome; on loss/ambiguity, reconcile by re-read
```

No external delivery attempt occurs before step 13. A delivery worker may act only from a canonical outbox state selected by the authority head.

## 6. RCR and decision bindings

The committed RCR/decision data must let an auditor prove that the ref update, forge event, forge position, and outbox effect belong to the same merge transition.

At minimum, the existing fields must be populated consistently:

- forge event batch root names the staged immutable event body;
- forge position root names the state after applying that batch;
- outbox root names the state containing its delivery obligation;
- predecessor and successor authority identities/generations obey the existing chain rules;
- repository sequence and decision sequence remain monotone and retry-stable under the existing protocol.

A root must never be updated without staging every body required to resolve it.

## 7. Delivery worker contract

The worker is a consumer of canonical outbox state, not part of merge publication.

It must:

- read from an authenticated authority position;
- claim/attempt an effect under the existing obligation protocol;
- present the stable idempotency identity to the destination where supported;
- distinguish acknowledged, refused, retryable, and ambiguous outcomes;
- persist the canonical transition for its result through the normal authority path;
- reconcile ambiguous outcomes before retrying a non-idempotent external action;
- respect cancellation, deadlines, and resource budgets;
- preserve terminal evidence and negative evidence.

A worker crash cannot erase the obligation because the obligation is already named by the canonical outbox root.

## 8. Crash and retry matrix

The implementation is incomplete without deterministic coverage of at least these boundaries:

| Boundary | Required recovery |
|---|---|
| before any staging | no visible change; ordinary retry |
| after event body staging | body remains unreachable; retry reuses identity |
| after position body staging | staged state remains unreachable; retry reuses identity |
| after outbox body staging | staged obligation remains unreachable; retry reuses identity |
| after decision/RCR staging | all staged bodies remain unreachable; retry or GC by retention policy |
| CAS loses cleanly | re-read winner; no stale effect replay |
| CAS response is ambiguous | authenticate/re-read head and outcome indexes before deciding to retry |
| CAS succeeds, process crashes before response | committed state is recoverable entirely from authority head and body store |
| worker crashes before external call | obligation remains pending/claimable under existing policy |
| worker crashes after call before acknowledgement persistence | reconcile using stable idempotency and destination evidence |
| duplicate identical merge request | return/recover the same terminal semantic outcome without duplicate delivery |
| competing distinct merge | one head wins; loser replans or refuses, never publishes a parallel outbox root |

Fault injection must target the actual production staging, flush, CAS, and reconciliation hooks, not a mock-only parallel implementation.

## 9. Required tests

### 9.1 Canonical and deterministic

- event, position entry, outbox effect, state body, and root bytes are stable;
- input ordering cannot change authenticated roots;
- every semantic field is change-sensitive;
- identical retries produce identical effect and successor-root identities;
- domain separation prevents cross-type identity reuse;
- malformed or non-canonical bodies are refused.

### 9.2 Atomicity

- successful merge changes ref, forge-position, and outbox roots together;
- no successful path carries either old delivery root forward;
- failed or losing CAS changes none of them canonically;
- a reader cannot observe the ref update without its forge position and obligation;
- a reader cannot observe an obligation whose event body is unresolved.

### 9.3 Recovery

- crash at every matrix boundary;
- ambiguous CAS reconciliation;
- duplicate retry before and after publication;
- outbox worker crash/restart and ambiguous destination response;
- stale predecessor and same-generation fork refusal;
- bounded body/map/effect counts before allocation-heavy work.

### 9.4 Integration

- production admission/store implementation, not only the reference model;
- committed merge event can be consumed from canonical outbox state;
- worker acknowledgement advances the canonical effect state without changing merge semantics;
- time-travel/audit at the committed position can resolve the merge event and delivery obligation;
- GC/retention keeps every body reachable from a live outbox obligation.

## 10. Implementation slices

Each slice must be complete and reviewable; no placeholder roots or fake durable adapters.

### Slice 1: persisted canonical state bridge

Add production-store read/stage support for the existing forge-position and outbox state bodies. Prove round-trip identity, bounds, malformed refusal, and deterministic roots. Do not change merge behavior yet.

### Slice 2: pure merge delivery transition

Create a pure function over authenticated predecessor state and the canonical merge event that returns successor forge-position state, outbox state, stable effect identity, and typed refusal. Differentially test it against the existing reference transition model where applicable.

### Slice 3: atomic admission wiring

Wire the pure transition into merge admission, stage all bodies, bind the exact roots into decision/RCR/head, and publish through the existing single CAS.

### Slice 4: fault and retry evidence

Exercise the production fault points and identical/competing retry matrix. Record exact revision and store profile.

### Slice 5: worker consumption

Only if not already implemented by the generic outbox worker, add the forge-event destination adapter. It consumes the canonical effect; it does not own a second pending table.

## 11. Completion evidence

The merge task remains incomplete until a revision-bound batch gate demonstrates:

- all required production paths and tests pass;
- the committed authority head changes `forge_position_root` and `outbox_root` for a merge event;
- event, position, outbox, decision, RCR, and head identities can be independently re-read and verified;
- identical retry and crash recovery do not duplicate delivery;
- no known defect or explicit non-claim remains in this contract's scope.

A source diff, unit test in only the reference crate, staged event body, green mock, or conversational summary is not sufficient closure evidence.

## 12. Explicit non-claims

The source boundaries below do not establish completion of the production paths
or the fault matrix. Completion requires the revision-bound evidence in §11.

It does not authorize hand-editing the authority head, advancing roots outside the normal CAS, weakening event/outbox canonical encoding, or marking the merge Bead verified or closed without its designated gate.
## 13. Current implementation boundaries

The native path composes `fgit-reference::merge_delivery` with the normal
admission evaluator, reference materializer, seal, and authority publication.
Its stable key uses the fields defined by
`fgit-codec::OutboxDeliveryIdentityInput`; the configured local audience is
`forge-projection`, with effect class `forge-event`. The existing legacy
seal format and its historical event bytes remain distinct compatibility
inputs. Native object validation reads and hashes the candidate commit, its
two ordered parents, merge base, and reachable trees before publication.
Native `MergeEffectPackage` inputs at `admit_merge_durable_in` enter this same
driver with their original seal. Supplied closure and evidence are checked
against node-owned object validation and the complete fold. Historical
Digest-valued packages retain their previous route. The authenticated-context
caller owns service-intake and quota authorization, like the node's lower-level
validated-receive primitive; this is not a session wrapper. Its caller-supplied
workspace epoch is only an asserted precondition: it cannot
authenticate a current workspace session because it carries no workspace or
snapshot identity.

The legacy `admit_merge` and `admit_merge_async` facades reject native payloads
before acquiring a seal. Their projection and materializer capabilities do
not establish native-object validation. Native callers use the explicit
native projection adapters; the original `OneNode` entrypoint dispatches to
that shared native driver internally. This preserves the existing permitted
native route without adding a second publication loop to a legacy facade.

For an existing native PR stream, the shared admission guard reads the exact
event selected by the authenticated forge frontier. A native closure refuses
with `ProtectedRefTransitionDenied`; a different source or target branch also
refuses with that code. An open or updated PR must bind the merge's exact source
and target tips, otherwise admission returns `EvidenceStale`. These checks
precede staging the merge effects. An earlier terminal outcome is still
resolved before current-state checks, preserving retry identity. New receipt
streams and legacy event encodings retain their existing semantics.

The native PR integration regressions in
`fgit-admission/tests/native_merge_delivery_faults/pull_request.rs` use
immutable event bodies selected by an initialized model authority head. They
exercise the production merge driver and canonical publication machinery,
including permitted merges and refusals without changes to ref/forge/outbox
roots. They do not establish a production PR open/update/close publication
API or filesystem crash durability for that API.

The additive `admit_workspace_merge_durable_in` path obtains that identity and
epoch from a node-owned session, checks the actual exported tree, and retains
the session lease through publication and any interrupted-request recovery.
Its explicit semantic precondition and process-local durability limit are
defined once in `GIT_TREE_FS.md` §6.1. The lower-level unbound API does not
acquire those workspace guarantees merely by receiving an epoch scalar.

The synchronous native and original-seal facades use private adapters whose
storage and projection operations finish before returning `Ready`. A single
poll enters the same async driver; no second seal, replan, or CAS loop exists.
Only synchronous capabilities can enter this facade. The durable node remains
asynchronous. Equivalence tests compare terminal outcomes and selected canonical
bytes, while explicit model schedules drive two candidates to the same CAS
token. The node's separate schedule test controls caller-future polling over
the real file-backed store and requires observed overlap; it does not claim
control over the store's internal disk-thread schedule.

`merge/native/delivery.rs` reads the selected forge and outbox maps and checks
payload, aggregate range, stable key, lifecycle predecessors, and receipt
bindings. An absent old genesis sentinel is accepted only after verifying
its exact derivation and unchanged authenticated history. A missing advanced
root is an error. The node materializer uses this same reader for receive,
merge, and snapshot projections.

`CanonicalOutboxEffectState` uses the existing obligation lifecycle.
`CanonicalOutboxDeliveryReceipt` binds the original payload, audience, key,
exact predecessor effect state, disposition, and bounded destination evidence.
`CanonicalOutboxProgress` records the existing `ReconcileState` and actual
`Observation` vocabulary, the persisted attempt ceiling, dispatch marker,
predecessor progress root, and bounded evidence. Its body is selected by
committed RCR order, not by immutable object existence. Lifecycle and progress
RCRs carry a typed witness under both ordinary invariant/outbox evidence
namespaces; `merge/native/history.rs` recognizes and validates these schemas.
Ordinary transaction-fold evidence continues to use its existing schema.

`deliver_forge_outbox_in` awaits an explicitly configured transport capability.
`outbox_delivery_context` selects the operator's finite background-controller
budget for the whole invocation, which may publish several transactions. A
shorter request context is also accepted; exhaustion preserves published
progress for a subsequent invocation. No operation extends its live budget or
substitutes a detached context to complete publication.
It publishes deferral before a call, persists a dispatch marker before send,
and probes any recovered in-flight dispatch. Completed observations are
published before terminal lifecycle settlement, so a restart after that
publication retains the original terminal evidence. The stored policy cannot
be increased or reset by retry. The initial reconciliation probe occupies
logical attempt 1; the bounded profile admits ceilings 2 through 16, at most
64 persisted transitions, and at most 4096 evidence bytes per observation.
Concurrent callers may repeat transport requests under the same stable key;
a strong destination must durably suppress duplicate effects. Weak
idempotency is refused before transport access. This is not a claim of one
physical request or support for arbitrary webhook destinations.

The file-backed process-death matrix interrupts native admission before its
first authority write and after awaited event, forge-position, obligation and
outbox-state writes, in both Git object formats. It checks the intercepted
bytes after reopening, their exact reuse on retry, and publication through one
coupled RCR. Candidate Git objects are already staged before this matrix starts;
the first-write case concerns admission, not upload. Separate cases exit before
and after the authority CAS. Receiver tests exit after persisted dispatch but
before any receiver filesystem effect, and after the receiver's durable effect
but before acknowledgement publication. Recovery verifies committed dispatch
history and probes the destination before deciding whether to send.

The embedded authority store is append-only for these immutable bodies and
exposes no deletion operation. Its retained decision history keeps progress,
effects, receipts, and payload commitments reachable. This profile does not
establish a distributed GC or checkpoint-pruning integration; such a collector
must preserve the complete live outbox and reconciliation closure before it
can be admitted.

The code and tests in this section do not close `frankengit-asa3`. The new
sync/async and scheduled-concurrency tests require revision-bound execution.
The new supervised workspace composition and the complete batch gate require
revision-bound execution before acceptance. Model fault tests and file-backed process-death
tests have different evidence classes; neither implies host power-loss or
filesystem fault coverage.

### 13.1 Original sealed-package integration

The original node entrypoint dispatches native events to
`admit_sealed_native_merge_durable_in`, which supplies the node-owned native
object validator to `admit_sealed_native_merge_async`. Both request forms use
`admit_merge_attempt_async`; the sealed form passes its original `SealAttempt`
and keeps its package preconditions together. There is no second native-style
seal, copied publication loop, alternative object store, or relaxed receive
materializer.

Commit `b588c0b592b774f426b29d5b97774658e3e66950` restores the checks omitted
when the shared driver and sealed-node tests were merged: the entire supplied
closure must equal the independently verified closure, and every declared
package object must belong to it. All six `CommitEvidence` fields must match
the complete prepared record: principal snapshot, actual forge event batch,
policy decision, invariant evidence, outbox effects, and retention delta.
Supplied roots are compared, never substituted into the published record.
Closure mismatches return `ObjectClosureIncomplete`; evidence mismatches return
`EvidenceInvalid`. Already-decided transactions recover before these
basis-dependent checks. Missing objects and staging failures remain retryable
infrastructure failures rather than fabricated terminal refusals.

Commits `53c7fdb4ccbd909bb450b286b285b5c1088901f5` and
`e560c0ac44ecb453a6566dfe99e450f2d6fbac6c` complete and register ten unit
regressions through the original public node API. They cover both object
formats, full-fold evidence and original identity, authenticated symbolic-HEAD
preservation, reopen/retry after later native publication, workspace and ref
staleness, changed-semantics key conflicts, missing objects, invalid ordered
parents, unrelated package objects, five immutable-staging conflicts, and
independent tampering with all six evidence identities. The positive fixtures
self-check actual native bytes; canonical HEAD is established in authenticated
genesis rather than assumed from the imported source's `HEAD` file. Existing
integration and process-death tests are retained.

Verification for these commits is limited to source review, lexical/delimiter
checks, and remote commit/blob inspection. Cargo, rustc, Rust compilation,
Clippy, and runtime tests were unavailable in the editing environment. This
integration is not a passing test report and does not satisfy the revision-bound
batch gate or close `frankengit-asa3`.

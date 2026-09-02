# Agent Control Plane Handoff Ancestry

**Status:** focused implementation contract; not repository authority  
**Owning architecture:** [`AGENT_CONTROL_PLANE_ARCHITECTURE.md`](AGENT_CONTROL_PLANE_ARCHITECTURE.md)  
**Lifecycle contract:** [`AGENT_CONTROL_PLANE_LIFECYCLE_CONTINUITY.md`](AGENT_CONTROL_PLANE_LIFECYCLE_CONTINUITY.md)  
**Implementation ledger:** [`AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`](AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md)  
**Authority proof:** `fgit-authority::AuthorityHeadAncestryReceipt`  
**Owning crate:** `crates/fgit-agent`

## 1. Problem

A handoff capsule is created against one exact authenticated repository head. By the time a receiver inspects it, repository authority may have advanced.

These facts are not sufficient to accept the handoff:

```text
receiver generation > source generation
same RepositoryId
claim has not expired
head body looks plausible
```

A larger generation does not prove ancestry. Another fork, slot, store, or repository incarnation can expose a numerically later head. Likewise, an authenticated historical receipt proves only what one store returned at one earlier read; it does not prove that a different current head descends from it.

The required proof is the exact bounded predecessor path already owned by `fgit-authority`:

```text
current HeadKey read + store authentication
    -> current canonical head identity
    -> predecessor_head_id walk
    -> exact source head identity and generation
```

## 2. Accepted authority relationships

`AgentHandoffAcceptance` recognizes two and only two relationships.

### 2.1 Same authenticated head

The source capsule and receiver name the same:

```text
RepositoryId
RepositoryAuthorityHeadId
HeadGeneration
```

The receiver still supplies its complete `IntentRun`, exact situation, executor identity, target-resolution evidence, and attenuated operation/budget/expiry scope.

### 2.2 Proven descendant head

The receiver names a strictly later head and supplies an `AuthorityHeadAncestryReceipt` whose fields agree exactly with both sides:

```text
receipt.repository_id
    == source.repository_id
    == receiver.repository_id

receipt.ancestor_head_id
    == source.authority_head_id

receipt.ancestor_generation
    == source.authority_head_generation

receipt.descendant_head_id
    == receiver.authority_head_id

receipt.descendant_generation
    == receiver.authority_head_generation

receipt.descendant_version_token
    == receiver.backend_version_token

receipt.hops
    == receiver_generation - source_generation
```

The receipt was produced only after a bounded exact predecessor walk. Every historical body is read by identity, decoded under the authority codec, re-identified, checked for repository continuity, and required to decrement generation by exactly one.

## 3. Complete receiver identity

Receiver acceptance compares more than numeric `RunId`.

The supplied run is re-committed as an `IntentRunCommitment`, and the receiver situation must retain that exact value. This binds:

```text
RunId
AuthorityReadReceiptId
allowed operation classes
resource budget
exclusive expiry
```

A same-ID receiver with a different authority read, scope, budget, or expiry is rejected before attenuation or inherited-effect interpretation.

The accepted value retains `receiver_run_commitment`; downstream task-transfer or execution code does not have to reconstruct what machine scope was accepted.

## 4. Exact current-slot driver

Validating an already-minted ancestry receipt is necessary but insufficient for a safe host integration. A host could otherwise:

1. prove ancestry against current slot A;
2. obtain a receiver situation from slot or store B;
3. pair the proof and receiver after either current state changed.

The sync and async host drivers close that seam:

```text
accept_handoff_at_current_authority(...)
accept_handoff_at_current_authority_async(...)
```

Each driver performs one coherent operation:

```text
read and authenticate current HeadKey
    -> prove bounded ancestry from capsule source
    -> require receiver head id/generation/token == that exact read
    -> consume zero-hop proof as same-head acceptance
       or nonzero proof as descendant acceptance
```

A byte-identical head body read from another store is not interchangeable because its `AuthorityVersionToken` differs. The driver refuses before receiver acceptance.

The asynchronous form shares the same semantic validation and refusal order; only authority I/O is awaited.

## 5. Acceptance identity

`AgentHandoffAcceptance` moved from identity domain v1 to v2.

The v2 commitment includes:

```text
capsule id
receiver situation id
receiver RunId
receiver IntentRunCommitment
receiver instance id
acceptance time
authority relation
optional AuthorityHeadAncestryReceiptId
receiver operation scope
receiver resource budget
receiver expiry
target-resolution evidence
complete inherited effect responsibilities
```

Same-head and descendant-head acceptances cannot collide. A descendant receipt cannot be validated and then omitted from the accepted identity.

## 6. Responsibility preservation

An ancestry proof changes only what repository authority position the receiver is allowed to inspect the handoff from. It does not weaken any handoff invariant.

The receiver must still remain within the capsule attenuation ceiling and retain scope for every outstanding effect action, including:

```text
AbortReservation
ReconcileCommittedEffect
ResolveEscalation
ContainLeak
```

The capsule and acceptance grant no capability, effect authority, task lease, or publication authority. High-value effects still require the receiver's own current capability ancestry and revocation proof at the consequential boundary.

## 7. Task-transfer boundary

Receiver acceptance is not task transfer.

The current task-coordination persistence envelope binds one authenticated-read basis to both predecessor and successor. That is correct for same-read claim, release, and transfer. It cannot soundly represent a source lease observed at one historical head and a successor assignment created under a later descendant head.

Therefore the following shortcut is explicitly rejected:

```text
prove descendant handoff acceptance
    -> simply remove the task kernel's exact-read equality check
    -> persist an ordinary single-basis transfer envelope
```

That would leave the durable write unable to prove which authority basis governed the predecessor and which governed the successor.

A future cross-head transfer slice must introduce a two-basis proof-carrying envelope that retains at least:

```text
source AuthorityReadReceiptId
source task snapshot and active lease
source capsule and acceptance identities
AuthorityHeadAncestryReceiptId
receiver AuthorityReadReceiptId and IntentRunCommitment
exact predecessor and successor task generations
one-shot CAS / flush / authenticated reread evidence
source cancellation projection
receiver post-transfer activation evidence
```

Until that exists, descendant-head acceptance is usable for review, responsibility inspection, receiver scope validation, and preparation, but it does not pretend to have mutated durable task ownership.

## 8. Refusal classes

The receiver path fails closed on:

- source-run reuse;
- zero receiver executor identity;
- receiver situation/run mismatch;
- receiver `IntentRunCommitment` mismatch;
- missing or mismatched authenticated receiver receipt;
- cross-repository acceptance;
- later head without an ancestry receipt;
- non-advancing descendant proof;
- ancestry repository mismatch;
- wrong ancestor head or generation;
- wrong descendant head or generation;
- wrong current-slot token;
- hop count differing from the full generation distance;
- receiver observation rollback;
- expired receiver run;
- target selector, run, executor, resolver, or evidence mismatch;
- operation, budget, or expiry amplification;
- inability to resolve one inherited effect responsibility;
- canonical framing failure.

The host driver separately distinguishes ancestry-walk failure, receiver/current-head mismatch, receiver/current-token mismatch, and receiver-acceptance refusal.

## 9. Source-level test matrix

Focused public-path source tests cover:

- later-head refusal without explicit ancestry;
- deterministic descendant acceptance;
- retained ancestry receipt and receiver run commitment;
- wrong-ancestor proof rejection;
- same-body cross-store token substitution refusal;
- same-ID/different-scope receiver refusal before attenuation checks;
- atomic synchronous current-head proof and acceptance;
- synchronous/asynchronous semantic parity.

Test source is not a test result. Revision-bound formatter, compiler, test, Clippy, registry, documentation, constitution, and fast-lane evidence is still required.

## 10. Non-claims

This slice does not provide:

- a cross-head task-transfer mutation or persistence envelope;
- automatic receiver task claim or action-plan adoption;
- descendant-policy compatibility analysis beyond exact repository ancestry;
- proof that source plan assumptions remain valid at the descendant head;
- receiver capability issuance;
- high-value effect authorization;
- durable codec or storage for `AgentHandoffAcceptance` v2;
- robot, native API, CLI, or MCP transport;
- ECC assembly or canonical publication;
- independent batch verification or Bead closure.

# Object-Store-Native Repository Decision Log

**Status:** normative architecture extension  
**Version:** 1.1  
**Last revised:** 2026-08-20

This document defines FrankenGit’s canonical publication substrate. It replaces the earlier assumption that a separate relational database or consensus-owned repository primary must be the source of truth.

The architecture takes the strongest part of Cursor Continuity’s WAL-first model—immutable push bodies in object storage, stateless materialization nodes, rendezvous routing as an optimization, conditional publication, gossip as a hint, and compaction as a shared durable event—and extends it with FrankenGit’s atomic forge semantics, stable transaction outcomes, proof-carrying conflict witnesses, root-last repair, and agent-scale batching.

## 1. Central claim

For each repository, canonical truth is:

1. immutable content-addressed objects;
2. immutable transaction seals;
3. an immutable sequence of `RepositoryDecisionBatch` objects;
4. a single small `RepositoryAuthorityHead` selected by a linearizable conditional compare-and-swap.

Everything else is a projection or accelerator: direct `TxId` outcome pointers, local FrankenSQLite tables, bare-repository views, pack indexes, search/graph generations, local caches, counters, queues, and routing hints.

The one authority primitive is not “a database transaction.” It is:

```text
compare_exchange(
    repository_head_key,
    expected_version_token,
    canonical(new_head_bytes),
) -> Won(new_version_token) | Lost(observed_version_token)
```

The backing authority store must prove that operation linearizable. “S3-compatible” is not sufficient by name; every backend passes the authority conformance suite.

## 2. Why this is better than one repository primary

A primary/lease architecture makes correctness depend on leader location, lease expiry, clock behavior, and failover routing. A CAS-head architecture has a smaller invariant:

- any healthy node may prepare a transaction;
- any node may attempt the head update;
- at most one candidate wins a given predecessor token;
- losers reread, deterministically revalidate or rebase, and retry the same sealed `TxId`;
- rendezvous hashing and per-core combiners make the healthy path fast but are not required for correctness;
- no materialization disk is a quorum member or durable source of truth.

The object store may itself use consensus internally. FrankenGit does not duplicate that machinery or synchronize an external reference database with an object log.

## 3. Required authority-store capabilities

An `AuthorityStore` profile declares and proves:

- read-after-write consistency for one key;
- strong conditional create (`put_if_absent`);
- linearizable conditional replacement using an unforgeable version token;
- no ABA ambiguity: a restored byte-identical body still receives a distinct version token, or the head body carries a monotone generation checked in the CAS;
- exact-byte range and whole-object reads;
- immutable object writes that either succeed completely or remain absent;
- authenticated transport and endpoint identity;
- bounded object size and documented error classes;
- versioning/lifecycle behavior that cannot resurrect a retired head silently;
- conditional behavior through gateways, proxies, replication, and regional failover;
- auditability of successful conditional writes.

Provider listing consistency is irrelevant to authority. Canonical recovery starts from known root keys and follows authenticated links.

### 3.1 Embedded profile

The single-node self-hosted profile implements the same trait with FrankenSQLite:

- one row stores head bytes, monotone generation, and digest;
- `BEGIN IMMEDIATE`/MVCC validation performs the compare-and-swap;
- immutable bodies live in the local object fabric;
- the database is an implementation of the authority primitive, not a second truth model;
- export produces the same decision batches and head object consumed by object-store deployments.

### 3.2 Cluster profile

A self-hosted HA installation may use an object store that passes the authority suite. A future pure-Rust `fgit-authorityd` may implement the trait with a small replicated state machine, but it is a separate later proof target—not an excuse to pull in a generic distributed database.

## 4. Canonical objects

### 4.1 Transaction seal

A deterministic key derived from `TxId` stores one immutable seal:

```rust
struct TransactionSealBody {
    tx_id: TxId,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    authenticated_principal_id: PrincipalId,
    idempotency_key_digest: Digest,
    canonical_request_digest: Digest,
    request_schema: SchemaId,
}
```

`put_if_absent(seal_key(tx_id), body)` has three outcomes:

- created: this body owns the identity;
- already present, byte-identical: idempotent retry;
- already present, different: `IdempotencyKeyReuse` request rejection.

Admission capability, policy epoch, issuer, and first-seen time are separate immutable admission receipts over the seal ID; they are not seal-body fields, so a legitimate retry never has to regenerate them and byte-identical retry matching remains sound.

A seal does not order or commit a mutation. It prevents two semantic requests from sharing one logical identity. The field-level definition above is a copy of the authoritative schema in [`NORMATIVE_PROTOCOL_CONTRACTS.md`](NORMATIVE_PROTOCOL_CONTRACTS.md) §5.2; that document wins on any divergence.

### 4.2 Prepared transaction capsule

Validation produces an immutable `PreparedTxnCapsule`:

```rust
struct PreparedTxnCapsule {
    tx_id: TxId,
    seal_id: TransactionSealId,
    basis_head_id: RepositoryAuthorityHeadId,
    basis_rcr_id: Option<RepositoryCommitId>,
    normalized_intent_root: Digest,
    net_effect_root: Digest,
    object_closure_root: Digest,
    read_witness_root: Digest,
    write_witness_root: Digest,
    policy_input_root: Digest,
    policy_decision_root: Digest,
    resource_receipt_root: Digest,
    verifier_root: Digest,
    preparation_profile: PreparationProfileId,
}
```

The capsule is advisory until publication. It makes expensive parsing, object validation, policy evaluation, and graph analysis reusable across CAS retries when its witnesses remain valid.

### 4.3 Repository decision

Every sealed transaction eventually acquires at most one terminal decision:

```rust
struct RepositoryDecision {
    decision_sequence: DecisionSequence,
    tx_id: TxId,
    seal_id: TransactionSealId,
    prepared_capsule_id: PreparedTxnCapsuleId,
    outcome: DecisionOutcome,
    decision_evidence_root: Digest,
}

enum DecisionOutcome {
    Committed { repository_commit_id: RepositoryCommitId },
    Refused { code: RefusalCode, refusal_record_id: RefusalRecordId },
}
```

A refusal consumes a decision sequence but does not advance the committed-RCR sequence. This preserves a complete audit of admitted decisions without pretending a refusal changed repository source state.

### 4.4 Repository decision batch

The publication unit may contain one or many ordered decisions:

```rust
struct RepositoryDecisionBatchBody {
    repository_id: RepositoryId,
    predecessor_head_id: RepositoryAuthorityHeadId,
    predecessor_head_generation: u64,
    first_decision_sequence: DecisionSequence,
    decisions: Vec<RepositoryDecision>,
    committed_rcrs: Vec<RepositoryCommitRecord>,
    resulting_ref_root: Digest,
    resulting_forge_position_root: Digest,
    resulting_outcome_index_root: Digest,
    resulting_retention_root: Digest,
    resulting_outbox_root: Digest,
    resulting_policy_epoch: PolicyEpoch,
    batch_evidence_root: Digest,
}
```

All ordering inside a batch is canonical. The combiner applies decisions sequentially to a scratch reference state and emits a normal form. A batch cannot contain two outcomes for one `TxId`, duplicate an RCR sequence, or skip the predecessor head.

### 4.5 Repository authority head

```rust
struct RepositoryAuthorityHeadBody {
    repository_id: RepositoryId,
    generation: u64,
    predecessor_head_id: Option<RepositoryAuthorityHeadId>,
    decision_tail_id: Option<RepositoryDecisionBatchId>,
    latest_decision_sequence: DecisionSequence,
    latest_committed_rcr_id: Option<RepositoryCommitId>,
    latest_repository_sequence: RepositorySequence,
    ref_root: Digest,
    forge_position_root: Digest,
    outcome_index_root: Digest,
    retention_root: Digest,
    outbox_root: Digest,
    configuration_root: Digest,
    policy_epoch: PolicyEpoch,
    format_registry_epoch: RegistryEpoch,
    last_checkpoint_id: Option<RepositoryCapsuleId>,
}
```

The head ID is the domain-separated digest of the unsigned canonical body. The store’s version token and the body’s monotone generation jointly prevent stale publication and ABA confusion.

## 5. Linearization

A batch becomes canonical at the successful conditional replacement of the repository head from its exact predecessor version token to the new head bytes.

Before the CAS:

- immutable Git objects may exist;
- seals and prepared capsules may exist;
- decision batch and candidate head bodies may exist;
- no new ref, forge transition, outcome, outbox effect, or retention root is visible canonically.

After the CAS:

- every decision in the batch is terminal;
- every committed RCR is visible in order;
- refs and forge positions move together;
- the outcome-index root includes every decision;
- outbox entries are eligible for delivery;
- retention roots protect the committed closure;
- readers following the new head must accept the batch or fail closed.

A client disconnect does not undo the CAS. The client queries by `TxId` through the outcome index or a derived direct pointer.

## 6. Direct outcome pointers are accelerators

The canonical outcome lives in the decision batch and authenticated outcome-index root. A background projector writes:

```text
/outcome-by-tx/v1/{tenant}/{repository}/{tx_id} -> DecisionPointer
```

with conditional create. A crash between head CAS and pointer creation cannot lose the outcome; recovery walks decision batches from the known head and repairs the accelerator. A conflicting pointer is an invariant violation. Garbage collection never treats the accelerator as the sole retention root.

## 7. Preparation lanes and flat combining

### 7.1 Per-core lanes

Ingress assigns each admitted transaction to one preparation lane for its lifetime. The lane owns:

- upload/quarantine stream;
- pack/object parser state;
- object closure builder;
- policy snapshot and witnesses;
- resource reservations;
- prepared capsule publication;
- cancellation/finalization.

Lane-local mutable buffers eliminate cross-core contention. Work stealing may move an unopened job; once preparation begins, migration requires an explicit state-transfer receipt.

### 7.2 Ready slots

Each lane publishes a bounded ready slot containing a prepared capsule ID and compact witness summary. Publication is reserve/commit/abort, never an untracked queue push.

### 7.3 Combiner

A combiner snapshots the current head and selects ready transactions using a deterministic policy:

1. continuation/retry age class;
2. starvation escalation class;
3. user-visible priority class;
4. admission logical time;
5. canonical `TxId` tie-break.

It validates witness compatibility, refines witnesses when economically justified, executes normalized intents against a scratch state, and emits one batch. The combiner is an optimization role, not an authority lease. Two combiners may race; one wins CAS and the other rebases.

### 7.4 Microbatch bounds

A batch is bounded by:

- maximum decisions;
- maximum canonical bytes;
- maximum object closures referenced;
- maximum preparation age;
- maximum time before an interactive transaction must be attempted;
- maximum policy/configuration epochs crossed;
- maximum replay/verification work.

The batch builder never waits indefinitely to improve amortization.

## 8. Conflict witnesses and deterministic rebase

A prepared transaction carries conservative read and write witness sets. Initial witnesses may be coarse:

- repository head;
- ref namespace family;
- forge entity family;
- protection-policy root;
- quota/retention domain;
- object-closure assumptions.

After a lost CAS, the rebase engine compares the old and new head delta.

### 8.1 Fast preserve

If every witnessed value and policy input remains equal, the prior normalized effect and decision evidence may be reused under a new predecessor link.

### 8.2 Value-of-information refinement

A coarse witness collision may be false. The engine estimates whether computing a finer witness is cheaper than redoing or refusing the transaction. Candidate refinements include:

- exact ref keys instead of ref-family root;
- exact CODEOWNERS/path-policy slices;
- PR/review/check entities instead of whole forge root;
- exact quota counters or escrow domain;
- exact object/subtree/symbol dependency slices;
- exact merge-queue prefix;
- graph-generation subproofs.

Refinement can only prove *less* conflict. If unavailable, over budget, or inconclusive, the conservative result stands.

### 8.3 True conflict

A true conflict re-evaluates the relevant intent against the new basis. The mismatch policy is explicit:

- `NoOp`: this statement contributes no effect;
- `StatementError`: this statement fails while earlier allowed statements may survive when the transaction contract permits partial statement success;
- `TxnAbort`: no effect from the logical transaction survives.

Git receive-pack atomicity and forge commands declare which policy classes they permit. No hidden last-writer-wins path exists for protected canonical state.

## 9. Intents, effects, and net-effect normal form

Clients submit intents: update refs, open/synchronize/merge a PR, add a review, publish a release, mutate labels, or create a package version. Finalization evaluates intents in order with read-your-own-writes and emits canonical effects.

Before hashing, effects are folded against basis and after-image into a target-disjoint normal form. Every source intent/effect maps to:

- a surviving canonical effect;
- identity no-op;
- inverse cancellation;
- absorption into a create/delete or stronger effect;
- explicit statement failure;
- transaction abort.

This prevents byte-order canonicalization from changing semantic applicability and lets a combiner reason about conflicts on final targets rather than redundant intermediate operations.

## 10. Staged, visible, and durable epochs

Every pipeline names three distinct states:

- **staged:** immutable bytes or candidate records exist but are not authoritative;
- **visible:** an authority root references the decision and readers may observe it;
- **durable:** placement, repair, and required failure-domain predicates are satisfied.

The transition graph is part of the acknowledgement profile; there is no universal inequality. V1’s default canonical source-code profile is `Absent -> Staged -> DurabilitySatisfied -> Visible`, because all replay-critical bytes must meet the promised durability class before head CAS. A derived projection may use `Absent -> Staged -> Visible(with DurabilityObligation) -> Durable`, but it exposes source position, durability class, and the unresolved obligation. Upload completion alone proves neither visibility nor durability.

## 11. Replica synchronization

### 11.1 Hints, not authority

After head CAS, the publisher sends small datagrams or messages carrying repository ID, new head ID, generation, and likely object locations. Lost, duplicated, reordered, or stale hints are harmless.

### 11.2 Read verification

Before serving a Git or forge read, a materializer compares its cached authority version with the store:

- unchanged/conditional-not-modified: serve locally;
- newer head: fetch decision batches and immutable objects, verify, apply, then serve;
- unavailable authority store: follow the deployment’s declared degraded-read policy; never claim current linearizability without a verified head.

### 11.3 Conflict-absorbing replica lattice

Non-canonical replicas track transaction observations in a lattice:

```text
Unknown < Reserved < Committed
Unknown < Reserved < Refused
Committed + Refused -> Conflict
```

`Conflict` is evidence of corruption or a protocol bug and fails closed. It is not resolved by timestamp or last writer. Canonical outcome remains whatever the authority head authenticates.

## 12. Compaction

Decision logs and object segments are compacted once into immutable reusable results.

A compaction record binds:

- exact input head/range;
- input segment and decision roots;
- algorithm/profile/toolchain identity;
- output packs/segments/indexes;
- logical-equivalence proof root;
- source-to-output totality map;
- resource and performance receipt;
- negative evidence from rejected candidate layouts.

Publication is another ordinary decision referencing the compacted generation. Replicas download the result instead of repeating expensive pack/delta/index work. Compaction cannot delete source material until the retention protocol proves all required restore and rollback horizons are closed.

## 13. Repair

RaptorQ or replica reconstruction yields candidate bytes in quarantine. Repair never overwrites authority directly.

1. Verify the original object/segment identity and structure.
2. Read current locator/manifest state.
3. If a healthy placement already exists, record a no-op repair.
4. Write repaired immutable bytes idempotently.
5. Submit a `RepairPlacementIntent` through the same decision-log authority.
6. CAS publication compares the locator/retention witness; a stale repair refuses or rebases.
7. Record repair evidence and update scrub scheduling.

This prevents a valid reconstruction of an old version from overwriting newer placement or retention state.

## 14. Failure matrix

The deterministic lab enumerates crashes at least at:

- before seal create;
- after seal create, before object staging;
- mid-upload or mid-pack validation;
- after object staging, before prepared capsule;
- after prepared capsule, before batch construction;
- after decision batch body, before head CAS;
- concurrent CAS winner/loser;
- after CAS, before response;
- after CAS, before direct outcome pointer;
- after CAS, before gossip;
- during materializer replay;
- during compaction output;
- after compaction output, before publication;
- during repair decode;
- after repaired put, before locator intent;
- during GC mark/grace/sweep.

Repeated crash and replay must converge to one authenticated head and at most one outcome per `TxId`.

## 15. Security properties

- A malicious object store cannot forge accepted history without breaking authenticated record identities/signatures, but denial, rollback, and omission remain threats addressed by anti-rollback witnesses and independent archives.
- Conditional-write credentials are capability-scoped to one repository head prefix and short-lived.
- Gateways cannot publish arbitrary heads; a candidate head must pass local canonical verification and policy before the authority client uses its capability.
- Head bodies are signed or MACed according to deployment profile; version tokens alone are not authenticity.
- Independent continuity witnesses may pin recent head IDs for high-value repositories.
- Operator restore to an older head is an explicit, audited new-generation restore operation; never silent fallback.

## 16. Non-claims

This design does not claim every object store offers linearizable CAS, that object-store durability replaces restore drills, that one CAS has infinite throughput, or that local materializations are unnecessary. It makes those assumptions explicit, testable, and replaceable while keeping canonical semantics independent of any one vendor or database.

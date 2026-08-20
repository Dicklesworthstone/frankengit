# FrankenGit Normative Protocol Contracts

**Status:** Normative architecture contract for the pre-implementation phase  
**Version:** 1.0  
**Last revised:** 2026-08-19  
**Precedence:** When this document conflicts with a summary, diagram, example, backlog item, or older prose in the comprehensive plan, this document wins until the conflict is removed. `VERIFY_SPEC.md` governs the evidence needed to claim an implementation satisfies these contracts.

FrankenGit is intended to preserve ordinary Git behavior while replacing the conventional assumption that one mutable bare repository is the durable source of truth. That is only safe if identity, admission, ordering, atomicity, recovery, and retry semantics are unambiguous. This document fixes those boundaries before implementation begins.

## 1. Normative vocabulary

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

- **Git object** means a blob, tree, commit, or annotated tag represented exactly as Git defines it.
- **Git object ID** means `(hash_algorithm, digest_bytes)`. SHA-1 and SHA-256 identities are distinct typed values, not interchangeable byte strings.
- **Internal object ID** means a domain-separated digest of a FrankenGit canonical envelope. It never replaces or rewrites a Git object ID.
- **repository epoch** is the monotonically increasing fencing epoch for one repository's canonical writer.
- **repository sequence** is the gap-free logical sequence assigned to admitted repository commits inside one epoch. Epoch and sequence are compared lexicographically.
- **forge position** is the authenticated logical position of each canonical forge stream, such as pull-request, issue, review, policy, and release streams.
- **materialization** is a disposable Git-compatible representation derived from canonical truth. It is never authoritative merely because it is locally complete.
- **request rejection** is a non-canonical response produced before transaction admission.
- **transaction refusal** is a canonical terminal outcome produced after a transaction identity has been sealed.
- **repository capsule** is a signed checkpoint. It is not the per-commit source of current forge-stream position.

## 2. Identity domains

### 2.1 Git identities remain native

FrankenGit MUST preserve the repository's native Git object format. A SHA-1 repository continues to expose SHA-1 object IDs; a SHA-256 repository exposes SHA-256 object IDs. The server MUST NOT silently translate object IDs, synthesize cross-format IDs, or treat equal digest bytes under different algorithms as the same object.

Every API carrying a Git object ID MUST include the algorithm. Textual APIs MAY use Git's conventional hexadecimal spelling only when repository context fixes the algorithm unambiguously.

### 2.2 Internal immutable identities

Every FrankenGit immutable record uses a domain-separated canonical encoding:

```text
InternalObjectId = H(
    "frankengit/object/v1" ||
    object_type ||
    canonical_encoding_version ||
    canonical_body_bytes
)
```

`H` is selected by a versioned cryptographic registry. The digest algorithm is part of the typed identity. Canonical body bytes exclude transport framing, storage location, mutable placement acknowledgements, and signatures unless a record explicitly defines otherwise.

### 2.3 Request ID and transaction ID are different

A `RequestId` identifies one network attempt and is useful for tracing. It has no idempotency authority.

A `TxId` identifies one admitted logical mutation. There is exactly one normative derivation:

```text
TxId = H(
    "frankengit/ref-txn/v1" ||
    tenant_id ||
    repository_id ||
    authenticated_principal_id ||
    idempotency_key ||
    canonical_request_digest
)
```

The idempotency key is supplied by the caller or generated once by an ingress adapter and returned before mutation admission. The canonical request digest binds every semantically relevant field, including expected old refs, proposed new refs, force flags, push options, policy-visible metadata, and requested forge events. A reused idempotency key with a different canonical request digest is a typed `IdempotencyKeyReuse` rejection and MUST NOT alias the first transaction.

A server nonce, retry count, wall-clock timestamp, connection ID, or receiving node MUST NOT participate in `TxId`; including any of those would destroy stable retry identity.

## 3. Admission boundaries and terminal outcomes

### 3.1 Pre-admission request rejection

Authentication failure, malformed framing, unsupported protocol capability, request-size violation, tenant suspension, and ingress rate limiting MAY reject a request before `TxId` is sealed. Such a response is request-scoped and is not inserted into repository history.

A pre-admission rejection MUST NOT claim that a repository transaction was refused, committed, or cancelled. The caller may retry after correcting the request or satisfying policy.

### 3.2 Transaction sealing

Admission seals:

```rust
struct SealedRefTxn {
    tx_id: TxId,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    principal: PrincipalSnapshot,
    canonical_request_digest: Digest,
    idempotency_key_digest: Digest,
    admitted_epoch: RepositoryEpoch,
    admission_policy_epoch: PolicyEpoch,
}
```

Sealing is itself durable enough that a retry can discover whether a terminal outcome already exists. Implementations MAY combine the seal and terminal record in one serializable metadata transaction when no asynchronous validation occurs; they MUST NOT expose a state in which two different canonical request bodies can win the same `TxId`.

### 3.3 Exactly one terminal outcome after sealing

Every sealed transaction eventually has at most one immutable terminal record:

```rust
struct TxnOutcomeRecord {
    tx_id: TxId,
    repository_id: RepositoryId,
    sealed_request_digest: Digest,
    outcome: TxnOutcome,
    decided_at: LogicalTime,
    deciding_epoch: RepositoryEpoch,
    evidence_root: Digest,
}

enum TxnOutcome {
    Committed { repository_commit_id: RepositoryCommitId },
    Refused { code: RefusalCode, refusal_record_id: InternalObjectId },
}
```

The storage key is `TxId`; insertion is compare-and-set from absent to exactly one value. `Committed` and `Refused` race through the same linearizable publication point. A second, byte-identical write is idempotent. A different second value is an invariant violation and a release-blocking failure.

Infrastructure failure before terminal publication leaves no terminal outcome and is retryable with the same `TxId`. Client disconnect or cancellation after sealing does not create a third terminal state and does not grant the client authority to erase the transaction. The server either completes validation to `Committed`/`Refused`, or safely abandons uncommitted work while retaining the seal for deterministic retry.

### 3.4 Cancellation ownership

Cancellation has three boundaries:

1. **Before sealing:** the request may disappear without canonical effect.
2. **After sealing but before the metadata commit:** cancellation requests cooperative drain. No partially visible canonical mutation is allowed. A later retry resumes or re-evaluates the same sealed request.
3. **After the metadata commit linearizes:** cancellation affects only response delivery and downstream side effects. The committed result remains canonical.

No API may report `cancelled` as though it proved the mutation did not commit. On an ambiguous connection loss, the client queries by `TxId`.

## 4. Canonical repository state

### 4.1 Repository Commit Record

A successful logical mutation publishes exactly one `RepositoryCommitRecord` (`RCR`):

```rust
struct RepositoryCommitRecord {
    repository_id: RepositoryId,
    epoch: RepositoryEpoch,
    sequence: RepositorySequence,
    parent: Option<RepositoryCommitId>,
    tx_id: TxId,
    principal: PrincipalSnapshot,
    canonical_request_digest: Digest,

    ref_delta_root: Digest,
    resulting_ref_root: Digest,
    object_closure_root: Digest,

    forge_event_batch_root: Digest,
    resulting_forge_position_root: Digest,

    policy_epoch: PolicyEpoch,
    policy_decision_root: Digest,
    invariant_evidence_root: Digest,
    outbox_root: Digest,

    optional_checkpoint_capsule: Option<RepositoryCapsuleId>,
}
```

The record's immutable identity is the domain-separated hash of its unsigned canonical body. `tx_id` and `(epoch, sequence)` are unique within the repository. `parent` must equal the previously visible RCR, except for repository creation.

The RCR binds both source-control state and the exact forge-event batch admitted with it. A pull request cannot become merged without the associated target ref update, and a target ref update represented as a PR merge cannot become visible without the corresponding forge transition.

### 4.2 Forge position is current state; capsules are checkpoints

`resulting_forge_position_root` is mandatory on every RCR. It authenticates the current positions of canonical forge streams after the admitted event batch.

A repository capsule is an occasional checkpoint over a known RCR and its roots. A carried-forward older capsule MUST NOT be interpreted as the current forge position. `optional_checkpoint_capsule` is either absent or points to a capsule generated for this exact RCR after all required checkpoint material has been durably staged.

### 4.3 Linearization point

The mutation linearizes at the serializable metadata commit that atomically makes all of the following visible:

- the new RCR at `(epoch, sequence)`;
- the updated repository head pointer;
- the `TxnOutcomeRecord::Committed` value for `TxId`;
- the resulting ref-root pointer;
- the resulting forge-position-root pointer;
- the outbox entries whose preconditions are the committed RCR.

Object bytes and immutable event bodies may be written before this point into a content-addressed quarantine/staging namespace. They are unreachable and garbage-collectable until the metadata commit references them. External notifications, webhooks, CI dispatch, indexing, and billing occur after the linearization point through the transactional outbox.

A refusal linearizes at the metadata commit that publishes `TxnOutcomeRecord::Refused` and its immutable refusal evidence. It does not advance repository sequence or mutate refs/forge state.

## 5. Reference transaction algorithm

The following order is normative. Variables are introduced before use, and all policy inputs come from one pinned snapshot.

```text
handle(request, authenticated_principal, request_context):
  1. Perform request-level framing, size, protocol, and coarse admission checks.
  2. Canonicalize the complete semantic request.
  3. Derive TxId using the one formula in §2.3.
  4. If a terminal TxnOutcomeRecord exists, return it.
  5. Seal SealedRefTxn or verify the existing seal matches byte-for-byte.
  6. Acquire repository writer authority for epoch E; reject stale E.
  7. Read one pinned RepositorySnapshot S containing:
       - current RCR/head, epoch, and sequence;
       - current ref root and requested ref values;
       - current forge-position root and relevant forge entities;
       - policy epoch and policy inputs;
       - retention/legal-hold state;
       - repository configuration and hash format.
  8. Validate expected-old ref values and force semantics against S.
  9. Validate the quarantined Git object graph and compute object closure C.
 10. Construct candidate ref delta D and candidate forge event batch F.
 11. Evaluate authorization and policy P against (S, D, F, C, principal).
 12. If P refuses, atomically publish one Refused outcome and return it.
 13. Stage immutable event bodies, decision evidence, roots, and outbox body.
 14. In one serializable metadata commit, compare that S is still current and:
       - allocate sequence S.sequence + 1 under epoch E;
       - publish the RCR and all resulting roots;
       - publish Committed outcome for TxId;
       - publish transactional outbox entries.
 15. If the compare fails, discard the candidate metadata transaction and retry
     from step 6 with the same TxId and sealed request.
 16. After commit, asynchronously materialize Git views and drain outbox effects.
 17. Return the immutable terminal outcome.
```

Policy is never evaluated against an uninitialized, mixed, or later snapshot. A retry may observe a newer snapshot and produce a refusal that the first attempt would not have produced, but it cannot change the sealed request or `TxId`. Implementations that need policy decisions stable across retries must explicitly pin and validate a policy epoch as part of the request contract.

## 6. Git transport and push compatibility

### 6.1 Fetch and push are distinct services

FrankenGit MUST use precise Git terminology:

- clone/fetch negotiate with `git-upload-pack` over smart HTTP or SSH;
- push negotiates with `git-receive-pack` over smart HTTP or SSH;
- Git protocol v2 defines capability advertisement and commands used by fetch-oriented flows such as `ls-refs` and `fetch`;
- FrankenGit MUST NOT claim that "protocol v2 push" is a compatibility requirement unless Git itself standardizes such a command and the registry is updated.

The compatibility registry records transport (`ssh`, `smart-http`), service (`upload-pack`, `receive-pack`), negotiated protocol version where applicable, object format, and capability set independently.

### 6.2 Push quarantine

Incoming pack data is untrusted. Before reference admission it MUST be held in a transaction-scoped quarantine and subjected to bounded validation:

- pkt-line and sideband framing limits;
- pack header, trailer, and checksum validation;
- object decompression limits and expansion-ratio limits;
- delta depth, delta fan-out, and aggregate reconstruction budgets;
- object type and canonical header validation;
- tree entry ordering, mode, and name validation;
- commit/tag header and encoding limits;
- object graph reachability and missing-object checks;
- submodule entry handling without recursively trusting the target;
- repository object-format consistency;
- advertised and hidden-ref authorization;
- expected-old ref and atomic-push semantics;
- signed-push certificate verification when requested by policy.

No quarantined object becomes a canonical retention root merely because bytes arrived. After an RCR commits, referenced objects are promoted by identity or made reachable through the canonical object-location map. Promotion is idempotent.

### 6.3 Atomic push

When the client requests atomic push and the server advertises it, all requested ref commands are one `RefTxn`: either one RCR commits every command or one refusal commits none. Without atomic capability, the server may preserve Git's per-ref success/failure behavior, but the mapping from one receive-pack session to one or more sealed transactions must be explicit and replayable.

### 6.4 Partial clone and promisor safety

Partial clone is a fetch optimization, not permission to lose canonical objects. Promisor declarations, filters, and omitted-object promises are typed and authenticated. A materialization may omit objects; canonical truth and retention accounting may not. Filters are resource-bounded and tested against Git's conformance corpus.

## 7. Repository capsules

A capsule consists of an unsigned body plus one or more signatures:

```rust
struct RepositoryCapsuleBody {
    repository_id: RepositoryId,
    epoch: RepositoryEpoch,
    sequence: RepositorySequence,
    repository_commit_id: RepositoryCommitId,
    ref_root: Digest,
    forge_position_root: Digest,
    object_manifest_root: Digest,
    segment_manifest_root: Digest,
    retention_root: Digest,
    policy_epoch: PolicyEpoch,
    format_registry_epoch: RegistryEpoch,
}

RepositoryCapsuleId = H(
    "frankengit/repository-capsule/v1" ||
    canonical(RepositoryCapsuleBody)
)
```

Signatures, storage locations, repair-symbol placement, and replica acknowledgements are attestations over `RepositoryCapsuleId`; they are not included in its identity. This avoids circular identity and permits signature/key rotation without changing the checkpoint body.

Capsule publication is root-last:

1. stage all referenced immutable manifests and segments;
2. verify each identity and closure;
3. collect the required durability/placement evidence;
4. construct and hash the unsigned body;
5. sign the body identity;
6. atomically publish the capsule pointer for the exact RCR;
7. only then allow older superseded checkpoint material to enter retention review.

A capsule does not create consensus, authorize a ref update, or override an RCR.

## 8. RaptorQ and repair boundaries

RaptorQ is an erasure-recovery mechanism for registered immutable byte objects. It is not a cryptographic hash, signature, authorization system, ordering protocol, consensus algorithm, freshness oracle, or substitute for replicated metadata.

Every encoded object class has a registry row specifying:

- canonical source bytes and object identity;
- symbol size and coding parameters;
- authenticated metadata needed to select symbols;
- maximum decode work, memory, and input count;
- placement and failure-domain policy;
- decode trigger and escalation path;
- cryptographic and structural post-decode verification;
- typed failure when recovery is impossible.

Decoded bytes are accepted only after all applicable original commitments verify: internal object ID, Git object ID, cryptographic digest, Merkle inclusion, canonical codec, expected length, and type-specific invariants. A successful decoder return without those checks is corruption, not recovery.

Mutable metadata, leases, authorization state, transaction seals, terminal outcomes, and repository head pointers are protected by ordinary replicated transactional storage, checksums, backups, and consensus/fencing. They MUST NOT depend on fountain-code reconstruction for correctness or current truth.

## 9. Writer fencing and multi-region operation

Each repository has at most one canonical writer epoch at a time. Writer authority is a lease or consensus-backed token carrying `RepositoryEpoch`. Every RCR metadata commit compares the writer epoch. A stale writer cannot publish even if it still has network connectivity and complete local state.

Failover advances the epoch. The first RCR in a new epoch points to the last committed RCR from the prior epoch and allocates sequence one (or continues a globally monotone sequence if the selected metadata design proves that invariant). The choice is registry-versioned; implementations MUST NOT sometimes reset and sometimes continue without encoding the rule.

Materializers and readers may be active-active. Canonical mutation is not asynchronous multi-master. A future sharded or parallel mutation path is admissible only after executable refinement proves equivalence to the single-sequencer semantics for overlapping invariant keys, idempotency, forge/ref atomicity, and recovery.

## 10. Authorization and policy snapshot semantics

Authorization has two layers:

- ingress authorization determines whether a principal may attempt the operation;
- commit policy evaluates the exact candidate mutation against one pinned repository snapshot.

The commit policy input includes the principal snapshot, authentication strength, actor type, proposed ref delta, object closure summary, forge transitions, current protections, CODEOWNERS/review state, status-check evidence, merge-queue position, policy epoch, and any approved emergency override.

Policy code is deterministic for canonical decisions. It may consume signed evidence produced by non-deterministic systems, but the evidence identity and acceptance rule are explicit. Wall clock, network calls, mutable external databases, and unversioned model output MUST NOT be read inside the canonical metadata transaction.

A policy decision record explains every decisive rule and binds its input root. Statistical detectors may request additional review, reduce resource budgets, or open a reversible quarantine; they may not silently grant authorization or serve as the sole basis for irreversible punishment.

## 11. Agent authority and evidence-carrying changes

An agent acts through an `IntentRun` sponsored by a human or service principal. Its authority is attenuated, repository-scoped, time-bounded, budget-bounded, and operation-specific. An agent token never inherits all authority of its sponsor by default.

An `IntentRun` binds:

- sponsor and agent identities;
- model/harness identity when supplied;
- repository and base RCR/capsule;
- allowed refs and path scopes;
- allowed read classes and secret classes;
- effect capabilities;
- compute, storage, network, and monetary budgets;
- expiration and revocation handle;
- required independent verifier classes;
- disclosure policy for generated provenance.

A Context Packet is a content-addressed, provenance-preserving view over a pinned repository state. It lists included and deliberately omitted material. Search results are evidence-linked candidates, not authority to read inaccessible content.

An Evidence-Carrying Change binds the proposed Git object closure, base state, tests/checks, tool receipts, materialized context identities, claimed invariants, known omissions, and verifier attestations. A verifier that shares the same mutable workspace, credentials, or hidden state as the proposing agent is not independent unless the policy explicitly accepts that weaker evidence class.

Agent cancellation follows the transaction rules in §3.4. Workspace cancellation additionally drains or revokes spawned tasks and effect capabilities through structured-concurrency regions. No orphan task retains a push credential after the Intent Run closes.

## 12. Forge events and projections

Canonical forge entities are event-sourced. Event bodies are immutable and domain-separated. Read models, search indexes, notification feeds, counters, and web pages are projections and may lag.

Every projection exposes or internally records the RCR/forge position through which it is complete. A stale projection cannot make an authorization decision without revalidation against canonical state. Projection repair replays canonical events; it does not invent missing events from the current UI state.

Webhook and CI delivery is at-least-once through an outbox unless a downstream protocol proves stronger semantics. Delivery IDs are stable and consumers receive idempotency guidance. A failed webhook never rolls back the repository commit that produced it.

## 13. Garbage collection, retention, and deletion

Reachability is computed from an authenticated root set, including:

- current refs and protected hidden refs;
- open pull-request heads and merge-queue refs;
- retained releases, packages, artifacts, and attestations;
- legal holds and administrator retention pins;
- unexpired repository capsules and backup manifests;
- replication and migration handoff roots;
- grace-period tombstones.

Deletion is a multi-stage protocol: mark, prove root exclusion, wait the configured grace/replica horizon, sweep immutable storage, and record evidence. A materialization's local `git gc` never decides canonical deletion.

User-visible deletion claims distinguish logical invisibility, scheduled physical deletion, backup expiration, and cryptographic erasure. Hosted-service policy must state which claim is being made.

## 14. Statistical adaptation boundaries

Conformal predictors, e-processes/e-martingales, bandits, and change detectors may adapt:

- cache and prefetch budgets;
- RaptorQ repair overhead within hard floors/ceilings;
- scrub priority;
- canary escalation;
- queue admission and reversible throttling;
- search/rerank budgets;
- anomaly-review priority.

They MUST NOT determine Git object identity, RCR order, ref atomicity, authorization, signature validity, retention roots, or whether committed data exists. Every adaptive controller has deterministic safe defaults, bounded actions, reset semantics, replayable observations, and a kill switch.

Any statistical coverage or false-alarm claim states its assumptions, calibration population, exchangeability/stationarity limitations, and exact decision rule. Operational telemetry is evidence about a deployment, not proof of universal behavior.

## 15. Security and non-claims

The architecture does not claim that:

- content addressing alone proves authorship;
- RaptorQ alone detects malicious corruption;
- signed commits imply trustworthy code;
- a successful CI job is safe to trust without runner and provenance policy;
- deterministic replay reproduces unrecorded external effects;
- object-store durability equals end-to-end recoverability;
- branch protection prevents administrators or compromised control planes from abusing override powers;
- an agent-generated explanation proves the change is correct.

Security-critical parsers run under strict resource budgets and, where appropriate, process or sandbox isolation. Hosted CI, package registries, webhooks, rendering, archive extraction, and repository import are separate untrusted-input threat surfaces, not incidental features.

## 16. Compatibility and evolution

All externally visible formats and protocols are versioned. The registries distinguish:

- implemented;
- differentially verified;
- experimentally available;
- specified only;
- explicitly unsupported.

Unknown enum variants and record versions fail closed at canonical mutation boundaries. Read paths may preserve and forward unknown fields only when the format defines that behavior.

A protocol change that alters identity, ordering, linearization, retention, authorization, or recovery requires:

1. an ADR;
2. migration and mixed-version semantics;
3. golden canonical encodings;
4. model/state-machine tests;
5. crash and retry fault campaigns;
6. compatibility evidence;
7. rollback or forward-only recovery instructions;
8. updated threat model and registry rows.

## 17. Minimum release-blocking invariants

An implementation cannot call its mutation core complete until executable evidence covers at least:

1. one canonical `TxId` derivation and key-reuse mismatch refusal;
2. at most one terminal outcome per sealed transaction;
3. no client cancellation ambiguity can create two outcomes;
4. RCR parent/epoch/sequence continuity;
5. atomic ref plus forge-event publication;
6. stale-writer fencing;
7. expected-old ref enforcement under races;
8. one pinned policy snapshot per attempt;
9. no quarantined object becomes a retention root before commit;
10. no committed object closure is omitted from canonical retention roots;
11. capsule identity excludes signatures/placement and binds the exact RCR;
12. carried-forward capsules cannot masquerade as current forge position;
13. repair output is never accepted without original commitments;
14. projection lag cannot authorize a mutation;
15. outbox retries cannot duplicate canonical events;
16. Git receive-pack conformance does not rely on a fictional protocol-v2 push command;
17. SHA-1 and SHA-256 object identities cannot collide at the type boundary;
18. GC cannot sweep any authenticated or grace-period root;
19. verifier independence class is enforced, not self-declared;
20. every refusal and commit is explainable from immutable evidence roots.

These invariants are the contract. Performance optimizations, regional placement, sharding, caching, and agent conveniences are subordinate to them.
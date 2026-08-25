# FrankenGit Normative Protocol Contracts

**Status:** normative architecture contract for the pre-implementation phase  
**Version:** 2.0  
**Last revised:** 2026-08-19  
**Precedence:** this document governs identity, admission, ordering, publication, recovery, retry, cancellation, Git compatibility, memory safety, agent authority, repair, generation activation, and release evidence. When a summary, diagram, backlog item, or older exploratory passage disagrees, this document wins until the conflict is removed.

FrankenGit preserves ordinary Git behavior while making repository truth independent of one mutable bare repository, one C Git process, one external metadata database, or one elected materialization primary. The production implementation is pure Rust, uses Asupersync as its sole runtime, forbids first-party unsafe code, and never links or invokes another Git engine in production.

## 1. Normative vocabulary

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

- **Git object** means a blob, tree, commit, or annotated tag encoded according to the repository’s declared Git object format.
- **Git object ID** means `(hash_algorithm, digest_bytes)`. SHA-1 and SHA-256 domains are distinct typed values.
- **internal object ID** means a domain-separated digest over one FrankenGit canonical body. It never replaces a Git OID.
- **transaction seal** is the immutable object that binds one logical mutation identity to one exact semantic request.
- **prepared transaction capsule** is reusable validation/policy/effect evidence against one authority-head basis.
- **repository decision** is the immutable terminal `Committed` or `Refused` result for one sealed transaction.
- **repository decision batch** is the immutable ordered publication body containing one or more terminal decisions and zero or more committed Repository Commit Records.
- **Repository Commit Record (RCR)** is the canonical source/forge mutation record for one committed logical transaction.
- **repository authority head** is the small authenticated root selected by one linearizable conditional write.
- **authority version token** is an opaque backend conditional-write token obtained from a previously authenticated head read and protected against ABA by the head’s monotone generation/predecessor checks.
- **decision sequence** orders every canonical terminal decision, including refusals.
- **repository sequence** orders committed RCRs only.
- **forge position** is the authenticated logical position of every canonical forge stream.
- **materialization** is a disposable Git-compatible or workspace representation derived from canonical truth.
- **generation authority** is an anti-rollback root that selects one immutable search, graph, compaction, policy, workspace, or release generation.
- **request rejection** occurs before a transaction seal and is not repository history.
- **transaction refusal** is a canonical terminal decision after sealing.
- **staged, visible, and durable** are distinct publication epochs defined in §9.

## 2. Constitutional implementation boundary

### 2.1 Pure-Rust Git engine

FrankenGit MUST implement in safe Rust:

- Git object parsing and encoding;
- native OID computation;
- pack parsing/writing and delta resolution;
- pack indexes, MIDX, bitmaps, and commit-graph materializations where supported;
- pkt-line, sideband, upload-pack, and receive-pack behavior;
- refs, symrefs, namespaces, atomic push, shallow/partial clone, tags, notes, and hidden refs;
- diff/merge behavior promised by the compatibility registry;
- quarantine, collision defense, reachability, and resource limits.

A production feature MUST NOT link `libgit2`, C Git, JGit, Dulwich, or another Git engine; invoke `git` as a subprocess; or hide an external engine behind a fallback. The upstream Git executable MAY run as a separately pinned, sandboxed differential oracle in development/conformance lanes.

### 2.2 Runtime and unsafe code

- Asupersync is the sole async runtime.
- Every first-party crate declares `#![forbid(unsafe_code)]`.
- No first-party production crate links foreign-language runtime code through FFI.
- Optimized paths retain a safe scalar/reference oracle.
- Dependency exceptions follow `DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md` and the checked registry.

## 3. Identity domains

### 3.1 Native Git identity

A repository has one declared object format. Every API that can cross repository context carries the hash algorithm explicitly. Equal digest bytes under different algorithms are not equal identities. FrankenGit MUST NOT silently translate SHA-1 to SHA-256 or expose an internal digest as a Git OID.

An internal Git envelope MAY bind the native OID, type, length, exact canonical object bytes, and a stronger internal digest for collision/corruption defense. Native compatibility identity remains unchanged.

### 3.2 Internal immutable identities

Every immutable FrankenGit body uses a versioned domain-separated encoding:

```text
InternalObjectId = H(
    domain_tag ||
    schema_id ||
    canonical_body_bytes
)
```

The typed identity includes algorithm and domain. Canonical body bytes exclude mutable placement, transport framing, store version tokens, and signatures unless the specific schema says otherwise.

### 3.3 Request and transaction identities

A `RequestId` traces one network attempt and has no idempotency authority.

There is exactly one normative derivation of the logical mutation identity:

```text
TxId = H(
    "frankengit/ref-txn/v2" ||
    tenant_id ||
    repository_id ||
    authenticated_principal_id ||
    idempotency_key ||
    canonical_request_digest
)
```

The canonical request digest binds every client-visible semantic field: expected-old refs, proposed new native OIDs, force/atomic flags, push options, requested forge transitions, policy-visible metadata, path/effect scope, and schema version. Pack encoding, quarantine placement, derived object-closure manifest, retry count, receiving node, connection, wall-clock timestamp, random server nonce, and authority-head basis are excluded. Equivalent retries may supply different valid pack encodings for the same requested object identities; the validated closure belongs to prepared evidence, not logical request identity.

Reusing an idempotency key with a different canonical request digest is a typed pre-decision rejection and MUST NOT alias the first request.

## 4. Authority-store contract

Canonical publication requires an `AuthorityStore` implementation that proves:

- strong `put_if_absent` for transaction seals;
- read-after-write consistency for known keys;
- linearizable compare-and-swap replacement of one repository head key;
- no lost updates through gateways, proxies, failover, or replication;
- monotone/ABA-safe version tokens or an equivalent body-generation check;
- complete-or-absent immutable object puts;
- bounded and typed errors;
- authenticated endpoint/credential scope;
- recovery from a known root without relying on object listing.

“S3-compatible” is not a proof. Each backend passes the authority conformance and fault suite. The embedded profile implements the same semantics with FrankenSQLite. A weaker backend cannot be used for canonical mutation merely because it stores bytes durably.

## 5. Sealing and admission

### 5.1 Pre-seal request rejection

Authentication failure, malformed framing, unsupported capability, request-size/resource violation, tenant suspension, and coarse ingress throttling MAY reject before a seal exists. Such a response MUST NOT claim `Committed`, `Refused`, or non-commit after an ambiguous attempt.

### 5.2 Transaction seal

The gateway canonicalizes the semantic request, derives `TxId`, and conditionally creates:

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

The deterministic seal key is scoped by tenant/repository/`TxId`.

- absent → create the stable request-identity body;
- present with matching principal/request/idempotency/schema fields → retry continues using the existing seal;
- present with any conflicting stable field → `IdempotencyKeyReuse` rejection.

Admission capability, policy epoch, issuer, and first-seen time are separate immutable admission receipts over the seal ID; they are not fields a retry must regenerate. Commit policy is reevaluated against the current pinned authority snapshot. A seal is durable identity, not a commit or ordering event. Request-scoped object staging may expire; the seal/request digest persists according to policy so a retry can safely re-upload equivalent missing bodies.

### 5.3 Exactly one terminal decision

A sealed transaction eventually appears at most once in the authenticated decision history as:

```rust
enum DecisionOutcome {
    Committed { repository_commit_id: RepositoryCommitId },
    Refused { code: RefusalCode, refusal_record_id: RefusalRecordId },
}
```

There is no canonical `Cancelled` terminal outcome. Infrastructure interruption before publication leaves the sealed transaction undecided and retryable. Client cancellation cannot erase or redefine a decision.

## 6. Prepared transaction capsule

Validation emits an immutable capsule against one authority-head basis:

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

The capsule MUST bind all inputs needed to decide whether it remains reusable after a lost CAS. It cannot authorize publication by itself.

Preparation includes:

- full Git quarantine/object validation;
- exact native OID and strong-digest checks;
- object closure/reachability;
- expected-old refs and force semantics;
- candidate forge transitions;
- one pinned policy/configuration snapshot;
- capability and quota checks;
- normalized intent/effect construction;
- conflict/read/write witnesses;
- deterministic decision evidence.

## 7. Repository Commit Record

Each successful logical transaction emits one RCR:

```rust
struct RepositoryCommitRecord {
    repository_id: RepositoryId,
    repository_sequence: RepositorySequence,
    parent_rcr_id: Option<RepositoryCommitId>,
    tx_id: TxId,
    principal_snapshot_id: PrincipalSnapshotId,
    canonical_request_digest: Digest,
    ref_delta_root: Digest,
    resulting_ref_root: Digest,
    object_closure_root: Digest,
    forge_event_batch_root: Digest,
    resulting_forge_position_root: Digest,
    policy_epoch: PolicyEpoch,
    policy_decision_root: Digest,
    invariant_evidence_root: Digest,
    outbox_effect_root: Digest,
    retention_delta_root: Digest,
}
```

The RCR identity hashes the unsigned canonical body. `parent_rcr_id` equals the previously committed RCR except repository creation. Source-control ref effects and associated forge transitions are one record. A PR merge cannot become visible without its target ref update, and an RCR classified as a PR merge cannot move the ref without the corresponding forge event batch.

## 8. Repository decision batch and authority head

### 8.1 Decision batch

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
    compaction_generation_link: Option<Digest>,
}
```

A decision sequence is gap-free across all terminal decisions. Repository sequence is gap-free across committed RCRs. Batch order is deterministic and each decision is evaluated with read-your-own-prior-decisions within the batch.

`batch_evidence_root` has one meaning: a Merkle commitment over this batch's
decision evidence. Its leaves follow `decisions` in canonical decision-sequence
order. A committed leaf carries that decision (including its final
`RepositoryCommitId`) followed by the canonical payload of its matching RCR,
which binds the policy, invariant, outbox, retention, and forge evidence roots.
A refused leaf carries that decision and its `RefusalRecordId`; the immutable
refusal record identity binds the refusal's evidence root. Leaves use the
registered `MerkleLeaf` domain, interior nodes use the registered `MerkleNode`
domain, both use schema family `decision-batch-evidence-merkle` version `1.0`,
and an odd-width level duplicates its final child. One decision has its leaf as
the root. `PublicationPlan::seal` derives and verifies this root from final
stamped records; no admission provider or caller may mint it.

`compaction_generation_link` is separately optional. It is `Some` exactly for
a compaction publication and carries that compaction record's generation
identity digest; ordinary decision batches carry `None`. Compaction validates
this linkage field and never repurposes `batch_evidence_root` for it.

### 8.2 Authority head

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

### 8.3 Linearization point

The mutation linearizes at the successful conditional replacement of the repository head from the exact predecessor authority version token to the new authenticated head bytes.

That successful conditional replacement of the repository head simultaneously makes canonical:

- every terminal decision in the referenced batch;
- each committed RCR in order;
- resulting ref and forge-position roots;
- outcome-index root;
- retention and outbox roots;
- policy/configuration position encoded in the head.

Bodies may be staged earlier but are unreachable canonically. External effects occur later through outbox obligations. Refusals consume decision sequence but do not advance repository sequence or source/forge roots.

### 8.4 Outcome accelerators

A direct `TxId` → decision pointer is a repairable accelerator, not a second truth. If missing after a crash, replay from the authority head reconstructs it. A conflicting accelerator fails closed.

The terminal decision record and the successor-head conditional replacement are **one atomic publication**: the outcome entry is part of what the head CAS makes durable, never a separate write issued after it. §8.3 already makes the referenced batch's terminal decisions canonical at that single linearization point, and this clause states the consequence a publisher must not evade — completing a decision with a second write that can be lost creates a window in which a head is canonical while its decision record is not. Duplicate-decision detection therefore consults the **authenticated decision stream reachable from the current head, never the presence or absence of an accelerator entry**. A missing accelerator row means "resolve this authoritatively from the head", never "no decision exists"; that inference is a time-of-check/time-of-use error which promotes a derived projection to authority, and a derived index may accelerate but never decide. A CAS loser reuses, revalidates, and reprepares the same sealed request and converges on the one terminal outcome. Ruled on bead `frankengit-fg007b-seal-races-ujf`, comment 1243, after an independent seal-race campaign exhibited a lost-response schedule that admitted a second terminal decision for a single `TxId`.

## 9. Publication epochs

Every persistent pipeline distinguishes **staged**, **visible**, and **durable**, but FrankenGit does not impose one universal ordering that would contradict different acknowledgement profiles.

- **staged:** immutable candidate bodies exist but no authority root references them;
- **visible:** an authority or generation root references them and clients may observe them;
- **durable:** the declared placement/repair/failure-domain predicate is satisfied.

Allowed transition graphs are profile-versioned. The default canonical source-code profile is:

```text
Absent -> Staged -> DurabilitySatisfied -> Visible
```

A lower-value derived generation MAY use:

```text
Absent -> Staged -> Visible(with DurabilityObligation) -> Durable
```

A workspace MAY have a local-visible overlay before a root-last durable snapshot. Every acknowledgement names the exact state/profile and outstanding obligation. Upload completion never implies visibility or durability, and visibility never implies a stronger durability class unless the profile proves it.

## 10. Canonical transaction algorithm

```text
handle(request, authenticated_principal, request_context):
  1. Perform bounded framing/protocol/size/coarse authorization checks.
  2. Canonicalize the complete semantic request.
  3. Derive the one TxId defined in §3.3.
  4. Query the outcome accelerator and authenticated outcome index.
  5. Conditionally create the stable TransactionSeal or verify the existing seal’s stable fields.
  6. Reserve object/quota/preparation obligations.
  7. Read one authenticated RepositoryAuthorityHead H and required immutable roots.
  8. Validate quarantine/object graph and compute exact closure C.
  9. Evaluate intents in source order against snapshot H with read-your-own-writes.
 10. Pin one policy/configuration epoch and evaluate deterministic policy.
 11. Produce target-disjoint net effects, witnesses, and PreparedTxnCapsule P.
 12. Publish P to a bounded per-core ready slot.
 13. A combiner rereads current head Hc and selects compatible ready capsules.
 14. Revalidate/refine witnesses and sequentially execute candidates on scratch state.
 15. Stage the RepositoryDecisionBatch B, RCR bodies, roots, and candidate head Hn.
 16. Attempt compare_exchange(head_key, Hc.version_token, canonical(Hn)).
 17. If CAS wins, settle publication obligations and return/query terminal outcome.
 18. If CAS loses, reread authority; if TxId is now terminal, return it.
 19. Otherwise deterministically preserve, refine, rebase, or re-evaluate the same sealed request.
 20. Drain outbox/materialization effects after commit under separate obligations.
```

No step shells out to Git in production. No policy decision reads mutable external network state inside the publication boundary.

## 11. Per-core preparation and microbatching

- A transaction remains owned by one preparation lane after parsing begins.
- Lane-local buffers and object validators avoid shared hot-path mutation.
- Ready-slot publication is reserve/commit/abort.
- A combiner may batch multiple compatible decisions into one head CAS.
- The deterministic selection/tie-break policy is versioned and receipted.
- Interactive latency, bytes, decisions, witness work, and policy epochs bound a batch.
- Two combiners may race; the head CAS, not combiner identity, establishes authority.

Each logical transaction retains its own `TxId`, terminal outcome, and RCR. Batching never changes client atomicity.

## 12. Conflict witnesses and value-of-information refinement

Prepared transactions begin with conservative witnesses over:

- exact or family-level refs;
- forge entities/streams;
- protection/CODEOWNERS/check policy;
- quotas and billing reservations;
- retention/legal-hold state;
- merge-queue prefix;
- object-closure assumptions;
- graph/search generation inputs used by policy.

After a lost CAS, exact changed roots are compared. If coarse witnesses collide, refinement MAY compute finer path, entity, symbol, subtree, or counter witnesses when expected saved abort/revalidation cost exceeds bounded refinement cost.

Refinement obeys:

1. it can only reduce a conservative false-conflict set;
2. it cannot change the sealed request;
3. it cannot waive policy or expected-old semantics;
4. inconclusive/failed/over-budget refinement retains the coarse conflict;
5. every refinement decision and input root is receipted.

## 13. Intent/effect semantics

Canonical commands are intents, not pre-baked effects. Evaluation is source-ordered and supports explicit mismatch policies:

- `NoOp`;
- `StatementError` where the transaction schema permits statement-local failure;
- `TxnAbort`.

Finalization folds intermediate intents/effects against basis and after-image into target-disjoint net-effect normal form. Every source intent maps to a surviving effect, identity/inverse/absorption no-op, statement error, or transaction abort. Sorting serialized effects MUST NOT alter semantic applicability.

Identity at evaluation takes precedence over last-writer provenance. When two source intents address the same target and the later intent's requested after-state already equals the scratch state at its own evaluation point, the later intent is the identity no-op and the earlier intent is the surviving effect — uniformly, and regardless of whether that scratch state arose from the basis or from the earlier intent. The identity classification is a local predicate on the pair (requested after-state, scratch state at evaluation) under read-your-own-writes; making it depend on how the scratch state came to hold that value would destroy that locality and make the disposition of an intent a function of history it cannot observe. Absorption by a succeeding intent is therefore reserved for a succeeding intent that requests a *different* after-state, which is a real overwrite. The surviving source MUST be the intent that produced the final transition: a later coincidental restatement did not produce it, and attributing the transition to it would make the recorded provenance causally false while leaving the folded effect and the total source map unchanged — which is precisely why the ambiguity is invisible to a normal-form equality check and must be fixed here rather than left to an implementation. In the reference vocabulary the two dispositions are `Absorbed(IdentityEffect)` and `Absorbed(OverwrittenBySucceedingIntent)`. Ruled on bead `frankengit-fg008a-normalform-impl-txh`, comment 1133, after a differential disagreement whose minimised case is pinned as permanent regression seed `0x5eed0008b00b1f2`.

Git receive-pack atomic capability maps all commands to one transaction. Without atomic capability, the mapping from a session to independently terminal ref transactions is explicit and replayable.

## 14. Cancellation and ambiguity

1. **Before seal:** cancellation may leave no canonical trace.
2. **After seal, before head CAS:** cancellation stops new work, drains effects, and may abandon staged candidates; the sealed request remains retryable and undecided.
3. **After head CAS:** canonical decision remains; only response/outbox/materialization work may cancel.

An API MUST NOT return `cancelled` in a form that proves non-commit after the CAS could have occurred. Ambiguous disconnects resolve by `TxId` lookup.

Asupersync regions own every child task, socket, process, credential, reservation, and obligation. Region close ends in quiescence or an explicit non-cooperative containment failure.

## 15. CALM and coordination

Every operation is registered according to `CALM_AND_OBLIGATIONS.md`.

Coordination-free after authentication:

- immutable verified object/segment/symbol/evidence puts;
- authorized cache warming;
- candidate generation bodies;
- replica/gossip hints.

Head/generation authority required:

- terminal outcomes;
- ref movement/deletion;
- forge state transitions;
- policy/generation activation;
- retention removal;
- package/release uniqueness;
- destructive GC publication.

Non-canonical replicas use conflict-absorbing lattices. Canonical refs/order are never last-writer-wins CRDT state.

## 16. Git transport and admission

### 16.1 Service precision

- clone/fetch negotiate with `git-upload-pack` over smart HTTP or SSH;
- push negotiates with `git-receive-pack` over smart HTTP or SSH;
- Git protocol v2 capability/commands apply where standardized, especially fetch-oriented `ls-refs` and `fetch`;
- FrankenGit MUST NOT claim a standardized “protocol v2 push” command.

ATP-Git is a separate FrankenGit-native capability, not a reinterpretation of Git protocol v2.

### 16.2 Quarantine

Incoming bytes remain transaction-scoped and non-retained until bounded validation covers:

- pkt-line and sideband framing;
- pack header/trailer/checksum;
- decompression and expansion ratio;
- delta depth/fan-out/aggregate work and cycles;
- thin-pack bases;
- object header/type/declared length;
- tree ordering/mode/name rules;
- commit/tag headers and encoding limits;
- native hash format;
- missing objects and exact reachability;
- hidden/advertised ref authorization;
- expected-old/force/atomic semantics;
- signed-push certificate policy;
- quotas, cancellation checkpoints, and wall/memory budgets.

Promotion is by verified identity and canonical retention root, never mutable directory rename as truth.

### 16.3 Fetch and partial clone

Partial clone/promisor state is a transfer/materialization optimization. Canonical retention remains complete. Probabilistic have summaries may reduce first-round bytes but cannot prove closure; final exact verification requests missing objects.

## 17. Object fabric and segmentation

Canonical Git objects preserve native OIDs and exact logical bytes. Internal envelopes may add strong digest/type/length. Object-aware segments provide:

- deterministic object ordering/profile;
- Merkle/index footer;
- range reads;
- content-addressed identity;
- immutable compaction inputs/outputs;
- RaptorQ profile where registered;
- rebuildable OID-to-location indexes.

Segment layout cannot alter logical object identity. Small-object, large-blob/LFS, hot/cold, and pack-view lanes are explicit profiles.

## 18. ATP-Git

FrankenGit-native transfer follows `ATP_GIT_PROFILE.md`:

- object/segment manifests;
- bounded exact/probabilistic have summaries;
- unique-payload deduplication;
- object/segment/pack delta plans and typed full fallback;
- typed path graph and bounded race/loser drain;
- swarm piece verification, rarity, and endgame caps;
- trust-scoped caches;
- RaptorQ transport with adaptive policy and hard bounds;
- deterministic receipts and path-trace replay.

Ordinary Git clients still receive standard Git streams.

## 19. TreeFS workspaces

`GIT_TREE_FS.md` is normative for sparse workspaces:

- immutable base commit/tree plus COW overlay;
- descriptor/capability-relative paths;
- no host traversal through Git symlinks;
- explicit case/Unicode/host representability behavior;
- lazy authorized fetch;
- source-ordered edit intents and total net-effect mapping;
- hierarchical conflict witnesses and proof-ordered merge ladder;
- staged/visible/durable workspace epochs;
- FUSE/FrankenFS or deterministic sparse-directory adapters;
- no ambient sponsor token or cloud metadata.

A workspace snapshot is a derived identity and cannot move repository refs without a normal sealed transaction.

## 20. Forge events and projections

Canonical forge entities are immutable events included in RCR batches. Issues, PRs, reviews, protections, queues, releases, packages, and administrator overrides use stable entity IDs and stream sequences.

Read models, counters, notifications, web views, search, and graphs are projections. Each records source RCR/forge position and may lag. A stale projection cannot authorize mutation without canonical revalidation.

Outbox delivery is at least once unless a downstream protocol proves stronger semantics. Stable delivery IDs and obligations prevent canonical event duplication. A failed webhook never rolls back an RCR.

## 21. Graph and search generations

Graph/search generations follow anti-rollback activation and `GRAPH_INTELLIGENCE_ARCHITECTURE.md`.

- Exact, deterministic-derived, and statistical graph classes remain distinct.
- Every graph algorithm that affects ordering/selection emits a tie-break/complexity/decision-path witness.
- Mixed-generation results are prohibited by default.
- Context Packets name every source generation and omission class.
- Centrality, semantic similarity, and inferred edges may rank/prioritize but cannot grant authorization, prove guilt, or justify deletion.
- Exact reachability used for retention/GC retains scalar/reference verification.

## 22. Generation publication

Search, graph, compaction, policy, workspace, and release generations use immutable bodies plus an anti-rollback authority record:

- exact predecessor;
- monotone sequence/generation;
- pending-attempt reconciliation;
- body/manifest/closure verification;
- fail closed on highest acknowledged generation corruption;
- older generation only through explicit restore/demotion policy.

A built directory is not active merely because it exists locally.

## 23. Repository capsules, backup, and restore

A capsule body binds exact authority head/RCR, decision-log position, ref/forge/object/segment/retention roots, policy/configuration/format epochs, and backup profile. Capsule ID hashes the unsigned body; signatures, placements, and repair-symbol locations attest to it but do not participate in identity.

`RepositoryCapsuleBody` also binds `outcome_index_checkpoint_root`: the
identity digest of the immutable `OutcomeIndexCheckpointBody` selected for that
capsule, or an explicit absent value when no checkpoint is available. This is
not `outcome_index_root`. A bare outcome-index root cannot accept a later
terminal outcome under the digest-sorted commitment, so it cannot terminate the
cumulative fold.

An `OutcomeIndexCheckpointBody` is repository-scoped immutable evidence. Its
canonical bytes bind the repository ID; the exact decision-tail ID and terminal
decision sequence it covers (both are present or both absent); its immediate
predecessor checkpoint digest (absent only at genesis); and the complete
retained terminal-decision leaf material in the authority-owned
digest-sorted outcome-index order. Its body identity is
`outcome_index_checkpoint_root`. A decoder re-derives that identity, verifies
the repository and exact position pairing, re-canonicalizes the retained leaf
material under the authority's one commitment order, and verifies every
predecessor link. A mismatched identity, leaf order, repository, position, or
predecessor is refused as unusable checkpoint evidence.

Outcome-index derivation first uses verified checkpoint leaves and replays only
terminal outcomes strictly after the checkpoint position. The decision-tail
bound therefore applies to that replay suffix rather than to the retained
prefix. A checkpoint predecessor walk accepts at most
`MAX_CHECKPOINT_PREDECESSORS = 65,536` links; a cycle is refused, and a
65,537th link returns the typed `PredecessorChainTooLong` refusal. Missing,
undecodable, mismatched, or otherwise unusable checkpoint evidence falls back
to the existing bounded genesis walk and retains its typed
`ReplayBoundExceeded` refusal rather than substituting a partial leaf set.

Checkpoint publication follows this section's root-last, anti-rollback rule:
stage and verify the complete immutable checkpoint evidence and predecessor
chain; bind its exact digest in the exact-head capsule body; then advance the
capsule pointer. A checkpoint older than the authenticated head position is an
acceleration hint, never current-state authority. The newest acknowledged
capsule root remains authoritative; recovery must not silently replace it with
an older checkpoint root.

Publication is root-last:

1. stage referenced immutable data/manifests;
2. verify identities/closure;
3. collect required durability evidence;
4. hash unsigned body;
5. sign according to deployment profile;
6. publish exact-head capsule pointer through anti-rollback authority;
7. only then consider superseded checkpoint material for retention review.

Recovery MUST NOT silently fall back to an older valid capsule when the newest acknowledged root is structurally present but fails authentication/closure. Older-state recovery is an explicit audited restore that advances a new authority generation.

A capsule is evidence of what was bound at publication, and nothing more. It does **not** prove that its contents are readable **now**: verifying a capsule establishes that the body is intact and its identity holds, not that the codec, key material, storage backend, or toolchain required to restore from it are still available at the moment of reading. A capsule that passes every digest check can still be unrestorable, and only an executed restore drill says otherwise. Nor does a capsule prove that any **recovery point or recovery time objective was met**: possession of a body attests to a bound position in the decision log, never to the interval between that position and the failure, nor to the duration of the recovery that follows. RPO and RTO are measured properties of a drill, and a capsule is an input to that measurement rather than a substitute for it. A signature over a capsule carries the same limit as every other signature in this document — it is evidence of authorship, never of trustworthiness (§ADR-0003) — so a signed capsule is not thereby a trusted one.

These are the three ways possession of a capsule is over-read, and they are stated here because the recovery chain built on this section consumes the capsule vocabulary and inherits the temptation.

## 24. RaptorQ and repair

RaptorQ is an erasure-recovery mechanism for registered immutable byte objects. It is not a hash, signature, authorization system, ordering protocol, consensus algorithm, freshness oracle, or substitute for the authority head.

Every encoded class declares source identity, symbol/profile parameters, placement domains, decode work/memory/input bounds, trigger/escalation, and post-decode checks. Candidate bytes are accepted only after original digest/OID/Merkle/canonical codec/length/type invariants pass.

Repair then uses the same current mutation authority:

1. decode in quarantine;
2. verify original commitments;
3. compare current placement/retention witness;
4. put immutable repaired bytes idempotently;
5. submit `RepairPlacementIntent`;
6. publish through head CAS or refuse/rebase stale repair;
7. record repair evidence.

The mutable authority head and current authorization/legal-hold state are not fountain-code reconstructed. Individual seals and decisions are small immutable records whose current meaning comes from the authenticated decision stream/checkpoint, not an opportunistic decoder result.

## 25. Garbage collection and retention

Authenticated roots include:

- current/protected/hidden refs;
- open PR/merge-queue refs;
- active seals/staging grace policy;
- releases/packages/artifacts/provenance;
- legal holds/admin pins;
- capsules/backups;
- migration/replication handoff;
- active workspaces/CI/agent effects where promised;
- grace tombstones.

GC is mark → proof → grace/replica/backup horizon → revalidation against current head/policy → sweep → evidence. Local `git gc`, cache eviction, or incomplete graph projection never decides canonical deletion.

## 26. Statistical adaptation and policy epochs

Conformal predictors, e-processes/e-martingales, no-regret controllers, off-policy evaluation, regime detectors, and Lyapunov/progress certificates may adapt only registered operational targets such as:

- batch/retry/path-race width;
- cache/prefetch;
- RaptorQ overhead and scrub priority within hard bounds;
- search/rerank/context budgets;
- canary escalation and reversible throttling;
- placement/capacity proposals.

Every adaptive artifact binds population, selection rule, exact sequence window, regime, candidate, pinned fallback, assumptions, action probabilities where relevant, numeric/toolchain/math fingerprint, and bounded retained evidence.

Promotion uses an exact-predecessor policy epoch. Unsupported assumptions, regime shift, incomplete support, evidence gap, arithmetic/resource bound, or alarm retains/reverts to deterministic fallback.

Statistical systems MUST NOT decide Git identity, head/RCR order, ref atomicity, authorization grants, signature validity, retention roots, committed existence, guilt, or irreversible punishment.

## 27. Claim and replay classes

Claims follow the checked lattice:

```text
invariant > proof > bounded_model > statistical > slo > benchmark
```

Weaker evidence cannot justify a stronger claim. Every artifact declares replay completeness:

- exact replay;
- structural replay;
- verifiable with named external artifacts;
- audit-only.

One trace, benchmark, or deployment does not become universal correctness or SLO evidence.

## 28. Agent authority

An agent acts only through a sponsored `IntentRun` binding:

- sponsor and agent/model/harness identities where available;
- repository and verified base `AuthorityReadReceipt`, plus an optional checkpoint and replayed suffix;
- allowed refs, paths, reads, effects, and secret classes;
- compute/storage/network/money/time budgets;
- expiration/revocation;
- required verifier-independence classes;
- disclosure/provenance policy.

Context Packets are content-addressed, source-positioned, authorization-scoped, and omission-explicit. Repository text cannot widen capabilities or approve effects.

An Evidence-Carrying Change binds proposed object/tree closure, base, TreeFS intent/effect map, Context Packets, tests/checks/tool receipts, resource use, claimed invariants, non-claims, omissions, and verifier attestations. Verifier independence is machine-classified over workspace, credentials, model/harness, context, oracle, sponsor, and human dimensions.

Intent-Run cancellation drains tasks, mounts, subprocesses, effect obligations, and secret leases. No orphan retains a push credential.

## 29. CI and hostile execution

CI is a separate hostile-compute plane. A job binds exact source/workspace input, runner image/toolchain, dependency locks, network/secret/cache policy, resources, logs/artifacts, and cancellation receipt. No cloud metadata or sponsor credential is ambient.

A green check means the named check produced a valid receipt in its evidence class. It does not prove universal safety.

## 30. Local verification and release

FrankenGit MUST NOT rely on GitHub-hosted Actions. `.github/workflows` are dispatch-only portable adapters that delegate to repository-owned commands and are intended for Doodlestein Self-Releaser/`act`. Deliberately enabled remote execution is non-authoritative and cannot replace any local evidence gate.

The authoritative release process follows `LOCAL_VERIFICATION_AND_RELEASE_PIPELINE.md`:

- attempt-scoped native target builds;
- resumable verified completed targets;
- exact asset contract;
- checksums, SBOM, provenance, signatures, installer/smoke tests;
- authoritative manifest withheld until every requested target succeeds;
- signed root-last local release manifest;
- remote GitHub Release reconciliation as distribution, not build truth.

A partial matrix cannot become an authoritative release.

## 31. Security and non-claims

FrankenGit does not claim:

- content addressing proves authorship;
- signed commits imply trustworthy code;
- object-store durability equals recoverability;
- RaptorQ detects malicious corruption without commitments;
- deterministic replay captures unrecorded external effects;
- a green CI job or agent explanation proves correctness;
- branch protection prevents privileged override abuse;
- Rust’s type system eliminates logic, crypto, parser, or authorization bugs;
- a graph/model score proves guilt or grants authority.

Untrusted surfaces include Git/pack parsers, archive/package/LFS import, Markdown/SVG/rendering, webhooks/URLs, CI, agent tools, object-store responses, backup/repair symbols, workflow parsing, and migration.

## 32. Minimum release-blocking invariants

The mutation/storage core cannot be called complete until executable evidence covers at least:

1. one canonical `TxId` derivation and key-reuse mismatch rejection;
2. at most one terminal decision per sealed `TxId`;
3. lost response/cancellation cannot create two outcomes;
4. head generation/predecessor and decision/RCR sequence continuity;
5. one head CAS publishes ref and forge effects atomically;
6. CAS losers preserve the same sealed request;
7. expected-old/force/atomic semantics under races;
8. one pinned policy/configuration snapshot per attempt;
9. witness refinement only removes false conflicts;
10. no staged/quarantined object becomes a retention root before commit;
11. committed closure is protected before acknowledgement according to profile;
12. SHA-1 and SHA-256 cannot collide at the type boundary;
13. production cannot invoke/link an external Git engine;
14. every first-party crate forbids unsafe;
15. replica conflict lattices do not hide contradictory terminals;
16. generation activation is exact-predecessor and anti-rollback;
17. carried-forward checkpoint cannot masquerade as current forge position;
18. repaired bytes require original commitments and current-authority publication;
19. projection/search/graph lag cannot authorize mutation or deletion;
20. no mixed-generation Context Packet without explicit joined receipt;
21. GC cannot sweep authenticated, held, active, or grace roots;
22. outbox retry cannot duplicate canonical events;
23. all effect obligations settle at region close;
24. Git receive-pack conformance does not rely on fictional protocol-v2 push;
25. verifier independence class is enforced, not self-declared;
26. release manifest cannot publish a partial target matrix;
27. every commit/refusal is explainable from immutable evidence roots;
28. crash/replay at every staged/visible/durable boundary converges or fails closed.

These contracts dominate performance, sharding, cache locality, hosted convenience, and agent autonomy.

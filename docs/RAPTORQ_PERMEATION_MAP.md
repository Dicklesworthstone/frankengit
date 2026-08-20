# FrankenGit RaptorQ Permeation Map

**Status:** Required architecture registry; implementation status is initially `specified` for every row.

> RaptorQ is used only for registered immutable byte objects. Decode success is never acceptance: the original cryptographic identity and structural codec must verify. RaptorQ does not provide authorization, consensus, ordering, freshness, or mutable-metadata durability. See [`NORMATIVE_PROTOCOL_CONTRACTS.md`](NORMATIVE_PROTOCOL_CONTRACTS.md#8-raptorq-and-repair-boundaries).

## 1. Doctrine

Every subsystem that persists, transfers, or archives a large immutable byte object must answer:

1. What are the canonical source bytes?
2. What original identity authenticates them?
3. Is RaptorQ useful for this object and failure model?
4. What are the exact coding parameters and maximum decoder resources?
5. Across which independent failure domains are source/repair symbols placed?
6. What triggers decode, and who is allowed to publish repaired placement?
7. Which original commitments and structural invariants must pass after decode?
8. What typed failure is returned beyond the repair budget?

“RaptorQ everywhere” means every eligible durable immutable class is considered and registered. It does **not** mean every byte is coded or that mutable control state uses fountain codes.

## 2. Object registry

| Key | Canonical source bytes | Original commitment | Intended use | Post-decode verification | Status |
|---|---|---|---|---|---|
| `git_loose_object_envelope` | typed Git object header plus uncompressed canonical body | native Git OID plus internal envelope ID | cold-object repair and transfer | length, type, native Git OID, envelope ID | specified |
| `git_pack_segment` | immutable validated pack segment with manifest | cryptographic segment ID, pack/object manifest roots | bulk storage and regional replication | segment ID, pack checksum, index/object closure | specified |
| `repository_object_segment` | sorted immutable object-envelope batch | segment ID and Merkle root | canonical object store compaction | canonical codec, every entry ID, Merkle root | specified |
| `repository_capsule_body` | unsigned canonical capsule body | `RepositoryCapsuleId` | checkpoint recovery | body ID, referenced RCR and root closure | specified |
| `capsule_manifest_segment` | immutable capsule dependency manifest | manifest ID/Merkle root | checkpoint distribution | canonical decode and every referenced ID | specified |
| `forge_event_segment` | ordered canonical event envelopes | segment ID, stream-chain roots | event-history backup/replication | event IDs, ordering, chain links, stream root | specified |
| `ref_snapshot_segment` | authenticated ref trie/radix segment | segment ID and resulting ref root | fast recovery/materialization | sorted canonical refs, node IDs, root recomputation | specified |
| `object_location_segment` | object ID to immutable placement records | segment ID/root | rebuildable location index checkpoint | canonical ordering, placement syntax, source-object existence | specified |
| `retention_root_segment` | legal hold, grace, backup, release, PR, and ref roots | retention manifest ID/root | GC safety checkpoint | canonical codec, policy epoch, root closure | specified |
| `search_generation_segment` | immutable lexical/vector index generation bytes | generation manifest ID and file digests | cheap index repair, never canonical truth | format checks, file digests, source-position receipt | specified |
| `graph_projection_segment` | immutable graph projection shard | generation ID and source-position root | repairable derived graph | schema/ID checks, source position, generation root | specified |
| `ci_artifact_chunk` | immutable uploaded artifact chunk | artifact digest and chunk manifest | hosted artifact durability | chunk digest, full artifact digest, manifest | specified |
| `ci_log_segment` | immutable sealed log bytes | log segment ID and run/evidence root | log durability/stream repair | digest, sequence, run binding, redaction policy | specified |
| `release_asset_chunk` | immutable release asset bytes | asset digest/manifest | release distribution | chunk/full digest, release-event binding | specified |
| `package_blob_chunk` | immutable OCI/package blob bytes | registry-native digest plus internal ID | package storage/replication | native digest, media type, manifest closure | specified |
| `lfs_object_chunk` | Git LFS object bytes | LFS SHA-256 OID and manifest | LFS durability/transfer | LFS OID, length, manifest | specified |
| `backup_stream_block` | canonical backup bundle block | backup manifest and block ID | offline/site-loss recovery | block ID, backup root, restore rehearsal | specified |
| `bulk_transfer_frame` | immutable transport block | object/segment ID and frame commitment | lossy/high-RTT transfer | frame auth, reconstructed object commitment | specified |

## 3. Explicit exclusions

These classes must use replicated transactional storage, consensus/fencing, checksums, backups, and ordinary recovery—not RaptorQ as a correctness dependency:

| Excluded mutable/control state | Reason |
|---|---|
| repository head pointer | current ordering and linearization authority |
| writer lease / epoch | freshness and stale-writer fencing |
| transaction seal | idempotency authority |
| `TxnOutcomeRecord` key/value | linearizable terminal result |
| authorization membership / revocation | current security policy |
| policy epoch pointer | current decision authority |
| quota/billing counters | transactional accounting |
| outbox delivery cursor | mutable delivery coordination |
| merge-queue scheduler state | current ordering/admission |
| legal-hold activation pointer | deletion safety authority |

Immutable snapshots or backups of those records may be encoded, but recovery must restore through the metadata system’s own consensus and validation protocol.

## 4. Coding envelope

Each encoded object has a canonical envelope:

```rust
struct RqObjectEnvelope {
    registry_key: DurableObjectKey,
    registry_epoch: RegistryEpoch,
    source_object_id: InternalObjectId,
    source_length: u64,
    source_digest: TypedDigest,
    symbol_size: u32,
    source_symbol_count: u32,
    repair_profile: RepairProfileId,
    object_specific_commitments: Vec<TypedCommitment>,
}
```

The envelope identity is authenticated independently of symbol payloads. Symbol identifiers include the source object ID, encoding symbol ID, profile, and envelope version. Implementations reject mixed source objects/profiles rather than handing attacker-selected symbol sets to an unbounded decoder.

## 5. Resource bounds

Every profile publishes hard limits:

- maximum source length and symbol count;
- symbol size range;
- maximum accepted repair symbols;
- duplicate-symbol handling;
- maximum matrix/decode memory;
- CPU/work-unit budget;
- cancellation checkpoints;
- maximum concurrent decodes per tenant/node;
- spill-to-disk behavior;
- malformed-symbol refusal codes.

Decode admission reserves resources before expensive work. A missing or corrupt object does not justify unbounded CPU or memory use.

## 6. Placement

Repair value depends on independent failures, not raw symbol count. Placement policy records domains such as:

- device;
- host;
- rack/availability zone;
- object-store failure domain;
- region;
- provider/account where contractually allowed;
- offline backup set.

Two symbols on the same doomed disk are not two durable copies. Placement receipts are attestations over an immutable object ID and policy epoch; they are excluded from the source object’s identity.

## 7. Repair protocol

1. Detect missing/corrupt source or failed commitment verification.
2. Pin the expected immutable source object ID and registry/profile epoch.
3. Collect authenticated, de-duplicated symbols within admission budgets.
4. Decode into a quarantine buffer.
5. Verify expected length and source digest.
6. Verify object-specific commitments: Git OID, Merkle root, codec, sequence, manifest closure, etc.
7. Record a `DecodeProof`/repair evidence artifact containing inputs, profile, work, and checks.
8. Publish repaired immutable placement idempotently.
9. Update derived location indexes after source identity is proven.
10. Escalate typed `InsufficientSymbols`, `CommitmentMismatch`, `MalformedEnvelope`, `BudgetExceeded`, or `RegistryUnsupported` when recovery cannot be accepted.

The repair path never mutates the logical object body. If decoded bytes do not match the original commitment, the system reports corruption or malicious input; it does not bless a new identity under the old name.

## 8. Adaptive overhead

A controller may choose repair overhead within deterministic minimum/maximum profiles using observed loss, durability, cost, and decode performance. Conformal bounds or e-process alarms may trigger reversible profile changes, but:

- the hard minimum for the object class remains enforced;
- observations and controller state are replayable;
- a regime change resets or widens uncertainty conservatively;
- no controller can reduce already-promised retention below policy;
- statistical evidence cannot waive post-decode commitments;
- an offline deterministic profile is always available.

## 9. Required evidence

A registry row cannot advance beyond `specified` without:

- canonical encoding goldens;
- independent encoder/decoder or RFC conformance vectors where applicable;
- random and adversarial erasure campaigns;
- bit-flip, truncation, duplication, and symbol-mix attacks;
- resource-exhaustion tests;
- cancellation and crash tests;
- post-decode commitment-negative tests;
- multi-domain placement simulations;
- end-to-end restore/rebuild rehearsal;
- benchmark artifacts for encode/decode overhead;
- proof that the uncoded compatibility path remains available where required.

## 10. Non-claims

A row marked `verified` means the named evidence passed for the named profile and corpus. It does not prove permanent recoverability, Byzantine consensus, malicious-provider resistance beyond authenticated commitments, or universal economic superiority. Public durability claims must include profile, placement assumptions, repair horizon, evidence date, and restore command.
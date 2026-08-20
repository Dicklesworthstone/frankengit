# FrankenGit RaptorQ Permeation Map

**Status:** normative design registry draft
**Last updated:** 2026-08-19

RaptorQ is a systematic fountain-code family used to reconstruct exact source bytes from a sufficient set of source and repair symbols. In FrankenGit it is a durability, repair, and transfer mechanism for selected immutable byte structures. It is not a hash, signature, encryption scheme, consensus protocol, transaction log, authorization system, or substitute for tested backups.

This document prevents “RaptorQ-enabled” from becoming a vague architectural adjective. Every durable or bulk-transferred byte structure must declare one of:

- **MUST encode:** the native format includes a required RaptorQ repair contract;
- **POLICY:** encoding is selected by an explicit durability/size/deployment policy;
- **MAY encode:** supported but not required for correctness or the default profile;
- **EXEMPT:** deliberately not encoded at this layer, with a stated protection mechanism;
- **DEFERRED:** decision blocked on measurement or a lower-layer contract.

The executable registry will supersede this prose when implemented.

---

## 1. Universal reconstruction contract

For every encoded object class, the registry row MUST define:

1. **Canonical source bytes:** the exact byte string being protected.
2. **Object identity:** tenant/namespace, class, format version, source length, and end-to-end digest.
3. **Partitioning:** source-block boundaries, symbol size, padding rules, and deterministic parameter derivation.
4. **Symbol identity:** object identity, source-block number, symbol index, codec/version, and length.
5. **Placement:** failure domains and rules preventing correlated loss.
6. **Minimum and adaptive redundancy:** deterministic floor, allowed upper bound, controller inputs, and fallback.
7. **Repair trigger:** scrub failure, missing replica, transfer loss, disaster restore, or explicit drill.
8. **Decode budget:** maximum symbols, memory, CPU, retries, and wall-clock duration.
9. **Verification:** exact digest plus structural checks required before admission.
10. **Evidence:** reconstruction fixture, fault campaign, performance/cost comparison, and production drill cadence.
11. **Deletion interaction:** when source and repair symbols may be garbage-collected.
12. **Encryption interaction:** whether encoding occurs before or after encryption and how keys/nonce metadata are protected.

A decoder returning bytes is not success. Success requires exact verification and admission under the destination object class.

---

## 2. Registry

| Object class | Status | Canonical source bytes | Verification after decode | Primary purpose |
|---|---|---|---|---|
| Git loose object ingress bytes | EXEMPT | client-supplied compressed or loose representation | Git framing/OID after normalization | transient compatibility input |
| Admitted Git object microsegment | MUST encode | deterministic microsegment containing exact admitted object records | segment digest, Merkle footer, each record length/type/Git OID | durable repository object fabric |
| Large immutable object segment | MUST encode | sealed segment bytes | segment digest, Merkle root, manifest, record checks | storage-efficient durability and repair |
| Repository Capsule record | EXEMPT at record layer | canonical capsule bytes | digest, signature, predecessor/root checks | small critical record; replicated transactionally |
| Capsule/checkpoint export bundle | MUST encode | canonical export bundle including manifests and required event ranges | bundle digest, member roots/signatures, replay validation | disaster recovery and offline transfer |
| Repository Commit Record | EXEMPT at record layer | canonical commit body plus receipt envelope | authority-domain replication, digest chain, state-machine replay | tiny ordered truth; coding adds little value |
| Repository Commit checkpoint segment | MUST encode | sealed authority-domain checkpoint/segment | segment root, commit chain, ref/event replay equivalence | durable log compaction and disaster restore |
| Forge event record | EXEMPT at record layer | canonical event bytes | event identity/signature/stream position | small ordered truth |
| Forge event segment/checkpoint | MUST encode | sealed event segment or projection-independent checkpoint | segment root, stream-chain, deterministic replay | durable collaboration recovery |
| Policy/key-history checkpoint | MUST encode | encrypted canonical checkpoint bundle | AEAD, digest, signatures, semantic validation | recover authorization interpretation |
| Search index generation | MAY encode | immutable index files/manifest | generation digest and rebuild comparison | faster recovery; index remains derived |
| Graph projection generation | MAY encode | immutable projection files/manifest | generation digest and replay/rebuild checks | faster recovery; graph remains derived |
| Embedding/vector generation | POLICY | immutable authorized index generation | digest, model/index identity, authorization scope | avoid expensive recomputation where economical |
| Git pack generated for fetch | EXEMPT | generated pack stream | pack checksum and requested-object closure | disposable compatibility output |
| Native FrankenGit bulk transfer stream | POLICY, default on large streams | exact object/segment/bundle bytes | end-to-end object digest and manifest | loss-resilient parallel transfer |
| Cross-region segment transfer | MUST encode for native transport | sealed segment bytes | destination digest/Merkle/manifest | repair-friendly WAN replication |
| Standard Git protocol ingress/egress | EXEMPT on wire | Git protocol bytes | protocol and object checks | strict client compatibility |
| CI log segment | POLICY | sealed log chunk/segment | digest, framing, attestation linkage | recoverability under retention class |
| CI artifact | POLICY, default above threshold | exact sealed artifact blob | artifact digest, provenance/attestation | economical artifact durability |
| Release artifact | MUST encode in managed durable class | exact signed release blob or encrypted envelope | digest, signature, provenance | high-value distribution durability |
| Package blob | POLICY, default above threshold | exact registry blob/envelope | ecosystem digest, Franken digest, provenance | package durability and transfer |
| Container layer | POLICY | exact OCI layer/envelope bytes | OCI digest, Franken digest, manifest linkage | large immutable package storage |
| Backup archive | MUST encode | encrypted canonical backup chunk/segment | AEAD, digest, manifest, restore replay | disaster recovery |
| Local NVMe materialization | EXEMPT | bare repo/worktree/cache files | capsule pin; rebuild on failure | disposable derived state |
| Workspace overlay | EXEMPT | mutable uncommitted workspace | evidence snapshot/commit on publication | disposable agent/human working state |
| Metrics and traces | MAY encode under retention policy | sealed telemetry segment | segment digest/schema | operational evidence, not repository truth |
| Secrets and encryption keys | EXEMPT | key material | KMS/HSM/threshold/escrow-specific controls | fountain coding is inappropriate for key custody |
| FrankenSQLite pages/WAL used by projection | DEFERRED to FrankenSQLite contract | implementation-defined | FrankenSQLite durability/recovery invariants | avoid double coding and split ownership |
| In-memory queues and RPC frames | EXEMPT | transient bytes | transport checksum/authentication/retry | not a durability object |

---

## 3. Deterministic object and symbol identity

A proposed native identifier is conceptually:

```text
RaptorObjectId = H(
  domain = "frankengit/raptor-object/v1",
  tenant_namespace,
  object_class,
  canonical_format_version,
  source_length,
  source_digest,
  encryption_profile,
  partition_profile
)

SymbolId = H(
  domain = "frankengit/raptor-symbol/v1",
  RaptorObjectId,
  source_block_index,
  encoding_symbol_id,
  symbol_length,
  codec_version
)
```

The exact canonical encoding and hash algorithm remain a G0 schema decision. Domain separation and algorithm identifiers are mandatory.

A symbol from one object, tenant, source block, codec version, or encryption profile cannot be accepted into another decode set merely because lengths match.

---

## 4. Encoding and encryption order

The default for private immutable payloads should be:

1. construct deterministic canonical plaintext object;
2. compute internal plaintext commitment where required for semantic identity;
3. encrypt into a self-describing AEAD envelope using policy-approved key management;
4. treat the exact ciphertext envelope as the RaptorQ source bytes;
5. distribute source and repair symbols across failure domains;
6. reconstruct ciphertext bytes, verify their outer digest, then decrypt and verify inner commitments.

This order repairs data without exposing plaintext to storage/repair workers and avoids repair-symbol malleability against unauthenticated plaintext. Convergent encryption and cross-tenant deduplication are disabled by default because they create confirmation and equality side channels.

Public Git object segments may use a different non-encrypted profile, but the profile is explicit in object identity.

---

## 5. Source-block construction

### 5.1 Microsegments

Small Git objects should not each carry independent fountain-code overhead. Deterministic microsegments aggregate records by a stable policy while preserving object-level lookup and verification.

A microsegment contains:

- format/version header;
- ordered record table;
- exact object type, length, Git OID algorithm/value, and Franken digest per record;
- object bytes;
- Merkle footer and segment digest;
- optional compression profile;
- source-block partition metadata.

Ordering cannot depend on arrival race, filesystem enumeration, process hash seeds, or wall-clock time. Candidate policies include digest order within a bounded sealing epoch or deterministic builder assignment. The final policy needs simulation and locality measurements.

### 5.2 Large objects

Large blobs, packs retained as canonical imports, artifacts, and checkpoints may be one or more independently repairable source blocks. Block size balances decode memory, parallelism, repair granularity, request cost, and symbol overhead.

### 5.3 Padding

Padding bytes and source length are canonical and unambiguous. Decoders truncate only to the authenticated source length after full object verification.

---

## 6. Redundancy policy

RaptorQ redundancy has two layers:

### 6.1 Deterministic floor

Each durability class specifies a minimum repair-symbol budget and placement across independent failure domains. This floor is part of the storage acknowledgement contract and cannot be reduced by a learned or statistical controller.

### 6.2 Adaptive headroom

Within policy bounds, an adaptive controller may add or retire repair symbols based on measured loss, repair demand, object heat, region health, bandwidth price, and decode margin. It may use e-process monitoring to detect regime change, but:

- it cannot go below the deterministic floor;
- it cannot delete the last recoverable set;
- actions are reversible and audited;
- policy epoch and controller identity are recorded;
- A/B or off-policy evaluation compares against simpler replication and fixed redundancy.

An adaptive controller is an economic optimization, never the source of durability truth.

---

## 7. Placement rules

Repair symbols are useful only when their failure correlation differs from source symbols. Placement policy must account for:

- device, node, rack, availability zone, region, and provider;
- storage class and lifecycle policy;
- encryption key dependency;
- administrative domain;
- network path;
- correlated software/format bugs;
- legal residency constraints;
- tenant isolation.

Storing all repair symbols beside the source on one filesystem does not satisfy a multi-failure-domain durability claim.

The manifest records intended and observed placement without making mutable placement metadata part of object identity.

---

## 8. Repair state machine

```text
Healthy
  -> Suspect(reason, evidence)
  -> InventoryVerified
  -> DecodePlanned(symbol_set, budget)
  -> Decoding
  -> CandidateReconstructed
  -> ExactVerification
  -> ReplacementPlaced
  -> ManifestReconciled
  -> Healthy
```

Terminal alternatives include:

- `InsufficientIndependentSymbols`;
- `DecodeBudgetExceeded`;
- `SymbolIdentityMismatch`;
- `CandidateDigestMismatch`;
- `StructuralVerificationFailed`;
- `KeyUnavailable`;
- `PlacementUnsatisfied`;
- `ObjectLogicallyDeleted`;
- `OperatorQuarantine`.

A failed decode does not mutate canonical manifests or overwrite the last known-good copy. Candidate bytes remain quarantined.

---

## 9. Garbage collection and deletion

Deletion is manifest-driven, not inferred from object-store listing.

Before source or repair symbols are retired, the collector proves:

- no retained Repository Capsule, ref/event checkpoint, legal hold, release/package manifest, backup policy, or active transfer requires the object;
- the deletion epoch and grace period have elapsed;
- alternative retained objects meet their declared recoverability;
- repair symbols do not outlive encrypted data in a way that defeats cryptographic erasure policy;
- deletion actions are idempotent and auditable.

Repair automation cannot resurrect a logically deleted object into reachable state. Discovery of residual symbols after deletion is an erasure-policy incident, not an invitation to reconstruct.

---

## 10. Verification matrix

Every `MUST encode` row requires:

1. canonical round-trip golden vectors;
2. symbol-order independence tests;
3. arbitrary erasure patterns up to the admitted recovery condition;
4. duplicate, corrupt, mixed-object, truncated, and excessive-symbol tests;
5. cancellation at every encode/decode/placement step;
6. exact post-decode structural verification;
7. deterministic parameter derivation across platforms;
8. memory and CPU budget enforcement;
9. placement-failure simulation;
10. backup/restore or transfer integration proof;
11. cost/performance comparison with replication-only and simpler erasure-code baselines;
12. periodic production-shaped reconstruction drill.

A fast encode benchmark without a destructive reconstruction campaign is not durability evidence.

---

## 11. Metrics

Required metrics by object class and policy epoch include:

- source bytes, repair bytes, and overhead ratio;
- independent symbol availability margin;
- encode/decode CPU, memory, and latency;
- repair trigger rate and cause;
- successful, refused, and failed repair counts;
- bytes transferred and request count per repair;
- correlated placement violations;
- scrub lag and last destructive drill;
- post-decode verification failures;
- storage and egress cost versus declared baseline;
- adaptive-controller action and rollback rate.

Metrics must not expose cross-tenant object identities or plaintext digest membership.

---

## 12. Open decisions and required experiments

The following remain open until measured:

- microsegment target size and sealing policy;
- source-block and symbol sizes by storage/transfer class;
- compression-before-encryption profiles;
- redundancy floors by failure-domain target;
- when fixed replication is cheaper or simpler than coding;
- whether hot objects should retain extra full replicas in addition to repair symbols;
- decode scheduling and parallelism under Asupersync budgets;
- browser/WASM decode support for portable recovery bundles;
- cross-provider placement economics;
- maximum object size for one source block;
- interaction with Git pack reuse and delta locality.

Each experiment must preserve exact correctness and include a replication-only control.

# FrankenGit RaptorQ Permeation Map

**Status:** normative design registry draft  
**Last updated:** 2026-08-19  
**Executable companion:** [`../registries/durable_objects.tsv`](../registries/durable_objects.tsv)

RaptorQ is a systematic fountain-code family used to reconstruct exact immutable source bytes from a sufficient suitable symbol set. In FrankenGit it is a durability, repair, and native-transfer mechanism for registered immutable byte structures. It is not a hash, signature, encryption scheme, authorization system, freshness oracle, ordering protocol, transaction log, compare-and-exchange primitive, consensus algorithm, or substitute for tested backups.

The phrase “RaptorQ-enabled” is forbidden unless it names an object class, profile, placement promise, decode budget, post-decode verification rule, evidence artifact, and non-claim.

Every durable or bulk-transferred byte structure declares one status:

- **MUST encode:** the declared managed durability profile requires a RaptorQ contract;
- **POLICY:** an identity-bound policy selects encoding within deterministic floors/ceilings;
- **MAY encode:** supported as an acceleration/recovery option but not required for correctness;
- **EXEMPT:** deliberately protected by another named mechanism;
- **DEFERRED:** blocked on measurement or an owning lower-layer contract.

---

## 1. Universal reconstruction contract

Every encoded class defines:

1. **Canonical source bytes** — the exact immutable byte string being protected.
2. **Typed identity** — tenant/namespace, object class, format/version, source length, digest algorithm/value, encryption and partition profiles.
3. **Partitioning** — source-block boundaries, symbol size, padding, deterministic parameter derivation, and maximum source-block count.
4. **Symbol identity** — source object, source block, encoding symbol ID, codec/profile version, payload length, and authenticated metadata.
5. **Placement** — intended and observed failure domains, key dependencies, and rules against correlated loss.
6. **Deterministic floor** — minimum source/repair availability promise that adaptation may never weaken.
7. **Adaptive headroom** — optional bounded policy, exact evidence window/regime, fallback, and reset.
8. **Repair trigger** — scrub failure, missing placement, restore, transfer loss, migration, or explicit destructive drill.
9. **Decode budget** — maximum accepted symbols, bytes, memory, CPU, retries, wall-clock, and parallelism.
10. **Post-decode verification** — every original cryptographic and structural commitment required before candidate acceptance.
11. **Authority check** — current logical state, retention, deletion, and replacement version must be revalidated before publishing a repaired placement.
12. **Evidence** — within/beyond/malicious-symbol fault corpus, replay command, cost/performance control, and production-shaped drill cadence.
13. **Deletion interaction** — source/repair retirement and residual-symbol incident policy.
14. **Encryption interaction** — encoding order and protection of key/nonce/profile metadata.

A decoder returning bytes is only `CandidateReconstructed`. Success requires exact verification and an authority-mediated placement update. Repair uses the same publication authority as ordinary writes; it cannot overwrite newer state merely because reconstructed bytes are valid for an older manifest.

---

## 2. Object-class registry

| Object class | Status | Canonical source bytes | Post-decode verification | Authority/retention owner |
|---|---|---|---|---|
| Git loose/pack ingress representation | EXEMPT | untrusted client transport bytes | pure-Rust pack/object validation and native Git OID | transaction quarantine |
| Admitted Git object microsegment | MUST encode in managed durable profile | deterministic sealed microsegment | segment digest, Merkle/index/footer, every record length/type/native OID/strong envelope digest | object manifest + object-closure root |
| Large repository segment | MUST encode in managed durable profile | exact sealed segment bytes | digest, Merkle root, manifest, authenticated index, every referenced object | segment-manifest/retention roots |
| Transaction seal body | EXEMPT | canonical immutable seal bytes | strong put-if-absent, exact request commitment, authority replay | seal namespace and decision stream |
| Prepared transaction capsule | POLICY | exact immutable prepared-candidate bytes | digest, base head receipt, witnesses, object/effect roots, expiry | active-seal/preparation roots |
| Repository Decision Batch record | EXEMPT at individual record layer | canonical batch bytes | digest, predecessor head/batch, sequences, RCR/refusal/effect roots | repository authority head |
| Decision-log archive/checkpoint segment | MUST encode | sealed contiguous decision/checkpoint segment | digest, chain continuity, sequence/root replay equivalence | checkpoint/backup retention |
| Repository Authority Head | EXEMPT | small authenticated mutable head body | linearizable exact-version CAS, monotone generation, body digest/signature profile | AuthorityStore |
| Repository Capsule body | EXEMPT at individual record layer | unsigned canonical checkpoint body | digest, signatures, exact authority/RCR and closure roots | checkpoint pointer/root |
| Capsule/backup export bundle | MUST encode | canonical encrypted export chunks/manifests | AEAD, digest, signatures, member roots, restore replay | backup policy/root |
| Forge event record | EXEMPT at individual record layer | canonical event bytes | event identity, actor/authenticator, stream/aggregate position | decision stream |
| Forge event/checkpoint segment | MUST encode | sealed canonical event/checkpoint bytes | digest, chain/aggregate roots, deterministic replay | checkpoint/backup root |
| Policy/key/format-history checkpoint | MUST encode | encrypted canonical checkpoint bundle | AEAD, digest, signatures, semantic validation | policy/key retention |
| Search generation | MAY encode | exact immutable index shards/manifest | generation digest, source authority position, shard/index checks | generation authority |
| Graph generation | MAY encode | exact immutable graph shards/manifest | generation digest, schema, source position, vertex/edge/index roots | generation authority |
| Embedding/vector generation | POLICY | immutable authorized generation | digest, model/tokenizer/index identity, authorization scope | generation authority |
| Generated Git fetch pack | EXEMPT | disposable pure-Rust pack output | pack checksum and requested closure | transfer region/cache |
| ATP-Git transfer block | POLICY, normally on large native transfers | exact manifest piece/object/segment block | piece/manifest commitment, length, ultimate object/segment identity | transfer actor/region |
| Cross-region repository segment transfer | MUST encode for native ATP profile | exact sealed segment bytes | destination digest/Merkle/manifest and placement receipt | object fabric |
| Ordinary Git wire stream | EXEMPT on wire | Git pkt-line/pack bytes | protocol, pack, object, reachability, and policy checks | Git gateway/transaction quarantine |
| CI log segment | POLICY | exact sealed log bytes | digest, framing, redaction/provenance linkage | evidence/artifact retention |
| CI artifact | POLICY, default above threshold | exact sealed artifact/envelope | typed digest, archive/media structure, provenance | artifact retention |
| Release artifact | MUST encode in managed release class | exact signed asset/envelope | digest, signature, SBOM/provenance/manifest linkage | release manifest/root |
| Package/OCI blob | POLICY | exact ecosystem blob/envelope | ecosystem digest, Franken digest, manifest/provenance | package retention |
| TreeFS base/cache generation | MAY encode | immutable tree/blob/cache segment | digest, source authority receipt, manifest | workspace/cache policy |
| TreeFS mutable overlay | EXEMPT | mutable uncommitted state | staged/visible/durable workspace epochs; snapshot before retention | workspace session |
| Local bare repo/worktree/materialization | EXEMPT | disposable derived filesystem bytes | source authority receipt; discard/rebuild | materializer/cache |
| Metrics/trace/evidence segment | POLICY | exact sealed telemetry/evidence segment | digest, schema, source/run identities | evidence/telemetry retention |
| Secrets/encryption keys | EXEMPT | key material | KMS/HSM/threshold/escrow-specific controls | key authority |
| FrankenSQLite pages/WAL | DEFERRED to FrankenSQLite profile | owning backend format | FrankenSQLite MVCC/durability/recovery contract; avoid double coding | embedded authority/projection owner |
| In-memory queue/RPC frame | EXEMPT | transient bytes | transport auth/checksum, retry, obligation settlement | owning region |

The TSV registry is the executable source of class status. This table explains the rationale and must not diverge from it.

---

## 3. Deterministic object and symbol identity

Conceptually:

```text
RaptorObjectId = H(
  domain = "frankengit/raptor-object/v1",
  tenant_namespace,
  object_class,
  canonical_format_version,
  source_length,
  source_digest_algorithm_and_value,
  encryption_profile,
  partition_profile
)

SymbolId = H(
  domain = "frankengit/raptor-symbol/v1",
  RaptorObjectId,
  source_block_index,
  encoding_symbol_id,
  symbol_length,
  codec_profile_version
)
```

`H` is selected by the canonical crypto registry. A symbol from another tenant, class, object, source block, codec version, encryption profile, or source length cannot enter the decode set because superficial dimensions happen to match.

Object identity excludes mutable storage locations and observed placement acknowledgements. Those are signed/authenticated receipts over the object/profile identity.

---

## 4. Encoding and encryption order

The default private-payload profile is:

1. construct deterministic canonical plaintext;
2. compute semantic/plaintext commitments required by the object class;
3. encrypt into a self-describing AEAD envelope using a versioned key/profile;
4. treat the exact ciphertext envelope as source bytes;
5. compute outer object identity and RaptorQ partition;
6. place source and repair symbols across independent domains;
7. reconstruct exact ciphertext;
8. verify outer digest/length/profile;
9. decrypt;
10. verify inner semantic commitments and structural codec;
11. publish a repaired placement only after current authority revalidation.

This permits untrusted storage/repair workers to manipulate symbols without plaintext. Convergent encryption and cross-tenant deduplication are disabled by default because they create equality/confirmation side channels and deletion/accounting ambiguity.

Public Git object segments may use a non-encrypted profile, but the profile remains identity material.

---

## 5. Source-block construction

### 5.1 Deterministic microsegments

Small Git/forge objects should not each pay independent coding overhead. A microsegment contains:

- format/profile header;
- canonical ordered record table;
- object class/type/length/native OID/strong envelope digest;
- exact payload bytes;
- authenticated random-access index;
- Merkle/footer and segment digest;
- optional compression/encryption profile;
- source-block partition metadata.

Ordering cannot depend on arrival race, filesystem enumeration, process hash seed, wall clock, thread ID, or storage listing. If a builder receives noncanonical input order, it refuses or produces a separately identified normalization record; it does not hide nondeterminism.

### 5.2 Large objects and segments

Large blobs, artifacts, package layers, checkpoint segments, and backup chunks use independently repairable source blocks. Block sizing balances:

- peak decode memory;
- encoder/decoder throughput;
- parallelism and cancellation responsiveness;
- repair granularity;
- object-store request/range economics;
- symbol overhead and loss concentration;
- ATP path bandwidth-delay product.

### 5.3 Padding

Source length and padding rule are authenticated. Decoders truncate only to the verified source length after complete object verification.

---

## 6. Redundancy and adaptation

### 6.1 Deterministic floor

Every managed durability class publishes a minimum independent source/repair availability and failure-domain placement promise. The floor is part of the storage acknowledgement and cannot be reduced by a statistical controller, cost spike, heat change, or missing telemetry.

### 6.2 Identity-bound adaptive headroom

Within hard floors/ceilings, a policy may add/retire repair symbols based on measured loss, repair demand, age/staleness, heat, region health, bandwidth/storage price, and decode margin.

Its identity binds:

- object population and class;
- exact observation window/sequence;
- selection/propensity rule;
- regime epoch and detector;
- candidate and deterministic fallback;
- assumptions/support/ESS where applicable;
- arithmetic/toolchain/math fingerprint;
- action bounds, reset, and kill switch.

Insufficient support, regime alarm, stale evidence, arithmetic bound failure, or policy mismatch selects fallback. Adaptation may improve economics; it never defines whether durability promises are satisfied.

---

## 7. Placement and trust

Repair symbols matter only when their failure correlation differs from the sources. Placement policy considers:

- device, process, node, rack, zone, region, provider;
- storage class/lifecycle;
- administrative and software version domain;
- encryption key and control-plane dependency;
- network path;
- legal residency;
- tenant boundary;
- correlated format/implementation bugs.

Storing all symbols beside the source on one filesystem does not satisfy a multi-domain claim. Cache/peer trust is scoped: verified local cache, same-tenant peer, cross-region replica, federation peer, and anonymous transfer source are distinct classes with different required checks and budgets.

---

## 8. Repair state machine

```text
Healthy
  -> Suspect(reason, evidence)
  -> InventoryAndAuthorityRead
  -> DecodePlan(symbol_set, profile, budget)
  -> DecodingInQuarantine
  -> CandidateReconstructed
  -> OriginalCommitmentsVerified
  -> CurrentAuthorityRevalidated
  -> RepairIntentPrepared
  -> AuthorityHeadCAS
  -> PlacementAndManifestReconciled
  -> Healthy
```

Typed terminal/refusal outcomes include:

- `InsufficientIndependentSymbols`;
- `DecodeBudgetExceeded`;
- `SymbolIdentityMismatch`;
- `CandidateDigestMismatch`;
- `StructuralVerificationFailed`;
- `KeyUnavailable`;
- `PlacementUnsatisfied`;
- `AuthorityReceiptStale`;
- `NewerLogicalVersionExists`;
- `ObjectLogicallyDeleted`;
- `RetentionPolicyChanged`;
- `OperatorQuarantine`.

A failed decode or lost head CAS does not overwrite the last known-good placement or mutate current manifests. Candidate bytes remain quarantined until explicitly retained or destroyed. A valid reconstruction of an old object is not authority to resurrect a logically deleted object.

---

## 9. Staged, visible, and durable states

For every encoded object/publication pipeline:

- **staged:** bytes/symbols exist but are not reachable from an accepted canonical root;
- **visible:** an authority decision references the object/placement for reads;
- **durable:** required profile and failure-domain receipts have been verified.

The owning profile declares the transition graph; there is no universal inequality. Managed canonical source objects use `Absent -> Staged -> DurabilitySatisfied -> Visible`. Lower-value derived objects may use `Absent -> Staged -> Visible(with DurabilityObligation) -> Durable`. Acknowledgements name the exact state/profile and unresolved obligation. Upload completion proves neither visibility nor durability.

---

## 10. Garbage collection and deletion

Deletion is root/manifest-driven, never inferred from bucket listing.

Before source or repair symbols retire, GC proves:

- no ref/object closure, PR/merge queue, active seal/preparation, checkpoint/backup, legal hold, release/package/artifact, migration/restore, grace tombstone, or transfer obligation needs them;
- deletion and replica/backup grace horizons elapsed;
- current authority still matches the proof basis;
- remaining placements meet declared recoverability;
- residual symbols do not defeat cryptographic-erasure claims;
- actions are idempotent and evidenced.

Repair automation cannot make a deleted object reachable. Discovering residual recoverable symbols after an erasure claim is a security/compliance incident.

---

## 11. Verification matrix

Every `MUST encode` profile requires:

1. canonical source/partition/symbol golden vectors;
2. deterministic parameter derivation across platforms;
3. symbol-order independence;
4. arbitrary admitted erasure patterns;
5. one-beyond-bound fail-closed drills;
6. duplicate, corrupt, mixed-object, forged-metadata, truncated, and excessive-symbol tests;
7. cancellation at every encode/decode/fetch/verify/place/CAS point;
8. exact cryptographic and structural post-decode verification;
9. peak CPU/memory/time/input-count budget enforcement;
10. correlated placement failure simulation;
11. repair racing newer write/deletion/policy change;
12. backup/restore or transfer integration;
13. replication-only and fixed-erasure controls;
14. production-shaped destructive reconstruction drill;
15. signed replay artifact with source/toolchain/profile/failure seed.

An encode-throughput benchmark without destructive reconstruction and authority-race evidence is not durability evidence.

---

## 12. Required metrics and evidence

By object class/profile/policy epoch:

- source/repair bytes and amplification;
- independent availability margin by failure domain;
- encode/decode CPU, peak memory, latency, cancellation delay;
- repair trigger, refusal, success, and failure causes;
- bytes/requests/egress per repair;
- placement-policy violations;
- scrub lag and last destructive drill;
- post-decode commitment failures;
- authority revalidation/CAS conflicts;
- newer-version/deletion races;
- storage/egress cost versus controls;
- adaptive action, fallback, reset, and rollback rate.

Metrics must not expose cross-tenant membership or plaintext digest confirmation.

---

## 13. Open experiments

- microsegment size/sealing/locality policy;
- source-block/symbol sizes by object and ATP path class;
- compression-before-encryption profiles;
- deterministic redundancy floors by promised failure domains;
- fixed replication versus RaptorQ crossover;
- hot full replicas plus repair symbols;
- Asupersync encoder/decoder cancellation granularity;
- SIMD-safe scalar/vector implementation strategy;
- browser/WASM recovery-bundle decode;
- cross-provider placement economics;
- very-large-object partitioning;
- Git pack/delta locality interaction;
- malicious-symbol and format-version isolation;
- repair versus cryptographic-erasure operational procedure.

Every experiment retains exact correctness, names assumptions, includes a simple control, and records negative results.

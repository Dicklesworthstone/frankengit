# ATP-Git: Adaptive Transport Protocol Profile for FrankenGit

**Status:** architecture profile  
**Version:** 1.0  
**Last revised:** 2026-08-19

FrankenGit reuses Asupersync’s ATP machinery as a first-class repository transport substrate. ATP-Git is not a replacement for Git smart HTTP or SSH at the public compatibility boundary. It is the native high-performance path for FrankenGit-aware clients, internal replication, agent workspaces, CI input distribution, object repair, migration, artifact transfer, and accelerated clone/fetch. Ordinary Git clients continue to receive valid Git protocol and pack streams produced by the pure-Rust Git engine.

## 1. Design goals

ATP-Git must:

- avoid re-sending bytes the receiver already possesses;
- exploit Git object identity and graph structure rather than treating repositories as flat files;
- choose direct, LAN, IPv6, Tailscale-provided, relay, MASQUE, mailbox, or swarm paths through one typed path graph;
- race paths safely and drain losers;
- resume from verified pieces after interruption;
- use RaptorQ where erasure recovery reduces feedback/latency cost;
- bound memory, decode work, decompression, and peer fan-out;
- produce deterministic transfer receipts;
- preserve authorization and cache trust domains;
- fall back precisely to ordinary Git pack transfer when evidence or peer capability is insufficient.

## 2. Transfer object model

### 2.1 Git object manifest

A transfer begins with an immutable manifest:

```rust
struct GitTransferManifest {
    manifest_id: GitTransferManifestId,
    repository_id: RepositoryId,
    source_rcr_id: RepositoryCommitId,
    object_format: GitHashAlgorithm,
    requested_roots: Vec<GitObjectId>,
    filter: GitObjectFilter,
    objects: Vec<TransferObjectEntry>,
    segments: Vec<TransferSegmentEntry>,
    reconstruction_plan_root: Digest,
    authorization_receipt_root: Digest,
    profile_id: AtpGitProfileId,
}

struct TransferObjectEntry {
    oid: GitObjectId,
    object_type: GitObjectType,
    logical_size: u64,
    strong_digest: Digest,
    storage_representation: StorageRepresentationId,
    segment_id: Option<SegmentId>,
}
```

The manifest binds logical objects, not one physical pack. A sender may satisfy it from canonical segments, cached packs, individual objects, or multiple peers. Reconstruction must produce the exact requested Git closure.

### 2.2 Piece identity

A transfer piece has a stable identity over canonical bytes and framing profile. Pieces may be:

- complete small Git objects;
- ranges from an immutable repository segment;
- pack slices aligned to verified pack/index boundaries;
- LFS/package/artifact chunks;
- RaptorQ source or repair symbols;
- compact index/manifest objects.

A piece is never marked verified merely because its transport checksum matches. Acceptance checks the manifest commitment and, where applicable, the reconstructed Git object ID and structural parser.

## 3. Bounded receiver knowledge

A receiver advertises what it already possesses through a bounded `HaveSummary`:

```rust
enum HaveSummary {
    ExactObjects { sorted_oids: Vec<GitObjectId> },
    ExactSegments { sorted_ids: Vec<SegmentId> },
    Probabilistic { profile: FilterProfileId, bytes: Vec<u8> },
    BasisRcr { rcr_id: RepositoryCommitId, generation_receipt: Digest },
}
```

Probabilistic summaries are hints only. A false positive may suppress an initial piece, but final closure verification detects the omission and issues an exact repair request. The protocol never accepts an incomplete checkout because a Bloom/XOR/Golomb summary said an object probably existed.

The sender produces one of:

- `AlreadyInSync`;
- `ObjectDeltaPlan`;
- `SegmentDeltaPlan`;
- `PackViewPlan`;
- `FullClosureFallback` with a typed reason.

## 4. Delta and deduplication

### 4.1 Unique-payload plan

Many logical paths or artifacts may share identical bytes. ATP-Git sends each unique content payload once and transmits a deterministic placement/reconstruction map. The receiver verifies each logical placement’s object identity and metadata separately.

### 4.2 Object-aware delta

Object-aware delta works above physical pack layout:

- unchanged Git objects are omitted by OID;
- changed large blobs may use content-defined chunks when the object-class profile permits;
- trees are transferred as changed nodes plus required ancestry;
- commits/tags remain whole canonical objects;
- derived packs are never canonical truth and can be rebuilt.

### 4.3 Pack-aware lane

For an ordinary Git client or a receiver whose best basis is a cached pack, ATP-Git may transfer immutable pack slices plus indexes. The plan binds the exact pack digest and object coverage. A pack delta is accepted only if the resulting pack parses and every advertised object resolves to the expected OID.

### 4.4 Deterministic fallback

Fallback reasons include:

- untrusted or unsupported basis;
- have-summary budget exceeded;
- delta work exceeds saved-byte estimate;
- missing chunk/index profile;
- authorization scope differs;
- compression/delta chain exceeds limits;
- receiver cannot verify the proposed representation;
- evidence for adaptive mode is insufficient.

Fallback is an explicit plan, not a timeout-induced surprise.

## 5. Typed path graph

ATP-Git models connectivity as a graph whose edges carry:

- transport/profile;
- endpoint and identity;
- authentication strength;
- privacy class;
- estimated RTT, bandwidth, loss, and cost;
- relay/mailbox trust;
- egress and monetary budget;
- MTU/symbol constraints;
- data-residency restrictions;
- current regime epoch.

Candidate paths include:

- same-process/local object store;
- same-host Unix/local socket;
- LAN QUIC;
- direct IPv4/IPv6 QUIC;
- Tailscale-supplied address candidates without a Tailscale library dependency;
- HTTPS/MASQUE-compatible relay;
- organization relay;
- offline mailbox/store-and-forward;
- multi-source swarm peers;
- ordinary Git smart HTTP/SSH fallback.

Path selection is capability- and policy-constrained before optimization. A cheap path that violates residency or cache trust is not an arm.

## 6. Race and loser drain

The transfer actor may start bounded parallel probes or initial streams. Selection proceeds through Asupersync’s structured race primitive:

1. reserve path attempts;
2. launch inside one owned region;
3. choose a winner using the declared path policy;
4. protocol-cancel every loser;
5. drain and finalize loser obligations;
6. publish the winner receipt;
7. continue transfer with no orphan socket, reservation, or secret.

A race result is not returned while a loser can still write pieces or hold a relay credential.

## 7. Swarm profile

Large public repositories, CI fan-out, migration, and regional warm-up may use multiple verified sources.

### 7.1 Piece tracker

The bounded tracker records:

- missing, requested, received-unverified, verified, and rejected pieces;
- peer availability and trust scope;
- rarity and estimated completion contribution;
- duplicate/endgame assignments;
- per-peer bad-piece evidence;
- total in-flight bytes and memory;
- source/repair-symbol class.

### 7.2 Scheduling

Default scheduling is rarest-first subject to:

- critical-path objects needed to begin useful work;
- sequential-read benefits for segment/range storage;
- peer trust and bandwidth;
- failure-domain diversity;
- decode rank for fountain-coded blocks;
- endgame duplication cap;
- fairness and egress budgets.

The tie-break policy is deterministic and emitted in the transfer witness.

### 7.3 Byzantine handling

A peer cannot corrupt state merely by serving a bad piece. Pieces verify against immutable commitments before entering the verified set. Repeated invalid pieces reduce or revoke the peer capability and create evidence; statistical anomaly scores may prioritize review but do not alone establish guilt.

## 8. RaptorQ transport

RaptorQ is useful when feedback is expensive or loss is nontrivial:

- WAN clone/fetch over high RTT;
- relay/mailbox transfer;
- swarm completion with missing pieces;
- repair-symbol distribution;
- large artifacts/packages/LFS objects;
- regional warm-up after failure.

It is generally not useful for tiny metadata or clean local NVMe reads.

### 8.1 Adaptive block parameters

The sender chooses source-symbol count, symbol size, repair overhead, fan-out, and pacing using:

- measured RTT/loss/goodput;
- encode/decode throughput;
- receiver memory/CPU budget;
- conformal upper bound on recent loss;
- low-tail bandwidth estimate;
- deterministic fallback profile;
- bounded no-regret exploration near the model optimum.

Larger blocks reduce relative concentration margin but increase coding work and recovery latency. The controller balances network-useful rate against encode/decode throughput, never exceeding hard memory/responsiveness limits.

### 8.2 Decode acceptance

Decoder success is only a candidate. The receiver verifies:

- transfer manifest identity;
- source object/segment digest;
- exact expected length;
- Git object ID where applicable;
- pack/segment structural invariants;
- authorization and repository namespace;
- Merkle inclusion or manifest closure.

## 9. Trust-scoped caching

Cache entries are keyed by content identity plus trust scope. Scopes include:

- public global;
- tenant shared;
- repository private;
- Intent-Run private;
- secret-bearing non-shareable.

A cache grant states who may read, whether plaintext may be shared, encryption key domain, expiration, and audit requirements. Content equality does not automatically authorize cross-tenant reuse. A public blob and a private blob with identical bytes may share a physical encrypted payload only if deletion, side-channel, and accounting policy explicitly permit it.

## 10. Transfer actor and obligations

One transfer actor owns:

- manifest negotiation;
- path race;
- have-summary/delta planning;
- QUIC/HTTP/SSH adapters;
- piece tracker;
- RaptorQ encode/decode;
- cache reads/writes;
- quota/egress reservations;
- progress receipts;
- final closure verification;
- cancellation and cleanup.

Obligation types include:

- `PathAttemptPermit`;
- `PieceRequestPermit`;
- `DecodeBudgetPermit`;
- `CacheWritePermit`;
- `EgressChargeReservation`;
- `RelayCredentialLease`;
- `ManifestCompletionObligation`.

Region closure proves every obligation committed, aborted, or explicitly transferred.

## 11. Determinism and replay

A transfer receipt binds:

- manifest and basis IDs;
- path graph snapshot;
- chosen and rejected paths;
- tie-break policy;
- adaptive policy epoch and fallback;
- RNG stream/seed where exploration is enabled;
- per-piece source and verification result;
- RaptorQ parameters and decode proof;
- resource use, bytes saved, and egress cost;
- cancellation/fallback events;
- final closure root.

Lab replay can replace live networks with a recorded path trace and deterministically reproduce planning, scheduling, cancellation, and verification. It does not claim to reproduce an unrecorded external network.

## 12. Public Git integration

Ordinary Git clone/fetch/push remains wire-compatible:

- upload-pack/receive-pack requests enter the pure-Rust Git engine;
- pack planning may internally use ATP-Git object/segment access;
- output is a valid Git pack/protocol stream;
- incoming packs may be ingested simultaneously into ATP-Git segments;
- FrankenGit-aware clients may negotiate ATP-Git through a separate capability/API without confusing it with Git protocol v2.

## 13. Verification gates

ATP-Git is not complete until evidence covers:

- exact and probabilistic have summaries;
- false-positive repair;
- delta/full fallback equivalence;
- interrupted resume;
- lost/duplicate/reordered path hints;
- race loser drain;
- swarm rarest-first/endgame bounds;
- malicious peer pieces;
- RaptorQ within/beyond-budget loss;
- cache trust isolation;
- cancellation at every reservation/commit boundary;
- deterministic path-trace replay;
- ordinary Git pack equivalence;
- p50/p95/p99 throughput, CPU, memory, egress, and recovery cost on named corpora.

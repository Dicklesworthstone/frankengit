# FrankenGit Verification Specification

**Status:** proposed
**Purpose:** define what evidence is required before FrankenGit may claim correctness, compatibility, repairability, performance, security, or readiness.

## 1. Verification doctrine

FrankenGit is a distributed source-control and code-collaboration system. Its failures can be silent, delayed, cross-layer, and expensive. A passing unit test suite is necessary and radically insufficient.

Verification follows five rules:

1. **Claims are scoped.** “Git compatible,” “crash safe,” and “repairable” are invalid without versions, workloads, deployment profiles, and exclusions.
2. **Failure is injected at protocol boundaries and instruction-level fault points.** Happy-path tests do not establish durability.
3. **Reference behavior is compared, not remembered.** Supported Git behavior is executed against pinned reference versions.
4. **Recovery is performed.** A backup, replica, or RaptorQ symbol set that has not reconstructed accepted state is unproved.
5. **Evidence is addressable.** Reports bind code, configuration, corpus, hardware, seeds, and artifacts.

## 2. Evidence levels

| Level | Name | Minimum evidence |
|---|---|---|
| E0 | Specified | invariant, assumptions, falsifier, owner |
| E1 | Local | unit, golden, property, parser/codec, deterministic fixtures |
| E2 | Simulated | deterministic concurrency/crash/cancellation/network/storage fault campaigns |
| E3 | Conformant | differential/reference implementation and corpus evidence |
| E4 | Distributed | real multi-process/node/store fault histories and recovery |
| E5 | Operational | production canary, SLO, rollback, restore, and long-horizon evidence |

A claim’s status is the minimum level across its critical subclaims.

## 3. Claim registry

Every public technical claim has a registry row.

```yaml
claim_id: FG-REF-IDEMPOTENT-001
statement: Retrying a RefTxn cannot produce a second different effect.
scope:
  protocol: RefTxnV1
  deployments: [single-node, clustered]
  cancellation: all defined phases
required_level: E4
assumptions:
  - cryptographic digest collision outside threat model
  - configured durable store satisfies probed behavior contract
falsifiers:
  - two committed result capsules for one TxnId
  - retry returns terminal refusal after the same transaction committed
evidence:
  - model/ref-idempotency.tla
  - artifacts/property/ref-idempotency.json
  - artifacts/sim/ref-idempotency-seeds.json
  - artifacts/chaos/ref-idempotency-history.edn
status: proposed
owner: fg-ref
```

The registry validator rejects:

- duplicate IDs;
- missing owner/falsifier;
- evidence files not present;
- expired evidence;
- scope broader than artifact metadata;
- “verified” without required level.

## 4. Core invariant suites

### 4.1 Git object identity

Properties:

- exact object bytes produce the expected SHA-1/SHA-256 OID;
- import/export preserves OIDs;
- pack/delta layout changes preserve object bytes;
- BLAKE3 envelope digest maps to exactly one Git OID/type/length in a domain;
- corruption is detected;
- SHA-1 collision-detection fixtures are rejected/handled like the declared reference profile;
- object-format mappings round-trip where supported.

Evidence:

- official Git test vectors;
- generated property corpus;
- real repositories;
- differential `git hash-object`, `cat-file`, `fsck`;
- fuzzing.

### 4.2 RefTxn

Properties:

- read-set preconditions hold at serialization point;
- write set is atomic;
- disjoint transactions commute;
- conflicting transactions have a legal serial order;
- stale cell/incarnation rejects;
- transaction is idempotent;
- cancellation before commit has no effect;
- cancellation after commit reconciles exact result;
- required objects and policy snapshot are bound;
- force push retains displaced state under policy;
- symbolic refs cannot form illegal cycles;
- multi-ref push is all-or-nothing.

Verification:

- pure state-machine property tests;
- model checking;
- randomized histories;
- linearizability checker;
- deterministic fault injection;
- real multi-node campaigns.

### 4.3 Repository Capsule

Properties:

- capsule content hashes/signatures verify;
- sequence/previous linkage is valid;
- current pointer never references missing child roots;
- root-last protocol survives crash at every step;
- all declared ref/object/stream positions reconstruct;
- stale capsule is detectable;
- capsule pin prevents GC;
- export from capsule matches ref/object roots.

### 4.4 Object fabric

Properties:

- immutable put conflict is detected;
- backend capability probe matches actual behavior;
- range reads reconstruct exact records;
- catalog never admits unverified placement;
- bad cache/store bytes are detected;
- one bad placement does not poison logical object when healthy copy exists;
- encryption domains prevent unauthorized cross-tenant read;
- compaction preserves logical object set;
- tiering preserves durability profile.

### 4.5 RaptorQ

Properties:

- canonical parameters reproduce symbols;
- systematic source bytes are exact;
- duplicate/reordered symbols do not count twice incorrectly;
- random and adversarial admissible erasure patterns reconstruct within stated threshold;
- insufficient symbols fail explicitly;
- corrupt symbols cannot produce an admitted wrong object;
- decoder resource limits hold;
- reconstructed segment passes digest, structure, Merkle, and Git OID validation;
- repair placement restores policy threshold.

Required evidence includes full reconstruction. “Repair symbols generated” is not accepted.

### 4.6 GC

Properties:

- every root class protects reachability;
- new objects after mark snapshot are protected;
- in-flight transaction pins required objects;
- shared pool references survive repository deletion;
- legal hold dominates normal deletion;
- tombstone/grace/recheck catches races;
- compaction old placements persist until replacement is admitted;
- current and retained capsules verify after sweep;
- restore works after GC.

GC is not enabled for destructive production sweep until E4.

### 4.7 Forge event streams

Properties:

- accepted command emits exactly one logical effect;
- duplicate request is idempotent;
- event encoding is canonical;
- checkpoints plus suffix reconstruct aggregate;
- projectors can rebuild to identical authoritative view;
- outbox is not lost between canonical commit and delivery;
- duplicate/out-of-order delivery is tolerated;
- unknown required schema blocks authoritative projection.

### 4.8 Capabilities and agents

Properties:

- scope cannot widen through delegation;
- expired/revoked capability refuses;
- repository content cannot mint authority;
- path/ref/tool/network/secret/budget limits are independent;
- cancellation revokes/reconciles grants;
- proposer cannot satisfy independent verifier policy;
- agent/sponsor identities persist through PR/RefTxn;
- secret broker denies fork/untrusted contexts;
- evidence binds exact capsule/head;
- budget overshoot is bounded by declared granularity;
- no child survives quiescence.

## 5. Git conformance program

### 5.1 Reference versions

Maintain a versioned matrix of Git releases and platforms. Each FrankenGit release declares:

- minimum/maximum tested clients;
- object formats;
- protocol versions/capabilities;
- behavior tier;
- known differences.

Reference binaries are pinned by digest and provenance.

### 5.2 Operation matrix

- init/import/clone;
- fetch;
- push;
- atomic push;
- force/delete;
- shallow clone/deepen/unshallow;
- partial clone filters and demand fetch;
- protocol v0/v1 where supported and v2;
- packfile URIs;
- bundles;
- tags and signatures;
- submodules;
- notes/replace refs under declared tiers;
- LFS;
- mirrors;
- hooks/push options;
- unusual paths/modes;
- SHA-1/SHA-256.

### 5.3 Differential method

For each case:

1. generate or load corpus repository;
2. execute operation against reference Git server/storage;
3. execute against FrankenGit;
4. compare protocol-visible status, refs, OIDs, object closure, outputs, and error class;
5. normalize only documented nondeterminism;
6. retain transcript and repository artifacts;
7. minimize divergence.

### 5.4 Corpus classes

- tiny exhaustive repositories;
- generated DAG shapes;
- criss-cross merges;
- long linear history;
- wide trees;
- deep trees;
- giant blobs;
- many refs;
- monorepos;
- fork networks;
- signed histories;
- malformed/adversarial packs;
- historical real-world repositories;
- platform path/Unicode edge cases.

### 5.5 Upstream Git tests

Port or adapt relevant Git test suite cases where licensing and harness fit. Maintain a mapping:

```text
upstream_test
 -> FrankenGit test
 -> compatibility tier
 -> divergences
 -> last upstream revision reviewed
```

Coverage is measured by behavior class, not raw test count.

## 6. Deterministic simulation

### 6.1 Controlled dimensions

- scheduler;
- clock;
- RNG;
- network;
- storage;
- process crash;
- cancellation;
- quota;
- backend throttling;
- corruption;
- worker fencing;
- upgrade version.

### 6.2 Fault points

Instrument before/after:

- quarantine write;
- object hash;
- segment write;
- placement verification;
- catalog publish;
- transaction prepare;
- policy decision;
- conditional commit;
- capsule child write;
- capsule pointer advance;
- outbox write;
- response send;
- GC mark/tombstone/sweep;
- repair decode/publish;
- relocation epoch switch;
- secret grant;
- runner spawn/kill;
- projection checkpoint.

### 6.3 Schedule exploration

Use:

- exhaustive bounded interleavings for small models;
- property-generated histories;
- deterministic seeded random;
- partial-order reduction;
- failure-biased schedules;
- regression seed corpus.

Every failure prints a one-command replay.

### 6.4 State oracle

The oracle compares:

- committed RefTxn model;
- visible ref snapshot;
- capsule roots;
- admitted object availability;
- canonical event aggregate;
- obligations/quiescence;
- audit/result map.

No oracle reads mutable projection as truth.

## 7. Cross-plane atomicity verification

Operations that combine Git ref state and forge state—especially pull-request merge, release publication, protected deployment, and policy activation—must pass an atomic Repository Commit Record suite.

Required properties:

- a crash before the commit record exposes neither the ref delta nor the canonical event batch;
- a crash after the commit record recovers both, even if no projector or physical event segment ran;
- replay produces exactly one canonical event identity and one ref effect;
- stale aggregate versions conflict deterministically beside stale ref read sets;
- an outbox retry can duplicate delivery attempts but cannot duplicate canonical events;
- a stale UI projection cannot cause a second merge or contradictory merge state;
- combined multi-ref/multi-aggregate records are all-or-nothing;
- capsule reconstruction includes the exact commit/event positions;
- canonical event bytes and ref-delta roots are content-addressed children written before the linearization point.

The test oracle reconstructs ref state and aggregate streams independently from Repository Commit Records and compares them with every live projection.

## 8. Multi-node fault campaigns

### 8.1 Cluster history

Capture invocation and response times/IDs plus internal commit receipts. Use linearizability/serializability checking.

### 8.2 Faults

- kill -9;
- machine reboot/loss;
- disk full/read-only;
- network partition/asymmetry;
- packet loss/delay;
- object-store proxy errors;
- stale DNS/routing;
- clock skew;
- cell failover;
- repeated retry;
- cache loss;
- key service outage;
- rolling mixed-version upgrade;
- repair/GC during foreground writes.

### 8.3 Success criteria

- safety invariants never violated;
- acknowledged durability contract met;
- typed refusals under unavailable prerequisites;
- bounded recovery;
- no leaked capabilities/obligations;
- exact incident boundary in evidence.

Availability targets may fail under faults outside profile; safety may not.

## 9. Backup and recovery verification

### 9.1 Required drills

- clean account/region restore;
- no cache/materialization;
- missing source placements reconstructed from repair;
- corrupted symbol ignored/identified;
- rotated server version;
- independent key recovery;
- export to normal Git and `git fsck`;
- rebuild forge projections;
- verify PR/issues/reviews/evidence counts and roots;
- restore shared fork pool;
- restore legal hold.

### 9.2 Sampling

All repositories get metadata verification. Full/reconstruction drills use risk/value/age and deterministic sampling, with minimum frequencies by durability tier.

### 9.3 Restore report

- source capsule;
- source materials;
- missing/corrupt items;
- repairs;
- resulting capsule;
- reference Git result;
- forge aggregate checks;
- duration/cost;
- tool versions;
- operator/service signatures.

## 10. Security verification

- threat-model traceability;
- auth/capability property tests;
- tenant isolation;
- cross-tenant dedup oracle;
- SSRF/egress;
- parser/decompression bombs;
- pack delta bombs;
- Markdown XSS/link/image;
- prompt injection;
- secret exfiltration;
- runner escape campaigns;
- webhook signature/replay;
- key rotation/revocation;
- admin dual control;
- supply-chain provenance;
- fuzzing;
- dependency audit;
- external assessment before 1.0.

Security tests never use production secrets.

## 11. E-process and statistical verification

For each monitor:

- define data and filtration;
- define null and action;
- simulate calibration under null;
- test optional stopping behavior;
- test missingness and instrumentation changes;
- test dependence/nonstationarity stress;
- version/reset state;
- compare with fixed hard guardrails;
- verify action is bounded/reversible;
- replay decisions.

A monitor can be “mathematically valid under assumptions” and operationally useless. Both validity and decision utility are evaluated.

## 12. Search, graph, and context verification

### 12.1 Search

- exact query correctness;
- lexical corpus metrics;
- symbol definition/reference;
- historical query;
- semantic relevance benchmark;
- source attribution;
- freshness;
- latency/cost;
- tenant isolation.

### 12.2 Graph

- edge source/evidence class;
- deterministic rebuild;
- stale watermark;
- high-degree bounds;
- provenance queries;
- no heuristic edge represented as canonical.

### 12.3 Context Packets

Evaluate:

- task success;
- relevant-source recall;
- irrelevant-byte/token rate;
- source correctness;
- stale detection;
- omissions;
- latency/cost;
- prompt-injection containment.

Human and agent evaluations use frozen tasks and blind comparisons where feasible.

## 13. Performance verification

### 13.1 Workloads

- cached/cold ref reads;
- small file/tree;
- clone/fetch by repo size and haves;
- push by object/ref shape;
- many disjoint refs;
- contended protected ref;
- workspace warm/cold/sparse;
- PR diff;
- search/context;
- CI cache/artifact;
- scrub/repair;
- restore;
- GC/compaction interference.

### 13.2 Baselines

- ordinary local Git;
- a conventional self-hosted forge where reproducible;
- coarse repository lease implementation;
- full-replica storage;
- no-RaptorQ replication;
- no-index/full-scan;
- cold and warm cache.

### 13.3 Reporting

Report:

- p50/p95/p99/p99.9;
- throughput;
- CPU/memory;
- bytes/requests;
- storage amplification;
- cost;
- correctness validation;
- confidence/variation;
- hardware and environment.

No benchmark may omit failed/refused operations from denominator without saying so.

## 14. Release gates

### Design preview

- E0 critical claims;
- schemas and models;
- no implementation language implying production.

### Alpha

- E2 core truth;
- E3 basic Git;
- successful full restore;
- destructive GC disabled or conservative.

### Beta

- E4 RefTxn/cell;
- E3 declared Git matrix;
- security test closure;
- recovery drills;
- upgrade/rollback;
- production canary.

### 1.0

- required E4/E5 claim matrix;
- external security review;
- external restore/migration;
- SLO and cost evidence;
- no unresolved critical invariant defect.

## 15. Continuous verification

CI lanes:

- fast unit;
- property;
- golden/schema;
- Git differential shard;
- deterministic simulation shard;
- fuzz smoke;
- dependency/license;
- unsafe ledger;
- docs/claim registry;
- performance smoke;
- wasm/platform;
- release provenance.

Scheduled lanes:

- long simulation;
- full Git corpus;
- fuzzing;
- chaos cluster;
- restore;
- RaptorQ reconstruction;
- GC;
- mixed-version upgrade;
- security campaigns;
- benchmark.

## 16. Evidence retention

Evidence artifacts are immutable and content-addressed. They include code/corpus/config digests and may themselves use repair/archive profiles.

Private/security-sensitive evidence can be encrypted and access-controlled while publishing a commitment and sanitized summary.

## 17. Failure disposition

Every discovered failure is classified:

- invariant violation;
- compatibility divergence;
- availability/SLO;
- evidence/harness defect;
- unsupported scope;
- security;
- performance/cost;
- documentation claim.

A failed test is never deleted because it is inconvenient. It is fixed, quarantined with an explicit release consequence, or used to narrow the claim.

## 18. Verification completion criterion

FrankenGit may call a feature complete only when someone other than its implementation author can:

1. state the observable contract;
2. run the evidence;
3. inject the declared faults;
4. reproduce the result;
5. identify the scope and limitations;
6. restore or roll back the feature’s state.

That is the minimum standard for a forge intended to preserve humanity’s software.

# ADR-0001: Canonical Repository State Is an Immutable Decision Stream, Not a Mutable Git Directory

- **Status:** proposed; revision 2 of this ADR, aligned with the v3 architecture (supersedes the original draft ADR text)
- **Date:** 2026-08-19
- **Decision owners:** FrankenGit architecture
- **Scope:** repository truth, publication, recovery, materialization, and compatibility

## Context

Git’s immutable object model is exceptionally strong, but most forges operationalize one mutable POSIX directory as the repository unit: loose objects, packs, indexes, refs, lock files, reflogs, maintenance products, and implementation-specific caches. That shape is convenient for an ordinary Git process. It also couples durability, consistency, placement, failover, maintenance, and throughput to a filesystem object that was not designed as a distributed authority boundary.

A forge additionally owns canonical state not represented by Git objects: ref movements, pull requests, reviews, issues, protections, merge queues, releases, package metadata, identities, policy decisions, retention roots, and external-effect obligations.

Cursor’s “Git at Any Scale” demonstrates that immutable object-store writes plus conditional publication can make local Git repositories disposable. The deeper FrankenGit synthesis adds:

- clean-room pure-Rust Git semantics rather than a C Git materialization as production engine;
- one object-store-native repository decision stream covering refs and forge events;
- stable transaction seals and queryable terminal outcomes;
- semantic witness refinement and microbatched publication;
- root-last checkpoints, repair, retention, and agent evidence;
- an embedded FrankenSQLite authority profile implementing the same contract for one-node self-hosting.

The original ADR draft still described a fenced authority-domain writer and treated capsules as routine materialization pins. This revision replaces that model with one authenticated authority head advanced by linearizable compare-and-exchange. Routing locality and preferred writers remain optimizations only.

## Decision

### 1. Canonical bodies are immutable

Canonical bodies include:

- exact admitted Git objects in their native object-ID domain;
- FrankenGit envelopes, segments, manifests, and authenticated indexes;
- transaction seals and prepared transaction capsules;
- repository decision batches and Repository Commit Records;
- canonical forge events and aggregate roots;
- policy/evidence records required to explain decisions;
- retention/legal-hold/migration/restore roots;
- root-last repository capsules, backups, and release manifests.

Bodies are written by strong put-if-absent under domain-separated typed identity. Arrival, placement, and storage listing do not establish order or reachability.

### 2. One small authority head establishes canonical order

Each repository has one `RepositoryAuthorityHead` key. Its authenticated body binds at least:

- monotone head generation;
- exact predecessor head identity;
- latest decision-batch identity;
- latest repository sequence/RCR;
- resulting ref root;
- resulting forge-position root;
- current retention/policy/key/format epochs required for interpretation.

A mutation linearizes only when the `AuthorityStore` successfully conditionally replaces the exact previously read head/version token with the candidate head. The immutable decision batch and all descendants are staged and verified first. A losing compare-and-exchange exposes nothing canonical; the same sealed `TxId` rereads, witness-refines/rebases where allowed, and retries.

Any eligible cell may prepare and attempt publication. Rendezvous hashing, locality, and a short-lived flat combiner optimize the healthy path but never become correctness prerequisites. There is no repository home cell, durable local primary, or separately authoritative ref database.

### 3. Transaction outcomes are derived from the canonical stream, with safe accelerators

A sealed `TxId` has at most one terminal canonical decision: commit or refusal. The decision is represented inside the immutable ordered decision stream. A direct `TxId -> outcome` index may be conditionally written as a rebuildable accelerator, but replay of the authenticated head chain remains sufficient to recover truth.

### 4. FrankenSQLite implements the local authority profile

Single-node/self-hosted mode uses FrankenSQLite for:

- the `AuthorityStore` compare-and-exchange contract;
- local object-location and TxId indexes;
- projections, queues, leases, and operational catalogs;
- MVCC snapshots and per-core preparation acceleration.

Its pages or rows are not a second logical truth universe. Export/recovery follows the same immutable decision objects and authority-head semantics as object-store deployments.

### 5. Everything else is a derived materialization

Derived state includes:

- bare repositories and worktrees;
- client-facing packs, loose-object layouts, MIDX, commit graphs, and bitmaps;
- TreeFS workspaces and CI checkouts;
- relational/local read models and queues;
- search, graph, structural, and vector generations;
- rendered Markdown, diffs, summaries, and API caches;
- regional object/pack caches and placement accelerators.

Every materialization names an `AuthorityReadReceipt`, source RCR/decision position, and generation identity. A repository capsule is a checkpoint/restore artifact, not the mandatory pin for every ordinary read.

## Consequences

### Positive

- Complete recovery does not require a surviving mutable Git filesystem or external metadata database.
- Any cell may attempt publication without a lease-elected repository primary.
- A single conditional head replacement gives a precise, testable linearization point.
- Expensive validation, object admission, witness refinement, graph/search preparation, and decision construction parallelize before a tiny ordered residue.
- Ref and forge effects are committed in one decision batch/RCR.
- Cold repositories require no running process or durable local checkout.
- Embedded and hosted deployments share one logical protocol.
- Repair, checkpoint, migration, GC, and release can be expressed as ordinary authority-mediated intents.
- Local Git materializations remain available for compatibility testing and derived acceleration but cannot redefine truth.

### Negative

- Every supported authority backend must prove strong create/read/conditional-replace and ABA-safe semantics rather than merely claim “S3 compatibility.”
- The project must own canonical codecs, reference replay, head recovery, microbatch ordering, and retry semantics.
- Object-store latency makes combining, caching, segmentation, and read receipts important for economics.
- Garbage collection must reason from authenticated roots and in-flight seals, not filesystem reachability or bucket listing.
- Debugging requires first-class decision/replay/receipt tooling.
- Mixed-version and backend migration need explicit compatibility protocols.

## Invariants

1. A mutation is canonical only after successful conditional replacement of the exact predecessor authority head.
2. Every accepted head names a verified immutable decision batch whose predecessor and resulting roots match.
3. Head generation is monotone and ABA-safe; an older valid head cannot silently replace a newer acknowledged head.
4. One sealed `TxId` has at most one terminal canonical decision.
5. A lost compare-and-exchange preserves the sealed request and either safely rebases under declared witnesses or refuses.
6. Ref and associated forge-event effects publish in one RCR/decision or neither does.
7. Quarantined, unverified, or merely uploaded bytes never become retention roots.
8. A derived materialization, projection, cache, capsule, or TxId index cannot authorize canonical mutation without current authority revalidation.
9. Repair publication goes through the same authority head and cannot overwrite newer logical state.
10. Replaying from a trusted head/checkpoint plus suffix reconstructs Git-visible refs, forge positions, outcomes, and retention roots.
11. Export to ordinary Git preserves native object identity without proprietary rewriting.
12. Production behavior is implemented in safe pure Rust and never falls back to another Git engine.

## Rejected alternatives

### A. Mutable bare repository as sole truth

Rejected because filesystem locking, replication, backup, and maintenance become canonical correctness boundaries.

### B. External relational ref database plus separate object WAL as co-authorities

Rejected because split publication, restore ordering, and operational reconciliation create dual truth. FrankenSQLite remains a backend/accelerator implementing the same authority contract, not a rival log.

### C. One leased home cell or primary writer

Rejected as a correctness dependency. Preferred routing and flat combining are useful, but failover must not require moving authoritative local state or trusting lease expiry.

### D. Asynchronous active-active multi-master refs

Rejected for ordinary Git refs and protected forge transitions. Advisory replicas may use conflict-absorbing CRDTs, but canonical publication has one authenticated order.

### E. Store all bytes as relational rows

Rejected because Git’s immutable object graph, range/segment economics, ATP transfer, and repair do not fit a general row store as the universal byte substrate.

### F. Replace Git with a new incompatible VCS

Rejected because ordinary Git clients, export, local autonomy, and ecosystem access are constitutional goals.

### G. Network filesystem as distributed repository

Rejected because it relocates rather than removes filesystem semantics, lock ambiguity, and correlated operational complexity.

### H. One object-store WAL without forge/agent/repair contracts

Rejected as incomplete. FrankenGit additionally needs typed ref/forge effects, terminal outcomes, policy/evidence, retention, checkpoints, repair, and agent control objects.

## Verification required before acceptance

- canonical codecs and golden vectors for seals, prepared capsules, decision batches, RCRs, and heads;
- a pure deterministic state machine and reference replay;
- model/DPOR exploration of duplicate, lost response, competing CAS, cancellation, crash, and retry schedules;
- AuthorityStore conformance suites for embedded and object-store profiles, including ABA and stale receipt attacks;
- proof that per-core preparation and microbatching refine the single-decision model;
- witness-refinement properties showing no true conflict can be removed;
- pure-Rust import/export and wire differential tests with pinned Git clients;
- complete recovery after deleting every materialization and rebuildable accelerator;
- corruption, RaptorQ, repair-versus-newer-write, GC, legal-hold, and restore campaigns;
- measured comparison with conventional bare-repository and external-database designs.

## Supersession rule

A future ADR may supersede this decision only if it preserves ordinary Git export and provides strictly clearer executable evidence for identity, ordering, atomicity, recoverability, and economics. An implementation shortcut cannot silently supersede the decision.

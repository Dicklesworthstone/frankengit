# ADR-0001: Canonical Repository State Is Not a Mutable Git Directory

- **Status:** proposed
- **Date:** 2026-08-19
- **Decision owners:** FrankenGit architecture
- **Scope:** repository truth, recovery, materialization, and compatibility

## Context

Git’s object model is exceptionally well suited to immutable source history, but the operational unit used by most forges is a mutable POSIX directory containing loose objects, packs, indexes, refs, lock files, logs, maintenance products, and implementation-specific caches. That unit is convenient because ordinary Git can execute directly against it. At large scale it also couples durability, consistency, placement, failover, maintenance, and performance to a filesystem-shaped object that was not designed to be a distributed service boundary.

A forge additionally owns mutable state that is not represented by Git objects: branch and tag movements, repository settings, policies, pull requests, reviews, approvals, issues, workflow state, packages, releases, identities, and audit history.

Cursor’s “Git at Any Scale” architecture demonstrates an important separation: durable state can live in an immutable object-store-backed log while local Git repositories are disposable materializations on NVMe. FrankenGit adopts the separation but requires a broader, publicly specified canonical model that also supports fine-grained reference transactions, independent recovery, repair, agent evidence, and self-hosting.

## Decision

FrankenGit’s canonical repository state consists only of:

1. **Exact admitted Git objects.** The original canonical Git object bytes and declared Git object identifier are preserved.
2. **Immutable FrankenGit envelopes, segments, and manifests.** These provide stronger content commitments, location, encryption, format/version, repair, and verification metadata without changing the embedded Git object.
3. **An atomic Repository Commit history.** RefTxn and forge commands are admitted as immutable Repository Commit Records containing ref deltas and/or canonical event batches, exact policy/evidence receipts, and one linearization point within an authority domain.
4. **Canonical forge event objects and streams.** Non-Git collaboration state is represented by versioned, attributable events whose admission is recoverable from Repository Commit Records.
5. **Policy, key, and identity history required to interpret canonical transitions.** Only the minimum replay-critical history is canonical.
6. **Root-last Repository Capsules.** A signed/checksummed capsule commits to a recoverable repository generation: ref roots, required object/segment roots, forge-event positions, predecessor, and relevant policy/key epochs.

The following are **derived materializations**:

- bare Git repositories;
- worktrees and agent workspaces;
- loose-object layouts and client-facing packfiles;
- pack indexes, multi-pack indexes, commit graphs, and bitmaps;
- relational tables and read models;
- search, graph, structural, and vector indexes;
- rendered Markdown, diffs, and summaries;
- CI build directories and caches;
- web/API response caches.

Derived state may be cached, replicated, evicted, corrupted, or rebuilt without changing canonical truth. Every materialization is pinned to a Repository Capsule and/or forge-event generation.

## Consequences

### Positive

- Complete repository recovery does not require a surviving mutable Git filesystem.
- Read and compute workers can use disposable local Git repositories for maximum compatibility and performance.
- Object admission is naturally parallel because immutable objects do not require a repository-wide lock.
- Ref mutation can be serialized narrowly through `RefTxn` instead of leasing every operation against the repository.
- Backups and disaster recovery have a precise recoverability root.
- Integrity, erasure repair, encryption, and placement become explicit object contracts.
- Search/graph/relational corruption cannot silently redefine repository truth.
- Agent workspaces can be sparse, ephemeral, and capsule-pinned.
- Self-hosted and hosted deployments share the same truth model even when their storage adapters differ.

### Negative

- The system must implement and verify a new transaction/capsule protocol.
- Ordinary Git maintenance products cannot be treated as the sole authoritative source.
- Materialization and pack-generation correctness require substantial differential testing.
- Garbage collection must reason from retained capsules/events/manifests rather than filesystem reachability alone.
- Operators need new doctor, recovery, and evidence tools.
- Migration and export paths must preserve exact Git semantics across two identity layers.
- The canonical event model adds schema/versioning obligations.

## Invariants

1. A reference cannot commit to required objects that have not passed admission and the promised durability class.
2. A Repository Capsule is published only after all required descendants are present and verified.
3. A combined repository operation admits its ref delta and canonical forge-event batch through one Repository Commit Record or neither effect.
4. A `RefTxnId` has exactly one terminal outcome and is bound to one request-byte commitment.
5. A stale writer cannot commit after its fence or authority epoch expires.
6. A derived materialization cannot authorize or define canonical mutation.
7. Reconstructing from canonical state yields Git-visible refs and objects equivalent to the committed generation.
8. Export to ordinary Git does not require proprietary object rewriting.
9. Repair produces exact bytes verified by independent content and structural commitments.

## Rejected alternatives

### A. Mutable bare repository as the sole source of truth

Rejected because it makes filesystem replication, locking, backup, and recovery the correctness boundary and turns every optimization into a risk to canonical state.

### B. Store all repository data as relational rows

Rejected because Git’s immutable object graph and pack/transport behavior do not map cleanly to a general row store, and because the database would become both byte store and semantic authority.

### C. Replace Git with a new incompatible version-control model

Rejected because compatibility, ecosystem access, local autonomy, and ordinary Git export are constitutional goals.

### D. Make a network filesystem the distributed repository

Rejected because it moves but does not remove filesystem semantics, lock behavior, failure ambiguity, and correlated operational complexity.

### E. Treat one object-store WAL as the complete public contract

Rejected as insufficient for FrankenGit’s goals. The system also needs fine-grained ref transactions, explicit forge events, repair manifests, recoverability capsules, self-hosted adapters, and agent evidence.

### F. Make CRDT branch heads multi-value by default

Rejected because ordinary Git users and protected-branch policies require a deterministic committed ref value. Federation may preserve divergent histories as separate signed events/refs, but local publication resolves under explicit policy.

## Verification required before acceptance

This ADR remains proposed until all of the following exist:

- canonical schemas and golden vectors;
- executable small-state model for `RefTxn` and capsule publication;
- deterministic crash/retry/cancellation exploration;
- import/export differential tests with ordinary Git;
- complete recovery after deletion of every derived materialization;
- stale writer and split-brain tests;
- corruption and repair campaigns;
- garbage-collection proof over retained capsules and event positions;
- measured comparison against a conventional bare-repository architecture.

## Supersession rule

A future ADR may supersede this decision only if it preserves ordinary Git export and provides strictly clearer evidence for durability, consistency, recoverability, and operational economics. An implementation shortcut cannot silently supersede the decision.

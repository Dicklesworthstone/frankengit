# FrankenGit Architecture

**Status:** pre-implementation architecture summary  
**Normative source:** [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md)  
**Full plan:** [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md`](COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md)

This document is the compact map of FrankenGit’s v3 architecture. It intentionally omits product detail and repeats only the contracts necessary to understand component ownership and data flow.

## 1. Architectural objective

Preserve ordinary Git at the edge while making canonical repository and forge state:

- independent of a mutable bare repository;
- published through one narrow conditional authority primitive;
- immutable, replayable, and independently recoverable;
- cheap to materialize near demand;
- efficient for large populations of agents and CI jobs;
- strictly pure Rust and memory-safe in first-party code;
- observable without letting projections, graphs, models, or repair paths become authority.

## 2. Constitutional invariants

1. **Pure Rust:** production never links or invokes C Git, `libgit2`, JGit, Dulwich, or another Git engine.
2. **Safe first-party code:** every crate uses `#![forbid(unsafe_code)]`.
3. **One runtime:** Asupersync owns async execution, cancellation, capabilities, obligations, ATP, and deterministic lab behavior.
4. **One repository authority:** only successful conditional replacement of the exact `RepositoryAuthorityHead` predecessor publishes repository state.
5. **Immutable canonical history:** seals, decisions, RCRs, batches, events, evidence, manifests, generations, and capsules are immutable.
6. **Atomic source/forge effects:** a merge/ref update and its forge transition are one `RepositoryCommitRecord`.
7. **No ambiguous cancellation:** disconnect/cancel never proves non-commit; outcome is queried by stable transaction identity.
8. **Staged/visible/durable are distinct:** a body can exist before authority selects it and before full durability obligations close.
9. **Repair uses normal authority:** verified reconstruction cannot overwrite newer or deleted state.
10. **Derived state is receipted:** every materialization/projection/generation names the canonical position it represents.
11. **Exact/statistical types are separate:** models and graphs cannot silently authorize, delete, or redefine truth.
12. **Local release authority:** repository-owned DSR lanes and signed root-last manifests, not hosted workflow status, define releases.

## 3. System topology

```text
                         +-------------------------+
                         | Git / API / agent users |
                         +------------+------------+
                                      |
                         +------------v------------+
                         | pure-Rust gateways      |
                         | SSH / smart HTTP / API  |
                         +------------+------------+
                                      |
              +-----------------------v-----------------------+
              | stateless execution cells                    |
              |                                               |
              | validation  policy  graph/search  TreeFS     |
              | local FrankenSQLite projections/caches        |
              | per-core preparation lanes + batch combiner   |
              +-----------+-------------------+---------------+
                          |                   |
             immutable puts/reads             | exact CAS
                          |                   |
               +----------v---------+   +-----v----------------+
               | object/segment     |   | AuthorityStore       |
               | decision/evidence  |   | repository head key  |
               | fabric             |   +-----+----------------+
               +----------+---------+         |
                          +-------------------+
                                      |
                    canonical decision stream/head
                                      |
          +---------------------------+---------------------------+
          |                           |                           |
 +--------v---------+       +---------v---------+       +---------v---------+
 | materializers    |       | forge/search/     |       | repair/checkpoint |
 | Git/TreeFS/packs |       | graph projections |       | GC/archive        |
 +------------------+       +-------------------+       +-------------------+
```

A cell may be preferred for a repository through rendezvous hashing, but it is not an authority owner. Any eligible cell can reread the head and attempt publication. Gossip is a freshness/cache hint only.

## 4. Canonical object model

### 4.1 Transaction seal

Created once with strong put-if-absent. Binds repository/tenant, principal snapshot, idempotency digest, canonical request digest, schema/capability/policy identity, and logical admission time. Identical retry is idempotent; different body is key-reuse rejection.

### 4.2 Prepared transaction capsule

Immutable reusable output of expensive preparation against one basis head:

- normalized intents and net effect;
- Git object closure;
- read/write/invariant witnesses;
- deterministic policy inputs/decision;
- resource/verifier/dependency receipts;
- required durability profile.

It is advisory until a decision batch containing its effect wins the head CAS.

### 4.3 Repository decision

One terminal outcome for one sealed transaction:

- `Committed { repository_commit_id }`; or
- `Refused { code, refusal_record_id }`.

Refusals advance decision audit order but not committed source sequence.

### 4.4 RepositoryCommitRecord

Binds the exact committed effects of one transaction:

- basis, actor, request, and transaction identity;
- ref delta/result root;
- admitted object closure;
- forge event batch/result position root;
- policy/evidence/conflict/verifier/resource roots;
- retention and outbox effects.

### 4.5 RepositoryDecisionBatch

Immutable ordered group of terminal decisions and committed RCRs against one exact predecessor head. Carries resulting authenticated roots. The batch may be staged by many contenders; only the winner selected by authority becomes canonical.

### 4.6 RepositoryAuthorityHead

Small canonical state root containing predecessor/generation, decision tail/sequence, latest committed RCR/repository sequence, ref/forge/outcome/retention/outbox/configuration roots, policy/format epochs, and checkpoint pointer.

The store’s exact predecessor version token plus monotone head generation prevents stale writers and ABA.

## 5. Mutation path

```text
request
  -> framing/auth/coarse admission
  -> canonicalize and derive stable logical identity
  -> terminal-outcome lookup
  -> seal put-if-absent
  -> read exact authority head
  -> validate Git quarantine/object closure
  -> evaluate intents/policy against one basis
  -> emit PreparedTxnCapsule
  -> append to per-core preparation lane
  -> combiner builds conflict graph and deterministic order
  -> finalize net-effect normal forms against scratch state
  -> stage decisions/RCRs/batch/candidate head
  -> conditional replace exact predecessor head
       won  -> all batch decisions terminal and visible
       lost -> reread, reuse/refine/rebase/reprepare, retry same seal
  -> transfer outbox/materialization obligations
  -> return immutable terminal outcome
```

No canonical effect is visible before the head CAS. Object bodies may be staged earlier but are unreachable and garbage-collectable until selected by roots.

## 6. Concurrency architecture

### 6.1 Per-core preparation lanes

Each lane follows `Writable -> Sealed -> Combining -> Retired -> Writable`. Preparation is append-only and bounded. Overflow/backpressure is explicit. Lane assignment and batch cuts are receipted.

### 6.2 Conflict witnesses

Conservative keys cover repository/config/policy, refs, forge aggregates, merge queue, quotas, retention/legal holds, paths/symbols, status evidence, and object visibility. Finer witnesses may prove independence.

### 6.3 Value-of-information refinement

Refinement runs only when expected saved retry/abort cost exceeds bounded CPU/I/O/latency plus risk margin. Failure to refine preserves correctness and only reduces concurrency.

### 6.4 Semantic rebase

Allowed ladder:

1. unchanged witness reuse;
2. deterministic intent replay;
3. structured ref/forge/path patch;
4. registered append/range/bitmap merge certificate;
5. typed retry/refusal/manual merge.

No raw byte/XOR source merge and no silent change to a sealed request.

## 7. Authority and storage profiles

### Embedded

FrankenSQLite provides the head compare-and-swap and local MVCC projections. Immutable bodies live in the local object fabric. Export uses the same canonical records as clustered deployments.

### Object-store cluster

A minimal pure-Rust adapter uses a backend that proves strong create/read/conditional replacement, ABA-safe version tokens, and failure semantics. Provider listing is not used for recovery.

### Future `fgit-authorityd`

A small pure-Rust replicated state machine may implement the exact `AuthorityStore` trait for operators without a suitable conditional object store. It does not introduce alternate transaction semantics.

## 8. Immutable object fabric

Owns typed immutable puts, exact/range reads, deterministic segments/manifests, placements/failure domains, encryption domains, lifecycle/retention evidence, and bounded streaming. Mutable location/scrub records do not alter logical object identity.

Logical object identities survive physical compaction/re-encoding. Compaction writes new immutable segments and publishes new manifests root-last.

## 9. Git engine

Production owns pure-Rust implementations of native object formats, hash domains, packs/deltas/DEFLATE, pkt-line/sideband, upload-pack, receive-pack, partial/promisor behavior, refs, commit graph/bitmap/MIDX/bundle materialization, diff/merge proposals, tags/notes/submodules/LFS adapters, and compatibility refusals.

Upstream Git is only a pinned external differential oracle. Unsupported operations fail visibly; there is no subprocess fallback.

## 10. ATP-Git

Native/internal transfer over Asupersync ATP provides:

- exact/probabilistic receiver have summaries;
- object/segment/pack delta planning;
- unique-payload dedupe and deterministic reconstruction;
- typed path graph and multipath racing;
- swarm rarity/endgame scheduling;
- adaptive RaptorQ/pacing within hard bounds;
- trust-scoped caches and peer evidence;
- budget/cancellation/replay receipts.

Ordinary Git remains the compatibility path. ATP-Git is an optimization/profile, not a different repository semantics.

## 11. TreeFS

A workspace is an immutable Git-tree base plus sparse semantic COW overlay. Reads require path/object capabilities and fetch lazily. Writes become typed intents with source-span lineage. Export constructs exact Git objects and a proposed transaction.

Adapters include direct Rust API, sparse directory, optional FrankenFS/FUSE mount, standard bare/worktree materialization, and archive streams. Every adapter is derived and receipted.

## 12. Forge events and projections

Canonical issues, PRs, reviews, protections, queue entries, releases, packages, agent runs, and audit events are immutable aggregates admitted by RCRs. Relational/API/UI/search/counter views are projections with exact source positions.

Outbox entries cover derived/external effects only. At-least-once delivery with stable IDs never duplicates canonical events.

## 13. Search and graph generations

Generations are immutable, predecessor-linked, monotone, anti-rollback, and root-last. Queries pin one generation vector. Mixed-generation results are refused or explicitly partial.

Graphs are typed as exact, deterministic-derived, or statistical. Stable external IDs and order coexist with dense integer adjacency for hot algorithms. Any user/operation-affecting algorithm declares tie-break and emits complexity/decision-path witness.

## 14. Agent and CI architecture

### Intent Run

Binds sponsor/agent/harness, exact base, objective, attenuated capabilities, budgets, evidence/verifier policy, expiry/revocation/disclosure.

### Context Packet

Content-addressed authorized source spans plus transformations, ranking/graph evidence, position, and omissions.

### Effect broker

Non-textual capability boundary for network, secret, CI, publication, package, billing, and external-service effects. Every accepted effect creates an obligation and receipt.

### Runner

Receives immutable `BuildInputCapsule`, isolated execution profile, bounded resources/egress/secrets/cache, cancellation/reaping, and exact check/artifact receipts.

## 15. Repair, checkpoint, and GC

Repair:

```text
detect -> quarantine -> gather -> decode -> verify original commitments
       -> reread authority/retention -> commit placement effect or discard
       -> attest
```

Checkpoint/capsule and derived-generation publication are body-first/root-last with anti-rollback. GC snapshots authenticated root classes, emits tombstones, waits safety horizons, revalidates current authority, commits deletion authorization, and sweeps placements idempotently.

## 16. CALM and obligations

Monotone immutable data/evidence can propagate without authority ordering. Bounded commutative state must expose merge/conflict laws. Refs, permissions, retention, queue positions, billing, and destructive state are coordinated through canonical authority.

Object writes, CAS attempts, outbox delivery, repair, secrets, runners, workspaces, context, and billing reservations are typed obligations. Region close must resolve or report every obligation.

## 17. Statistical policy

Every conformal/e-process/no-regret/OPE/change-point/Lyapunov artifact binds metric, population, selection, exact sequence window, regime, candidate/fallback policy, assumptions, implementation/toolchain/numeric fingerprint, and retained evidence.

Statistical policy can tune bounded operational choices. It cannot decide identity, authorization, ref order, retention roots, current truth, or irreversible sanctions.

## 18. Local verification and release

Repository-owned commands are authority. Workflow YAML is a local DSR/`act` adapter. Target builds have stable run/attempt identities and exact input manifests. Verified completed targets may be resumed only when all identity fields match.

The signed release manifest is published last after the entire requested matrix and exact assets verify. GitHub Releases is reconciled as a mirror.

## 18a. Ambition extensions built on the same primitives

Five proposal-class capabilities reuse this architecture without adding truth machinery (comprehensive plan §18.7, §29.8, §31.8, §34.8, §40.8; backlog FG-037..FG-041):

- **verified reads:** Merkle inclusion proofs from any answer to a named authenticated head make mirrors/CDNs trustless;
- **decision-addressed snapshots:** `fg at <decision>` opens the full forge exactly as of one decision, and bisection generalizes from commits to forge state;
- **cross-organization evidence exchange:** content-addressed evidence packs travel between organizations with claim classes intact — tightening, never bypassing, local checks;
- **deterministic build-output reuse:** declared-deterministic CI outputs become trust-scoped derived state keyed by exact `BuildInputCapsule` identity;
- **mechanized proof of the ordered residue:** machine-checked theorems for seal/outcome/batch/head transitions occupy the top of the claim lattice.

## 19. Strict dependency DAG

Foundation → protocol/storage primitives → canonical engines → derived intelligence/hostile-execution protocols → products/adapters.

L3 siblings cannot reach into each other’s internals; L4 orchestrates public contracts. Crates appear only with real final-abstraction slices. The registry checker rejects banned dependencies, first-party unsafe/FFI/subprocess Git, layer violations, empty scaffolds, and unpinned local workflow actions.

## 20. Degradation matrix

| Failure | Safe behavior |
|---|---|
| Authority unavailable | verified snapshot/bounded-stale reads by policy; no canonical mutation |
| CAS loss | no visibility; deterministic revalidation/retry same seal |
| Cell/local disk lost | rebuild from head/object fabric; no canonical loss |
| Gossip lost | slower head/cache discovery; verify authority directly |
| Object placement corrupt | quarantine/repair/refuse according to durability state |
| Projection/generation lost | rebuild from canonical sources; freshness receipt degrades |
| ATP unavailable | fall back to ordinary Git/object transfer |
| Semantic refinement unavailable | conservative conflict/retry; correctness unchanged |
| Model/statistical evidence unavailable | deterministic fallback policy |
| Runner compromised | contain/revoke; receipts/artifacts untrusted; authority unaffected |
| Release host unavailable | target incomplete; no release manifest |
| Higher acknowledged root unresolved | fail closed; never silently roll back |

## 21. Architectural acceptance

The architecture is acceptable only when implementation evidence demonstrates:

- one terminal outcome per sealed transaction under duplicate/lost-response/cancel races;
- exact head predecessor/generation continuity and atomic ref/forge roots;
- pure-Rust Git compatibility for the declared matrix;
- safe resource bounds for hostile objects/packs/documents/workflows/packages;
- reference-equivalent per-core batching/rebase;
- TreeFS path/capability/export/crash semantics;
- repair-through-authority and GC root safety;
- generation anti-rollback and graph decision witnesses;
- obligation quiescence for sessions, agents, runners, repair, and release;
- complete local DSR release without hosted Actions;
- claims no stronger than their immutable evidence.

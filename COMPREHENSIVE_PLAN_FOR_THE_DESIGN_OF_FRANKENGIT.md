# Comprehensive Plan for the Design of FrankenGit

**Version:** 2.0, fresh-eyes audited  
**Date:** 2026-08-19  
**Status:** pre-implementation architecture  
**Normative protocol:** [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md)  
**Evidence contract:** [`VERIFY_SPEC.md`](VERIFY_SPEC.md)

> This document is the comprehensive product and execution plan. For identity, ordering, linearization, transaction outcomes, push admission, retry/cancellation, writer fencing, capsule identity, agent authority, and RaptorQ boundaries, the normative protocol document wins. No section below is an implementation or performance claim.

## 0. Executive summary

FrankenGit is a clean-sheet, Git-compatible software forge intended to be:

- self-hostable from one machine to a globally distributed installation;
- usable as a paid hosted service at FrankenGit.com;
- economical for enormous repositories, histories, artifacts, and agent workloads;
- safe and deterministic at canonical mutation boundaries;
- unusually recoverable and auditable;
- first-class for humans and autonomous coding agents;
- open to ordinary Git clients and migration tooling rather than requiring a new VCS.

The central architectural move is to separate **canonical truth** from **Git materialization**. Immutable Git objects, canonical forge events, sealed mutation requests, terminal outcomes, authenticated roots, and ordered Repository Commit Records form truth. Bare repositories, packs, worktrees, commit graphs, indexes, CI checkouts, web views, and search/graph generations are disposable products of that truth.

A successful mutation publishes one `RepositoryCommitRecord` (RCR) binding both its ref delta and forge-event batch. The serializable metadata commit that publishes the RCR also publishes the new head, terminal transaction outcome, resulting roots, and transactional outbox. This creates a precise linearization point and removes split-brain states between Git and the forge product.

The architecture is deliberately radical in repair, evidence, and agent ergonomics—but conservative in authority. RaptorQ repairs registered immutable byte objects and is followed by original commitment verification. Conformal/e-process systems adapt bounded operational policy but never decide identity, authorization, committed truth, or deletion safety. Agents receive attenuated capabilities and provenance-bearing context rather than ambient credentials and giant clones.

## 1. Mission and product thesis

### 1.1 Mission

Build the most reliable and agent-efficient Git forge that can still meet users where they already are: ordinary Git clients, familiar pull requests, issues, reviews, protections, CI, releases, packages, webhooks, and APIs.

### 1.2 Why a new forge architecture is justified

Existing forges are highly capable, but their historical architecture often couples repository truth to mutable filesystem state and treats product records, queues, CI, search, and caches as separately coordinated systems. At agent scale, this creates waste and ambiguity:

- thousands of concurrent workers clone the same large repositories;
- sparse context requests are implemented as broad filesystem access;
- ref updates and PR/merge state cross service boundaries;
- local repository placement affects failover and cost;
- repair and deletion semantics depend on hidden operational convention;
- APIs expose human-oriented objects but not stable evidence and context receipts;
- retries and cancellation can leave clients uncertain whether an effect happened.

FrankenGit addresses those at the data-model and protocol level rather than adding another cache around a conventional monolith.

### 1.3 Product positioning

A mature FrankenGit should serve four overlapping markets:

1. **Individuals and small teams:** a simple single-node binary or container with straightforward backup/export.
2. **Enterprises and sovereign installations:** self-hosting, SSO, audit, policy, data residency, private runners, and migration tools.
3. **FrankenGit.com:** globally hosted forge with usage-based storage/compute and premium operational guarantees.
4. **Agent-heavy engineering:** sparse workspaces, context packets, effect capabilities, evidence-carrying changes, high mutation concurrency, and machine-readable streaming APIs.

### 1.4 Truthfulness constraint

The current repository is architecture only. “Implemented,” “compatible,” “self-healing,” “linearizable,” “open source,” and performance claims advance only through named evidence and final licensing. The current custom rider is source-available rather than OSI open source; see `docs/LICENSING_DECISION.md`.

## 2. Goals and non-goals

### 2.1 V1 goals

- Git smart HTTP and SSH for upload-pack/fetch and receive-pack/push.
- SHA-1 repositories; SHA-256 support either V1 or a clearly gated follow-on based on implementation cost.
- atomic multi-ref push when negotiated; precise non-atomic compatibility otherwise.
- shallow and partial clone, promisor semantics, tags, notes, submodules, and Git LFS.
- event-sourced issues, pull requests, reviews, labels, milestones, releases, protections, and merge queue.
- transactional outbox for CI, webhooks, indexing, notifications, and billing.
- disposable Git materialization and sparse COW workspaces.
- deterministic reference state machine and replayable evidence.
- backup/restore capsules and at least one end-to-end verified RaptorQ-protected immutable class.
- agent Intent Runs, Context Packets, effect broker, and Evidence-Carrying Changes.
- progressive lexical/semantic/graph retrieval carrying canonical position.
- hosted multi-tenancy primitives: isolation, quotas, accounting, abuse controls, and operational evidence.

### 2.2 Explicit V1 non-goals

- replacing Git with a new user-facing VCS;
- asynchronous active-active multi-master canonical mutation;
- full GitHub API/Actions semantic compatibility on day one;
- arbitrary user code running inside the control plane;
- Pages, Codespaces, or every GitHub product surface;
- federation before single-site canonical semantics are proven;
- statistical systems granting authorization or deciding irreversible punishment;
- claiming every byte is RaptorQ-coded;
- empty crate scaffolding presented as progress.

## 3. Constitutional principles

### 3.1 Compatibility at the edge, clean design inside

Git wire and object behavior is preserved where promised. Internal APIs, storage, and forge events are clean-sheet, typed, versioned, and deterministic.

### 3.2 One owner per invariant

Every invariant has one authoritative module/service and one evidence path. Duplicated enforcement may provide defense in depth but cannot create competing truth.

### 3.3 Immutable bodies, small mutable roots

Large data and historical records are immutable. Mutable metadata consists of small pointers, leases, policies, counters, and queues protected by a transactional replicated substrate.

### 3.4 Root-last publication

A root, checkpoint, generation, or capsule is published only after all dependencies are durable and verified. Readers never interpret a partially assembled root as complete.

### 3.5 Typed refusal, not accidental behavior

Malformed, unsupported, stale, unauthorized, over-budget, conflicting, and unrecoverable conditions return stable typed refusals with evidence. Panics and connection drops are not protocol semantics.

### 3.6 Structured concurrency

Long-lived sessions, validation, materialization, repair, projection, CI, and agent runs own all child tasks. Cancellation is request/drain/finalize; shutdown ends in quiescence or an explicit non-cooperative failure.

### 3.7 Evidence over adjectives

Claims bind artifacts, versions, inputs, commands, and scope. Tests, models, benchmarks, fault campaigns, and deployment telemetry remain distinct evidence classes.

## 4. Three-plane architecture

### 4.1 Canonical truth plane

Owns:

- native Git object identities and immutable envelopes;
- canonical forge events;
- transaction seals and terminal outcomes;
- writer epochs and repository sequence;
- RCR chain;
- authenticated ref and forge-position roots;
- policy decision/evidence roots;
- retention/legal-hold roots;
- outbox entries;
- capsules and backup manifests.

### 4.2 Materialization plane

Owns rebuildable views:

- bare repositories and packs;
- commit graphs, bitmaps, MIDX/indexes;
- partial/promisor views;
- local edge caches;
- agent/CI workspaces;
- release/package/LFS download caches.

Every materialization carries a source RCR/capsule receipt. Stale or corrupt views are discarded and rebuilt, not reconciled as peers of canonical truth.

### 4.3 Intelligence/projection plane

Owns:

- issues/PR web read models;
- notification feeds;
- search index generations;
- code/ownership/dependency graph generations;
- analytics and operational telemetry;
- agent Context Packets;
- anomaly-review queues.

Projection lag is explicit. Canonical effects revalidate current truth.

## 5. Canonical identities and data model

### 5.1 Hash agility

All digest-bearing types include algorithm and domain. Native Git object IDs remain native. Internal records use a versioned cryptographic registry and domain-separated canonical bytes.

SHA-1 collision handling must not rely on wishful thinking. Git’s native identity is preserved for compatibility while internal envelopes can bind stronger digests, length, type, and repository format. The exact collision-defense policy receives its own ADR and compatibility tests.

### 5.2 Stable transaction identity

`RequestId` traces one attempt. `TxId` identifies one admitted logical mutation and uses the sole formula in the normative protocol. Reusing an idempotency key with a different semantic request is refused.

### 5.3 Transaction seal and outcome

A seal binds principal, repository, canonical request digest, idempotency digest, admission epoch, and policy epoch. After sealing, at most one terminal `TxnOutcomeRecord` becomes visible: committed RCR or canonical refusal.

Connection loss and cancellation never become proof of non-commit. Clients can query the immutable outcome by `TxId`.

### 5.4 Repository Commit Record

The RCR includes:

- repository ID, epoch, sequence, parent, TxId, principal, request digest;
- ref delta and resulting ref root;
- admitted object closure root;
- forge-event batch and resulting forge-position root;
- policy epoch/decision root;
- invariant evidence root;
- outbox root;
- optional capsule generated for this exact RCR.

The RCR identity hashes the unsigned canonical body.

### 5.5 Forge events

Event streams include stable entity IDs and sequence/chain commitments. Event examples:

- issue opened/edited/closed/reopened;
- PR opened/synchronized/reviewed/queued/merged/closed;
- review/comment/suggestion lifecycle;
- label/milestone/assignee changes;
- protection/policy epoch changes;
- release/package/artifact publication;
- administrator override and audit events.

Events are canonical; UI rows are projections.

### 5.6 Authenticated roots

Initial root implementations should favor simple deterministic structures with reference implementations and goldens over clever data structures. Required roots include refs, forge positions, object closure/manifests, policy decision inputs, retention, outbox, and segment manifests.

## 6. Canonical mutation protocol

### 6.1 Admission phases

1. request framing/size/protocol checks;
2. authentication and coarse capability admission;
3. semantic canonicalization and TxId derivation;
4. terminal-outcome lookup;
5. seal creation/verification;
6. fenced writer acquisition;
7. one pinned repository snapshot;
8. expected-old and object-closure validation;
9. candidate ref/forge construction;
10. deterministic policy evaluation;
11. immutable staging;
12. serializable compare-and-commit;
13. outbox/materialization after commit.

### 6.2 Linearization

The successful mutation linearizes when the metadata transaction atomically publishes the new RCR/head, terminal committed outcome, ref/forge roots, and outbox entries. Refusal linearizes when its terminal refusal record is published; it does not advance repository sequence.

### 6.3 Concurrency

The V1 model permits broad parallel work around one logical per-repository commit order. The sequencer is not necessarily one thread or one machine; it is one serializable order with epoch fencing.

Disjoint repositories scale independently. Within a repository, validation and object writes parallelize. A later physically sharded commit path must prove equivalence for all invariant keys—not merely different ref strings.

### 6.4 Cancellation and retry

- pre-seal cancellation: no canonical transaction;
- post-seal/pre-commit: cooperative drain, no partial canonical state, retry same TxId;
- post-commit: canonical result remains, downstream/response work may cancel;
- transient infrastructure failure: no terminal outcome, retry;
- deterministic policy/conflict failure: immutable terminal refusal.

## 7. Git object and protocol layer

### 7.1 Services

- `git-upload-pack`: clone/fetch over SSH and smart HTTP; v0/v1 and v2 commands where applicable.
- `git-receive-pack`: push over SSH and smart HTTP.
- REST/webhook/LFS/package protocols remain distinct adapters.

No architecture or test row calls receive-pack a standardized “protocol v2 push.”

### 7.2 Push quarantine

Incoming pack data is attacker-controlled and held outside canonical roots. Validation includes:

- pkt-line/sideband limits;
- pack checksum and trailer;
- compression ratio and expanded-byte budgets;
- delta depth/fan-out/aggregate work;
- thin-pack base resolution;
- object header/type/length;
- tree ordering, modes, and path names;
- commit/tag header limits;
- graph reachability and missing objects;
- native hash-format consistency;
- hidden/private ref advertisement and authorization;
- expected-old/force/atomic semantics;
- signature/certificate policy;
- tenant quotas and cancellation checkpoints.

### 7.3 Fetch/materialization

Fetch planning chooses from immutable object segments, pack cache, or on-demand pack construction. Optimizations include bitmaps, MIDX, commit graphs, regional caches, and bundle URIs, but the scalar/reference object closure remains the correctness oracle.

Partial clone filters are typed and resource-bounded. Promisor receipts bind omitted object promises to canonical state. Materialization incompleteness never weakens canonical retention.

### 7.4 Git LFS

LFS uses its SHA-256 object identity, separate batch/transfer protocol, quotas, resumability, verification, and retention roots. Locks, if supported, are forge metadata with explicit ownership and force-unlock evidence.

### 7.5 Compatibility registry

`docs/GIT_COMPATIBILITY_MATRIX.md` decomposes transport, service, protocol, capability, object format, and forge/API surface. Each row records status, oracle versions, fixtures, accepted divergences, and resource-limit behavior.

## 8. Storage architecture

### 8.1 Immutable object/event store

Requirements:

- content-addressed idempotent put/get;
- conditional creation and verified length/digest;
- range reads and streaming;
- object metadata independent of provider listing consistency;
- placement receipts and failure domains;
- encryption policy and key rotation;
- lifecycle tiers without breaking retention promises;
- deterministic segment/manifests;
- scrub and repair evidence.

### 8.2 Metadata substrate

The initial implementation should use a well-understood transactional substrate rather than invent consensus. Selection criteria:

- serializable transactions or equivalent compare-and-commit;
- linearizable key operations for seal/outcome/head;
- consensus-backed leader/fencing semantics;
- backup/restore and change feed;
- predictable single-repository hot-key behavior;
- multi-tenant operational isolation;
- documented failure modes and client library quality;
- local single-node development path.

Candidates must be benchmarked and fault-tested; the plan does not prematurely declare a winner.

### 8.3 Segmentation

Immutable objects/events are grouped into canonical segments for economic storage, streaming, checksumming, repair, and indexing. Segment formation must not change logical identity. Manifests map logical IDs to immutable placements and can be rebuilt from source segments.

### 8.4 Encryption and deletion

Envelope encryption uses per-tenant/repository/object-class keys according to policy. Key IDs and algorithms are versioned. Deletion claims distinguish logical invisibility, scheduled physical deletion, backup expiration, and cryptographic erasure.

## 9. Repository capsules, backup, and recovery

### 9.1 Capsule body

Binds exact RCR, epoch/sequence, ref root, forge-position root, object/segment manifest roots, retention root, policy epoch, and format registry epoch.

### 9.2 Identity and signatures

The capsule ID hashes the unsigned body. Signatures, placement acknowledgements, and repair-symbol locations attest over that ID and can rotate without identity drift.

### 9.3 Root-last publication

All dependency objects are staged and verified; durability evidence is collected; body is hashed/signed; exact-RCR capsule pointer is atomically published. Old capsule material enters retention review only afterward.

### 9.4 Restore

A restore lane must:

1. select/verify a trusted capsule;
2. reconstruct/verify referenced immutable material;
3. restore metadata roots under a new controlled epoch;
4. replay later RCR/event records;
5. rebuild indexes/materializations;
6. verify refs/forge/object closure and policy/retention state;
7. produce a signed restore report and measured RPO/RTO.

Backups without regular restore rehearsal do not justify recovery claims.

## 10. RaptorQ integration

### 10.1 Eligible classes

Repository/object/event segments, manifests, backups, artifacts, packages, LFS chunks, release assets, and bulk-transfer blocks may be registered.

### 10.2 Ineligible correctness state

Head pointers, writer leases, seals, outcomes, authorization, policy pointers, quota counters, legal-hold activation, and queue cursors use transactional replication—not fountain codes.

### 10.3 Acceptance rule

Decode in quarantine, then verify source digest, expected length, internal ID, native Git/LFS/package identity, Merkle/manifest closure, and structural codec. Only verified bytes receive an idempotent repaired placement.

### 10.4 Adaptive coding

Controllers may choose overhead within policy floors/ceilings based on evidence and cost. They cannot weaken promised retention or waive commitments. Profiles, observations, decisions, and resets are replayable.

## 11. Garbage collection and retention

### 11.1 Root catalog

Includes current/protected/hidden refs, PR/merge-queue heads, releases/packages/artifacts, legal holds, administrator pins, backup/capsule roots, migration handoffs, and grace tombstones.

### 11.2 Protocol

1. snapshot authenticated roots;
2. compute/verify reachability;
3. mark candidates with proof/evidence;
4. wait grace and replica/backup horizons;
5. revalidate roots/policy epoch;
6. sweep immutable placements;
7. record result and repair indexes.

Local `git gc` never decides canonical deletion.

## 12. Forge product model

### 12.1 Issues and discussions

Event-sourced, stable IDs, Markdown source plus safe deterministic rendering, edit history, reactions, labels, milestones, assignment, references, and position receipts.

### 12.2 Pull requests and reviews

A PR binds source/target repository/ref, base/head histories, review state, checks, policy epoch, and merge attempts. Review anchors preserve original diff coordinates and explicitly become outdated/remapped rather than silently attaching to wrong lines.

### 12.3 Branch protection

Policy evaluates exact candidate mutation against one pinned snapshot, including reviews, CODEOWNERS, statuses, signatures, merge queue, bypass identity, and policy epoch. Projection/UI state is never the sole authorization source.

### 12.4 Merge queue

Queue entries and synthetic refs are canonical forge state. CI receipts bind exact synthetic head/object closure. Target movement invalidates stale results according to versioned policy. Merge transition and target ref update share an RCR.

### 12.5 Releases, packages, and artifacts

Immutable bytes have typed digests/manifests and retention roots; mutable metadata changes are events. OCI is the preferred first package protocol. Provenance, signature, quota, malware-review hooks, and deletion semantics are explicit.

### 12.6 Webhooks and APIs

Outbox delivery is at least once with stable delivery IDs, signatures, attempts, and replay. API compatibility is registry-scoped; pagination, errors, timestamps, race behavior, and idempotency are tested, not approximated from endpoint names.

## 13. Search and graph

### 13.1 Progressive retrieval

- phase 0: path/symbol/lexical/metadata results quickly;
- phase 1: semantic retrieval and richer ranking;
- phase 2: graph/context expansion and optional reranking.

Results stream with stable IDs and source positions. Failure of refinement does not erase valid initial results.

### 13.2 Immutable generations

Index and graph generations are immutable and bind source RCR/forge position. A root-last generation pointer publishes only after all shards/manifests verify. Rebuild from canonical source is always possible.

### 13.3 Authorization

Documents are filtered by canonical authorization before disclosure. Embeddings, snippets, caches, and graph neighbors inherit access labels. Cross-tenant indexes are prohibited unless cryptographic/policy isolation is proven.

### 13.4 Agent Context Packets

Retrieval produces bounded content-addressed packets with spans, transforms, ranks, omissions, and authorization receipts. A packet is evidence about supplied context, not a proof of repository completeness.

## 14. Agent-native system

### 14.1 Intent Runs

Bind sponsor, agent/harness identity, repository/base, canonical intent, attenuated capabilities, budgets, evidence/verifier policy, expiration, revocation, and disclosure.

### 14.2 Workspaces

Immutable base plus COW overlay, descriptor-relative safe access, lazy authorized fetch, separate output/cache/secret/effect channels, and structured-concurrency lifecycle. No sponsor token or ambient cloud metadata.

### 14.3 Effect broker

Every side effect carries capability, canonical parameters, input root, idempotency key, and budget reservation. Receipts bind exact result and resource use. Agents can prepare requests for human approval without pretending execution.

### 14.4 Evidence-Carrying Changes

Bind proposal closure, base state, Context Packets, tool/check receipts, invariants, non-claims, omissions, and verifier attestations. Independence is machine-classified along workspace, credentials, model/harness, context, oracle, and human dimensions.

### 14.5 Prompt injection

Repository/external text is untrusted. It cannot widen capabilities, disclose secrets, suppress checks, approve itself, alter base state, or change disclosure. Effects remain behind a non-textual capability boundary.

## 15. CI and untrusted execution

CI is a separate hostile-compute product, not a helper process inside the forge.

Requirements:

- immutable runner image/toolchain identities;
- sandbox/VM boundary appropriate to threat model;
- no host/cloud metadata access;
- egress policy and package proxy;
- secret broker with fork/trust policy;
- cache namespaces by trust domain and immutable keys;
- exact source RCR/object closure receipt;
- bounded CPU/memory/disk/network/time;
- cancellation/reaping with no orphan processes;
- artifact/log provenance and redaction;
- reproducible check receipt schema;
- runner compromise containment and rotation.

A green job means the named check produced a valid receipt in its evidence class—not that code is universally safe.

## 16. Security architecture

Primary trust boundaries:

- Internet/Git protocol gateway;
- authentication/capability service;
- repository metadata writer;
- immutable object storage;
- materializers/caches;
- renderer/search/graph pipelines;
- CI runners;
- agent workspaces/effect broker;
- webhooks/importers/package registries;
- operator/admin plane;
- backup/repair infrastructure.

High-priority attacks include pack/decompression bombs, path traversal, hidden-ref disclosure, stale-writer publication, branch-protection TOCTOU, token confusion, fork secret exfiltration, CI escape/cache poisoning, webhook SSRF/replay, active Markdown/SVG content, package/LFS cross-tenant access, GC root omission, malicious repair symbols, projection authorization, prompt injection, and administrator override abuse.

`SECURITY_THREAT_MODEL.md` owns the detailed matrix and must evolve with each surface.

## 17. Anytime-valid operational intelligence

Permitted adaptive targets:

- cache/prefetch;
- scrub/repair priority and coding overhead within bounds;
- canary escalation;
- reversible admission throttles;
- queue/search/rerank budgets;
- anomaly-review priority;
- capacity planning.

Forbidden canonical targets:

- identity or signature validity;
- RCR ordering or ref atomicity;
- authorization grants;
- retention roots/deletion safety;
- whether committed data exists;
- irreversible sanctions based solely on a detector.

Each controller has safe defaults, hard action bounds, observation/evidence log, assumptions, reset semantics, and kill switch.

## 18. Multi-region and failover

### 18.1 V1 model

- active-active reads/materializations/projections;
- one canonical writer epoch per repository;
- consensus/lease-backed epoch fencing;
- immutable object placement across policy-defined domains;
- asynchronous outbox/projection replication with explicit positions;
- failover that advances epoch and resumes from last committed RCR.

### 18.2 Failure evidence

Test partitions, delayed/duplicated messages, process pause, disk/object-store failure, stale leader, lost response, rolling upgrade, clock anomalies, and region loss. Public RPO/RTO claims come from restore/failover artifacts over named configurations.

### 18.3 Future parallel commit

Potential invariant-key scheduling or sharded metadata must refine the reference model. It cannot be justified only by different ref names because policy, forge, quota, retention, and queue invariants overlap.

## 19. Hosted service economics

### 19.1 Cost model

Track independently:

- canonical immutable bytes by class/tier;
- repair overhead and failure-domain placement;
- metadata operations/storage;
- egress and regional replication;
- materialization/cache footprint;
- search/vector/graph generations;
- CI compute and artifact/log retention;
- agent context/compute/effect usage;
- backup/restore reserve;
- abuse/security overhead.

### 19.2 Pricing principles

Free/open-source community operation should not require proprietary control-plane dependencies. FrankenGit.com can charge for managed availability, scale, global placement, enterprise identity/policy, compliance evidence, hosted runners, high retention, premium support, and agent resources.

Quotas and billing are transactional and explainable. Statistical systems can recommend or reversibly throttle but cannot silently bill or delete.

### 19.3 Multi-tenancy

Tenant IDs are present in identities and authorization. Storage dedup across tenants is allowed only if encryption, access, deletion, side-channel, and accounting semantics are explicit; safest initial hosted design may dedup within tenant only.

## 20. Human and machine interfaces

### 20.1 Human UI

Fast, accessible, familiar forge workflows with explicit freshness/position where relevant. Complex evidence is summarized but inspectable. Overrides and destructive operations show scope and durable audit identity.

### 20.2 CLI

`fg` (provisional) provides repository/forge operations, migration, admin, diagnostics, capsule/restore, evidence inspection, and agent Intent Runs. JSON/JSONL/TOON-like compact formats and stable exit/refusal codes are first-class.

### 20.3 APIs

Native typed API exposes canonical positions, TxId/outcome lookup, Context Packets, evidence, and capabilities. GitHub-compatible REST/GraphQL subsets are adapters with an explicit compatibility registry.

### 20.4 Observability

Telemetry includes positions/IDs without leaking secrets/content. Operators can trace request → seal → RCR/outcome → outbox → projection/materialization. Metrics do not become canonical state.

## 21. Implementation organization

A Rust workspace is expected, using edition 2024 and a strict DAG. Crates appear only with real vertical slices. Likely domains:

- typed identities/errors/canonical codec/crypto;
- Git object/pack/protocol;
- reference model/simulator;
- metadata transaction kernel;
- immutable storage/segments/location;
- policy/evidence/claims;
- materializer;
- capsule/backup/repair;
- forge events/projections;
- search/graph;
- agent context/workspace/effects;
- CI runner protocol;
- gateway/API/CLI;
- conformance/fault/benchmark harness.

Unsafe code is forbidden by default and, if eventually required for measured SIMD/mmap/syscalls, isolated in named boundary crates with local invariants, Miri/sanitizer/fuzz evidence, and scalar oracle paths.

External dependencies are minimized and justified by capability/evidence rather than ideology. Critical protocols/encodings remain under project control; commodity cryptography and consensus clients should favor mature audited implementations.

## 22. Verification strategy

### 22.1 Reference and model evidence

- deterministic pure state machine;
- canonical encoding goldens;
- property/model tests for seals/outcomes/RCR roots;
- bounded model checking for races;
- deterministic schedule exploration;
- crash-point enumeration;
- metamorphic invariants.

### 22.2 Git differential evidence

- real Git client version matrix;
- official/source-derived fixtures;
- upload-pack/receive-pack packet transcripts;
- pack/object corpus, fuzz, malformed/adversarial cases;
- shallow/partial/LFS/signature/atomic behavior;
- accepted divergence registry.

### 22.3 Storage/recovery evidence

- object corruption/loss/truncation;
- root-last interruption;
- stale placement/index;
- full backup restore;
- capsule replay;
- RaptorQ erasure and malicious-symbol campaigns;
- GC/legal-hold races;
- region failover.

### 22.4 Security evidence

- parser fuzzing/resource bounds;
- tenant/auth capability negatives;
- CI/workspace escape tests;
- secret/fork/cache/webhook/import/render attacks;
- dependency and supply-chain gates;
- audit/override tamper evidence.

### 22.5 Performance/economic evidence

Benchmarks are versioned artifacts with datasets, hardware, configs, raw samples, warm/cold state, correctness checks, and replay commands. Claims compare relevant baselines and include tail latency, CPU, memory, storage amplification, egress, and recovery cost.

## 23. Roadmap and gates

### Phase A — Freeze semantics

Canonical codecs, IDs, refusals, TxId/seal/outcome, RCR, roots, capsule, compatibility, durable-object and claim registries; pure model; docs CI.

### Phase B — Git correctness core

Safe object/pack core; upload-pack and receive-pack differential harness; one-node quarantine and object store.

### Phase C — Canonical transaction kernel

Metadata sequencer, policy snapshot, ref/forge atomicity, outbox, crash/retry/cancellation evidence.

### Phase D — Materialization and recovery

Git materializer, partial clone, capsule/backup/restore, GC/retention, first RaptorQ object class.

### Phase E — Forge product

Issues, PRs, reviews, protection, merge queue, releases, webhooks, API subset, LFS.

### Phase F — Agent system

Intent Runs, capability broker, Context Packets, COW workspaces, effect receipts, Evidence-Carrying Changes.

### Phase G — Search/graph/CI

Progressive retrieval, graph projection, untrusted CI boundary, package/artifact surfaces.

### Phase H — Distributed/hosted

Replicated metadata/failover, multi-region placement, tenant quotas/accounting, migration, hosted SLO evidence.

No phase is complete because APIs exist; its named evidence gates must pass.

## 24. Key unresolved decisions

1. Final license/open-source-commercial structure.
2. Metadata substrate and local-to-cluster migration path.
3. V1 SHA-256 creation/import scope.
4. Canonical codec format and crypto registry.
5. Initial segment sizing/compaction policy.
6. Exact GitHub API and Actions compatibility subset.
7. CI sandbox substrate.
8. Hosted deletion, residency, and backup guarantees.
9. First RaptorQ-protected object class/profile.
10. Dependency/reuse boundaries with Franken-family crates.
11. Federation timing and trust model.

Each becomes an ADR with alternatives, migration, evidence, and non-claims.

## 25. Final architectural judgment

The project’s strongest opportunity is not “GitHub, rewritten in Rust.” It is a forge whose canonical mutation, recovery, and agent interfaces were designed for a world where software development is performed by large populations of concurrent agents and audited by humans and other agents.

The design should remain alien-artifact ambitious in recoverability, evidence, sparse context, and economics. It must remain boringly precise in the parts that decide truth. The audited architecture now has one identity, one terminal outcome, one linearization point, one current forge-position root, one checkpoint meaning, one push vocabulary, and explicit limits on repair/statistical/agent authority. That is the foundation on which the radical system can safely be built.
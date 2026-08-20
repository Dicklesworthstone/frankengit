# FrankenGit Research Provenance and Architectural Lineage

**Status:** initial public research ledger
**Last updated:** 2026-08-19

FrankenGit combines ideas from existing systems and from the public Franken project family. This document records which ideas informed the design, what is being adopted, what is being changed, and what is not yet validated. It is not a claim that every cited system endorses the resulting architecture.

The project should maintain this ledger as the plan evolves. A feature inspired by an external system still requires an independent specification, license review, implementation, and evidence path.

---

## 1. Cursor: Git at Any Scale

**Source:** [Git at Any Scale](https://cursor.com/blog/git-at-any-scale), Cursor, 2026.

### Relevant ideas

- Keep ordinary Git as the execution engine instead of immediately replacing it.
- Store durable repository state in immutable object storage plus an ordered, linearizable log.
- Treat local repositories on NVMe as disposable caches/materializations.
- Use generation fencing so stale workers cannot publish after losing authority.
- Rehydrate repositories on demand and move work between a stateless compute fleet and durable storage.
- Recognize that full-repository materialization and coarse coordination become future scaling limits.

### FrankenGit adoption

FrankenGit adopts the central separation between **durable truth** and **disposable Git execution state**. It also adopts generation fencing and the practical insight that object storage can make a cost-effective durable substrate.

### FrankenGit divergence

FrankenGit proposes:

- exact immutable Git objects plus public Franken envelopes/segments rather than a product-private WAL alone;
- narrow serializable `RefTxn` operations over declared refs and invariant keys, allowing safe concurrency for disjoint mutations;
- root-last Repository Capsules as explicit recoverability commitments;
- canonical event streams for forge state;
- RaptorQ repair contracts and destructive reconstructability evidence;
- self-hosted and hosted deployment profiles sharing one protocol;
- first-class agent intent, capabilities, workspaces, context, evidence, and budgets;
- a public compatibility and verification program.

These are proposals, not demonstrated superiority. They require measurement against the simpler WAL/materialization architecture.

---

## 2. Git specifications and implementation

**Sources:**

- [Git protocol version 2](https://git-scm.com/docs/protocol-v2)
- [Partial clone design notes](https://git-scm.com/docs/partial-clone)
- [Git hash-function transition documentation](https://git-scm.com/docs/hash-function-transition)
- Git object, pack, index, commit-graph, bitmap, bundle, signature, and transport documentation and test suites.

### Relevant ideas and constraints

- Git object bytes and identifiers have exact compatibility semantics.
- Protocol v2 provides capability negotiation and command-oriented transport.
- Partial clone/promisor semantics allow clients and servers to omit selected objects under explicit rules.
- SHA-1/SHA-256 transition requires algorithm-aware object identity and interoperability planning.
- Git’s own test suite and real client versions are necessary compatibility evidence.

### FrankenGit rule

The Git boundary is a specification and conformance problem, not an opportunity for approximate emulation. FrankenGit may add internal commitments and representations, but supported client-visible behavior must be exercised against ordinary Git.

---

## 3. Asupersync

**Source:** [Dicklesworthstone/asupersync](https://github.com/Dicklesworthstone/asupersync)

### Inherited ideas

- structured concurrency and tree-shaped task ownership;
- cancellation as a protocol with bounded quiescence;
- regions, budgets, capabilities, obligations, and typed outcomes;
- deterministic simulation and schedule exploration;
- evidence and decision layers separated from the runtime kernel;
- no orphan tasks and explicit external-effect accounting;
- adaptive RaptorQ transfer work with deterministic lower bounds;
- e-process and confidence-sequence machinery for anytime-valid monitoring.

### FrankenGit application

Asupersync is the proposed orchestration substrate for request scopes, object admission, materialization, transfers, repair, CI, agent runs, webhooks, and operator workflows. Cancellation must preserve the distinction between committed, refused, failed, and cancelled outcomes. Capabilities and obligations are architectural, not merely ergonomic.

### Constraint

Runtime abstractions do not define Git or transaction semantics. FrankenGit truth-plane state machines remain independently specified and testable.

---

## 4. FrankenSQLite

**Source:** [Dicklesworthstone/frankensqlite](https://github.com/Dicklesworthstone/frankensqlite)

### Inherited ideas

- explicit VFS/pager/WAL/MVCC/B-tree/execution layering;
- “exactly-once effect, at-least-once promise” discipline;
- typed corruption and fail-closed recovery;
- actor/runtime integration without losing database semantics;
- compatibility and differential conformance as executable claims;
- a RaptorQ permeation map requiring every durable/exchanged byte structure to declare its protection status;
- proof by actual reconstruction rather than encode/decode unit tests alone;
- observability and evidence as owned layers.

### FrankenGit application

FrankenGit adopts the permeation-registry concept for repository segments, transaction/event checkpoints, artifacts, backups, and transfers. FrankenSQLite is a candidate projection/metadata engine, but projections remain derived from canonical repository/forge events. FrankenGit does not delegate ref truth to a convenient table without preserving the `RefTxn` contract.

---

## 5. FrankenFS

**Source:** [Dicklesworthstone/frankenfs](https://github.com/Dicklesworthstone/frankenfs)

### Inherited ideas

- immutable content-addressed blocks and copy-on-write state;
- snapshots, versioned roots, deterministic replay, and repair tooling;
- separation of on-disk format, block, journal, MVCC, allocation, namespace, repair, and operator layers;
- safe Rust by default and carefully isolated platform boundaries;
- conflict and expected-loss thinking rather than simplistic last-writer-wins;
- doctor tooling as part of the product.

### FrankenGit application

FrankenGit workspaces and Git materializations are sparse copy-on-write views pinned to a Repository Capsule. Descriptor-relative path security, snapshot continuity, deterministic recovery, and first-class doctor/repair commands inherit FrankenFS’s discipline. FrankenGit does not require FrankenFS as the only local filesystem.

---

## 6. FrankenSearch

**Source:** [Dicklesworthstone/frankensearch](https://github.com/Dicklesworthstone/frankensearch)

### Inherited ideas

- hybrid lexical, fuzzy, structural, semantic, and reranked retrieval;
- evidence fusion rather than one opaque score;
- durable, versioned index generations;
- explicit model/tokenizer/index identities;
- bounded agentic retrieval;
- quality canaries, off-policy evaluation, and no-regret/adaptive selection under evidence controls;
- provenance-preserving context windows.

### FrankenGit application

FrankenSearch informs Context Packets and repository search across code, docs, issues, reviews, history, tests, artifacts, ownership, and dependencies. Results must carry capsule/event position, source span, retrieval channel, model/index identity, and omissions. Search remains derived and cannot authorize mutations or define repository truth.

---

## 7. Franken Markdown

**Source:** [Dicklesworthstone/franken_markdown](https://github.com/Dicklesworthstone/franken_markdown)

### Inherited ideas

- small, dependency-lean, deterministic rendering core;
- explicit parser/AST/emitter/layout boundaries;
- source maps and span preservation;
- safe profiles for untrusted content;
- resource caps and hostile-input handling;
- parallel human-readable and compact machine-oriented representations;
- no unsafe code, panic, or unbounded interpretation in the core.

### FrankenGit application

Franken Markdown is the proposed safe renderer for README files, issues, reviews, discussions, comments, agent reports, and evidence summaries. Source spans must survive rendering so comments and findings point to stable content. Raw HTML and active content are policy-controlled and isolated.

---

## 8. FrankenGraphDB

**Source:** [Dicklesworthstone/frankengraphdb](https://github.com/Dicklesworthstone/frankengraphdb)

### Inherited ideas

- event-sourced canonical state and reconstructable projections;
- canonical codecs, content-hashed identities, append-only segments, Merkle commitments, writer manifests, and root-last checkpoints;
- strict layering and named unsafe boundary crates;
- evidence/claim registries and explicit epistemic status;
- RaptorQ source-block durability and repair;
- deterministic simulation and reference implementations;
- conformal prediction, e-processes, no-regret selection, off-policy evaluation, and regime detection separated from deterministic graph truth;
- no empty prototype crates: a module lands with a real final-abstraction slice.

### FrankenGit application

FrankenGraphDB most directly informs Repository Capsules, canonical forge-event streams, claim/evidence registries, graph projections, versioned roots, repair, and the structure of the comprehensive plan. Its calibration tools inform bounded operational decisions, not source-control correctness.

---

## 9. RaptorQ / RFC 6330

**Source:** [RFC 6330: RaptorQ Forward Error Correction Scheme for Object Delivery](https://www.rfc-editor.org/rfc/rfc6330).

### Relevant idea

RaptorQ encodes source symbols and additional repair symbols so an object can be reconstructed from a sufficient suitable set. It is systematic: source symbols remain directly usable.

### FrankenGit application

FrankenGit proposes RaptorQ for sealed immutable segments, checkpoints, backups, large artifacts, and native bulk transfer according to [RAPTORQ_PERMEATION_MAP.md](RAPTORQ_PERMEATION_MAP.md).

### Explicit non-claims

RaptorQ does not establish integrity, authenticity, secrecy, authorization, ordering, transaction commitment, or logical retention. Reconstructed bytes require exact independent verification.

---

## 10. Anytime-valid inference and e-processes

**Representative source:** Aaditya Ramdas et al., [Game-theoretic statistics and safe anytime-valid inference](https://arxiv.org/abs/2210.01948), and the broader e-value/e-process literature.

### Relevant idea

E-processes support sequential evidence monitoring under optional stopping when their assumptions and construction are valid.

### FrankenGit application

Potential uses include canary regressions, corruption/repair-rate shifts, latency/error regimes, secret-scanner drift, cache divergence, runner anomalies, search-quality degradation, and adaptive redundancy headroom.

### Explicit non-claims

An e-value is not a cryptographic proof, guilt score, universal anomaly detector, or permission to mutate repository truth. Inputs, null interpretation, resets, delayed labels, action thresholds, and maximum reversible response must be registered.

---

## 11. GitLab Gitaly/Praefect

**Sources:** GitLab documentation for [Gitaly](https://docs.gitlab.com/administration/gitaly/) and repository storage/cluster behavior.

### Relevant ideas

- dedicated Git RPC/storage services;
- local fast storage for repository operations;
- replicated repository nodes and failover coordination;
- operational lessons around replication, consistency, backup, and repository placement.

### FrankenGit comparison

FrankenGit agrees that Git execution benefits from fast local storage, but does not make replicated mutable repository directories the only durable truth. Repository cells materialize Git views from an immutable object/transaction/event substrate.

---

## 12. Forgejo and GitLab product surface

**Sources:** [Forgejo](https://forgejo.org/) and [GitLab](https://gitlab.com/) public documentation.

### Relevant ideas

- complete self-hosted forge surface;
- repositories, collaboration, packages, Actions/CI, webhooks, organizations, permissions, and migration expectations;
- the operational importance of a coherent single product rather than disconnected storage primitives.

### FrankenGit constraint

A storage research prototype is not a GitHub replacement. The roadmap includes the full collaboration, execution, package, identity, migration, and operator surface, while preserving a small truth plane.

---

## 13. Radicle and local-first signed collaboration

**Source:** [Radicle](https://radicle.xyz/) documentation.

### Relevant ideas

- local-first Git repositories;
- peer-to-peer distribution;
- signed identities and collaborative artifacts;
- user ownership independent of one hosted service.

### FrankenGit application

FrankenGit’s later federation profile uses signed forge events and Repository Capsules, local policy evaluation, and ordinary Git data ownership. It does not require every deployment to be peer-to-peer or reinterpret branch heads as uncontrolled multi-value state.

---

## 14. Supply-chain and attestation standards

Candidate standards to evaluate during G5 include:

- in-toto attestations;
- SLSA provenance;
- Sigstore transparency/signing components;
- SPDX and CycloneDX SBOM formats;
- OCI image and artifact specifications;
- package-ecosystem-native integrity metadata.

No standard is automatically adopted merely because it is popular. The selected profile must bind to Repository Capsules, workflow identity, runner trust domain, policy, and exact artifacts without creating a second contradictory provenance system.

---

## 15. Original FrankenGit synthesis

The following combination is the project’s proposed synthesis rather than a direct copy of one cited system:

1. Git-compatible immutable objects as external truth substrate.
2. Stronger Franken envelopes and deterministic repairable segments.
3. Narrow serializable `RefTxn` commands installed as atomic Repository Commit Records, instead of repository-wide mutation leases or disconnected ref/social logs.
4. Root-last Repository Capsules binding recoverable repository and forge generations.
5. Event-sourced collaboration state with disposable relational/search/graph projections.
6. Agent Intent Runs, attenuated capabilities, capsule-pinned workspaces, Context Packets, effect ledgers, and evidence-carrying changes.
7. RaptorQ permeation by explicit object class and proof of reconstruction.
8. E-processes and adaptive decision tools confined to reversible operational support.
9. One protocol spanning personal, self-hosted clustered, multi-region, federated, and managed deployment profiles.
10. A claim registry that refuses to turn architecture prose into unearned facts.

The synthesis is a hypothesis until implemented and compared under adversarial workloads.

---

## 16. Provenance rules for future contributions

When adding an externally inspired mechanism:

1. cite the primary public source;
2. identify the exact idea, not merely the project name;
3. distinguish adoption, adaptation, and divergence;
4. record license and patent considerations;
5. state which FrankenGit failure mode or cost it addresses;
6. provide a simpler baseline;
7. define falsifying evidence;
8. avoid copying code or private material without explicit authorization;
9. update the threat model and dependency/claim registries;
10. preserve attribution in generated public documentation.

Good provenance strengthens original work by making the actual contribution legible.

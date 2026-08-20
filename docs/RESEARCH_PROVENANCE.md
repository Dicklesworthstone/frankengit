# FrankenGit Research Provenance and Architectural Lineage

**Status:** public mechanism-level research ledger  
**Architecture version:** 3.0  
**Last revised:** 2026-08-19

This ledger records which concrete mechanisms informed FrankenGit, how they were adapted, which claims were deliberately not imported, and where the resulting design is original synthesis. Repository names alone are not provenance. Future revisions should pin exact source revisions/files and preserve the distinction among implemented source behavior, source design work, FrankenGit proposal, and FrankenGit evidence.

The companion [`FRANKEN_SUITE_DEEP_DIVE_SYNTHESIS.md`](FRANKEN_SUITE_DEEP_DIVE_SYNTHESIS.md) provides the subsystem placement matrix.

## 1. Cursor Continuity: Git at Any Scale

**Primary source:** Cursor, “Git at Any Scale,” published 2026-08-18.

### Mechanisms observed

- Each push is represented by an immutable WAL/delta body in S3-compatible object storage.
- The push becomes visible through a conditional update of the WAL index/head.
- Any server can attempt publication; rendezvous hashing selects a preferred healthy server for locality/batching rather than correctness authority.
- UDP gossip notifies peers of new WAL/version state but is only a hint.
- Readers verify freshness against the object-store ETag/version.
- Local NVMe Git repositories are disposable materializations and cold repositories may have zero local replicas.
- Compaction is performed once and shared through the immutable WAL.
- The architecture does not require a separately authoritative relational database.

### FrankenGit adoption

- immutable body before conditional root;
- stateless execution cells and disposable Git materializations;
- preferred routing/gossip as optimization only;
- one object-store-native authority key per repository;
- shared immutable compaction/materialization.

### FrankenGit extension

- decision bodies include terminal outcomes, RCRs, forge effects, retention/outbox roots, and evidence—not only Git deltas;
- stable seals and outcome lookup remove retry/cancellation ambiguity;
- per-core preparation and flat combining microbatch many decisions per head transition;
- conflict witnesses and semantic normal form permit safe reuse/rebase;
- repair/checkpoint/generation/release share root-last/anti-rollback laws;
- pure-Rust Git, ATP-Git, TreeFS, graph fabrics, and agent capability/evidence protocols.

### Non-imported assumption

A mutable local Git repository or preferred server is never repository authority. Object-store product naming is not evidence that conditional semantics are sufficient; every backend passes the `AuthorityStore` suite.

## 2. Git specifications, source, and test corpus

**Primary sources:** Git object/pack/protocol/partial-clone/hash-transition documentation, source, and tests; pinned upstream Git releases used as external oracles.

### Constraints imported

- native object framing and hash identity are exact compatibility semantics;
- SHA-1 and SHA-256 are typed object-format domains;
- pack/delta/DEFLATE, pkt-line, upload-pack, receive-pack, shallow/partial/promisor, refs, signatures, and error behavior require differential evidence;
- protocol v2 is command/capability negotiation where Git defines it; push remains receive-pack rather than a fictional standardized v2 command;
- observable ordering/tie-breaks/errors/resource refusal matter;
- object import/export must preserve native history.

### FrankenGit divergence

Upstream Git is never linked or invoked in production. It is a separately pinned, sandboxed conformance oracle. FrankenGit owns a clean-room pure-Rust implementation and returns typed unsupported/refusal rather than hidden subprocess fallback.

## 3. Asupersync

**Source:** `Dicklesworthstone/asupersync`.

### Runtime mechanisms

- region-owned task trees and quiescent close;
- explicit capability context (`Cx`) rather than ambient runtime authority;
- cancellation request → drain → finalize;
- typed outcomes and two-phase reserve/commit effects;
- obligations and graded resource algebra;
- deterministic lab runtime with virtual time, trace replay, vector clocks, Mazurkiewicz/Foata normalization, and DPOR-style schedule reduction;
- capability/dependency gates and one-runtime discipline.

### ATP mechanisms

Source areas inspected include ATP architecture, delta planning, dedupe, path graph, swarm strategy/piece tracking, cache trust, adaptive RaptorQ, and autotune.

Imported mechanisms:

- manifests and receiver have summaries;
- `AlreadyInSync` / delta / full-fallback planning;
- unique-content transfer plus deterministic reconstruction;
- typed path candidates and security/privacy/budget constraints;
- bounded path racing with loser cancellation/drain;
- swarm rarity, peer availability, and endgame duplication;
- trust-scoped caches and peer evidence;
- identity-bound adaptive RaptorQ/block/pacing policy;
- transfer actor owning the complete lifecycle.

### CALM/CRDT mechanisms

- registry classification of monotone coordination-free versus coordinated operations;
- conflict-absorbing CRDT lattices for advisory/noncanonical replicas;
- explicit convergence/conflict witnesses rather than last-writer-wins folklore.

### FrankenGit application

Asupersync is the sole runtime. ATP becomes ATP-Git. Obligations own object writes, CAS attempts, repair, secrets, runners, outbox, workspaces, context, and release effects. Lab/DPOR is the concurrency verification substrate. CALM classification determines which data can propagate without authority ordering.

### Non-imported claim

Runtime correctness does not define Git or repository transaction semantics; FrankenGit maintains an independent pure reference state machine and refinement evidence.

## 4. FrankenSQLite

**Source:** `Dicklesworthstone/frankensqlite`, including MVCC, per-core WAL architecture, deterministic rebase, physical merge, witness refinement, conflict model, retry policy, commit combiner, critical invariants, and RaptorQ permeation work.

### Mechanisms imported

- per-core writable → sealed → flushing/combining lanes;
- flat combining/group commit with a small ordered residue;
- immutable snapshots and explicit publication states;
- deterministic intent replay and structured semantic patches;
- physical merge certificates such as append/range/bitmap proofs where domain laws permit;
- conservative conflict witnesses refined only when value-of-information is positive;
- birthday/AMS-F2/HLL/SpaceSaving conflict sketches used only for routing/refinement;
- Beta-Bernoulli expected-loss retry policy, regime reset, and starvation escalation;
- exact invariant catalogs tied to executable evidence hooks;
- durable/exchanged byte classes required to declare protection/repair semantics.

### FrankenGit application

- per-core preparation lanes and repository decision combiner;
- semantic rebase after authority-CAS contention;
- hierarchical ref/forge/path/symbol/policy/retention conflict witnesses;
- embedded `AuthorityStore` profile and local MVCC projections/caches;
- retry/refinement policy under deterministic hard bounds.

### Important boundary

FrankenSQLite is not a separate distributed source of truth reconciled with the decision stream. In embedded mode it implements the authority primitive. In clustered mode it is local derived state.

## 5. FrankenFS

**Source:** `Dicklesworthstone/frankenfs`, including writeback/MVCC design, repair/writeback serialization, adaptive refresh, repair autopilot/evidence/pipeline, RCU/snapshots, crash matrices, and parallel-create negative evidence.

### Mechanisms imported

- immutable/COW bases and safe snapshot/epoch reads;
- explicit staged, visible, and durable state;
- crash matrices around body, checksum, sync, root visibility, and cleanup;
- repair serialized through the same mutation authority as normal writes;
- typed repair evidence/scrub ledgers;
- Beta-posterior/expected-loss redundancy refresh;
- mounted/adapter safety gates and kill switches;
- durable negative-result ledger.

### Critical negative result

Removing a low-level lock or creating per-core lanes does not establish end-to-end concurrent-writer scaling when higher shared metadata/invariants still conflict. FrankenGit therefore measures committed decisions per head transition and uses full invariant witnesses; “different refs” is not independence by itself.

### FrankenGit application

TreeFS, workspace epochs, placement publication, repair-through-authority, crash matrices, GC/restore discipline, and negative evidence.

### Deliberate strengthening

FrankenGit first-party code forbids unsafe without named boundary exceptions. Optional FrankenFS/FUSE integration is an adapter, not the only workspace implementation.

## 6. FrankenSearch and Quill

**Source:** `Dicklesworthstone/frankensearch`, including architecture overview, Quill plan, generation identity/authority/root, durability, and evidence artifact contracts.

### Mechanisms imported

- progressive `Initial`, `Refined`, and `RefinementFailed` result phases;
- lexical/path/symbol baseline that remains useful without models;
- evidence-linked fusion and deterministic ordering;
- Quill merge-by-concatenation over disjoint absolute IDs;
- columnar sort-based ingest and searchable in-memory delta before durable seal;
- immutable generation identity with sequence+nonce, exact predecessor, anti-rollback floor, dual/root checks, and fail-closed unresolved publication recovery;
- no mixed-generation queries;
- descriptor-relative generation-root admission;
- unified replay artifact packs and source/toolchain/model/index identities.

### FrankenGit application

Search, code intelligence, review-anchor, graph, and Context Packet generations use the same monotone authority pattern. Progressive results carry exact repository/generation/source positions and authorization.

### Non-imported claim

Search relevance never becomes authorization or canonical repository truth.

## 7. franken_markdown

**Source:** `Dicklesworthstone/franken_markdown`, including AST/source-span/core API, safe file publication, batch orchestration/budgets, optimization proof checklist, and performance artifact schema.

### Mechanisms imported

- parse once into a source-spanned canonical document model;
- derive human HTML/PDF, compact agent text, APIs, search chunks, and anchors from one lineage;
- core/host split with host-supplied bytes/capabilities rather than ambient filesystem/network;
- safe defaults and explicit hostile-input resource limits;
- deterministic outputs and native/WASM parity targets;
- deterministic worker budget from CPU, memory, mode, and variance;
- stable output order independent of scheduling;
- complete per-input receipts;
- staged all-or-nothing multi-output writes;
- optimization checklist binding speed to unchanged output/order/spans/security;
- performance artifacts with source/toolchain/host/build/raw samples/goldens/hypothesis/non-claims.

### FrankenGit application

README/issues/PR/review/release/policy/evidence rendering, review-anchor lineage, agent Context Packet spans, batch receipts, staged document outputs, and performance proof discipline.

## 8. FrankenGraphDB

**Source:** `Dicklesworthstone/frankengraphdb`, including Chronicle commit/root, Strata, reference intents/effects, calibration/e-process/no-regret/OPE/policy/regime/Lyapunov/progress, claims, and evidence.

### Canonical/storage mechanisms imported

- one immutable stream/version universe;
- body first, commit marker/root last;
- two-slot/anti-rollback roots where an older valid root must not hide a torn higher acknowledgement;
- graph-structured LSM and temperature tiers;
- deterministic canonical codecs/content identities;
- intent/effect separation and net-effect normal form;
- total mapping from source intents to surviving effects/no-ops;
- no empty prototype crates and no in-memory substitute presented as durable storage.

### Statistical/governance mechanisms imported

- conformal/e-process identity binds metric, population, selection, exact sequence window, regime, candidate/fallback, assumptions, and implementation fingerprint;
- no-regret receipts include action distribution/weights and numeric fingerprint;
- fixed-point OPE requires support/effective-sample-size gates;
- stream-sequenced policy epochs distinguish answer-preserving, answer-affecting, and canonical-state-affecting effects;
- regime alarms select deterministic fallback;
- Lyapunov/progress diagnostics carry explicit non-claims;
- claim lattice: invariant > proof > bounded model > statistical > SLO > benchmark;
- replay completeness: replayable / structural / verifiable with artifacts / audit only.

### FrankenGit application

Repository decision chronicle, authenticated heads/capsules, object/generation tiers, graph query evidence, policy promotion, operational adaptation, claim registry, replay packs, and issue/agent effect normal form.

## 9. FrankenNetworkX

**Source:** `Dicklesworthstone/franken_networkx`, including class/storage semantics, algorithms, runtime/CGSE, views, durability, parity and performance doctrines.

### Mechanisms imported

- observable behavior includes return type, iteration order, tie-break, exception class/message, and serialization;
- insertion-order-stable external node table with dense integer adjacency hot representation;
- closed `TieBreakPolicy` and per-run `ComplexityWitness`/decision-path hash;
- revision-keyed immutable/cached views;
- strict fail-closed mode versus bounded registry-approved hardened recovery with `DecisionRecord`;
- safe deterministic algorithms for shortest/k-shortest paths, SCC/condensation, cycle bases, dominators, articulation/bridges/biconnected components, matching/min-cost flow, max-flow/min-cut/Gomory-Hu, topological sort/transitive reduction, PageRank/HITS/centrality, k-core/community/partitioning, connectivity/robustness, and temporal/dynamic graphs;
- RaptorQ-protected artifacts and negative-results/performance proof discipline.

### FrankenGit application

Typed commit/object/dependency/ownership/review/build/agent/provenance/placement graphs; deterministic reviewer/context/build/placement decisions; reachability/GC; fragility/min-cut; agent/task flow/matching; graph decision witnesses.

### Non-imported claim

Python/NetworkX compatibility or FFI is not a production dependency. FrankenGit consumes stable pure-Rust surfaces or ports mechanisms behind its own contracts.

## 10. Doodlestein Self-Releaser

**Source:** `Dicklesworthstone/doodlestein_self_releaser`, including README, act compatibility, repository templates/config, attempt/resume and asset contracts.

### Mechanisms imported

- `.github/workflows` reused locally through `act`/DSR rather than depended on as hosted infrastructure;
- Linux through local/container/native lanes and macOS/Windows on registered native hosts via SSH;
- stable release-run and per-target attempt identities;
- resume reuses only exact verified completed target artifacts;
- authoritative release manifest withheld until all requested targets succeed;
- exact one-primary-asset-per-target, checksum sidecar, and companion-file allowlist;
- fail-closed symlink/path/basename collision/unlisted artifact handling;
- signed release manifests, SBOM, provenance, installer smoke, host/toolchain/source fingerprints;
- remote release reconciliation against local manifest.

### FrankenGit application

The local verification/release protocol and future hosted dogfood path. GitHub Releases is a mirror/distribution adapter, not authority.

## 11. RaptorQ / RFC 6330

**Primary source:** RFC 6330 and related implementation/evidence work in Asupersync/Franken projects.

### Imported property

Systematic source and repair symbols can reconstruct an immutable object from a sufficient suitable set under a declared profile.

### FrankenGit use

Registered immutable repository/decision/object segments, checkpoint/export bundles, search/graph/evidence generations, artifacts/packages/LFS/release assets, and ATP transfer blocks where economic/recovery evidence supports coding.

### Explicit non-claims

RaptorQ does not establish integrity, authenticity, secrecy, authorization, ordering, current metadata, consensus, retention, or logical deletion. Every reconstruction verifies original commitments and current authority before publication.

## 12. Anytime-valid inference and adaptive control literature

**Representative areas:** conformal prediction, e-values/e-processes/e-martingales, no-regret/bandit control, off-policy evaluation, changepoint detection, Beta-Bernoulli decision models, Lyapunov/drift/queue stability.

### FrankenGit use

Bounded ATP/cache/search/context/witness/refinement/retry/scrub/repair/canary/resource policies.

### Required discipline

Population, selection/propensity, exact sequence window/filtration, regime, candidate/fallback, assumptions, support/ESS, arithmetic/toolchain implementation, reset and maximum action are identity material. Insufficient support selects deterministic fallback.

### Forbidden promotion

Statistical evidence cannot decide object identity, signatures, authority order, authorization, retention roots, current truth, irreversible sanction, or billing without deterministic records.

## 13. Existing forge and local-first precedents

### GitLab/Gitaly/Praefect

Relevant for Git RPC/storage operations, repository placement/replication/failover lessons, product/operational reality, and object-pool hazards. FrankenGit differs by treating mutable repository directories as derived materializations.

### Forgejo/Gitea/GitLab/SourceHut

Relevant for full self-hosted product surface, migration, organizations/permissions, CI/actions, packages, webhooks, and operator expectations. FrankenGit must become a coherent product, not only a storage paper.

### Radicle/local-first systems

Relevant for signed identities, offline/local ownership, peer exchange, and collaborative artifacts. FrankenGit federates operation classes according to CALM and does not make protected refs uncontrolled multi-value state.

### Supply-chain standards

in-toto, SLSA, Sigstore, SPDX, CycloneDX, OCI, package-native integrity, and reproducible-build practices are compatibility/evidence candidates. They are adopted only where they compose without a contradictory provenance authority.

## 14. Original FrankenGit synthesis

The following combination is not copied from one source:

1. Pure-Rust Git compatibility plus immutable object-store decision authority.
2. Stable transaction seals/outcomes and atomic ref-plus-forge RCRs.
3. Per-core preparation, flat combining, conflict graph, value-of-information witness refinement, and semantic rebase.
4. ATP-Git object-graph transfer and TreeFS sparse semantic workspaces.
5. Typed repository graph fabrics with deterministic decision/complexity witnesses.
6. CALM operation registry plus obligation-owned side effects.
7. Repair serialized through current authority and explicit staged/visible/durable epochs.
8. Identity-bound adaptive policy with stream-sequenced policy epochs and deterministic fallback.
9. Claim lattice, replay completeness, and append-only negative evidence.
10. Local DSR root-last release authority independent of hosted Actions.
11. One embedded-to-hosted canonical format and protocol universe.

This remains a proposal until implementation, fault, conformance, security, performance, and operational evidence supports each claim.

## 15. Provenance rules for future contributions

When adding an externally inspired mechanism:

1. cite the primary source and exact revision/file/section;
2. state whether the source behavior is implemented, proposed, measured, or inferred;
3. name the exact mechanism, not only the project;
4. distinguish adoption, adaptation, divergence, and rejected interpretation;
5. record license/patent/dependency implications;
6. identify the FrankenGit failure/cost it addresses;
7. provide a simpler baseline and falsifier;
8. update threat, claim, dependency, verification, and negative-evidence registries;
9. avoid copying code/private material without authorization;
10. preserve attribution in public generated documentation.

Good provenance makes the genuinely original synthesis legible and prevents architectural cargo culting.

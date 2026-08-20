# FrankenSuite Deep Architecture Audit

**Date:** 2026-08-19  
**Scope:** FrankenGit v2 first-cut architecture, reviewed against source-level mechanisms in Asupersync/ATP, FrankenSQLite, FrankenFS, FrankenSearch/Quill, franken_markdown, FrankenGraphDB, FrankenNetworkX, Doodlestein Self-Releaser, and Cursor’s object-store Git design  
**Disposition:** v3 architecture replaces or narrows every finding below

## Executive verdict

The first cut had the right product thesis—Git compatibility, immutable truth, disposable materializations, RaptorQ, calibrated operations, and agent-native collaboration—but imported most sibling-project ideas at slogan level. Several hidden assumptions would have produced a conventional forge with exotic decorations:

- an external metadata database remained co-authoritative with the object log;
- one writer epoch/home cell remained a correctness dependency;
- “use Asupersync” did not import obligations, CALM, ATP, or deterministic schedule coverage;
- “use MVCC” did not import per-core lanes, semantic rebase, witness refinement, or expected-loss retry;
- repair was not fully serialized through current mutation authority;
- capsules were overused as current-state/materialization pins;
- the graph layer was underspecified as generic search/context intelligence;
- workflow YAML still implied hosted GitHub Actions execution;
- the dependency constitution allowed far more external machinery than the user intended;
- several protocol documents contained mechanical duplication and stale transaction language.

The v3 design now makes the deepest reusable mechanisms structural.

## Critical architectural findings

### D-001 — Dual truth: external metadata store plus immutable log

**Problem:** The old architecture committed RCR/head/outcome/ref/forge pointers in a serializable metadata substrate while object/event bytes lived in an immutable store. This creates two recovery orders, two backup surfaces, and a potential co-authority split.

**Correction:** Canonical truth is one immutable `RepositoryDecisionBatch` stream plus one authenticated `RepositoryAuthorityHead` advanced by exact-version compare-and-exchange. FrankenSQLite is an embedded implementation/accelerator of the same `AuthorityStore` contract, never a separate global truth database.

**Documents:** [`OBJECT_STORE_DECISION_LOG.md`](OBJECT_STORE_DECISION_LOG.md), [`NORMATIVE_PROTOCOL_CONTRACTS.md`](NORMATIVE_PROTOCOL_CONTRACTS.md), [`ADR-0001-CANONICAL-STATE.md`](ADR-0001-CANONICAL-STATE.md).

### D-002 — Home-cell/writer-epoch correctness dependency

**Problem:** The first cut required one canonical writer epoch and treated failover as moving authority to a new writer. Lease expiry and local placement would remain correctness-critical.

**Correction:** Any eligible cell may prepare and attempt publication. Rendezvous hashing and a flat combiner are healthy-path optimizations. Order is established only by successful CAS of the exact predecessor head/version token. Stale cells lose CAS or fail authenticated receipt validation.

### D-003 — Asupersync imported as runtime branding, not protocol machinery

**Problem:** The plan named structured concurrency but omitted effect obligations, graded resources, CALM classification, conflict-absorbing advisory CRDTs, ATP path/swarm machinery, and DPOR/Mazurkiewicz schedule evidence.

**Correction:** Add a FrankenGit Asupersync profile, obligation-typed effects, executable CALM registry, ATP-Git profile, trust-scoped caches, transfer actors, and deterministic Lab/DPOR release gates.

**Documents:** [`CALM_AND_OBLIGATIONS.md`](CALM_AND_OBLIGATIONS.md), [`ATP_GIT_PROFILE.md`](ATP_GIT_PROFILE.md), [`VERIFY_SPEC.md`](../VERIFY_SPEC.md).

### D-004 — MVCC language without FrankenSQLite’s actual concurrency architecture

**Problem:** Different refs were too easy to treat as independent, and the plan did not explain how thousands of agents avoid false conflicts without weakening serial semantics.

**Correction:** Per-core preparation lanes, flat-combined microbatches, conservative multi-domain witnesses, value-of-information refinement, deterministic intent replay/structured patches, conflict certificates, sketches for routing only, and bounded expected-loss retry.

### D-005 — Repair could bypass current authority

**Problem:** Exact RaptorQ reconstruction was correctly required, but the publication path could be read as direct replacement of a missing/corrupt placement.

**Correction:** Repair produces quarantined candidate bytes, verifies original commitments, rereads current authority, prepares a repair intent, and publishes locator/manifest changes through the same head CAS as ordinary mutations. A valid old reconstruction cannot overwrite a newer version or resurrect deletion.

### D-006 — Missing staged/visible/durable state machine

**Problem:** “Uploaded,” “published,” and “durable” were not consistently separated across objects, workspaces, generations, artifacts, and releases.

**Correction:** Every pipeline declares staged, visible, and durable epochs/receipts and which acknowledgement it returns. Root-last publication is mechanical rather than adjectival.

### D-007 — Capsules confused checkpoint state with current authority

**Problem:** Agent workspaces and materializations were described as capsule-pinned even when the capsule might lag current RCR/forge state; successful publication was said to return a new capsule.

**Correction:** Ordinary reads/workspaces pin an authenticated `AuthorityReadReceipt` and named generation set. A capsule is optional checkpoint acceleration for an exact RCR/head; current state may include a verified suffix. Publication returns the terminal outcome and new authority receipt, not an automatically generated capsule.

### D-008 — Generic “graph intelligence” lacked exact graph semantics

**Problem:** The first cut did not separate canonical commit/object graphs, deterministic derived dependency/review/build graphs, and statistical inferred risk/expertise edges. Tie-break and traversal order were not receipts.

**Correction:** Introduce a typed repository graph fabric with authority classes, immutable generations, stable external IDs plus dense integer adjacency, closed tie-break policies, complexity/decision-path witnesses, and explicit forbidden decisions. Centrality/ML can rank or escalate; it cannot grant authority.

**Document:** [`GRAPH_INTELLIGENCE_ARCHITECTURE.md`](GRAPH_INTELLIGENCE_ARCHITECTURE.md).

### D-009 — Search/context could mix generations

**Problem:** Progressive retrieval was described, but the packet contract did not fully prevent lexical, semantic, graph, and authorization outputs from different source positions.

**Correction:** Search/graph generations activate through anti-rollback authority records. Context Packets name every source generation, authority receipt, omission, and join witness. `Initial`, `Refined`, and `RefinementFailed` preserve valid early answers without mixing authority.

### D-010 — Agent protocol contained duplicated fields and stale base semantics

**Problem:** `ContextPacket` repeated `capsule_id`; publication repeated approvals/checks; the workspace base and publication return were capsule-centric; effects were logged but not uniformly obligation-typed.

**Correction:** Rewrite the Agent Protocol around AuthorityReadReceipt, optional checkpoint+suffix, TreeFS manifest, explicit refresh relations, source-generation set, decision witnesses, effect obligations, and ordinary head-CAS publication.

### D-011 — File/workspace model was still conventional checkout-shaped

**Problem:** Sparse workspaces were a product feature, not a first-class Git-tree filesystem contract. Path safety, lazy authorization, intent logs, and crash epochs were incomplete.

**Correction:** Define Git TreeFS: immutable tree/blob bases, descriptor-relative capability roots, sparse lazy fetch, COW overlay, append-only intent log, snapshot publication, cross-platform path threat corpus, and ordinary Git closure export.

**Document:** [`GIT_TREE_FS.md`](GIT_TREE_FS.md).

### D-012 — Document/review/search spans lacked one canonical lineage

**Problem:** Rendering, review anchors, API positions, search spans, and agent context risked separate parsers and drift.

**Correction:** Parse once into a source-spanned canonical document/diff model; derive human HTML, API, compact agent data, review anchors, and search spans from that lineage. Use staged multi-output publication and deterministic worker budgets.

### D-013 — Adaptive systems were under-identified

**Problem:** “Conformal/e-process controller with fallback” did not bind population, selection, exact sequence window, regime, candidate/fallback, assumptions, support/ESS, arithmetic/toolchain, and retained evidence.

**Correction:** Make those fields identity material. Promotion happens through anti-rollback policy epochs; regime alarms revert to fallback. Claim lattice prevents statistical evidence from being laundered into correctness or authorization.

### D-014 — Dependency policy was too permissive and had unsafe escape hatches

**Problem:** The plan allowed generic mature dependencies, isolated unsafe boundary crates, and commodity external implementations. That contradicted the user’s stronger closed-universe and strictly safe-Rust requirement.

**Correction:** Production is clean-room pure Rust, first-party `#![forbid(unsafe_code)]` with no boundary exceptions, Asupersync sole runtime, FrankenSuite preferred, and only explicit fundamental audited pure-Rust crates. C Git/libgit2/JGit/Dulwich/gix/Tokio/rusqlite/native SDK stacks are denied for production. The executable dependency registry must approve every dependency.

**Document:** [`DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md`](DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md).

### D-015 — Pure-Rust Git was not a hard constitutional boundary

**Problem:** The first plan could be read as using ordinary Git materializations or an external Git implementation for hard operations.

**Correction:** All production object, pack, wire, diff, merge, archive, and checkout semantics are implemented in safe pure Rust. Upstream Git executables are sandboxed pinned conformance oracles only. Unsupported behavior returns a typed refusal.

### D-016 — RaptorQ “permeation” still mixed record and archive layers

**Problem:** Small mutable authority records, decision logs, transfer blocks, and checkpoint archives needed clearer class ownership. Decoder success and candidate placement were not enough; current authority/deletion races needed explicit states.

**Correction:** Rewrite the permeation map with class statuses, authority owners, ATP blocks, staged/visible/durable states, current-authority revalidation, newer-version/deletion refusals, and destructive drill matrix.

### D-017 — Negative evidence was not a constitutional artifact

**Problem:** Failed performance/cutover/proof attempts could disappear, causing future agents to repeat them.

**Correction:** Add a negative-evidence document and executable registry. Revisit conditions are explicit; negative evidence prevents repeated mistakes without freezing inquiry forever.

### D-018 — Hosted GitHub Actions remained an accidental execution path

**Problem:** The workflow triggered on pull requests and the documentation verifier was Python-only. The DSR example pointed to a nonexistent release workflow, while `full`/`release` lanes returned success despite being dormant.

**Correction:** Workflow YAML is dispatch-only and contains no unique logic or third-party action dependency. Repository-owned Rust/shell commands are authoritative and run locally/through DSR. DSR points to the actual workflow. Dormant full/release lanes refuse rather than emit false green status. A root-last signed release manifest is withheld until the full native matrix succeeds.

### D-019 — The original backlog encoded the superseded architecture

**Problem:** It specified authority-domain writers and a single-node commit store before the new AuthorityStore/decision-head model, and omitted ATP-Git, TreeFS, graph witnesses, local release, and witness refinement.

**Correction:** Replace with a 36-slice G0–G3 dependency graph (since extended to a 41-slice G0–G4 graph by the ambition-extension wave) covering constitutions, reference model, authority profiles, pure-Rust Git, object fabric, concurrency, ATP, TreeFS, forge, agents, graphs/search, repair/GC, CI, DSR, and distributed failover.

### D-020 — Verification tooling could admit arbitrary dependencies

**Problem:** The bootstrap checker banned a handful of known crates but did not fail an unregistered new dependency.

**Correction:** Manifest validation becomes closed-world: every dependency must match an active allow row or be a first-party workspace crate. Build scripts/proc macros/foreign runtime features require explicit policy. The checker itself remains zero-dependency safe Rust.

## Claims deliberately narrowed

- The decision-log design is specified, not yet proven against a real object-store backend.
- Pure-Rust Git parity is a goal until differential/fuzz/resource evidence exists.
- RaptorQ recoverability applies only to registered classes/profiles/placements.
- Per-core preparation and witness refinement are concurrency hypotheses until model and benchmark artifacts pass.
- ATP-Git is a native optional protocol, not ordinary Git compatibility.
- Graph/search/statistical output is evidence, not canonical authority.
- A complete architecture and bootstrap checker are not an implemented forge.
- The current license is source-available, not OSI-approved open source.

## Remaining launch decisions

1. Final open-source/commercial license structure.
2. Canonical codec and cryptographic algorithm registry.
3. First object-store authority adapter and conformance evidence.
4. Exact FrankenSuite crate revisions/features in `constellation.lock`.
5. Initial pure-Rust compression/TLS/SSH/crypto components admitted under the constitution.
6. V1 SHA-256 scope.
7. CI sandbox substrate.
8. Hosted residency/deletion/backup promises.
9. First managed RaptorQ durability profile.
10. GitHub API/Actions compatibility subset.

These are explicit ADR/evidence gates, not hidden implementation choices.

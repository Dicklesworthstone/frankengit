# FrankenSuite Deep-Dive Synthesis for FrankenGit

**Status:** architectural source-of-ideas ledger  
**Version:** 1.0  
**Last revised:** 2026-08-19

This document records the mechanisms imported from the user’s related projects after a source-level deep dive. It exists to prevent the architecture from collapsing rich prior work into vague slogans such as “use MVCC,” “use graphs,” or “add RaptorQ.” Each inherited idea is mapped to a concrete FrankenGit subsystem, an invariant, an evidence path, and a misuse boundary.

FrankenGit is not a mechanical merger of sibling repositories. It reuses stable crates where appropriate and imports architectural patterns where direct reuse would create the wrong coupling. Canonical Git semantics remain independently specified and differentially tested.

## 1. Asupersync: execution correctness becomes structural

### 1.1 Region-owned repository operations

Asupersync’s core contribution is not simply an executor. It gives every task an owner, every cancellation a drain/finalize protocol, every effect a capability context, and every deterministic test a controlled scheduler/clock/RNG.

FrankenGit applies this to:

- Git protocol sessions;
- object upload and validation;
- repository decision preparation and CAS attempts;
- materializer catch-up;
- graph/search generation builds;
- agent Intent Runs;
- CI jobs and subprocess trees;
- repair, compaction, backup, and restore;
- webhooks and release publication.

A push handler may not return while a child can still publish a head, write an object, use a secret, or consume quota. “Fire and forget” is replaced by explicit transfer to another supervised region.

### 1.2 Outcome and refusal discipline

FrankenGit distinguishes:

- successful value;
- typed domain refusal/error;
- cancellation with reason and ambiguity rules;
- panic/containment failure.

This is essential around Git pushes: cancellation after head CAS cannot be represented as “the push did not happen.” The protocol returns or later resolves the immutable transaction outcome.

### 1.3 Obligations and graded resources

Asupersync’s obligation system becomes FrankenGit’s effect type system. Object admission, authority CAS, outbox delivery, secret leases, runner slots, repair placement, context budgets, and billing reservations are linear obligations. The resource grade tracks bytes, CPU, memory, network, money, secrets, or failure-domain capacity. See `CALM_AND_OBLIGATIONS.md`.

### 1.4 ATP object transport

ATP contributes:

- content manifests and exact delta plans;
- unique-payload deduplication with deterministic reconstruction;
- typed path graphs;
- bounded path races and loser drain;
- swarm piece tracking, rarity, and endgame duplication;
- native QUIC/relay/mailbox profiles;
- RaptorQ transport and adaptive block sizing;
- trust-scoped caches;
- replayable transfer receipts.

FrankenGit specializes these around Git object graphs in `ATP_GIT_PROFILE.md`.

### 1.5 CALM and CRDT boundaries

Asupersync’s CALM/CRDT work supplies a rigorous answer to “what can be eventually consistent?” Immutable object puts and evidence additions are monotone. Ref movement, terminal outcomes, retention removal, and policy activation are not. Non-canonical replicas use conflict-absorbing lattices rather than last-writer-wins, while the canonical repository head remains ordered by CAS.

### 1.6 Deterministic lab and DPOR

The Asupersync lab contributes:

- virtual time and deterministic scheduling;
- controlled RNG streams;
- quiescence and obligation oracles;
- vector-clock/resource conflict tracking;
- Mazurkiewicz trace reduction and Foata normal forms;
- DPOR-like schedule exploration;
- minimal crashpacks;
- export to model-checking artifacts.

FrankenGit uses this to explore head-CAS races, cancellation, ref/forge atomicity, outbox delivery, materializer replay, GC, repair, and runner teardown without pretending raw stress counts cover meaningful interleavings.

### 1.7 Dependency gates

Asupersync’s dependency governance—especially bans on hidden Tokio and external transport stacks—becomes a workspace-level FrankenGit gate. The production graph has one runtime universe.

## 2. FrankenSQLite: high-concurrency preparation without weakening order

### 2.1 MVCC as witness discipline

The important import is not “put refs in a database.” It is explicit read/write witnesses, snapshot boundaries, first-committer-wins validation, serializability checks, and immutable evidence of conflicts.

FrankenGit prepared transactions carry witnesses over refs, forge entities, policies, quotas, retention, and object assumptions. Publication validates those witnesses against one authority head.

### 2.2 Per-core WAL lanes become preparation lanes

FrankenSQLite’s per-core double-buffered WAL design separates parallel body work from a tiny ordered residue. FrankenGit mirrors that:

- one lane owns a transaction’s parse/validation state;
- lane-local buffers avoid central allocator/lock traffic;
- a sealed prepared capsule is published to a bounded ready slot;
- the combiner orders only compact decisions and roots;
- no result becomes visible without the authority-head certificate.

### 2.3 Flat combining and microbatch publication

The commit combiner’s per-thread slots inspire one CAS for multiple compatible repository decisions. This amortizes object-store conditional-write latency without making the batch the user-visible transaction. Each `TxId` keeps its own terminal outcome and RCR.

### 2.4 Deterministic semantic rebase

FrankenSQLite’s rebase/merge ladder distinguishes:

- intent replay;
- structured patches;
- append-only and range/bitmap proofs;
- unsafe byte-level merge.

FrankenGit uses this for ref/forge commands and TreeFS edits. Same-ref updates remain conflicts unless expected-old semantics permit exactly one. Forge sets/maps may commute only through a registered algebra. Source files use source-spanned/structured witnesses or explicit textual conflicts, never raw byte overlay.

### 2.5 Witness refinement as value of information

Coarse witnesses are cheap but cause false conflicts. FrankenSQLite’s refinement framework provides the right asymmetry:

- correctness starts conservative;
- the system estimates expected abort/revalidation cost;
- it spends bounded work to refine only when likely useful;
- failure to refine cannot admit an unsafe commit; it merely loses concurrency.

FrankenGit refinements include exact ref keys, path/CODEOWNERS slices, PR/check entities, symbol dependencies, queue prefixes, and quota domains.

### 2.6 Conflict sketches and heavy hitters

AMS-style second moments, cardinality sketches, and heavy-hitter summaries can route hot refs/paths/entities to better preparation lanes, choose batch width, and predict contention. These summaries never decide correctness; exact witnesses still validate publication.

### 2.7 Expected-loss retry

Retry delay becomes a bounded decision problem using observed success/conflict rates, cost, starvation age, and regime reset. Hard ceilings and deterministic fallback prevent an adaptive retry controller from turning into unbounded latency.

### 2.8 FrankenSQLite’s proper boundary

FrankenSQLite is the local authority backend and derived MVCC engine for:

- embedded single-node head CAS;
- local outcome/ref/forge indexes;
- projector state;
- queues and runner/agent state;
- search metadata;
- evidence catalogs.

It is not a second distributed source of truth beside the immutable decision log.

## 3. FrankenFS: workspace semantics, repair serialization, and crash honesty

### 3.1 Staged, visible, durable

FrankenFS’s writeback-cache work demonstrates why “written” is not one state. FrankenGit adopts staged/visible/durable epochs for repository decisions, workspace overlays, projections, artifacts, and releases. Every acknowledgement names its boundary.

### 3.2 Repair uses the normal mutation authority

A valid RaptorQ decode can still be stale. FrankenFS’s repair/writeback serialization leads to a hard FrankenGit rule: repair writes immutable candidate bytes, then submits a normal locator/retention intent against current authority. It cannot overwrite newer placement state out of band.

### 3.3 Copy-on-write and block-level versioning

Git TreeFS imports immutable base + overlay, snapshot IDs, range/path witnesses, and safe merge proof families. Unchanged Git subtrees remain shared by identity. See `GIT_TREE_FS.md`.

### 3.4 Crash matrix

FrankenFS’s explicit crash points become a release gate, not a prose promise. FrankenGit enumerates interruption around body/checksum/sync/visibility, repeated crash/replay, and all authority boundaries.

### 3.5 RCU/snapshot reads

Read paths acquire immutable generation/head snapshots and never observe half-published mutation. Hot caches can use safe epoch/version invalidation without making local memory authoritative.

### 3.6 Adaptive repair refresh

The repair autopilot’s Beta posterior and expected-loss comparison inform:

- coding overhead;
- refresh timing;
- metadata weighting;
- eager/lazy/hybrid policy;
- scrub priority.

Hard durability floors dominate. Statistical adaptation cannot reduce promised protection or bypass post-decode verification.

### 3.7 Negative evidence

FrankenFS records failed cutovers and hypotheses. FrankenGit formalizes a negative-evidence ledger so later agents cannot rediscover the same dangerous idea without confronting prior artifacts. Examples include shared-metadata conflicts that survive lower-level lock improvements and performance changes that lose once correctness/operations are included.

## 4. FrankenSearch: progressive answers and anti-rollback generations

### 4.1 Progressive retrieval

FrankenSearch’s `Initial`, `Refined`, and `RefinementFailed` result phases map directly to code/issue/graph retrieval. FrankenGit returns useful exact lexical/path/symbol candidates quickly, then semantic/graph/rerank improvements. Failure of refinement cannot erase a valid initial answer.

### 4.2 Quill-style lexical architecture

The native Quill design contributes:

- immutable segment generations;
- absolute/disjoint document ID intervals so merge can be concatenation;
- columnar sort-based ingest instead of per-document hash-heavy mutation;
- searchable in-memory delta before durable seal;
- deterministic tie-breaks and scalar oracle;
- incumbent engine only as a conformance oracle, not production dependency.

FrankenGit applies this to code, commit messages, issues, reviews, symbols, and evidence.

### 4.3 Generation activation authority

A built index is not active merely because files exist. The anti-rollback generation root provides:

- sequence and nonce identity;
- exact predecessor;
- dual-slot/checksummed local authority;
- fail-closed unresolved-attempt recovery;
- monotone floor preventing silent old-generation fallback.

Search, graph, materialization, compaction, policy, and release generations all adopt this pattern.

### 4.4 No mixed-generation context

A Context Packet cannot combine lexical results from one source generation, embeddings from another, and graph paths from a third without naming the deliberate join. Default retrieval pins one coherent source position and generation set.

### 4.5 Capability-safe file roots

FrankenSearch’s descriptor-relative generation-root admission informs TreeFS and local artifact readers: canonicalize before I/O, reject symlink/cross-device/identity-changing paths, and verify before/after witnesses and size caps.

### 4.6 Unified replay artifacts

Search evaluation bundles dataset, models, config, raw results, judgments, metrics, failure traces, and replay command. FrankenGit uses the same pattern for Git conformance, graph decisions, authority faults, CI, and releases.

## 5. franken_markdown: one source-spanned document lineage

### 5.1 Parse once

Markdown source is parsed into one canonical AST with source spans. Human HTML, compact agent view, API representation, search documents, and review anchors derive from that lineage. FrankenGit does not maintain separate browser, API, and agent parsers that drift.

### 5.2 Safe host/core boundary

The renderer core receives bytes, fonts/assets, options, and resource limits. It has no ambient filesystem/network authority. Remote image or repository asset acquisition is a host effect through capabilities.

### 5.3 Determinism and safe defaults

Raw HTML is escaped by default; URLs, SVG, images, code fences, and resource sizes are bounded. Fixed source/options/assets produce stable output. Unsafe active content does not become a hidden execution channel in issues or PRs.

### 5.4 Staged multi-output publication

franken_markdown’s transactional `--to both` model generalizes to release and forge publication: preflight path aliases/collisions, stage every body, replace roots only after all dependencies succeed, and roll back sibling outputs on failure.

### 5.5 Deterministic worker budgets

Batch worker count is a pure function of CPU cap, memory budget, per-job RSS estimate, mode, and variance. FrankenGit applies this to render, index, graph, pack, repair, and CI workers instead of “one worker per core” folklore.

### 5.6 Complete receipts

Every input is accounted as success, failure, refusal, or skip; output ordering is independent of completion order. This becomes the default for batch Git imports, repository migration, release matrices, and multi-agent runs.

### 5.7 Optimization proof checklist

Ordering, tie-break, floating-point behavior, scalar fallback, RNG, golden outputs, deterministic repeat, target family, p95/p99, and rollback are checked before a performance change is accepted.

## 6. FrankenGraphDB: canonical temporal streams and evidence-governed adaptation

### 6.1 One version universe

FrankenGraphDB unifies MVCC, time travel, branches, replication, and subscriptions over immutable commits. FrankenGit’s RCR/decision stream similarly becomes the one version axis for refs and forge events. Branches/agent overlays are explicit derived lineages, not parallel truths.

### 6.2 Body first, marker/root last

The Chronicle commit marker and root protocol maps directly to decision batches and authority heads. Immutable bodies may exist early; visibility begins only at one final authenticated root update.

### 6.3 Anti-rollback recovery

FrankenGraphDB’s two-slot root rule is subtle and important: if the highest acknowledged generation is structurally present but fails authentication/closure, recovery must fail closed rather than silently use an older “valid” root. FrankenGit restores older state only through an explicit new-generation restore event.

### 6.4 Identity-bound conformal/e-process systems

Every adaptive result binds:

- metric and population;
- selection rule;
- exact sequence window;
- regime epoch;
- candidate and fallback;
- assumptions;
- numeric/toolchain/math fingerprint;
- bounded retained evidence.

FrankenGit imports this for path tuning, repair, cache, batching, retry, canaries, search budgets, and anomaly review.

### 6.5 Off-policy evaluation and promoted policy epochs

Candidate operational policies are evaluated against logged action probabilities/outcomes with support and effective-sample gates. Promotion is a stream-sequenced policy epoch with exact predecessor and pinned fallback. Statistical evidence may promote answer-preserving physical policy; canonical-state changes require deterministic guards.

### 6.6 Regime detectors revert; they do not improvise

Page-Hinkley/CUSUM-style alarms identify nonstationarity and revert candidate to fallback. They do not synthesize a novel policy in the canonical path.

### 6.7 Lyapunov/progress certificates

Queue, drain, repair, migration, and compaction controllers may emit bounded progress/stability evidence with explicit assumptions. A favorable certificate does not prove universal termination or future behavior.

### 6.8 Claim lattice

FrankenGit adopts a claim type system:

```text
invariant > proof > bounded_model > statistical > slo > benchmark
```

Evidence cannot be laundered upward. A benchmark cannot justify a correctness invariant; one operational trace cannot become a universal SLO; a statistical detector cannot become authorization.

### 6.9 Replay completeness taxonomy

Artifacts declare whether they are:

- exactly replayable;
- structurally replayable;
- verifiable given external artifacts;
- audit-only.

“Deterministic” is never used without naming intercepted inputs and residual external effects.

### 6.10 Intent/effect separation and normal form

The graph reference model’s intent pipeline informs repository/TreeFS/forge mutation. Intents are evaluated in source order, mismatch policy is explicit, mutation potential is monotone, and final effects are target-disjoint with total source-to-destination/no-op mapping.

### 6.11 Honest storage slices

FrankenGraphDB refuses to present an in-memory map as a storage engine. FrankenGit follows the same rule: the first implementation slice must include real canonical bytes, root publication, reopen/recovery, corruption refusals, and evidence—not a fake trait over a `HashMap`.

## 7. FrankenNetworkX: deterministic graph algorithms as systems machinery

### 7.1 Observable behavior includes order

FrankenNetworkX treats return type, iteration order, tie-break, exception class/message, and serialization as contract. FrankenGit applies the same discipline to:

- diff order;
- ref advertisement;
- pack planning;
- graph traversal and context selection;
- reviewer/runner assignment;
- merge-queue ordering;
- error/refusal surfaces.

### 7.2 Integer-indexed hot representation, stable external IDs

Graph storage uses stable insertion/canonical order at the boundary and dense integer adjacency for hot loops. FrankenGit’s graph generations, object closure, dependency graph, and placement graph use the same split.

### 7.3 Canonical Graph Semantics Engine

A closed tie-break policy and per-run complexity/decision witness prevent “equivalent” graph results from drifting by hash order or thread schedule. See `GRAPH_INTELLIGENCE_ARCHITECTURE.md`.

### 7.4 Algorithm families imported

- shortest/k-shortest paths for provenance and context explanations;
- SCC/condensation/cycle bases for dependency and coordination cycles;
- dominators, articulation points, bridges, and biconnected components for blast radius;
- PageRank/HITS/centralities for advisory relevance/expertise;
- matching and min-cost flow for reviewers, agents, runners, and repair placement;
- max-flow/min-cut/Gomory-Hu for separation and failure-domain reasoning;
- topological sort/transitive reduction for CI and dependency DAGs;
- k-core/community/partitioning for monorepo structure;
- connectivity/robustness for durability and placement.

Graph scores remain evidence unless an exact graph/algorithm is explicitly part of deterministic policy.

### 7.5 Strict and hardened modes

Strict mode fails closed. Hardened mode permits only bounded registry-approved recovery and emits a DecisionRecord. Silent graph repair or edge invention is forbidden.

### 7.6 Differential surface ledgers

FrankenNetworkX’s generated coverage/divergence/delegation ledgers inspire FrankenGit’s Git compatibility universe. Every promised protocol/API symbol or behavior has present/partial/missing/unsupported status and an oracle corpus.

## 8. Doodlestein Self-Releaser: local workflows become release evidence

### 8.1 Workflow YAML as portable lane description

FrankenGit may keep `.github/workflows` for familiarity and DSR/`act` execution, but remote GitHub Actions is not an authority or availability dependency. Workflow steps call repository-owned scripts; no release logic exists only in hosted Actions expressions or services.

### 8.2 Native host matrix

Linux jobs run locally/through `act`; macOS and Windows execute on native SSH hosts. Each target records host/toolchain/source fingerprints and attempt-scoped logs.

### 8.3 Resume and root-last release manifest

Completed target artifacts remain immutable and verified across resume. The authoritative release manifest is withheld until every requested target succeeds. Partial runs are evidence, not releases.

### 8.4 Exact asset contract

Every target maps to one unique asset basename, checksum sidecar, optional signature, SBOM, and explicitly listed companion files. Symlinks, unsafe paths, collisions, missing files, and unlisted directory discovery fail closed.

### 8.5 Signed reproducible release pack

FrankenGit’s local release lane binds commit, lockfile, constellation, nightly/compiler, target, build profile, binary/archive digests, checksums, minisign/cosign-style signature policy, SBOM, test receipts, and DSR run identity. GitHub Releases is a distribution adapter, not the source of build truth.

## 8a. Product-surface stack: fastapi_rust, sqlmodel_rust, frankentui

The forge is not only a truth engine; it needs a gateway, projections, and interfaces. Three sibling projects supply these on the sole runtime, keeping the whole stack in one Rust universe.

### 8a.1 fastapi_rust -> gateway/API
Pure-Rust, Asupersync-native web framework (typed routing, zero-copy parsing, deterministic testing, OpenAPI generation). It becomes `fgit-gateway`/`fgit-api`; its OpenAPI generation is unified with the schema registry so ONE schema source drives Rust types, validators, OpenAPI, and generated clients (no handwritten wire structs). No Tokio.

### 8a.2 sqlmodel_rust -> projection read-models
SQLModel-style typed models + compile-time-checked query builders, via the `sqlmodel-frankensqlite` backend (asupersync + fsqlite only). It becomes the substrate for DERIVED projection read-models over the mandated embedded engine. Hard boundary: projections only (never a second source of truth beside the decision log), and only the frankensqlite backend is admitted — the C-SQLite/Postgres/MySQL backends are excluded.

### 8a.3 frankentui (ftui) -> terminal UI and an optional parallel web skin
A mature pure-Rust terminal-UI kernel with an `asupersync-executor` feature and a WASM backend. It becomes `fgit-tui` (operator/agent/SSH console) and, optionally, a parallel terminal-style web surface. It is deliberately NOT the primary web UI: that is a familiar GitHub-like DOM-oriented pure-Rust->WASM app (Leptos or Dioxus, SSR + Tailwind, real DOM, so text selection / a11y / SEO all work), because a terminal aesthetic (and a canvas-painted WASM UI) would hurt most web users. What the surfaces share is the Rust substrate (canonical types, franken_markdown rendering, the verified-read verifier as native code), not one look; a generated TypeScript client and React reference are the supported alternative front-end.

## 9. Cross-project synthesis: new FrankenGit mechanisms

The deep dive produces several mechanisms that no single sibling project contains alone.

### 9.1 Repository Decision Fabric

Cursor’s object-store WAL + FrankenGraphDB root-last commits + FrankenSQLite flat combining + Asupersync obligations yield an immutable decision log with one CAS authority head, per-core preparation, microbatch publication, stable outcomes, and deterministic rebase.

### 9.2 Git TreeFS

FrankenFS COW/MVCC + Git tree identity + franken_markdown source spans + ATP lazy fetch yield sparse authorized workspaces that build new commits without full checkout.

### 9.3 Repository Graph Fabric

FrankenNetworkX deterministic algorithms + FrankenGraphDB temporal storage + FrankenSearch progressive retrieval yield exact and inferred graph views with generation receipts and decision witnesses.

### 9.4 Evidence-Carrying Change

GraphDB claim lattice + Asupersync effect/obligation receipts + TreeFS total intent mapping + Search/Markdown provenance yield a change object that says what the agent saw, omitted, attempted, changed, tested, spent, and cannot claim.

### 9.5 Repair as publication

FrankenFS repair serialization + RaptorQ + decision-log CAS means a repaired placement is accepted through the same current-state authority as normal storage changes.

### 9.6 Local release authority

DSR root-last manifests + franken_markdown staged outputs + GraphDB evidence identities + claim lattice produce a release process that is fully local, resumable, signed, and independent of GitHub-hosted runners.

## 10. Mechanism placement matrix

| Mechanism | Correct FrankenGit role | Forbidden misuse |
|---|---|---|
| Native Git OID | external Git identity | replaced by internal digest |
| Strong internal digest | envelope/segment/evidence integrity | pretending to be client-visible Git OID |
| Authority-head CAS | one linearization point | untested weak object-store conditional write |
| Decision batch | amortized ordered terminal decisions | user-visible transaction collapse |
| Per-core lane | parallel preparation | independent canonical truth |
| Witness refinement | avoid false conflicts | weaken conservative safety result |
| CALM registry | classify coordination need | label non-monotone state eventual by convenience |
| Obligation | own unfinished effect/resource | best-effort cleanup |
| ATP-Git | native/internal efficient transfer | confusing with Git protocol v2 |
| RaptorQ | erasure repair/transport | integrity, authorization, consensus, freshness |
| TreeFS | sparse COW workspace | host path as canonical repository identity |
| FrankenSQLite | embedded authority/derived MVCC | competing global ref database |
| Graph generation | exact/derived graph view | opaque universal knowledge graph |
| Centrality/ML | advisory ranking | authorization or guilt |
| E-process/conformal | bounded adaptation evidence | canonical correctness decision |
| Negative evidence | prevent repeated failed ideas | excuse never to revisit under changed assumptions |
| DSR workflow | local reproducible lane | dependence on hosted Actions availability |

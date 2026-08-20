# FrankenGit Research Provenance

**Purpose:** Record which ideas influenced FrankenGit, how they were adapted, and what local evidence is still required. Inspiration is not proof and does not transfer guarantees automatically.

## Cursor: Git at any scale

### Adopted

- Ordinary Git repositories can be disposable materializations rather than durable truth.
- Immutable object storage can hold durable repository data economically.
- Generation fencing prevents stale materializers from publishing as current.
- Local NVMe and regional caches should be treated as accelerators.

### Extended

- FrankenGit makes ref and forge transitions one canonical RCR rather than maintaining a separate ref log and product database without a shared commit object.
- Current forge-position roots, terminal transaction outcomes, policy evidence, retention roots, and capsules become first-class authenticated state.
- Sparse agent workspaces and Context Packets avoid full-repository materialization where possible.
- Registered RaptorQ protects eligible immutable segments, followed by original commitment verification.

### Rejected overread

The Cursor architecture does not prove that object storage alone solves canonical ordering, authorization, Git protocol compatibility, or cross-product atomicity. FrankenGit supplies separate contracts and evidence gates for those concerns.

## Git and GitHub behavior

Git itself is the primary compatibility oracle for object formats, pack behavior, upload-pack, receive-pack, protocol negotiation, shallow/partial clone, refs, atomic push, signatures, and hash transition. GitHub is an oracle only for the explicitly selected API/forge compatibility subset.

No prose summary substitutes for differential tests against named versions and fixtures. In particular, Git protocol v2 fetch commands must not be generalized into a fictional standardized v2 push command.

## Asupersync

### Adopted

- region-owned tasks and no orphan-task doctrine;
- capability-scoped effects rather than ambient runtime authority;
- explicit request/drain/finalize cancellation;
- deterministic schedule/replay laboratories;
- typed outcomes/refusals;
- bounded adaptive controls and evidence surfaces.

### Adapted

FrankenGit applies structured concurrency to Git sessions, validation, materialization, CI, agent workspaces, outbox workers, repair, and shutdown. Canonical repository transaction truth remains in the RCR/outcome protocol; a runtime task outcome cannot override a committed mutation.

## FrankenSQLite

### Adopted

- explicit transaction and durability invariants;
- MVCC/snapshot thinking and compare-at-commit validation;
- root-last publication;
- typed page/object identities;
- strict layered crates and narrow unsafe boundaries;
- differential/conformance harnesses;
- information-theoretic repair as a registered, evidence-gated mechanism.

### Adapted

FrankenGit versions refs and forge positions rather than database pages. The single-sequencer reference model is deliberately simpler than speculative multi-writer metadata until equivalence is proven.

### Rejected overread

Concurrent page writers do not imply asynchronous multi-master ref mutation is safe. Repository policy, merge queues, quotas, forge entities, and retention roots create cross-ref invariants.

## FrankenFS

### Adopted

- immutable block/object identities;
- copy-on-write/MVCC materialization concepts;
- evidence-linked repair and scrub ledgers;
- explicit writeback/visibility/durability phases;
- failure-domain-aware repair placement;
- userspace inspectability and deterministic fault campaigns.

### Adapted

FrankenGit materializations are userspace Git views over canonical immutable objects. Local `git gc`, pack compaction, or worktree state never decides canonical retention/deletion.

## FrankenSearch

### Adopted

- progressive initial/refined results;
- lexical and semantic retrieval as complementary signals;
- deterministic immutable index generations;
- graceful degradation;
- position/source receipts and explainability;
- streaming machine-readable output.

### Adapted

Every search/graph generation binds the RCR/forge position through which it is complete. Authorization is applied before result disclosure and revalidated for canonical effects.

## franken_markdown

### Adopted

- deterministic rendering from one typed representation;
- small auditable cores and constrained dependencies;
- safe escaping/sanitization and resource limits;
- staged writes and sibling-output rollback;
- agent/CI-oriented capabilities and diagnostics;
- native/WASM parity as an evidence question.

### Adapted

FrankenGit renders Markdown, diffs, code, diagrams, and artifacts through safe bounded pipelines. Rendered output is a projection and never an authorization source.

## FrankenGraphDB

### Adopted

- canonical event streams and rebuildable graph projections;
- root-last checkpoints and immutable manifests;
- versioned registries and claim governance;
- deterministic simulation and evidence records;
- conformal/e-process/no-regret mechanisms separated from canonical truth;
- strict dependency layering and explicit unsafe islands.

### Adapted

Issues, pull requests, reviews, releases, policies, and merge queues are event-sourced. The graph is a derived projection used for search, ownership, dependency analysis, and context construction—not a second source of canonical mutation truth.

## RaptorQ / fountain coding

### Adopted

Application-layer fountain coding is useful when immutable objects must survive erasure/loss or traverse lossy/high-RTT paths without rigid replica grouping.

### Local requirements

FrankenGit must provide its own canonical envelopes, parameter registry, decoder bounds, placement policy, post-decode cryptographic/structural verification, failure codes, fault corpus, and restore evidence. RaptorQ provides no authorship, authorization, ordering, freshness, or consensus.

## Conformal prediction and e-processes

### Adopted

Finite-sample calibration and anytime-valid sequential evidence can improve operational decisions under optional stopping.

### Local restrictions

Every claim states assumptions and calibration population. Controllers are bounded and reversible. Statistical outputs may prioritize review or adapt resource/repair budgets but cannot determine identities, committed truth, authorization, guilt, or deletion safety.

## Existing forge systems

GitLab/Gitaly/Praefect, Gitea/Forgejo, SourceHut, Gerrit, GitHub, Bitbucket, Azure DevOps, and local-first/federated systems such as Radicle provide product and protocol lessons. FrankenGit does not claim novelty merely because it recombines known techniques. Novelty claims, if any, require a prior-art matrix and precise claim language.

Particularly important lessons include:

- Git compatibility edge cases dominate perceived correctness;
- administrative and migration tooling are product features;
- CI runners are a separate hostile-compute security boundary;
- webhooks require stable delivery identities and retries;
- replication availability claims need partition/failover evidence;
- federation adds identity, moderation, deletion, and consistency problems beyond transport.

## Evidence rule

For every inherited idea, the implementation issue must record:

1. source/inspiration;
2. FrankenGit-specific adaptation;
3. assumptions that do not transfer;
4. local invariant owner;
5. local tests/fault campaigns;
6. evidence artifact and replay command;
7. explicit non-claims.

This ledger should grow with implementation. It must never be used as authority laundering: a cited project or paper does not prove FrankenGit’s implementation has the cited property.
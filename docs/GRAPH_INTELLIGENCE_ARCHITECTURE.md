# FrankenGit Graph Intelligence Architecture

**Status:** normative architecture profile (bound as normative for graph semantics by `NORMATIVE_PROTOCOL_CONTRACTS.md`, which wins on any conflict)  
**Version:** 1.1  
**Last revised:** 2026-08-20

FrankenGit treats graph structure as a first-class systems substrate, not merely a semantic-search accessory. Git itself is a family of graphs: commit ancestry, tree/object reachability, refs, path history, dependencies, ownership, reviews, builds, provenance, agents, capabilities, placements, and failures. FrankenNetworkX supplies deterministic graph semantics and algorithm families; FrankenGraphDB supplies immutable temporal graph storage, time travel, incremental maintenance, query planning, and evidence-governed adaptive execution.

The design deliberately avoids one giant, semantically muddy “knowledge graph.” Each graph view declares its node/edge ontology, source position, freshness, authority class, canonical tie-breaks, and permitted decisions.

## 1. Graph classes

### 1.1 Canonical exact graphs

These graphs are derived directly from canonical source records and may participate in correctness after exact verification:

1. **Commit DAG** — commit nodes and parent edges.
2. **Git Object Reachability Graph** — commit/tag/tree/blob nodes and typed containment/reference edges.
3. **Ref Root Graph** — refs/symrefs to object identities and namespace relationships.
4. **Retention Graph** — canonical roots, legal holds, capsules, artifacts, packages, and object closure.
5. **Decision Lineage Graph** — authority heads, decision batches, RCRs, outcomes, and predecessor edges.
6. **Forge Causality Graph** — canonical PR/issue/review/check/policy events and entity chains.
7. **Provenance Graph** — source, build input, toolchain, runner, artifact, signature, release, and package edges.

An “exact” graph still needs a versioned builder and closure proof. A stale projection cannot make a canonical decision.

### 1.2 Deterministic derived graphs

These are reproducible from canonical inputs but may depend on parsers or normalization profiles:

1. **Path History Graph** — file identities, renames/copies, versions, commits, and review anchors.
2. **Symbol Graph** — definitions, references, calls, imports, inheritance, types, macros, generated symbols.
3. **Build Graph** — targets, actions, declared/observed inputs, outputs, caches, runners.
4. **Ownership Graph** — paths/symbols/components to people, teams, review history, policy roles.
5. **Review Graph** — changes, reviewers, comments, suggestions, checks, approvals, dismissals.
6. **Agent Coordination Graph** — Intent Runs, tasks, leases, messages, effects, verifier relationships.
7. **Capability Flow Graph** — principals, delegated capabilities, secrets, effects, and revocations.
8. **Placement Graph** — objects/segments/caches/regions/failure domains and repair symbols.
9. **Failure/Evidence Graph** — incidents, hypotheses, experiments, artifacts, claims, and counterevidence.

A derived graph’s identity binds parser/model/toolchain/profile versions and source RCR/forge positions.

### 1.3 Statistical or inferred graphs

These include probable ownership, semantic similarity, inferred dependencies, change-risk, agent expertise, anomaly affinity, and predicted conflict. They are explicitly labeled and cannot silently replace exact edges.

## 2. Immutable graph generations

Every graph view publishes immutable generations:

```rust
struct GraphGenerationBody {
    graph_view_id: GraphViewId,
    schema_id: GraphSchemaId,
    source_rcr_id: RepositoryCommitId,
    source_forge_position_root: Digest,
    builder_profile: BuilderProfileId,
    parser_model_root: Digest,
    vertices_root: Digest,
    edges_root: Digest,
    index_manifest_root: Digest,
    evidence_root: Digest,
    predecessor_generation_id: Option<GraphGenerationId>,
}
```

Activation uses an anti-rollback authority record with exact predecessor linkage. An unresolved publication attempt is reconciled fail-closed. Readers select one generation per graph view; a query may intentionally join several views only when the receipt names every contributing generation and the join policy. Cross-time joins additionally name each exact position and label the result as a cross-time join rather than a single-position view; this is the one join rule shared with `AGENT_PROTOCOL.md` §7.2 and normative invariant 20.

## 3. Storage model

The graph fabric combines:

- insertion-order-stable external identity tables;
- dense integer IDs for hot traversals;
- immutable delta blocks for recent changes;
- sealed compressed CSR/CSC runs for warm adjacency;
- archived anchors for cold history;
- versioned properties and visibility intervals;
- content-addressed manifests and roots;
- deterministic compaction reused by all replicas.

Hot algorithms traverse integer rows without hashing strings. External node identities, insertion/canonical order, attributes, and parallel-edge keys remain stable at the boundary. Cache entries carry graph revision/generation and cannot be reused across silent mutation.

## 4. Canonical Graph Semantics Engine for FrankenGit

Every graph algorithm that can influence a user-visible or operational decision declares:

- algorithm family/version;
- input graph generation(s);
- directed/multigraph/weight semantics;
- edge/property filters;
- exact tie-break policy;
- seed/RNG stream where applicable;
- complexity model and observed operation count;
- bounded resource profile;
- decision-path digest;
- result root and explanation paths.

A `GraphDecisionWitness` generalizes FrankenNetworkX’s `ComplexityWitness`:

```rust
struct GraphDecisionWitness {
    graph_generation_ids: Vec<GraphGenerationId>,
    algorithm_profile: GraphAlgorithmProfileId,
    n: u64,
    m: u64,
    dominant_term: ComplexityTerm,
    observed_ops: u64,
    tie_break_policy: TieBreakPolicyId,
    seed: Option<u64>,
    decision_path_root: Digest,
    result_root: Digest,
    resource_receipt_root: Digest,
    evidence_class: EvidenceClass,
}
```

Equal-score choices may never depend on hash-table iteration or thread schedule. Ordering policies are closed and named; golden tests over them are a required conformance gate before any related claim advances past proposal.

## 5. Algorithm-to-system map

### 5.1 Reachability, closure, and retention

- DAG traversal and transitive closure validate Git object closure.
- Dominator trees identify objects/subtrees through which all paths to a retained object pass.
- Strongly connected components should be trivial in Git’s object graph; a cycle is corruption except where an ontology explicitly allows it.
- Incremental reachability maintains GC/partial-clone/materialization certificates.
- Cut proofs and root-to-object paths explain why an object is retained.

Exact scalar/reference traversal is authoritative. Bitmaps, sketches, and indexes accelerate but do not weaken closure proof.

### 5.2 Dependency and architecture analysis

- SCC condensation exposes dependency cycles.
- Feedback vertex/edge sets propose minimal cycle-breaking changes.
- Transitive reduction removes redundant build/dependency edges for explanation.
- Topological order schedules builds, migrations, and merge trains.
- Dominators identify architectural choke points.
- Articulation points, bridges, and biconnected components identify fragile integration boundaries.
- k-core and core decomposition distinguish subsystem cores from peripheral code.
- community/partition algorithms propose monorepo shards and context boundaries.

These are advisory unless a policy names an exact deterministic algorithm and verifies its graph source.

### 5.3 Review and ownership

- Bipartite matching assigns reviewers to changes under expertise, independence, load, and conflict-of-interest constraints.
- Min-cost flow assigns multiple reviewers/agents/runners while respecting capacities and diversity.
- Maximum matching detects unstaffed review demand.
- PageRank/HITS/eigenvector-like signals rank expertise candidates, but do not grant authority.
- Temporal paths explain how ownership evidence was acquired.
- Min-cut can enforce separation between proposer and verifier trust domains.

Final reviewer requirements remain deterministic policy; graph scores propose candidates.

### 5.4 Change-risk and context selection

- Betweenness/load centrality identifies files/symbols that bridge many paths.
- Articulation/bridge analysis identifies changes with disproportionate blast radius.
- Shortest and k-shortest dependency paths explain why a file or symbol enters a Context Packet.
- Steiner-tree/set-cover approximations select compact connected context over multiple requested symbols/tests.
- Personalized PageRank or diffusion expands context from changed nodes under a hard budget.
- Community structure preserves subsystem diversity.
- Dominator paths prioritize configuration/build files that govern many targets.

Every Context Packet includes graph-generation and decision witnesses; omitted material remains explicit.

### 5.5 Merge and conflict planning

- An interaction graph connects prepared transactions whose witnesses overlap.
- Coloring or independent-set heuristics propose conflict-free microbatches.
- Connected components isolate retry groups.
- Weighted matching pairs changes with merge/rebase workers.
- Cut/bridge analysis detects shared policy/retention/forge metadata that makes apparently disjoint refs non-independent.
- Temporal graph differences explain why a previous conflict certificate became stale.

The batch combiner still validates exact witnesses. A graph heuristic cannot authorize concurrent publication by itself.

### 5.6 CI and runner scheduling

- Build DAG topological order exposes critical path and parallelism.
- List scheduling uses deterministic tie-breaks and resource profiles.
- Min-cost flow assigns jobs to runners under architecture, trust, data locality, and cost constraints.
- Bipartite matching handles scarce hardware and secret eligibility.
- Critical-path/PERT-style metrics drive priority.
- Cache/artifact provenance paths prevent incompatible reuse.
- Failure correlation graphs identify common-mode runner or dependency failures.

### 5.7 Object placement and repair

- Placement graph nodes are segments, symbols, stores, zones, regions, keys, and caches.
- Min-cut/failure-domain analysis verifies that declared durability does not collapse under one correlated failure.
- Matching/flow assigns new repair symbols to capacity-constrained domains.
- Shortest path selects economical verified repair sources.
- Betweenness identifies relay/cache bottlenecks.
- Connectivity and k-edge/k-node robustness provide interpretable placement certificates.

RaptorQ reconstruction still requires original commitments and same-authority locator publication.

### 5.8 Agent coordination

- Task DAGs and dependency closure guide multi-agent work.
- Matching assigns agents by capability, context locality, and budget.
- SCC/cycle detection finds coordination deadlocks.
- Wait-for graph spectral/structural monitors provide early warning.
- Lease/message graphs support orphan and lost-ownership detection.
- Proposer/verifier separation is a graph constraint over workspace, credentials, model/harness, context, and sponsor edges.
- Community structure may allocate agents to subsystems while bridge agents handle interfaces.

## 6. Strict and hardened graph modes

Like FrankenNetworkX, graph ingestion and algorithms expose two explicit modes:

- **Strict:** malformed, ambiguous, inconsistent, unsupported, or non-canonical input fails closed.
- **Hardened:** only registry-approved bounded recovery is allowed, and each recovery emits a `DecisionRecord`.

There is no silent “best effort” mode. Examples of bounded recovery include skipping one corrupt optional property segment while preserving exact vertex/edge identity, or falling back from an approximate index to scalar traversal. Inventing an edge or changing tie-break order is not recovery.

## 7. Temporal semantics

Each edge/property declares validity:

```text
created_at <= as_of < retired_at
```

The half-open interval prevents simultaneous visibility of retired and replacement versions at one sequence. Queries bind source RCR/forge positions and temporal mode:

- current canonical;
- as-of RCR;
- between two positions;
- branch/agent overlay;
- projected/inferred with model epoch.

Cross-time joins are explicit; a current ownership edge cannot be silently joined to a historical symbol graph.

## 8. Incremental maintenance

A committed RCR emits graph deltas keyed by affected ontology and source identities. Maintenance uses:

- append-only delta blocks;
- differential/incremental operators for affected regions;
- exact invalidation by generation/revision;
- root-last generation publication;
- deterministic background compaction;
- fallback full rebuild when incremental evidence is incomplete.

An incremental result must match the full rebuild oracle over the conformance corpus before it is authoritative for that graph class.

## 9. Graph query execution

FrankenGraphDB contributes:

- worst-case-optimal joins for multi-way graph patterns;
- factorized intermediates to avoid Cartesian explosion;
- temporal/version-aware scans;
- incremental subscriptions;
- graph/vector/text fusion;
- plan certificates and deterministic tie-breaks;
- calibrated adaptive plan selection with pinned fallback.

Query plans are physical policy. They may adapt only through promoted policy epochs and must preserve answer semantics.

## 10. GraphRAG and Context Packets

Graph expansion is bounded by:

- authorized vertex/edge classes;
- source generation;
- hop/type/path constraints;
- token/byte/time budgets;
- diversity requirements;
- maximum result cardinality;
- deterministic tie-break/seed;
- exact explanation paths.

The packet records which graph paths caused inclusion and which budget boundary caused omission. Statistical relevance may order candidates, but exact path identities and authorization are verified before content disclosure.

## 11. Verification

Release gates must cover, before any related claim advances past proposal:

- insertion/order and tie-break parity;
- stable external IDs with dense internal indices;
- snapshot/revision invalidation;
- full versus incremental generation equivalence;
- temporal half-open visibility;
- graph corruption/cycle injections;
- deterministic algorithm witnesses;
- scalar versus optimized traversal;
- multigraph/directed/weight semantics;
- resource-bound refusal;
- no mixed-generation Context Packet;
- policy refusal when graph evidence is stale or statistically inferred;
- replay from canonical events;
- negative-result retention for failed graph optimizations.

## 12. Authority boundaries

Graph systems may:

- prove exact reachability from authenticated roots;
- produce deterministic build ordering from an exact DAG;
- enforce explicitly configured graph constraints whose source and algorithm are canonical;
- provide evidence and recommendations.

Graph systems may not:

- turn centrality into authorization;
- infer guilt from anomaly/community edges;
- delete objects from an incomplete graph;
- merge transactions based only on predicted independence;
- reveal unauthorized nodes through embeddings, degrees, counts, or explanation paths;
- treat one stale generation as current because it is locally available.

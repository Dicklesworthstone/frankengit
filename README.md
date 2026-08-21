# FrankenGit

**A clean-room, pure-Rust, Git-compatible forge designed for humans, autonomous coding agents, extreme scale, and independently verifiable recovery.**

> **Status:** pre-implementation architecture and public design review. FrankenGit is not yet a usable Git server or GitHub replacement.
>
> **License status:** the current repository license is source-available, not OSI-approved open source. A genuine open-source/commercial structure must be selected before the first code release. See [`docs/LICENSING_DECISION.md`](docs/LICENSING_DECISION.md).
>
> **Normative contract:** [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md) governs identity, admission, publication, authority, cancellation, repair, and release-blocking invariants.

FrankenGit is not “GitHub rewritten in Rust.” It is a forge designed around a different center of gravity:

- **one immutable repository decision stream and one tiny conditional authority head, rather than a mutable bare repository plus a separately authoritative product database;**
- **a production implementation that is pure Rust, strictly memory-safe in first-party code, and never links or invokes C Git, `libgit2`, or another Git engine;**
- **parallel, per-core preparation and microbatched publication instead of forcing expensive work through one repository process;**
- **Git-object-aware adaptive transport, sparse semantic workspaces, typed graph fabrics, evidence-carrying agent changes, and locally reproducible releases;**
- **repair, checkpoints, indexes, policy promotion, and release publication that all follow the same body-first/root-last, anti-rollback discipline.**

The project is a synthesis of concrete machinery from Asupersync, FrankenSQLite, FrankenFS, FrankenSearch, franken_markdown, FrankenGraphDB, FrankenNetworkX, and Doodlestein Self-Releaser — with the gateway/API on fastapi_rust, projection read-models on sqlmodel_rust's FrankenSQLite backend, a familiar GitHub-like web UI (DOM-oriented pure-Rust/WASM, Leptos or Dioxus with SSR and Tailwind, native source-spanned rendering and trustless verified reads; a generated TypeScript client and React reference are the supported alternative), plus a terminal TUI (and an optional parallel terminal-style web surface) on the frankentui (ftui) kernel — combined with the object-store-native insight in Cursor’s “Git at Any Scale.” The detailed source-to-design map is in [`docs/FRANKEN_SUITE_DEEP_DIVE_SYNTHESIS.md`](docs/FRANKEN_SUITE_DEEP_DIVE_SYNTHESIS.md); the concrete defects found in the first-cut architecture and their dispositions are in [`docs/FRANKENSUITE_DEEP_AUDIT_2026-08-19.md`](docs/FRANKENSUITE_DEEP_AUDIT_2026-08-19.md).

Those product-stack choices are settled, while integration is deliberately gated on their owned sibling repositories converging to one Asupersync 0.4.x constellation and registry-resolvable FrankenSQLite dependencies. The exact runtime, cancellation, connection, retry, shutdown, and verification contract is in [`docs/ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md`](docs/ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md).

---

## TL;DR

### The problem

A conventional forge accumulates several partially authoritative systems:

- refs and objects inside mutable repository directories;
- issues, pull requests, protections, and queues inside a database;
- CI, artifacts, packages, search, graph, and notifications in separate services;
- caches and replicas with different notions of freshness;
- agents operating through human-shaped APIs and overly broad tokens;
- release systems whose “truth” is a remote workflow status and a mutable asset page.

At agent scale, the waste compounds: hundreds of workers clone or hydrate the same repository, assemble overlapping context, rerun overlapping work, produce ambiguous retries, and retain enormous derived state.

### The proposed solution

For each repository, FrankenGit defines canonical truth as:

1. immutable Git objects and immutable internal records;
2. immutable transaction seals and prepared evidence capsules;
3. an immutable sequence of `RepositoryDecisionBatch` objects;
4. one small authenticated `RepositoryAuthorityHead` selected by a linearizable conditional compare-and-swap.

A mutation becomes canonical only when the exact predecessor head is conditionally replaced. Any execution cell can prepare or attempt publication. Rendezvous routing, local caches, per-core lanes, and commit combiners make the healthy path fast but never become authority.

Everything else is rebuildable: bare repositories, packs, MIDX, bitmaps, commit graphs, FrankenSQLite read models, issue/PR tables, search/vector/graph generations, CI workspaces, dashboards, counters, and notification feeds.

---

## The architecture in one diagram

```text
Git clients / humans / agents / CI / mirrors
                    |
          pure-Rust Git/API gateways
                    |
          stateless execution cells
          /         |          \
 per-core prep   local MVCC   immutable bodies
 lanes/combiner  and caches   and segments
          \         |          /
             AuthorityStore
        conditional repository-head CAS
                    |
      immutable repository decision stream
                    |
     materializers / forge projections /
     search / typed graphs / repair / CI
```

The one strong operation is deliberately small:

```text
compare_exchange(
  repository_head_key,
  exact_predecessor_version_token,
  canonical_new_head_bytes
)
```

A backend is not trusted because it calls itself “S3-compatible.” It must pass the `AuthorityStore` conformance and fault suite, including ABA, ambiguous-response, proxy, failover, lifecycle, and version-token behavior.

The single-node profile implements the same authority interface with FrankenSQLite. Clustered deployments may use a conforming object store or a future small pure-Rust `fgit-authorityd`. Product semantics do not change with the backend.

---

## Core innovations

### 1. Repository decisions, not a database/repository split

A successful repository mutation publishes one `RepositoryCommitRecord` binding:

- exact ref effects and resulting authenticated ref root;
- exact admitted Git object closure;
- exact forge-event batch and resulting forge-position root;
- policy input, decision, and evidence roots;
- retention and outbox effects;
- conflict, verifier, and resource receipts.

A merged PR cannot reach a state where the target ref moved but the PR remains open, or vice versa. Both effects belong to one committed record and one authority-head transition.

A `RepositoryDecisionBatch` may include many ordered terminal decisions and committed records. Refusals receive decision order for audit/idempotency but do not pretend to advance source history.

### 2. Stable retry identity and immutable outcomes

A network attempt and a logical mutation are distinct. Ingress seals one canonical semantic request under one stable transaction identity. Reusing the idempotency key with different semantics fails closed.

After sealing, the transaction eventually has one terminal result:

- committed repository record; or
- canonical typed refusal.

Connection loss and cancellation are never reported as proof of non-commit. The client queries the authenticated outcome index by transaction identity.

### 3. Per-core preparation and group publication

Object validation, policy-independent analysis, graph/search work, tests, semantic effect construction, and witness generation run in parallel. Per-core append-only lanes avoid central hot locks and allocator traffic. A flat combiner:

1. gathers a bounded microbatch;
2. constructs the transaction conflict graph;
3. chooses a deterministic admissible order;
4. evaluates intents against scratch state;
5. emits target-disjoint net effects;
6. stages one decision batch and candidate head;
7. attempts one conditional head replacement.

CAS losers do not discard all expensive work. They revalidate coarse witnesses, refine them only when the expected saved retry cost exceeds bounded refinement cost, deterministically rebase safe semantic intents, and retry the same sealed transaction.

“Different refs” is not automatically independence: branch protection, merge queues, quotas, retention, policy epochs, and forge aggregates can overlap even when ref strings do not.

### 4. ATP-Git: transport the object graph, not just a file

Asupersync’s Adaptive Transport Protocol becomes FrankenGit’s native internal and aware-client transport profile. ATP-Git can use:

- exact and bounded probabilistic receiver have-sets;
- Git object/segment/pack delta plans;
- unique-byte deduplication with deterministic reconstruction;
- typed path graphs across direct, LAN, IPv6, tunnel, relay, mailbox, or other policy-approved paths;
- bounded multipath racing with loser cancellation and drain;
- swarm rarity and peer-availability scheduling;
- endgame duplicate requests;
- adaptive RaptorQ overhead and pacing;
- trust-scoped caches and peer evidence;
- complete deterministic transfer receipts.

It accelerates internal replication, agent/CI inputs, migration, repair, artifacts, and FrankenGit-aware clone/fetch. Ordinary Git clients still receive standards-compatible smart-HTTP/SSH streams from the pure-Rust Git engine. ATP-Git never changes native Git object identity or semantics.

See [`docs/ATP_GIT_PROFILE.md`](docs/ATP_GIT_PROFILE.md).

### 5. Git TreeFS: a million workspaces without a million clones

An agent or CI job opens:

- an immutable Git tree/object base pinned to an exact repository state;
- a sparse, capability-scoped copy-on-write semantic overlay;
- lazy authorized object reads;
- typed edit intents and source-span lineage;
- explicit staged, visible, and durable output epochs.

The reference interface is a direct Rust API. Sparse-directory and FrankenFS/FUSE adapters support ordinary tools. Export produces exact Git objects plus a proposed repository transaction; the workspace never gains publication authority merely because a file exists locally.

See [`docs/GIT_TREE_FS.md`](docs/GIT_TREE_FS.md).

### 6. Typed graph fabrics, not one opaque “knowledge graph”

FrankenGit maintains separate graphs for:

- commit ancestry and object reachability;
- files, symbols, calls, imports, and dependencies;
- ownership and review history;
- builds, checks, artifacts, and provenance;
- agents, tasks, capabilities, and evidence;
- object placement, failure domains, repair, and retention;
- federation and trust observations.

Exact, deterministic-derived, and statistical edges have different types and authority limits. Graph algorithms that can influence reviewer assignment, build order, context assembly, merge planning, placement, or risk declare an observable tie-break policy and emit a decision-path/complexity witness.

The algorithm palette includes reachability, SCC/condensation, dominators, bridges/articulation, shortest and k-shortest paths, matching, min-cost flow, max-flow/min-cut, topological/critical path, transitive reduction, centrality, community/k-core, and dynamic graph maintenance.

See [`docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md`](docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md).

### 7. CALM classification and obligation-typed side effects

Every operation is classified as:

- monotone/coordination-free;
- bounded commutative;
- coordinated.

Append-only immutable objects, evidence, and some social events can propagate without global coordination. Refs, authorization, retention, billing, merge queues, and destructive transitions require ordered authority.

Every side effect that acquires responsibility creates an obligation: object placement, authority-CAS attempt, secret lease, runner allocation, outbox delivery, workspace output, repair, context fetch, or billing reserve. An obligation must commit, abort, transfer, or drain before its Asupersync region closes. “Fire and forget” is not a valid state.

See [`docs/CALM_AND_OBLIGATIONS.md`](docs/CALM_AND_OBLIGATIONS.md).

### 8. Repair is an authority-governed mutation

RaptorQ and replicas may reconstruct bytes, but decoder success is not acceptance. Recovered bytes must verify their original length, digest, internal/Git/LFS/package identity, manifest/Merkle closure, tenant namespace, and structural codec.

A verified repair then revalidates the current placement/retention authority before publishing. A repair prepared against stale state cannot overwrite a newer placement or resurrect deleted data.

RaptorQ applies only to registered immutable classes where coding wins against simpler replicas. It is not consensus, cryptographic integrity, authorization, or current metadata.

See [`docs/RAPTORQ_PERMEATION_MAP.md`](docs/RAPTORQ_PERMEATION_MAP.md).

### 9. Identity-bound conformal/e-process policy

Conformal bounds, e-processes/e-martingales, no-regret controllers, off-policy evaluation, changepoint detection, Beta posteriors, and Lyapunov/progress governors may adapt bounded operational policies such as:

- ATP path/block/repair parameters;
- cache and prefetch budgets;
- scrub/repair priority;
- search/rerank/context budgets;
- witness-refinement and retry policy;
- reversible admission throttles;
- canary escalation and resource allocation.

The evidence identity includes metric, population, selection rule, exact sequence window, regime epoch, candidate/fallback policy, assumptions, and numeric/toolchain fingerprint. Insufficient support or regime shift selects the deterministic fallback.

Statistics never decide Git identity, signatures, authorization, ref atomicity, retention roots, whether committed data exists, or irreversible punishment.

### 10. Local, root-last releases through DSR

FrankenGit does not depend on GitHub-hosted Actions. Repository-owned commands define verification. Workflow YAML is a thin portable adapter executed locally through Doodlestein Self-Releaser/`act`, with macOS and Windows lanes on registered native hosts.

A release is authoritative only after the complete target matrix, exact asset set, checksum sidecars, SBOM, provenance, signatures, installer/extraction/version/smoke tests, and verification evidence pass. The signed local release manifest is published last. GitHub Releases is reconciled as a distribution mirror.

See [`docs/LOCAL_VERIFICATION_AND_RELEASE_PIPELINE.md`](docs/LOCAL_VERIFICATION_AND_RELEASE_PIPELINE.md).

---

## Beyond parity: what the architecture unlocks

The core innovations above make FrankenGit a correct, economical forge. The same primitives — one authenticated head, an immutable decision stream, content-addressed evidence, and pinned build capsules — also unlock five capabilities no incumbent forge can copy without rebuilding its storage layer. All five are proposal-class designs (see the claim lattice); each has a comprehensive-plan section and a backlog slice.

### Verifiable reads, not just verifiable writes

Every FrankenGit read already derives from an authenticated `RepositoryAuthorityHead`. The verified-read protocol goes all the way: any ref, object-membership, PR-state, or outcome answer can be served with a Merkle inclusion proof connecting it to a head the client verifies independently. A verifying client trusts only the head chain — not the serving cell, mirror, or CDN. That makes FrankenGit the first forge with trustless read serving: to verifying clients, mirrors and caches become cryptographically incapable of lying, because a wrong answer fails proof verification instead of being believed. The authenticated roots already exist in the head schema; this is an API surface, not new truth machinery. (Plan §18.7, backlog FG-037.)

### Time travel as a product primitive

Because canonical state is an immutable decision stream, “the entire forge at decision N” is a well-defined object — not a reconstruction heuristic over mutable tables. `fg at <decision>` opens a complete read-only forge snapshot: refs, pull requests, reviews, the policy epoch, and CI receipts exactly as they stood. Bisection generalizes from commits to forge state — binary-search the decision sequence for the transition that changed a policy outcome, a review requirement, or a CI result. Incumbent forges cannot offer this without rebuilding storage around an immutable stream. (Plan §31.8, backlog FG-038.)

### The evidence economy

Evidence-Carrying Changes and check receipts are content-addressed and self-describing, so they can travel between organizations with their claims intact. A dependency bump can arrive carrying its upstream’s replayable test evidence and provenance, verified locally under the same claim-class rules the local repository enforces — imported evidence can tighten but never bypass local checks, and a claim never upgrades in transit. This turns the claim lattice from an internal discipline into a network protocol, and it compounds: organizations that publish strong evidence make their artifacts cheaper for everyone downstream to adopt safely. (Plan §34.8, backlog FG-039.)

### Deterministic build outputs as derived state

FrankenGit already treats packs and indexes as “compute once, share by profile identity.” CI outputs with fully pinned `BuildInputCapsule`s are the same shape: when a workflow step is declared deterministic, its outputs become trust-scoped, content-addressed derived state keyed by exact capsule identity. A global build cache — remote-build-cache economics in the style of Bazel — falls out of machinery the CI protocol already requires, with the same trust-domain isolation that protects ordinary caches from fork poisoning. (Plan §29.8, backlog FG-040.)

### Formal verification of the tiny core

The whole design concentrates trust into a deliberately small ordered residue: seals, terminal outcomes, batch admission, one head compare-and-swap, root-last publication. That core is small enough for actual mechanized proof, not just bounded model checking — theorems like terminal-outcome uniqueness, head-chain continuity, and anti-rollback under interrupted publication, machine-checked against the same executable reference model the differential tests use. The top of the claim lattice (`proof`, `invariant`) becomes occupied, not just defined. (Plan §40.8, backlog FG-041.)

---

## Pure Rust and dependency constitution

The production implementation is pure Rust on Rust 2024 with a dated current nightly pin.

Non-negotiable rules:

- every first-party crate uses `#![forbid(unsafe_code)]`;
- no C/C++ FFI or linked native Git/crypto/network/compression/database engine;
- no production subprocess invocation of `git` or another VCS engine;
- upstream Git is a separately executed, pinned differential oracle only;
- Asupersync is the sole async runtime;
- FrankenSuite crates are preferred for existing mechanisms;
- external crates are exceptional, fundamental, pure-Rust, registry-approved, and dependency-evidence tracked;
- no Tokio, generic ORM/database/framework stack, opaque distributed system, or alternate runtime in production;
- no empty crate scaffolds or in-memory maps presented as final durable abstractions.

World-class performance is expected from algorithmic work reduction, safe portable SIMD, dense layouts, bounded arenas, per-core lanes, immutable sharing, batching, and cache-aware data structures—not raw pointers or hidden C fallbacks.

See [`docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md`](docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md) and [`registries/dependency_policy.tsv`](registries/dependency_policy.tsv).

---

## Git compatibility is constitutional

FrankenGit preserves ordinary Git where it claims support:

- native SHA-1 and SHA-256 object identity as distinct typed domains;
- exact object framing, pack/delta/DEFLATE, pkt-line, sideband, upload-pack, and receive-pack;
- protocol-accurate fetch/clone and push terminology;
- atomic/non-atomic push semantics;
- shallow/partial/promisor operation;
- tags, notes, submodules, signed pushes, LFS, commit graphs, bitmaps, MIDX, bundles, and migration subsets according to explicit registry rows;
- observable iteration order, tie-breaks, error/refusal behavior, and resource limits.

FrankenGit does **not** claim a fictional standardized “protocol v2 push” command. Fetch and push are tracked as separate services/capability matrices.

Compatibility is differential against pinned upstream Git versions and source-derived/adversarial corpora. “Clone worked once” is not evidence of compatibility.

See [`docs/GIT_COMPATIBILITY_MATRIX.md`](docs/GIT_COMPATIBILITY_MATRIX.md).

---

## Agent-native collaboration

An agent operates through a signed `IntentRun` sponsored by a human or service principal. Authority is attenuated by repository, ref, path, object/secret/effect class, network domain, time, compute, storage, transfer, token, and monetary budget.

The run receives provenance-preserving `ContextPacket` objects and a TreeFS workspace. Network, secret, CI, publication, package, and external-service effects go through a non-textual capability broker and return immutable receipts.

An `EvidenceCarryingChange` binds:

- exact base authority state and proposed Git object closure;
- workspace intents and net effect;
- context identities, transforms, ranks, and omissions;
- tests/checks/build/tool/effect receipts;
- claimed invariants and explicit non-claims;
- graph/conflict/complexity witnesses;
- verifier attestations and independence class;
- requested publication/effects and budgets.

Prompt injection inside repository or retrieved text cannot widen capabilities, reveal secrets, suppress mandatory verification, approve itself, or alter retention/disclosure policy.

See [`docs/AGENT_PROTOCOL.md`](docs/AGENT_PROTOCOL.md).

---

## Deployment profiles

### Embedded

- one binary/node;
- FrankenSQLite authority profile and local immutable object fabric;
- same canonical formats and transaction semantics as clustered operation;
- local TreeFS/materializations/search/graph;
- portable capsule backup/export.

### Self-hosted cluster

- stateless execution cells;
- conforming conditional authority backend or future `fgit-authorityd`;
- policy-driven immutable placement;
- active-active reads/materializations/projections;
- any eligible cell may attempt canonical publication;
- no repository “home cell” correctness dependency.

### FrankenGit.com

Adds managed global placement, quotas/accounting, SSO/SCIM, audit/compliance, hosted runners, premium retention/recovery, abuse controls, support, and measured SLOs. It must not fork canonical formats or make self-hosted correctness depend on proprietary services.

### Offline/local-first

Exact capsules, immutable bundles, local refs/forge events, and evidence can be exchanged later. Remote protected refs become observations or proposed transactions, never CRDT last-writer-wins authority.

---

## Verification doctrine

The project distinguishes:

```text
invariant > proof > bounded_model > statistical > slo > benchmark
```

Weaker evidence cannot justify a stronger claim. Every public claim names scope, evidence, assumptions, current source/toolchain/profile, and expiry/revalidation rule.

Replay completeness is explicit:

- replayable;
- structural replay;
- verifiable when named external artifacts are supplied;
- audit only.

Failed hypotheses, rejected architectures, performance regressions, and cutover failures live in an append-only negative-evidence ledger so future agents do not repeat them.

### Checked claim status

This block is generated by `fgit-registry-check claims-status`. The checker
refuses a stale block and automatically demotes a verified row when a committed
artifact no longer matches its exact digest.

<!-- franken-claims-status:begin -->
| Claim | Class | Effective status | Scope | Readiness wording |
| --- | --- | --- | --- | --- |
| CLM-001 | CLAIM-006 | verified | claim-artifact-identity-binding | artifact-change-demotes-this-narrow-claim |
<!-- franken-claims-status:end -->

The initial local commands are:

```bash
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
./scripts/verify.sh full
./scripts/verify.sh release
```

The documentation/constitution/fast bootstrap lanes exist today. `full` and `release` deliberately return a typed exit-3 refusal until real conformance, fault, native-target, and artifact gates land; a dormant gate never reports success.

See [`VERIFY_SPEC.md`](VERIFY_SPEC.md) and [`docs/NEGATIVE_EVIDENCE_LEDGER.md`](docs/NEGATIVE_EVIDENCE_LEDGER.md).

---

## Planned workspace

Crates appear only with a real final-abstraction slice. The prospective strict DAG contains:

- foundation: typed IDs/refusals, canonical codec, claims, evidence, resources, registry checker;
- Git/storage primitives: objects, packs, wire, authority, object fabric, RaptorQ, ATP-Git, TreeFS, crypto policy;
- canonical engines: reference model, transaction kernel, chronicle, policy, forge events, GC, repair, materialization, generation authority;
- derived systems: search, typed graphs, document lineage, agents, CI protocol, packages, projections;
- products/adapters: gateway, API, CLI, node, runner, operations, browser/WASM.

The repository currently contains only the constitutional bootstrap checker rather than dozens of empty placeholder crates.

See the full map in [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md`](COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md#43-prospective-implementation-architecture).

---

## Repository map

| Document | Purpose |
|---|---|
| [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md`](COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md) | 53-section v3 product, system, and execution plan |
| [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md) | Authoritative identity, authority, transaction, repair, and release laws |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Compact component and data-flow map |
| [`docs/OBJECT_STORE_DECISION_LOG.md`](docs/OBJECT_STORE_DECISION_LOG.md) | Immutable decision batches and conditional authority head |
| [`docs/ATP_GIT_PROFILE.md`](docs/ATP_GIT_PROFILE.md) | Git-object-aware adaptive transfer profile |
| [`docs/GIT_TREE_FS.md`](docs/GIT_TREE_FS.md) | Sparse semantic COW workspace design |
| [`docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md`](docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md) | Typed repository graph fabrics and algorithms |
| [`docs/CALM_AND_OBLIGATIONS.md`](docs/CALM_AND_OBLIGATIONS.md) | Coordination classes and effect ownership |
| [`docs/FRANKEN_SUITE_DEEP_DIVE_SYNTHESIS.md`](docs/FRANKEN_SUITE_DEEP_DIVE_SYNTHESIS.md) | Mechanism-by-mechanism inheritance from source projects |
| [`docs/FRANKENSUITE_DEEP_AUDIT_2026-08-19.md`](docs/FRANKENSUITE_DEEP_AUDIT_2026-08-19.md) | Defects found in the first-cut architecture and v3 dispositions |
| [`docs/FRESH_EYES_AUDIT_2026-08-19.md`](docs/FRESH_EYES_AUDIT_2026-08-19.md) | Independent fresh-eyes audit of the pre-revision repository |
| [`docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md`](docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md) | Pure-Rust, safe-only, closed-dependency rules |
| [`VERIFY_SPEC.md`](VERIFY_SPEC.md) | Evidence classes, test/fault/security/performance/release gates |
| [`SECURITY_THREAT_MODEL.md`](SECURITY_THREAT_MODEL.md) | Adversaries, trust boundaries, attacks, controls, residual risks |
| [`docs/RAPTORQ_PERMEATION_MAP.md`](docs/RAPTORQ_PERMEATION_MAP.md) | Eligible immutable classes, coding profiles, repair acceptance |
| [`docs/GIT_COMPATIBILITY_MATRIX.md`](docs/GIT_COMPATIBILITY_MATRIX.md) | Decomposed Git/forge compatibility targets |
| [`docs/AGENT_PROTOCOL.md`](docs/AGENT_PROTOCOL.md) | Intent Runs, Context Packets, effects, evidence, cancellation |
| [`docs/LOCAL_VERIFICATION_AND_RELEASE_PIPELINE.md`](docs/LOCAL_VERIFICATION_AND_RELEASE_PIPELINE.md) | DSR/local lanes and root-last release manifest |
| [`docs/INITIAL_ISSUE_BACKLOG.md`](docs/INITIAL_ISSUE_BACKLOG.md) | Dependency-ordered first executable slices |
| [`docs/RESEARCH_PROVENANCE.md`](docs/RESEARCH_PROVENANCE.md) | Exact source lineage and adaptations |
| [`AGENTS.md`](AGENTS.md) | Human and coding-agent contribution contract |

Machine-validated registries live under [`registries/`](registries/README.md).

---

## Near-term execution

1. Freeze constitutions, registries, terminology, canonical primitives, and goldens.
2. Implement the std-only registry/constitution checker and local evidence pack.
3. Build the pure reference transaction/head state machine and faultable authority store.
4. Add the FrankenSQLite embedded authority profile and prove equivalence.
5. Implement exact Git object framing and pack/delta quarantine in pure Rust.
6. Complete one ordinary upload-pack/receive-pack vertical slice.
7. Add immutable segments and the first ATP-Git exact have/delta/dedupe path.
8. Prototype per-core preparation and flat combining against the reference model.
9. Implement TreeFS direct API and export-to-Git-intent.
10. Expand only when the corresponding conformance/fault/security evidence closes.

The phase plan is in [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md`](COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md#44-delivery-roadmap).

---

## What FrankenGit is not

- not a new incompatible VCS;
- not a wrapper around C Git or `libgit2`;
- not a mutable bare repository designated as canonical truth;
- not a repository-primary or home-cell architecture;
- not a relational forge database reconciled asynchronously with Git refs;
- not asynchronous multi-master ref mutation;
- not RaptorQ used as consensus, hashing, or authorization;
- not graph/model output used as hidden policy authority;
- not agent text interpreted as capabilities;
- not GitHub-hosted Actions used as release truth;
- not yet implemented, benchmarked, production-ready, or honestly describable as OSI open source under the current license.

---

## License

The current license is MIT-shaped source availability with an OpenAI/Anthropic restriction. That restriction means it is **not** an OSI-approved open-source license. The project intends to decide a genuine open-source core/client/protocol plus commercial hosted model before implementation release. Until then, public wording must remain exact.

---

## Public design review

The architecture is intentionally public before implementation so contradictions can be found while they are cheap. Useful review focuses on concrete invariants, counterexamples, protocol compatibility, authority-store semantics, resource/security bounds, graph/transport algorithms, dependency closure, and executable evidence—not on whether the plan sounds ambitious.

# FrankenGit

**A clean-room, pure-Rust, Git-compatible forge designed for humans, autonomous coding agents, extreme scale, and independently verifiable recovery.**

> **Status:** active implementation and pre-release integration (spec-first design, transitioning from pre-implementation). FrankenGit now contains substantial final-abstraction slices and a narrow executable one-node boundary, but it is not yet a general-purpose Git server, a production-ready forge, or a GitHub replacement.
>
> **License:** `LicenseRef-MIT-OpenAI-Anthropic-Rider` — the MIT licence plus the OpenAI/Anthropic rider. Decision D14 was resolved by the repository owner on 2026-08-23.
>
> Because that rider withholds rights from named parties, the licence is **not** OSI-approved open source; the repository is source-available and must be described that way. See [`docs/LICENSING_DECISION.md`](docs/LICENSING_DECISION.md).
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

## Current one-node integration boundary

The checked-in `fgit-cli` library contains a narrow, configuration-free one-node
surface for exercising the same authority, admission, and object-selection
abstractions the finished system will use. It does not consult a configuration
file: callers supply the storage directory, tenant ID, and repository ID
explicitly. The final `fg` binary exposes this surface: the `CliOutcome::At`
rendering arm (missing at the 2026-08-25 snapshot, repaired in `0f6a81b7`) is
landed, and `cargo check -p fgit-cli --all-targets` passes at the current
revision. The surface remains an implementation and conformance boundary
rather than a complete server profile, and it will not by itself prove that a
selected durability epoch or broader compatibility matrix has completed.

```bash
cargo run -p fgit-cli -- init ./fgit-data \
  11111111111111111111111111111111 \
  22222222222222222222222222222222

cargo run -p fgit-cli -- doctor ./fgit-data \
  11111111111111111111111111111111 \
  22222222222222222222222222222222
```

`init` creates or re-authenticates the empty canonical authority head.
`import` verifies a bounded local object source composed of loose objects and
checksum-bound idx-v2/pack-v2 pairs, then publishes its source refs through the
sealed admission/RCR/head-CAS path. The pack-import focused integration target
is checked in and all 17 cases — the original 14 plus the resource-bound
expansion — pass in a local run at `e296eb3f`; orchestrated batch
verification remains the revision-bound gate. The verified-read defect that
previously kept the wider node package gate red was fixed in `7ccaf8b`
(layout-selected ref roots), and the whole `fgit-node` target set passes
locally at that revision. `doctor` authenticates the head and can re-verify
one explicitly named native object; it is not yet a complete replay, fabric,
repair, or causal-diagnosis suite. `export` writes an authority-selected pack
to a previously absent path. One emitted pack is bounded by the documented
write-side envelope (`--pack-max-expanded-mib`; 128 MiB expanded by default),
and an over-envelope clone receives a diagnosable Fatal sideband refusal
rather than an unexplained early EOF.

`serve` accepts a bounded raw git-daemon service run, drains every admitted
session, and reports accepted/completed/refused counts before it exits. The
upload-pack lane is enabled by default. The receive-pack lane is available only
when the operator explicitly supplies `--receive-principal
<principal-id-hex>`; without that binding, a push is refused and publishes
nothing. Receive-pack reuses the bounded framing, quarantine, validation,
policy, sealed-admission, and exact-predecessor authority-CAS path rather than
making socket-local refs authoritative. Its compatibility default remains one
session and one in-flight client; callers explicitly opt into larger non-zero
`--max-sessions` and `--max-in-flight` bounds. The bring-up transcript below
deliberately names the one-session bound. One pushed pack is bounded by the
documented receive session envelope — size ceilings
(`--receive-max-input-mib`, `--receive-max-expanded-mib`) and a
work-proportional session budget, `base + admitted bytes x rate` clamped to a
hard ceiling (`--session-timeout-secs`, `--session-secs-per-mib`,
`--session-max-extension-secs`) — and an over-budget verdict is delivered
through report-status, never a silent hangup (see
[`docs/GIT_COMPATIBILITY_MATRIX.md`](docs/GIT_COMPATIBILITY_MATRIX.md)).
Ingress time cannot consume the independent server-work budget that starts
after the pack trailer. Smart HTTP, production SSH, and a native API are still
absent. Ordinary production push over authenticated transports remains
unsupported; the raw git-daemon receive lane is the composition slice the
`first_push.sh` E2E suite exercises with a real `git` client. No command
treats local object placement, a routing hint, or a connection-local ref map
as canonical state.

[`scripts/one_node_bringup.sh`](scripts/one_node_bringup.sh) exercises the
intended empty-repository lifecycle end to end — verified at `be60ac19`,
completing in about 40 s — with a new empty storage directory, an unused
loopback address, and an absent export path:

```bash
scripts/one_node_bringup.sh "$(mktemp -d)" \
  11111111111111111111111111111111 \
  22222222222222222222222222222222 \
  127.0.0.1:9418 \
  /tmp/frankengit-one-node.pack
```

The script records the exact `fg init` → `fg doctor` → one explicitly bounded
`fg serve` session → `fg export` commands and their observed output in
`bring-up.transcript` below the supplied storage directory. Set `FG_BIN` to a
prebuilt `fg` binary to avoid its default `cargo run -p fgit-cli --` launcher.
It intentionally exercises an empty repository and does not claim the full Git
compatibility matrix. The non-empty clone campaign is pinned by
`first_clone.sh`; the raw receive campaign is pinned separately by
`first_push.sh`, including the disabled-by-default refusal twin, initial and
incremental pushes, retry behavior, and clone-back identity.

### Repository-side agent triage

The checked-in `scripts/bv_compat.sh` launcher is an operational compatibility
surface, not part of the future `fgit-agent` product plane. It gives pinned
`bv` versions a complete read-only graph by projecting the repository-owned
`batch_pending` state to non-claimable `review` in a private temporary file,
then verifies that the authoritative tracker hash did not change. Graph scores
remain advisory: an agent may claim a bead only when the exact ID appears in
`br ready --unassigned --no-db --json`.

### Reality snapshot: 2026-09-04

The implementation has moved well beyond an architecture-only repository, but
most of the product vision remains ahead:

- The canonical core is real code: typed SHA-1/SHA-256 identities, canonical
  bodies, transaction seals, intent/effect folding, immutable decision batches,
  terminal outcomes, authenticated heads, and exact-predecessor CAS publication
  have reference, laboratory, and durable embedded slices.
- The clean-room Git substrate now includes bounded object parsing, owned
  DEFLATE, pack/delta read and write paths, pkt-line, upload-pack, receive-pack
  parsing, quarantine/admission, authority-selected pack materialization, local
  loose-plus-idx/pack source reconstruction, and bounded raw git-daemon
  upload-pack plus explicitly enabled receive-pack composition. All 17 cases
  of the focused pack-import target — including the
  resource-bound expansion — and the full `fgit-node` test set pass in local
  runs at `e296eb3f` (the verified-read defect named by the 2026-08-25
  snapshot was fixed in `7ccaf8b`); orchestrated batch verification remains
  the revision-bound gate. Those parts do not yet amount to a completed Git
  compatibility matrix.
- Object fabric, ATP-Git, TreeFS, RaptorQ repair, verified-read proofs, forge
  events and merge computation, graph algorithms, agent/evidence protocols,
  hostile-runner policy, recovery, and release attempts have bounded vertical
  slices. Several are internal libraries or refusal-bounded compositions rather
  than deployable product surfaces.
- Raw git-daemon receive-pack/push has landed behind an explicit operator
  principal, but smart HTTP, production SSH, the native REST/API gateway,
  projections, search, issues/notifications, the web UI, the TUI, MCP,
  production hostile-execution isolation, and the actual release publication
  path are not complete. The sealed-merge admission path through the real
  store+projection reaches head CAS correctly at HEAD `1b8561c1`
  (`fgit-admission/tests/merge_admission_race.rs` 6/6, exactly-one-winner
  holds); the remaining half of FG-029a is routing admitted merge's
  forge events through the existing outbox — neither code path nor a
  dedicated test exists for that half today, and the bead is in flight
  (`frankengit-asa3`).
- The position-addressed forge snapshot projector and the `fg at` command
  have landed: parser, projection, binary rendering, the second-endpoint
  diff subcommand, the continuous-consistency check on both endpoints
  (`verify_continuous_consistency` at fgit-cli/src/lib.rs:1299 and 1374),
  and the authenticated decision-history read for non-current positions
  (`fgit-node::snapshot_history_in`, 7dc8b4e8). The 6 `fg at` integration
  tests pass at HEAD `fe3bb04a`, including `fg_at_diff_projects_both_requested_endpoints`
  and the `TargetAheadOfAuthority` refusal for a decision index the
  authority has not reached. The remaining gap is an end-to-end test
  over non-empty durable history: no test today populates a historical
  decision and then projects across it, so the historical path is
  code-anchored but not test-anchored for a real batch.
- The dependency graph tracks these gaps, including external convergence gates
  for fastapi_rust, sqlmodel/FrankenSQLite, and FrankenTUI. The smart-HTTP gap is
  tracked explicitly by FG-105 rather than being hidden inside raw-socket or
  REST work.
- The constitution lane currently reports exactly 8 errors, all one root
  cause: `sqlmodel-core` 0.4.x requests asupersync's `test-internals` feature
  (which vendors the `visibility` proc-macro) in a *normal* dependency, so
  feature unification arms the derive guard against every first-party manifest
  that declares asupersync. The fix is an owned-sibling republish, specified in
  blocked bead `frankengit-sqlmodel-test-internals-defect-o7qc` and recorded as
  NEG-032; the 42 pre-admission registry-row drift errors that shared the lane
  were corrected at `60e57e5e`.

The claims registry remains the public proof boundary. Its verified rows cover
narrow artifact identity and contained Lean-model theorems; they do not prove
general Git compatibility, Rust refinement of the complete implementation,
forge completeness, multi-region readiness, performance leadership, or release
readiness. Closed beads, crate count, test presence, and a successful local
scenario will not be treated as substitutes for revision-bound evidence.

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

The core innovations above are intended to make FrankenGit a correct,
economical forge. The same primitives — one authenticated head, an immutable
decision stream, content-addressed evidence, and pinned build capsules — will
also unlock five capabilities that are difficult to graft onto a mutable forge.
The repository contains bounded internal slices for several of them, but none
is yet a shipped end-user capability. Each will remain scoped by the claim
lattice, its comprehensive-plan section, and its backlog work.

### Verifiable reads, not just verifiable writes

Every supported FrankenGit read will derive from an authenticated
`RepositoryAuthorityHead`. The verified-read protocol will let a ref,
object-membership, PR-state, or outcome answer carry a Merkle proof connecting
it to a head the client verifies independently. The authenticated roots and
bounded proof/verifier slices exist; public API integration, complete proof
coverage, mirror/CDN serving, and product UX do not. When those surfaces land, a
verifying client will trust the head chain rather than the serving cell. (Plan
§18.7, backlog FG-037.)

### Time travel as a product primitive

Because canonical state will remain an immutable decision stream, “the entire
forge at decision N” will be a well-defined object rather than a reconstruction
heuristic over mutable tables. `fg at <decision>` will open a complete read-only
forge snapshot, and bisection will generalize from commits to forge state. A
bounded in-memory projector and library-level command parser/report surface now
exist, but authority-history loading, checkpoint use in the production call
path, two-ended diff projection, continuous-consistency enforcement, binary
rendering, and non-empty durable CLI evidence are still missing. No finished
time-travel CLI experience exists yet. (Plan §31.8, backlog FG-038.)

### The evidence economy

Evidence-Carrying Changes and check receipts will be content-addressed and
self-describing so they can travel between organizations without silently
upgrading their claims. Schema, signing, import-policy, and adversarial slices
exist, but no deployed cross-organization exchange service exists. Imported
evidence will be allowed to tighten local checks and will never bypass them.
(Plan §34.8, backlog FG-039.)

### Deterministic build outputs as derived state

FrankenGit will treat deterministic CI outputs like other profile-identified
derived artifacts: trust-scoped, content-addressed, and keyed by the exact
`BuildInputCapsule`. Internal reuse and poisoning-evidence slices exist, while
the production workflow coordinator, hostile-execution substrate, and deployed
cache service remain incomplete. (Plan §29.8, backlog FG-040.)

### Formal verification of the tiny core

The design concentrates trust into a deliberately small ordered residue: seals,
terminal outcomes, batch admission, one head compare-and-swap, and root-last
publication. Contained Lean theorems now cover named properties under explicit
boundary assumptions, as recorded in the generated claim table below. They are
not a proof of the production Rust implementation: the refinement bridge still
has uncovered histories and no claim may cross that boundary without matching
evidence. (Plan §40.8, backlog FG-041.)

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
| CLM-002 | CLAIM-002 | verified | fg041-lean-theorem:terminal_outcome_is_unique | machine-checked-within-the-contained-lean-model-under-three-named-boundary-assumptions-only |
| CLM-003 | CLAIM-002 | verified | fg041-lean-theorem:ref_and_forge_visibility_is_atomic | machine-checked-within-the-contained-lean-model-under-three-named-boundary-assumptions-only |
| CLM-004 | CLAIM-002 | verified | fg041-lean-theorems:accepted_publish_is_continuous,head_chain_is_continuous_and_monotone,interrupted_publication_is_anti_rollback | machine-checked-within-the-contained-lean-model-under-three-named-boundary-assumptions-only |
| CLM-005 | CLAIM-002 | verified | fg041-lean-theorems:unsealed_decision_is_not_fabricated,crash_retry_does_not_lose_or_fabricate_decision | machine-checked-within-the-contained-lean-model-under-three-named-boundary-assumptions-only |
| CLM-006 | CLAIM-006 | implemented | fg036c-multicell-read-admission-storage-and-capacity-benchmark | reproducible-benchmark-over-one-named-single-host-configuration-only-with-exact-counts-for-storage-and-admission-and-noise-floor-gated-timings |
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

No invocation is evidence for a later revision. A green local crate test, a
dirty-worktree lane, a `batch_pending` bead, or an older replay artifact will not
be described as proof that current `main` is verified. The orchestrated batch
gate and the generated claim registry will remain the revision-bound sources of
truth.

See [`VERIFY_SPEC.md`](VERIFY_SPEC.md) and [`docs/NEGATIVE_EVIDENCE_LEDGER.md`](docs/NEGATIVE_EVIDENCE_LEDGER.md).

---

## Workspace progress and planned expansion

Crates appear only with a real final-abstraction slice. The prospective strict DAG contains:

- foundation: typed IDs/refusals, canonical codec, claims, evidence, resources, registry checker;
- Git/storage primitives: objects, packs, wire, authority, object fabric, RaptorQ, ATP-Git, TreeFS, crypto policy;
- canonical engines: reference model, transaction kernel, chronicle, policy, forge events, GC, repair, materialization, generation authority;
- derived systems: search, typed graphs, document lineage, agents, CI protocol, packages, projections;
- products/adapters: gateway, API, CLI, node, runner, operations, browser/WASM.

The repository now contains dozens of first-party `fgit-*` crates plus the
constitutional registry checker. Implemented crate-level slices include the
foundation, Git/storage, transaction/chronicle, embedded authority, object
fabric, TreeFS, repair, statistics, graph, forge, identity/policy, agent,
runner, release, node, and CLI layers. A crate being present means only that its
bounded final-abstraction slice exists; it does not mean the complete subsystem
or its product integration is ready. Search, projection, gateway/API, web, TUI,
operations, package-registry, and several hosted-service surfaces will still
need their owning implementation and evidence slices.

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

The next integration work will prioritize capability gaps rather than crate
count:

1. The raw git-daemon receive-pack slice will be extended into smart HTTP and
   production SSH, while the pinned-client compatibility campaign grows its
   restart, fault, and larger-repository evidence without weakening finite
   resource bounds.
2. The snapshot engine will be connected to authenticated decision/capsule
   history, project both requested diff endpoints, enforce latest-state
   consistency, and render through the actual `fg` binary before `fg at` is
   described as a product capability.
3. Forge merges will move from real computation plus an incomplete durable
   composition to the same asynchronous materialization and exactly-one-head-CAS
   path used by admitted receive operations.
4. Identity and policy will be wired into receive, merge, transport, and
   disclosure boundaries before broader multi-tenant surfaces open.
5. fastapi_rust, sqlmodel/FrankenSQLite, and FrankenTUI will converge on the one
   runtime/dependency constellation before smart HTTP, native REST,
   projections/search, web, and TUI product layers are admitted.
6. Workflow coordination and production hostile-execution isolation will land
   before CI is described as deployable; release publication will remain
   refused until the full/release gates and native target matrix are real.
7. Multi-cell, repair, verified-read, performance, and hosted-service claims
   will expand only from revision-bound conformance, fault, security, and
   economics evidence.

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
- not yet a complete network push service, smart-HTTP/SSH forge, native API,
  hosted multi-region service, or releasable product;
- not yet supported by evidence broad enough to claim general Git
  compatibility, performance leadership, production readiness, or complete
  Rust-level formal verification;
- not honestly describable as OSI open source under the current license (D14
  resolved it as `LicenseRef-MIT-OpenAI-Anthropic-Rider`, whose OSI marker is
  `no`).

---

## License

The license is `LicenseRef-MIT-OpenAI-Anthropic-Rider`: the MIT licence together with the OpenAI/Anthropic rider, recorded as decision D14 by the repository owner on 2026-08-23. The full text is in [`LICENSE`](LICENSE).

The rider withholds all rights from OpenAI, Anthropic, their affiliates, and anyone acting on their behalf. Because the Open Source Definition forbids discriminating against persons or groups, these terms are **not** an OSI-approved open-source license, and the repository is described as source-available. Public wording must remain exact: name the license, and do not call it open source while the rider stands.

---

## Public design review

The architecture and its growing implementation are intentionally public so
contradictions can be found before they harden into product semantics. Useful
review will continue to focus on concrete invariants, counterexamples, protocol
compatibility, authority-store semantics, resource/security bounds,
graph/transport algorithms, dependency closure, and executable evidence—not on
whether the plan sounds ambitious or the repository contains many files.

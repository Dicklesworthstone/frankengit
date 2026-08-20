# FrankenGit Initial Public Issue Backlog

**Status:** proposed G0–G6 dependency graph (granular truth: the bead graph in `.beads/`)  
**Last updated:** 2026-08-20  
**Rule:** an issue closes only with its named evidence artifact; source existence alone is not completion.

This backlog implements the v3 object-store decision-log architecture in final-abstraction vertical slices. It intentionally begins with identities, reference models, authority semantics, and pure-Rust Git conformance rather than UI scaffolding. Empty crates, placeholder traits disconnected from a runnable slice, and foreign-Git production fallbacks are prohibited by [`AGENTS.md`](../AGENTS.md).

Suggested labels:

- areas: `truth`, `git`, `object-fabric`, `concurrency`, `runtime`, `transport`, `workspace`, `forge`, `agent`, `graph`, `search`, `repair`, `security`, `verification`, `release`;
- types: `spec`, `model`, `implementation`, `conformance`, `fault`, `benchmark`, `counterexample`;
- gates: `G0`, `G1`, `G2`, `G3`, `G4`, `G5`, `G6`;
- risk: `critical`, `high`, `medium`.

## Dependency map

```text
FG-001 constitution + registries
  ├─ FG-002 canonical codec and IDs
  │    ├─ FG-003 reference state machine
  │    ├─ FG-004 AuthorityStore contract
  │    │    ├─ FG-005 embedded FrankenSQLite authority profile
  │    │    └─ FG-006 object-store authority conformance profile
  │    ├─ FG-007 transaction seal/outcome
  │    ├─ FG-008 intent/effect normal form
  │    ├─ FG-009 decision batch + authority head
  │    └─ FG-010 checkpoint/capsule formats
  ├─ FG-011 Asupersync kernel profile
  │    ├─ FG-012 obligation/effect primitives
  │    ├─ FG-013 deterministic Lab + DPOR harness
  │    └─ FG-014 per-core preparation + flat combiner
  ├─ FG-015 pure-Rust Git object core
  │    ├─ FG-016 pure-Rust pack reader
  │    ├─ FG-017 pure-Rust pack writer
  │    ├─ FG-018 upload-pack
  │    └─ FG-019 receive-pack/quarantine
  ├─ FG-020 object envelope + microsegment
  │    ├─ FG-021 object fabric/location/retention
  │    ├─ FG-022 ATP-Git delta/dedupe profile
  │    ├─ FG-023 ATP-Git path/swarm profile
  │    └─ FG-024 first RaptorQ durability class
  ├─ FG-025 witness refinement/conflict certificates
  ├─ FG-026 TreeFS workspace core
  └─ FG-027 source-spanned document/diff core

FG-003 + FG-004..010 + FG-014 + FG-019 + FG-021 + FG-025
  └─ FG-028 one-node end-to-end clone/fetch/push slice

FG-028
  ├─ FG-029 canonical forge events + atomic PR merge
  ├─ FG-030 agent Intent Run/effect/evidence slice
  ├─ FG-031 graph fabric + deterministic witnesses
  ├─ FG-032 progressive search/generation authority
  ├─ FG-033 checkpoint/restore/repair/GC slice
  ├─ FG-034 hostile CI receipt slice
  └─ FG-035 local DSR release evidence

FG-029..035
  └─ FG-036 distributed object-store deployment and failover campaign

FG-028 (+ named prerequisites per issue)
  ├─ FG-037 verified-read inclusion proofs      (also needs FG-009)
  ├─ FG-038 decision-addressed forge snapshots  (also needs FG-029)
  ├─ FG-039 portable cross-org evidence exchange (also needs FG-030)
  └─ FG-040 deterministic build-output reuse     (also needs FG-034)

FG-003 + FG-009
  └─ FG-041 mechanized proof of the ordered residue
```

---

## G0 — Constitution, identity, and executable semantics

### FG-001 — Make the constitutional registries executable

**Areas:** verification, dependency, claims  
**Risk:** critical

Implement and validate the checked-in dependency, invariant, publication, CALM, durable-object, graph-view, claim-class, verification-lane, and negative-evidence registries.

**Acceptance:**

- zero-dependency `fgit-registry-check` compiles on the pinned nightly;
- registries reject duplicate/unsorted IDs, bad schemas, unknown statuses, broken references, and unregistered dependencies;
- first-party unsafe/FFI/foreign-Git/Tokio/build-script/proc-macro violations fail closed;
- Markdown links/fences, sole `TxId` formula, workflow delegation, and source-available wording are mechanically checked;
- local replay artifact records source tree, toolchain, command, exit code, and report digest.

### FG-002 — Freeze canonical codec, crypto registry, and typed identities

**Areas:** truth, codec, crypto  
**Risk:** critical

Define one canonical encoding profile for immutable FrankenGit bodies and typed algorithm-agile identities without rewriting native Git OIDs.

**Acceptance:**

- domain/version/length framing and unknown-field rules;
- unsigned-body versus signature/attestation envelope convention;
- no floats, maps with ambiguous order, platform integers, locale, or wall-clock identity inputs;
- SHA-1/SHA-256 Git OIDs remain distinct types from internal IDs;
- golden valid/invalid vectors and independent minimal verifier;
- algorithm registry and migration/mixed-version semantics;
- mutation corpus proving noncanonical encodings do not share an identity.

### FG-003 — Build the pure deterministic repository reference model

**Areas:** truth, model, verification  
**Risk:** critical

Implement the smallest complete semantic oracle for seals, decisions, refs, forge aggregates, outcomes, retention roots, and authority heads.

**Acceptance:**

- no I/O, ambient time, randomized hash order, or runtime dependency;
- operations consume an explicit snapshot and produce typed intents/effects/refusals;
- replay from genesis/head yields byte-stable roots;
- exhaustive small-state tests cover duplicate, reorder, refusal, cancellation, CAS loss, and crash points;
- model state can be serialized into golden traces;
- implementation paths must differential-test against this oracle.

### FG-004 — Specify and test the `AuthorityStore` contract

**Areas:** truth, storage  
**Risk:** critical

Define the backend-neutral primitive set used for seals, immutable bodies, authority-head reads, and conditional replacement.

**Acceptance:**

- strong put-if-absent, read-after-write, authenticated read receipt, exact-version CAS, monotone generation, and ABA protection;
- no correctness dependence on listing, notifications, clocks, or lease expiry;
- linearizability history schema and checker;
- fault suite for stale reads, duplicated responses, lost acknowledgements, reordered retries, partial backend failure, and malicious receipt substitution;
- explicit refusal for backends that cannot prove the contract.

### FG-005 — Implement the embedded FrankenSQLite authority profile

**Areas:** truth, FrankenSQLite, self-hosting  
**Risk:** critical

Use FrankenSQLite to implement the same `AuthorityStore` semantics for a one-node deployment and local development.

**Acceptance:**

- no C SQLite/rusqlite dependency;
- compare-and-exchange and immutable-body transactions match the reference model;
- crash matrix around body write, sync, head CAS, outcome accelerator, and restart;
- per-core staging uses FrankenSQLite MVCC without creating a second truth universe;
- export/import to the canonical object/decision format;
- performance artifact compares the embedded path with a filesystem baseline.

### FG-006 — Implement an object-store authority conformance adapter

**Areas:** truth, object store, hosted  
**Risk:** critical

Implement one provider-neutral adapter over an object-store API that exposes the exact `AuthorityStore` contract.

**Acceptance:**

- provider SDK is not a broad unregistered dependency; adapter uses a small Franken/approved HTTP and signing surface;
- version/ETag/conditional semantics are independently verified, not assumed from product naming;
- backend capability receipt records exact API/region/configuration;
- Jepsen-style concurrent histories pass the local checker over injected faults;
- unsupported semantics refuse startup rather than degrade silently;
- no bucket listing participates in current truth or recovery.

### FG-007 — Implement transaction seal, stable `TxId`, and terminal outcome lookup

**Areas:** truth, idempotency  
**Risk:** critical

Implement the sole normative transaction identity and permanent semantic request seal.

**Acceptance:**

- same principal/repository/idempotency key/body maps to one `TxId` across retries;
- same key with different body is a typed conflict;
- pre-seal rejection is distinguished from post-seal canonical refusal;
- client cancellation/disconnect never claims non-commit;
- outcome lookup works after crash and accelerator loss by replaying the decision stream;
- concurrent commit/refusal races can publish at most one terminal decision.

### FG-008 — Implement intent evaluation and net-effect normal form

**Areas:** truth, policy, GraphDB inheritance  
**Risk:** critical

Separate evaluation-order intents from target-disjoint canonical effects, following FrankenGraphDB’s normal-form discipline.

**Acceptance:**

- before/after workspace diff produces deterministic target-disjoint effects;
- every source intent maps to one surviving effect or explicit no-op reason;
- create/delete and repeated edits fold correctly;
- effect order is canonical and independent of map/hash/process order;
- policy evaluates one pinned snapshot and exact candidate effect root;
- apply(normal form, basis) equals evaluator workspace for the reference corpus.

### FG-009 — Implement `RepositoryDecisionBatch` and `RepositoryAuthorityHead`

**Areas:** truth, publication  
**Risk:** critical

Create the immutable ordered decision batch and the one authenticated CAS-published head.

**Acceptance:**

- batch binds predecessor, contiguous repository sequences, RCRs/refusals, resulting roots, evidence, and outbox obligations;
- head binds exact predecessor head, monotone generation, batch identity, latest sequence, ref/forge/retention/policy roots;
- body-first/head-last crash matrix;
- CAS loss exposes no canonical candidate effects;
- replay verifies every link and reconstructs current state;
- two-slot or equivalent anti-rollback recovery refuses ambiguous newest state.

### FG-010 — Freeze checkpoint, capsule, backup, and restore bodies

**Areas:** truth, recovery  
**Risk:** critical

Define root-last checkpoints over an exact authority head/RCR without confusing checkpoint cadence with current state.

**Acceptance:**

- unsigned body identity excludes signatures, placement, and mutable acknowledgements;
- checkpoint binds exact authority head, decision suffix boundary, ref/forge/object/retention/policy/format roots;
- body/manifest/segment staging precedes pointer activation;
- older valid checkpoint cannot masquerade as current acknowledged head;
- restore report proves suffix replay and rebuilt materializations;
- destructive drill fixtures cover missing/corrupt source and repair objects.

---

## G1 — Runtime, concurrency, pure-Rust Git, and object fabric

### FG-011 — Define the FrankenGit Asupersync runtime profile

**Areas:** runtime, dependency  
**Risk:** critical

Pin the exact Asupersync capabilities used by gateways, transfers, publication, repair, projections, agents, and shutdown.

**Acceptance:**

- one runtime/feature universe, no Tokio compatibility in production;
- explicit `Cx`, budget, deadline, cancellation, RNG, and effect capabilities;
- region tree and task ownership for every long-lived service;
- runtime profile identity is attached to evidence artifacts;
- deterministic Lab and production profiles share typed protocol behavior;
- foreign reactor/runtime dependencies fail the constitution gate.

### FG-012 — Implement obligation-typed canonical and external effects

**Areas:** runtime, effects, CALM  
**Risk:** critical

Use reserve/commit/abort obligations — plus explicit acknowledgement for externally observed effects — for object staging, head publication, outbox delivery, package/release upload, and agent effects.

**Acceptance:**

- every reserved effect reaches committed/aborted/terminally quarantined state before region close;
- committed externally observed effects carry a distinct acknowledged state: post-commit retry is idempotent, and region close either records the acknowledgement or leaves an explicit unacknowledged-effect record, never silence;
- cancellation cannot silently drop a committed effect or publish half an effect;
- external APIs with weak idempotency use an explicit reconciliation state machine;
- obligation ledger is replayable and linked to `TxId`/Intent Run;
- CALM registry class determines where coordination is required;
- quiescence oracle detects orphan tasks, credentials, and unresolved effects.

### FG-013 — Build deterministic Lab, DPOR, and crash-point exploration

**Areas:** runtime, verification  
**Risk:** critical

Create a reusable deterministic harness for authority, transfer, repair, workspace, generation, and effect protocols.

**Acceptance:**

- virtual time, deterministic RNG, failpoints, packet/object-store fault injection;
- vector-clock/Mazurkiewicz trace identity and DPOR reduction;
- schedule coverage receipt names explored equivalence classes and bounds;
- cancellation/crash can occur at every declared yield/publication point;
- minimized counterexample replay command;
- no raw stress count may substitute for schedule coverage.

### FG-014 — Implement per-core preparation lanes and flat combining

**Areas:** concurrency, performance  
**Risk:** high

Import FrankenSQLite’s per-core staging/combiner architecture for hot repository publication.

**Acceptance:**

- deterministic lane state machine (`Writable -> Sealed -> Combining -> Retired -> Writable`, exactly as in the comprehensive plan §16.2);
- object validation, intent evaluation, witness creation, and candidate effects remain parallel;
- one bounded combiner builds a decision batch and attempts one head CAS;
- overflow/fallback is explicit and cancel-correct;
- reference-model equivalence for all batch sizes and interleavings;
- same-binary A/A and A/B artifacts include tail latency, fairness, aborts, CPU, and memory.

### FG-015 — Implement exact pure-Rust Git object core

**Areas:** git, memory safety  
**Risk:** critical

Parse, validate, hash, and emit blob/tree/commit/tag objects exactly in safe Rust.

**Acceptance:**

- streaming checked-arithmetic parsers with object/header/depth budgets;
- exact tree ordering/mode/name and commit/tag header behavior;
- typed SHA-1/SHA-256 OIDs;
- no FFI, C Git, libgit2, gix, or subprocess fallback;
- differential corpus against pinned upstream Git executables as external oracles;
- malformed/adversarial/fuzz corpus and stable typed refusals.

### FG-016 — Implement safe pure-Rust pack reader and delta resolver

**Areas:** git, security, performance  
**Risk:** critical

Implement pack v2 ingestion, indexes, OFS/REF deltas, thin packs, and bounded reconstruction.

**Acceptance:**

- checksum/trailer and object-count validation;
- depth/fan-out/expanded-byte/ratio/memory/time budgets;
- cycle/missing-base/duplicate/truncation/ref-mismatch refusals;
- scalar reference resolver plus optimized bounded path;
- quarantine never creates retention reachability;
- differential, fuzz, mutation, and decompression-bomb evidence.

### FG-017 — Implement deterministic pure-Rust pack planning and writing

**Areas:** git, performance  
**Risk:** high

Generate compatible packs from canonical objects without relying on upstream Git.

**Acceptance:**

- deterministic baseline profile and explicit non-deterministic optimization profile if ever needed;
- reachability closure, object order, delta candidate/tie-break policy, and bitmap/commit-graph inputs are receipted;
- output validates through independent parser and pinned Git clients;
- cancellation produces no valid partial publication;
- benchmark against upstream Git on representative histories with byte-equivalence/non-equivalence classifications;
- optimization proof binds output semantics to the scalar/reference planner.

### FG-018 — Implement `git-upload-pack` and partial clone

**Areas:** git, protocol  
**Risk:** critical

Implement smart-HTTP/SSH upload-pack, v0/v1 and v2 fetch commands, shallow and promisor behavior.

**Acceptance:**

- pkt-line/capability/state-machine goldens;
- have/want negotiation and reachability against pure reference closure;
- shallow/deepen/unshallow and filter/promisor corpus;
- hidden-ref authorization at advertisement and object disclosure;
- streaming cancellation, backpressure, and deterministic error behavior;
- packet transcript differential evidence across pinned client versions.

### FG-019 — Implement `git-receive-pack`, quarantine, and atomic publication

**Areas:** git, truth, security  
**Risk:** critical

Implement push negotiation and admission through the decision-log protocol.

**Acceptance:**

- create/update/delete/force, report-status, sideband, push options, atomic and non-atomic semantics;
- transaction-scoped quarantine and pure-Rust pack validation;
- expected-old refs, hidden refs, protections, quotas, signatures, and object closure use one pinned authority read;
- atomic push maps to one RCR/decision; non-atomic mapping is explicit and replayable;
- response loss resolves by `TxId` lookup;
- no standardized “protocol v2 push” fiction.

### FG-020 — Implement immutable object envelope and deterministic microsegment

**Areas:** object fabric, repair  
**Risk:** critical

Define and implement the final storage abstraction for small admitted objects.

**Acceptance:**

- exact embedded Git bytes plus native OID, strong internal digest, length/type, namespace, format, encryption/compression profile;
- deterministic ordered records, authenticated index, Merkle footer, and segment digest;
- encoder refuses noncanonical input order rather than silently sorting intent;
- random-access lookup and full verification;
- truncation, transplant, duplicate, mixed-namespace, and nondeterministic-builder tests;
- measured size/locality comparison with loose objects and packs.

### FG-021 — Implement object fabric, location manifests, and retention roots

**Areas:** object fabric, storage, GC  
**Risk:** critical

Implement immutable put/get/range, verified placements, segment manifests, rebuildable locators, and authenticated retention roots.

**Acceptance:**

- storage listing is never authority;
- locator/index loss rebuilds from manifests/segments;
- placement receipts name failure domains and encryption dependencies;
- staged/visible/durable states are explicit;
- no object becomes canonical or retained before decision publication;
- range/read/corruption/failure-domain fault suite and economic metrics.

### FG-022 — Implement ATP-Git have-summary, delta, and reconstruction profile

**Areas:** transport, ATP  
**Risk:** high

Specialize Asupersync ATP for canonical object/segment/manifest transfer.

**Acceptance:**

- authenticated peer capability and inventory summary;
- `AlreadyInSync`, delta, unique-content, and full-transfer plans;
- false-positive summaries affect efficiency only;
- deterministic reconstruction order and exact manifest/object verification;
- trust-scoped cache keys and bounded memory;
- ordinary pure-Rust Git pack fallback when capability/evidence is absent.

### FG-023 — Implement ATP-Git path graph, racing, swarm, and transfer actor

**Areas:** transport, runtime  
**Risk:** high

Add typed multi-path transfer and verified piece scheduling.

**Acceptance:**

- typed direct/LAN/IPv6/tunnel/relay/mailbox path candidates with security/privacy/cost attributes;
- bounded path racing with deterministic policy receipt and loser drain;
- verified/unverified piece states, rarity, peer availability, endgame duplication, and adversarial peer penalties;
- one transfer actor owns discovery through final verification/quiescence;
- path-controller adaptivity is identity-bound and falls back deterministically;
- fault/partition/loss/duplication/reorder/cancellation corpus.

### FG-024 — Implement first RaptorQ-protected durable class

**Areas:** repair, object fabric  
**Risk:** critical

Protect one immutable repository segment class end to end.

**Acceptance:**

- registered canonical source bytes, source-block/symbol profile, deterministic floor, placement policy, and decode budgets;
- corruption/erasure/mixed-object/malicious-symbol campaigns within and beyond promise;
- decoder output accepted only after original digest/Merkle/object/codec checks;
- repair candidate publishes through current authority and cannot overwrite newer state;
- destructive reconstruction drill and replication-only control;
- no blanket “self-healing” claim beyond this class/profile.

### FG-025 — Implement conflict witnesses and value-of-information refinement

**Areas:** concurrency, policy  
**Risk:** critical

Permit high concurrency without using different ref names as a false independence proof.

**Acceptance:**

- conservative witness families for refs, paths, symbols, policy inputs, forge entities, quota/retention/queue keys;
- optional sketches estimate overlap but cannot prove absence;
- refinement spends bounded CPU/bytes only when expected saved abort cost exceeds cost;
- refined witnesses may remove false conflicts but never a reference-model true conflict;
- deterministic semantic rebase ladder and conflict certificate;
- starvation/fairness/retry policy with regime reset and escalation.

### FG-026 — Implement Git TreeFS workspace core

**Areas:** workspace, filesystem, agent  
**Risk:** critical

Provide an immutable-tree plus copy-on-write workspace without requiring a full mutable checkout.

**Acceptance:**

- descriptor-relative/capability-rooted path API;
- lazy authorized blob fetch, sparse path set, overlay intent log, snapshot root, and deterministic materialization;
- symlink/reparse/hardlink/device/path traversal corpus across platforms;
- staged/visible/durable workspace epochs and crash replay;
- no ambient sponsor token, host metadata, or unrestricted network;
- export to ordinary worktree and Git object closure with exact source receipt.

### FG-027 — Implement one source-spanned document/diff lineage

**Areas:** forge, rendering, review  
**Risk:** high

Use one canonical parsed/source-span lineage for Markdown, comments, reviews, diffs, search spans, APIs, and agent context.

**Acceptance:**

- safe pure-Rust parser/AST/render profiles with exact source spans;
- stable review anchors and explicit outdated/remap outcomes;
- human HTML, compact machine, and API representations derive from one AST;
- resource bounds and active-content policy;
- staged multi-output publication with rollback;
- golden cross-surface equivalence and malicious Markdown/SVG corpus.

---

## G2 — End-to-end forge, agent, graph, search, recovery, CI, and release

### FG-028 — Deliver one-node end-to-end clone/fetch/push vertical slice

**Areas:** integration, truth, git  
**Risk:** critical

Combine the embedded authority profile, object fabric, pure-Rust Git services, and decision publication into a runnable one-repository server.

**Acceptance:**

- initialize/import, clone, fetch, push, delete, force, atomic push, restart, and export;
- no external Git/database/runtime process in production path;
- lost response, duplicate request, crash at every publication point, and materialization deletion recover correctly;
- refs/object closure/outcomes match pinned Git clients and reference model;
- complete replay/evidence bundle and installation/doctor path;
- performance baseline names hardware, corpus, cold/warm state, and correctness checks.

### FG-029 — Implement canonical forge events and atomic pull-request merge

**Areas:** forge, truth  
**Risk:** critical

Implement issues/PR/reviews/protections/checks/merge attempt sufficient for one atomic PR merge.

**Acceptance:**

- immutable events and deterministic aggregate roots;
- PR open/synchronize/review/check/merge transitions;
- source/target movement and policy snapshot semantics;
- merge ref update and merged forge event share one RCR;
- outbox delivery cannot duplicate canonical events;
- projection loss/rebuild and mixed-generation authorization negatives.

### FG-030 — Implement minimal Agent Protocol vertical slice

**Areas:** agent, workspace, effects  
**Risk:** critical

Support one local agent harness from signed/authorized intent through evidence-carrying publication.

**Acceptance:**

- Intent Run, attenuated capability chain, AuthorityReadReceipt, Context Packet, TreeFS workspace, effect obligations, evidence records, and Evidence-Carrying Change;
- repository text cannot widen authority;
- producer/verifier independence class is machine-checked;
- cancellation drains tasks, processes, secrets, prepared transactions, and external effects;
- publication uses ordinary sealed `RefTxn` semantics;
- budget, prompt-injection, secret, stale-base, duplicate-effect, and fabricated-evidence corpus.

### FG-031 — Implement typed repository graph fabric and decision witnesses

**Areas:** graph, NetworkX/GraphDB inheritance  
**Risk:** high

Build commit, object, dependency, ownership/review, build, agent, provenance, and placement graph generations.

**Acceptance:**

- each graph view has authority class, source position, schema, builder, and activation receipt;
- stable external IDs/order plus dense integer adjacency hot path;
- closed tie-break policies and per-execution decision-path/complexity witnesses;
- exact algorithms for ancestry/SCC/dominators/bridges/cuts/matching/topology as selected by registry;
- inferred/statistical edges are visibly separate and advisory;
- no graph score or stale generation can grant authorization.

### FG-032 — Implement progressive lexical/semantic/graph search generation

**Areas:** search, context  
**Risk:** high

Deliver immediate exact/lexical/symbol results followed by optional semantic/graph refinement.

**Acceptance:**

- `Initial`, `Refined`, and `RefinementFailed` streaming states;
- Quill-style immutable segments with merge-by-concat over disjoint absolute document IDs;
- root-last anti-rollback generation authority and no mixed-generation read;
- every result names exact source RCR/generation/span/authorization;
- Context Packet lists omissions and coverage class;
- deterministic fallback remains useful when models/refinement are unavailable.

### FG-033 — Implement checkpoint, restore, repair, and garbage collection slice

**Areas:** recovery, repair, GC  
**Risk:** critical

Prove that canonical truth survives total materialization/index loss and bounded immutable-object damage.

**Acceptance:**

- root-last repository capsule and backup export;
- restore to clean embedded/object-store target with suffix replay;
- registered RaptorQ repair through authority-mediated intent;
- authenticated root catalog includes refs, PR/queue, seals, holds, migration, restore, artifacts, and grace tombstones;
- mark/prove/grace/revalidate/sweep protocol;
- repair-versus-newer-write, GC race, legal hold, cryptographic erasure, and residual-symbol incidents;
- signed restore report with measured RPO/RTO.

### FG-034 — Implement hostile CI execution receipt slice

**Areas:** CI, security, evidence  
**Risk:** critical

Run one untrusted repository job as a separate hostile-compute product.

**Acceptance:**

- immutable runner image/toolchain identity and exact source closure;
- bounded CPU/memory/disk/network/time/processes;
- no cloud metadata or ambient host secrets;
- fork/trust-scoped secret broker and cache namespaces;
- cancellation/reaping leaves no orphan process/effect;
- logs/artifacts/provenance/redaction receipts;
- green means only the named evidence class, not universal safety.

### FG-035 — Implement local DSR verification and release evidence

**Areas:** release, supply chain  
**Risk:** critical

Make repository-owned commands and Doodlestein Self-Releaser the release path.

**Acceptance:**

- workflow YAML contains no unique logic and is executable locally through `act`/native hosts;
- exact source, dirty-state, toolchain, dependency constellation, host, command, environment, and artifact identities;
- one target attempt identity per native platform;
- cancellation/resume reuses only byte-verified exact-input artifacts;
- symlink, traversal, collision, target substitution, and unlisted asset tests;
- checksums, signatures, SBOM, provenance, installer smoke, source archive, and root-last manifest;
- GitHub Releases is a distribution adapter, never release truth.

---

## G3 — Distributed and hosted proof

### FG-036 — Prove distributed authority, placement, and failover

**Areas:** distributed, hosted, fault  
**Risk:** critical

Run the same logical protocol across multiple cells/regions without a home-cell correctness dependency.

**Acceptance:**

- any eligible cell may prepare/attempt publication;
- rendezvous routing and gossip are hints only;
- object placement spans declared failure domains;
- stale/malicious cells cannot publish an older head or fabricated receipt;
- concurrent CAS, partition, process pause, object-store degradation, region loss, clock anomaly, and rolling-upgrade campaigns;
- failover requires no mutable Git directory transfer;
- measured availability, tail latency, RPO/RTO, storage/egress amplification, and cost;
- public SLO claims remain scoped to the exact deployment/evidence horizon.

## G4 — Ambition extensions

These slices are proposal-class product differentiators built entirely from machinery earlier gates already prove. None of them may introduce a second truth mechanism, and each advances claims only through its registered evidence.

### FG-037 — Implement verified-read inclusion proofs

**Areas:** truth, transport, security  
**Risk:** high

Serve Merkle inclusion proofs connecting any ref/object-membership/forge-position/outcome answer to a named authenticated head (comprehensive plan §18.7).

**Acceptance:**

- proof envelope is capability-negotiated and versioned; unproven responses remain valid;
- an independent minimal verifier (no FrankenGit server code) validates proofs against a pinned head;
- a tampering mirror/CDN corpus proves wrong answers fail verification instead of being believed;
- absence proofs cannot become existence oracles across authorization boundaries;
- bounded-stale and snapshot reads carry proofs against their named older head;
- proof generation cost is bounded, cacheable per head/root, and measured.

### FG-038 — Implement decision-addressed forge snapshots and forge bisection

**Areas:** forge, product, evidence  
**Risk:** medium

Expose `fg at <decision|rcr|capsule>` read-only snapshots and decision-sequence bisection (comprehensive plan §31.8).

**Acceptance:**

- a snapshot binds one exact decision/RCR position and reports it in every answer;
- refs, PR/review state, policy epoch, and check receipts render exactly as of that position;
- bisection over a decision range locates a named forge-state transition deterministically;
- disclosure uses current authorization while historical policy renders as data; revoked access is never resurrected;
- snapshot projections are derived state: destroy-and-rebuild yields identical answers;
- works against snapshots/exports without a hosted service.

### FG-039 — Implement the cross-organization evidence-exchange profile

**Areas:** evidence, federation, security  
**Risk:** high

Let evidence envelopes, check receipts, and Evidence-Carrying Changes travel between organizations with claims intact (comprehensive plan §34.8).

**Acceptance:**

- exchange schema binds origin trust domain, signer identity/key history, claim class, and replay-completeness grade;
- imported claims never upgrade in transit; policy maps each grade to what it may satisfy;
- imported evidence can tighten but never bypass locally required checks;
- equivocation between exported and origin evidence becomes durable conflict evidence;
- a dependency-update corpus proves an upstream evidence pack verifies locally end to end;
- adversarial campaigns cover forged provenance, replayed packs, and trust-domain confusion.

### FG-040 — Implement deterministic build-output reuse

**Areas:** CI, cache, provenance  
**Risk:** high

Serve declared-deterministic workflow outputs from a trust-scoped content-addressed cache keyed by exact `BuildInputCapsule` identity (comprehensive plan §29.8).

**Acceptance:**

- reuse requires exact capsule-identity match; policy names which check classes accept reuse;
- reuse receipts name the original producing run; provenance never claims a fresh execution;
- trust-domain isolation passes the §29.5 cache-poisoning campaigns;
- declared-nondeterministic steps are never reused; a failed spot-check reverifies the class and records negative evidence;
- measured hit rate, latency, and compute-cost artifacts on a real workload;
- reuse never substitutes for release-lane target-native verification.

### FG-041 — Mechanize proofs for the ordered residue

**Areas:** verification, truth, model  
**Risk:** high

Machine-check the core theorems of the seal/outcome/batch/head protocol against the executable reference model (comprehensive plan §40.8).

**Acceptance:**

- an ADR selects the proof toolchain under the dependency constitution and records alternatives;
- machine-checked theorems: terminal-outcome uniqueness, head-chain continuity/monotonicity, atomic ref/forge visibility, no lost/fabricated decision under crash/retry/ambiguity, anti-rollback under interrupted publication;
- the mechanized model and the executable reference model are kept equivalent by generated or differential artifacts;
- trace-refinement evidence connects implementation histories to the proved model per §40.5;
- claims registry rows at `proof` rank link the proof artifacts and their assumptions;
- gaps are explicit non-claims, never rounded up.

## G5 — Product completion and platform waves

A completeness audit of the comprehensive plan against gates G0-G4 found that the seed slices above cover the truth/transport/workspace/verification core but not the full v1 product and platform surface. The G5 slices below close that gap; their authoritative, fully elaborated definitions (background, acceptance, test plans, dependencies) live in the bead graph (`.beads/issues.jsonl`, slugs `fg042`..`fg065`), which is the granular planning truth. One-line summaries:

- **FG-042** identity/authentication core: users, orgs, teams, tokens, deploy keys, principal snapshots, and the threat-model §7.5a account-takeover controls;
- **FG-043** policy engine: PolicySnapshots, the deterministic policy language, the full protected-ref vocabulary, break glass, rollout modes;
- **FG-044** pure-Rust diff/merge-base/three-way merge engine (a dependency FG-029 silently assumed; now explicit);
- **FG-045** issues, discussions, labels, and notification projections, with a worked event-upcaster;
- **FG-046** webhook delivery product over the transactional outbox (signatures, rotation, replay, SSRF controls, dead letter);
- **FG-047** SSH transport service with typed command dispatch and deploy-key auth;
- **FG-048** schema registry + multi-target codegen and the native REST API (no handwritten wire structs);
- **FG-049** GitHub compatibility API and forge-state import with a machine-readable gap matrix;
- **FG-050** server-rendered web UI per the §31.7 principles (a client of the public APIs, never a bypass);
- **FG-051** full `fg` CLI surface and the §37.8 doctor verb family;
- **FG-052** materialization accelerators: commit-graph, bitmaps, MIDX, bundles, archives, sparse/FUSE adapters (D7);
- **FG-053** Git LFS over the artifact fabric;
- **FG-054** identity-bound statistical policy framework (§33) that the adaptive controllers cite;
- **FG-055** evidence envelopes, claims registry machinery, and generated status (fgit-claim/fgit-evidence);
- **FG-056** resource governance, tenant quotas, admission outcomes, fairness, abuse controls (§36);
- **FG-057** cryptography registry, key management, and encryption domains (ADR D8);
- **FG-058** SHA-256 repository support (ADR D3);
- **FG-059** repository incarnations, rename/delete lifecycle, and migration protocol (§11.1, §37.5);
- **FG-060** artifact/release payload fabric and package phase 1 (§30);
- **FG-061** open-decision ADR sweep: D5, D9, D10, D12, D13, D15;
- **FG-062** license-model resolution (D14 — launch-blocking);
- **FG-063** federation and local-first collaboration phase (§23);
- **FG-064** context-assembly optimizer and reviewer/runner routing (§25.5, §27.6);
- **FG-065** hosted multi-tenant operations: evacuation, capability readiness, incident-mode drills, mixed-version upgrades (§37).

## G6 — Doc-derived completion (normative machinery from the full doc set)

A second audit swept the full supporting doc set (NORMATIVE_PROTOCOL_CONTRACTS, VERIFY_SPEC, SECURITY_THREAT_MODEL, AGENT_PROTOCOL, ATP_GIT_PROFILE, GIT_TREE_FS, CALM_AND_OBLIGATIONS, GRAPH_INTELLIGENCE_ARCHITECTURE, RAPTORQ_PERMEATION_MAP, OBJECT_STORE_DECISION_LOG, GIT_COMPATIBILITY_MATRIX, and all registries) against the bead graph and found normative machinery, conformance obligations, and required-v1 rows not owned by any G0-G5 bead. The G6 slices close those; authoritative definitions live in the bead graph (`.beads/`, slugs `fg066`..`fg086`). Summaries:

- **FG-066** cross-cutting security/adversarial program (VERIFY §22): attack-matrix lane + resource-ceiling enforcement + the orphan attack rows (token rollback/forgery, tenant/key confusion, poisoning, operator/DSR compromise);
- **FG-067** benchmark evidence harness (VERIFY §23 / §38.4 proof contract) the perf beads presuppose;
- **FG-068** toolchain-refresh lane executing the D15 nightly-advancement policy;
- **FG-069** build-script/proc-macro enumeration + golden-expansion audit for authority-sensitive generated code;
- **FG-070** CALM registry load-bearing conformance lane (prove every row is enforced);
- **FG-071** cross-tenant isolation/existence-oracle campaign (normative invariant 17, release-blocking);
- **FG-072** verifier-independence classification + enforcement (AGENT_PROTOCOL §independence);
- **FG-073** effect-broker ledger + external-effect reconciliation ('maybe it happened' is not terminal);
- **FG-074** SubIntent delegation, attenuation-ancestry proof, bounded fan-out;
- **FG-075** trust-scoped ATP transfer cache with grants + poisoning quarantine;
- **FG-076** TreeFS 11-point crash/cancellation interruption matrix (the doc's own gated corpus);
- **FG-077** RaptorQ permeation for the remaining MUST-encode durable classes (fg024 was the first class only);
- **FG-078** scrub scheduler + durability health ledger (the repair machine's continuous trigger — 'scrub' was in zero beads);
- **FG-079** decision-log/segment compaction protocol (OSDL §12: compaction as an ordinary decision);
- **FG-080** temporal graph query modes + cross-time join receipts (GRAPH §7 — 'temporal' was in zero beads);
- **FG-081** advisory architecture-analysis graph products (feedback sets, transitive reduction, k-core, shard proposals, drift);
- **FG-082** graph algorithm set wave 2 (min-cost flow, k-shortest paths, centrality family) that fg064 depended on but no bead built;
- **FG-083** merge queue engine (required-v1; existed only as a policy predicate before);
- **FG-084** git-notes conformance + policy controls (required-v1);
- **FG-085** submodule gitlink preservation + non-delegation (required-v1);
- **FG-086** external head-continuity witness profile (optional high-value anti-rollback, OSDL §15).

## Backlog governance

- Issue IDs are stable and never silently reused.
- Splitting an issue preserves a parent and dependency update.
- Closing an issue records claim level, artifact IDs, replay command, and explicit non-claims.
- Failed hypotheses enter [`docs/NEGATIVE_EVIDENCE_LEDGER.md`](NEGATIVE_EVIDENCE_LEDGER.md) and `registries/negative_evidence.tsv`.
- A later optimization cannot bypass the reference model, authority contract, pure-Rust boundary, or evidence gate merely because it benchmarks well.

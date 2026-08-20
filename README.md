# FrankenGit

**A spec-first architecture for a Git-compatible, self-hostable software forge built for humans and autonomous coding agents.**

> **Current status:** pre-implementation architecture and public design review. FrankenGit is not yet a usable Git server or GitHub replacement.
>
> **Normative contract:** [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md) defines transaction identity, terminal outcomes, ref/forge atomicity, push admission, policy snapshots, writer fencing, checkpoint identity, retry/cancellation, agent authority, and RaptorQ boundaries. It overrides older exploratory examples that disagree with it.
>
> **Licensing status:** the current custom rider is source-available, not an OSI-approved open-source license. FrankenGit intends to select a genuine open-source/commercial model before the first code release. See [`docs/LICENSING_DECISION.md`](docs/LICENSING_DECISION.md).

FrankenGit starts from a simple observation: a hosted forge should not make one mutable bare repository on one machine the source of truth. Git-compatible repositories, worktrees, packs, commit graphs, search indexes, CI workspaces, and web projections can all be disposable materializations. Canonical truth should instead be immutable, content-addressed, transactionally ordered, recoverable, independently verifiable, and cheap to reproduce near demand.

The design combines the strongest ideas from the Franken family:

- **Asupersync:** structured concurrency, capability-scoped effects, cancellation through quiescence, deterministic replay, and typed outcomes.
- **FrankenSQLite:** explicit MVCC/transaction invariants, root-last publication, typed corruption handling, evidence-linked claims, and information-theoretic durability research.
- **FrankenFS:** immutable block/object identities, repair ledgers, bounded self-healing, strict layering, and crash-consistency gates.
- **FrankenSearch:** progressive lexical/semantic retrieval, deterministic generations, source-linked explanations, and agent-friendly streaming output.
- **franken_markdown:** deterministic safe rendering, small auditable cores, resource bounds, and one canonical representation feeding human and machine surfaces.
- **FrankenGraphDB:** canonical event streams, generated registries, graph projections, calibrated adaptive systems, and a separation between deterministic truth and statistical evidence.

## The thesis

A conventional forge tends to accumulate several partially authoritative systems:

- Git refs and objects in local repositories;
- pull-request and issue rows in a database;
- merge queues and branch protections in services;
- CI state in another database;
- search and graph indexes built asynchronously;
- caches and replicas that know different subsets of history.

FrankenGit instead defines one atomic repository mutation primitive. A successful mutation publishes a **Repository Commit Record** (`RCR`) that binds:

- the exact ref delta;
- the resulting authenticated ref root;
- the admitted Git object closure;
- the exact canonical forge-event batch;
- the resulting forge-position root;
- the policy epoch and decision evidence;
- the transactional outbox for downstream effects;
- the immutable terminal outcome for the transaction identity.

That prevents split-brain product states such as “the target branch moved, but the pull request still says open,” or “the UI says merged, but the ref update never committed.”

## Three planes

### 1. Canonical truth plane

The truth plane owns Git object identities, sealed mutation requests, terminal transaction outcomes, repository commit records, authenticated roots, forge events, retention roots, policy epochs, writer fencing, and signed repository capsules.

Canonical state is deterministic. Statistical models, search indexes, caches, CI projections, and local Git repositories cannot authorize a mutation merely because they look current.

### 2. Materialization plane

The materialization plane produces ordinary Git-facing views:

- smart-HTTP and SSH upload-pack/receive-pack services;
- bare repositories and pack caches;
- partial-clone/promisor views;
- sparse copy-on-write agent workspaces;
- commit graphs, bitmaps, indexes, and CI checkouts;
- regional edge caches.

Materializations are disposable. Their loss is an availability event, not loss of canonical truth.

### 3. Intelligence plane

The intelligence plane provides progressive search, code/ownership/dependency graphs, context packets, policy evidence, anomaly review, merge assistance, and agent orchestration. Every result carries provenance and a canonical position. Intelligence may propose or prioritize; it does not silently redefine source-control truth.

## The key protocol objects

### Stable logical transaction identity

`RequestId` identifies one network attempt. `TxId` identifies one admitted logical mutation and is derived exactly once from tenant, repository, authenticated principal, idempotency key, and the canonical semantic request digest. Server nonce, retry count, connection ID, and wall-clock time are excluded so retries converge on the same identity.

### Linearizable terminal outcome

After admission, one immutable `TxnOutcomeRecord` eventually resolves to either:

- `Committed { repository_commit_id }`, or
- `Refused { code, refusal_record_id }`.

Infrastructure interruption before decision is retryable and leaves no terminal result. Client cancellation after admission cannot prove non-commit; the client queries by `TxId`.

### Repository Commit Record

An RCR is the unit of canonical repository history. It binds both Git and forge state. The linearization point is the serializable metadata commit that makes the RCR, new head pointer, terminal outcome, resulting roots, and outbox entries visible together.

### Repository capsule

A capsule is an occasional signed, root-last checkpoint over one exact RCR. Its identity is the hash of an unsigned canonical body. Signatures, replica acknowledgements, repair-symbol placement, and storage locations attest to the capsule ID but do not participate in it. Every RCR carries current forge-position state independently; an older capsule cannot masquerade as current state.

## Git compatibility without protocol fiction

FrankenGit preserves ordinary Git as a constitutional boundary:

- clone/fetch use `git-upload-pack` over smart HTTP or SSH;
- push uses the separate `git-receive-pack` service;
- Git protocol v2 is negotiated for commands such as `ls-refs` and `fetch`;
- the design does **not** invent a standardized “protocol v2 push” command;
- SHA-1 and SHA-256 Git object IDs are typed and never silently translated;
- push quarantine validates framing, packs, deltas, decompression budgets, object structure, reachability, hidden-ref authorization, expected-old refs, and atomic-push semantics;
- partial clone, shallow history, LFS, signed pushes, tags, notes, submodules, and GitHub-compatible APIs each receive independent conformance rows.

See [`docs/GIT_COMPATIBILITY_MATRIX.md`](docs/GIT_COMPATIBILITY_MATRIX.md).

## RaptorQ, used precisely

RaptorQ protects registered immutable byte objects such as repository segments, checkpoint manifests, backups, artifacts, package chunks, and bulk-transfer blocks. It is not a hash, signature, ordering protocol, consensus algorithm, authorization system, freshness oracle, or replacement for replicated transactional metadata.

A decoder return is never sufficient. Reconstructed bytes must revalidate against the original cryptographic identity, expected length, Merkle commitment, Git object ID where applicable, and type-specific canonical codec. Decode work and memory are bounded. Mutable leases, transaction outcomes, policy state, and repository head pointers use conventional replicated transactional storage.

The complete registry doctrine is in [`docs/RAPTORQ_PERMEATION_MAP.md`](docs/RAPTORQ_PERMEATION_MAP.md).

## Anytime-valid evidence, not statistical government

Conformal calibration, e-processes/e-martingales, bandits, and changepoint detectors may adapt cache budgets, scrub priority, repair overhead within hard limits, canary escalation, reversible throttling, search budgets, and anomaly-review priority.

They do not decide Git object identity, ref atomicity, authorization, signature validity, retention roots, guilt, or whether committed data exists. Every controller has deterministic safe defaults, bounded actions, reset semantics, replayable observations, and a kill switch.

## Agent-native collaboration

An agent operates through a signed **Intent Run** sponsored by a human or service principal. Authority is attenuated by repository, ref, path, effect type, secret class, time, compute, storage, network, and monetary budget.

A run receives content-addressed **Context Packets** pinned to canonical state. A packet lists included and deliberately omitted material, preserving provenance instead of dumping an unbounded repository into context.

An **Evidence-Carrying Change** binds:

- base RCR/capsule;
- proposed Git object closure;
- context identities and omissions;
- tests, static checks, and tool receipts;
- claimed invariants and explicit non-claims;
- independent verifier attestations;
- requested effects and budgets.

A verifier that shares the proposing agent’s mutable workspace, credentials, or hidden state is not automatically independent. Policy records verifier evidence classes explicitly.

See [`docs/AGENT_PROTOCOL.md`](docs/AGENT_PROTOCOL.md).

## Safety and evidence doctrine

The project distinguishes:

- **specified** — a design contract exists;
- **implemented** — code exists and local tests pass;
- **differentially verified** — behavior matches named Git/GitHub oracles over a versioned corpus;
- **fault-validated** — crash, retry, partition, corruption, cancellation, and resource-exhaustion campaigns pass;
- **operationally validated** — replayable deployment artifacts support bounded reliability/performance claims.

No README sentence may silently promote one level to another. `VERIFY_SPEC.md` defines release gates, evidence schemas, model checking, deterministic schedule exploration, fuzzing, differential tests, recovery drills, and claim registries.

## Initial architecture

```text
Git/SSH/HTTP clients, humans, agents, CI, mirrors
                         |
                 protocol/API gateways
                         |
              admission + capability checks
                         |
       repository sequencer / fenced writer epoch
                         |
     +-------------------+-------------------+
     |                                       |
immutable object/event staging       serializable metadata
     |                               RCR + roots + outcome
     |                                       |
object storage + repair symbols       transactional outbox
     |                                       |
     +-------------------+-------------------+
                         |
        materializers / projections / indexes
                         |
     Git views, web UI, search, graph, CI, agents
```

The V1 correctness oracle is a small, explicit per-repository sequencer. Parallel ingestion, validation, object writes, materialization, search, and CI can scale independently. Physically parallel canonical commits are a later optimization admitted only after executable refinement proves equivalence for overlapping invariant keys.

## Repository map

- [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md`](COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md) — full product and execution plan.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — condensed topology and ownership map.
- [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md) — authoritative protocol semantics.
- [`docs/FRESH_EYES_AUDIT_2026-08-19.md`](docs/FRESH_EYES_AUDIT_2026-08-19.md) — defects found and dispositions.
- [`VERIFY_SPEC.md`](VERIFY_SPEC.md) — executable evidence and release gates.
- [`SECURITY_THREAT_MODEL.md`](SECURITY_THREAT_MODEL.md) — adversaries, trust boundaries, attacks, and mitigations.
- [`docs/AGENT_PROTOCOL.md`](docs/AGENT_PROTOCOL.md) — agent identity, context, effects, evidence, and cancellation.
- [`docs/RAPTORQ_PERMEATION_MAP.md`](docs/RAPTORQ_PERMEATION_MAP.md) — encoded object classes and post-decode verification.
- [`docs/GIT_COMPATIBILITY_MATRIX.md`](docs/GIT_COMPATIBILITY_MATRIX.md) — decomposed Git and forge compatibility targets.
- [`docs/INITIAL_ISSUE_BACKLOG.md`](docs/INITIAL_ISSUE_BACKLOG.md) — dependency-ordered implementation slices.
- [`docs/LICENSING_DECISION.md`](docs/LICENSING_DECISION.md) — open-source/commercial options and current truthfulness rule.
- [`AGENTS.md`](AGENTS.md) — contributor and coding-agent doctrine.

## What FrankenGit is not

- not a new incompatible version-control system;
- not a claim that Git’s object model should be discarded;
- not “GitHub UI plus an object store”;
- not asynchronous multi-master canonical mutation;
- not RaptorQ standing in for consensus or cryptographic integrity;
- not model output standing in for authorization or proof;
- not an implemented product today;
- not yet honestly describable as OSI open source under the current custom rider.

## Near-term execution order

1. Freeze canonical encodings, IDs, refusals, RCR/outcome/capsule schemas, and registries.
2. Build a pure reference model and deterministic state-machine simulator.
3. Implement Git object/pack validation and a differential upload-pack/receive-pack harness.
4. Implement one-node metadata sequencing plus immutable object staging.
5. Prove idempotency, cancellation, crash recovery, and ref/forge atomicity.
6. Add disposable Git materialization and partial clone.
7. Add event-sourced issues, pull requests, reviews, protections, and merge queue.
8. Add agent Intent Runs, Context Packets, and Evidence-Carrying Changes.
9. Add search/graph projections with canonical position receipts.
10. Add multi-node replication, root-last capsules, backup restore, and registered RaptorQ repair.
11. Add hosted multi-tenancy, quotas, billing evidence, abuse controls, and regional placement.
12. Advance public claims only as the corresponding evidence gates close.

## Verification

The documentation itself has a machine-checkable integrity gate:

```bash
python3 scripts/verify_docs.py
```

It checks the intended tree, relative links, balanced code fences, forbidden transfer artifacts, immutable action pins, pre-implementation/licensing status, and the presence of the corrected transaction/push/capsule contracts.

## Audit result

The fresh-eyes review preserved the project’s radical parts while removing several dangerous ambiguities. The exact findings—publication flattening, protocol-v2 push confusion, duplicate transaction identity, missing terminal outcomes, mixed policy snapshots, stale capsule semantics, circular identity risk, quarantine/reachability conflation, over-broad RaptorQ language, agent cancellation ambiguity, licensing mismatch, and omitted security/compatibility surfaces—are recorded in [`docs/FRESH_EYES_AUDIT_2026-08-19.md`](docs/FRESH_EYES_AUDIT_2026-08-19.md).

The result is still ambitious. It is now ambitious in a way that can be implemented, falsified, replayed, and audited.
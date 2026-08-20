# ADR-0001: Canonical State Is Not a Mutable Bare Repository

- **Status:** Accepted for architecture phase
- **Date:** 2026-08-19
- **Owners:** FrankenGit architecture
- **Refined by:** [`NORMATIVE_PROTOCOL_CONTRACTS.md`](NORMATIVE_PROTOCOL_CONTRACTS.md)

## Context

A traditional Git forge commonly treats a bare repository on local or network storage as the authoritative source of refs and objects, while issues, pull requests, protections, queues, CI, and web state live in separate databases and services. At scale this creates several problems:

- repository placement and failover become control-plane operations with user-visible consequences;
- caches and replicas can accidentally acquire authority;
- a ref update and its forge transition may commit independently;
- whole-repository materialization wastes storage and network when workloads need a sparse subset;
- recovery depends on reconstructing undocumented relationships among Git files, database rows, queues, and indexes;
- agents are encouraged to clone broad state and use ambient credentials rather than request precise context/effects.

Git’s object model is excellent and remains the compatibility contract. The questionable assumption is that one mutable filesystem layout must also be the canonical distributed state machine.

## Decision

FrankenGit canonical truth consists of:

1. immutable native Git objects and typed native Git object IDs;
2. immutable canonical forge-event bodies;
3. sealed logical mutation requests and immutable terminal outcomes;
4. an ordered chain of `RepositoryCommitRecord` values atomically binding ref and forge transitions;
5. authenticated resulting roots and explicit retention roots;
6. fenced writer epochs and a serializable metadata publication point;
7. periodic signed root-last repository capsules for recovery checkpoints.

Bare repositories, packs, commit graphs, indexes, worktrees, CI checkouts, and regional caches are **materializations** derived from canonical truth. They may be complete, sparse, delayed, rebuilt, or discarded. Their local mutation does not become canonical until admitted through the repository transaction protocol.

The initial correctness oracle uses one fenced logical sequencer per repository. Parallel validation, object ingestion, materialization, search, CI, and independent repositories scale horizontally. More parallel canonical commit paths require executable refinement to the single-sequencer semantics.

## Consequences

### Positive

- Ref and forge state can publish atomically through one RCR.
- Repository placement becomes an availability/performance concern rather than truth ownership.
- Materializations can be placed near humans, agents, and CI demand.
- Partial clone and sparse agent workspaces become native rather than afterthoughts.
- Recovery has explicit immutable roots and replay order.
- Search/graph/UI projections can expose exactly how current they are.
- GC and deletion reason from authenticated retention roots, not local reflogs alone.
- Object storage and RaptorQ can improve immutable-byte recoverability without contaminating metadata ordering.

### Negative / costs

- The system must implement and verify Git protocol compatibility rather than delegating all semantics to a local `git-receive-pack` process.
- Canonical encodings, object-location maps, retention roots, RCRs, and projections add engineering complexity.
- A metadata sequencer can become a throughput hotspot if poorly designed.
- Debugging requires tools that relate canonical state to disposable materializations.
- Import/export and disaster recovery need end-to-end rehearsals, not only object-store backups.
- Operators must understand that a local bare repository can be valid yet stale or non-authoritative.

## Rejected alternatives

### A. Treat local bare repositories as truth and replicate them

This preserves conventional implementation simplicity but retains placement coupling, difficult ref/forge atomicity, filesystem-level recovery ambiguity, and expensive whole-repository replication.

### B. Replace Git with a new VCS

Rejected. Ordinary Git clients, object identities, history, and protocol behavior are constitutional compatibility goals. FrankenGit changes server architecture and forge semantics, not the user’s fundamental VCS.

### C. Make object storage the sole source of truth without a metadata state machine

Immutable bytes alone cannot decide current refs, ordering, authorization, idempotency, terminal outcomes, legal holds, or forge transitions. Content addressing is necessary but insufficient.

### D. Active-active asynchronous multi-master ref mutation

Rejected for V1. Conflict-free ref names do not imply conflict-free branch protection, quotas, forge entities, retention, or merge queues. A fenced writer epoch gives a clear correctness oracle.

### E. Put every derived projection inside the canonical transaction

Rejected. Search, graph, UI, notifications, and CI would make commits slow and fragile. Canonical events plus a transactional outbox let projections lag explicitly and repair by replay.

## Invariants

This ADR is satisfied only if executable evidence proves:

- local materialization loss cannot lose canonical committed state;
- a stale materializer or writer cannot publish canonical mutation;
- RCR publication atomically binds ref and forge roots plus terminal outcome;
- retries resolve by stable `TxId` rather than duplicate mutation;
- projection lag cannot authorize a commit without canonical revalidation;
- GC cannot derive deletion solely from local repository reachability;
- a repository capsule binds one exact RCR and cannot masquerade as current state after later RCRs;
- Git object IDs remain native and hash-algorithm typed.

## Follow-up decisions

- ADR for canonical serialization and hash registry;
- ADR for the initial metadata substrate and failover envelope;
- ADR for object segmentation and placement;
- ADR for the V1 Git compatibility subset;
- ADR for licensing before code contributions/releases;
- ADR for CI runner isolation;
- ADR for hosted data residency/deletion claims.
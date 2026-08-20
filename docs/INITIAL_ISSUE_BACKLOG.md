# FrankenGit Initial Implementation Backlog

**Status:** Architecture backlog, not evidence of implementation. Every slice must cite the normative invariant(s) it owns and the evidence gate that closes them. Empty scaffolding is prohibited.

## Sequencing doctrine

A slice is complete only when it provides a final-abstraction vertical capability with typed refusals, cancellation/retry semantics, tests, evidence artifacts, and honest public status. Dependency order is intentional: later product surfaces must not invent their own identity, storage, or mutation semantics.

## G0 — Constitutional and reference foundations

### FG-001 — Canonical encoding and typed identity registry

Deliver versioned canonical codecs and typed identities for repository, tenant, principals, native Git OIDs, internal object IDs, `TxId`, RCR, events, roots, outcomes, refusals, and capsules.

**Evidence:** golden bytes; round-trip/property tests; algorithm/type confusion negatives; cross-platform determinism.

### FG-002 — Pure repository state-machine reference model

Implement an in-memory deterministic model of seals, outcomes, RCR chain, refs, forge positions, policy epochs, writer epochs, outbox, and retention roots.

**Evidence:** model invariants; generated command sequences; deterministic replay; mutation testing.

### FG-003 — Documentation/registry checker

Turn protocol, claim, durable-object, compatibility, refusal, and evidence registries into machine-checked inputs.

**Evidence:** negative fixtures for missing owners, duplicate IDs, contradictory status, unpinned formats, and broken links.

## G1 — Git object and wire correctness

### FG-004 — Safe Git object and pack core

Parse and validate loose objects, pack/index formats, deltas, trees, commits, and tags with strict resource budgets and native SHA-1/SHA-256 typed identities.

**Evidence:** Git corpus differential tests; fuzzing; delta/decompression bombs; malformed object suites; memory/CPU caps.

### FG-005 — Upload-pack reference service

Implement smart-HTTP/SSH fetch paths, v0/v1 compatibility and v2 `ls-refs`/`fetch`, shallow/partial clone, sideband, filters, and promisor receipts.

**Evidence:** matrix of real Git clients; packet transcript goldens; failure compatibility; cancellation and slow-client tests.

### FG-006 — Receive-pack quarantine service

Implement push framing, quarantine, thin-pack completion, object closure, expected-old refs, deletes, force, atomic capability, push options, report-status, and signed-push hooks.

**Evidence:** real client differential corpus; malicious pack cases; atomic multi-ref races; duplicate/retry tests; no fictional protocol-v2 push path.

## G2 — Canonical mutation kernel

### FG-007 — One-node sealed transaction/outcome store

Implement stable `TxId`, seal mismatch refusal, terminal `TxnOutcomeRecord`, and lookup after ambiguous disconnect.

**Evidence:** concurrent duplicate attempts; commit/refusal race; cancellation at every checkpoint; crash before/after terminal publication.

### FG-008 — Repository Commit Record sequencer

Implement fenced writer epoch, pinned snapshot, policy decision input root, RCR chain, resulting ref/forge roots, and serializable linearization.

**Evidence:** stale writer; expected-old race; ref/forge atomicity; sequence/parent continuity; deterministic refusal evidence.

### FG-009 — Immutable staging, promotion, and location map

Stage incoming objects/events before commit, make canonical reachability only through admitted RCR/roots, and promote placement idempotently.

**Evidence:** crash between every stage; orphan collection; committed closure never missing; malicious location/index corruption.

### FG-010 — Transactional outbox

Publish webhook/CI/index/billing effects atomically with the RCR, deliver at least once with stable delivery identities, and repair cursors by replay.

**Evidence:** duplicate delivery, crash/restart, poison consumer, reordering, projection rebuild.

## G3 — Materialization and recovery

### FG-011 — Disposable Git materializer

Build bare/sparse Git views from canonical state; report source RCR/capsule; detect and discard stale/corrupt materializations.

**Evidence:** delete/rebuild drills; byte/behavior equivalence; concurrent readers; bounded startup; partial object availability.

### FG-012 — Root-last repository capsule

Implement unsigned capsule identity, signatures, exact RCR binding, dependency manifests, placement evidence, and root-last publication.

**Evidence:** signature rotation without ID drift; missing dependency; stale capsule; crash at every publication step; restore rehearsal.

### FG-013 — Registered RaptorQ repair for one segment class

Start with one immutable repository segment class; implement bounded encode/decode, independent placement, post-decode commitments, and repair evidence.

**Evidence:** RFC/independent vectors; erasure/bitflip/mixed-symbol attacks; budget exhaustion; restore from damaged placement.

### FG-014 — GC, retention, and deletion protocol

Build authenticated root catalog, mark/prove/grace/sweep phases, legal holds, PR/queue/release/artifact roots, and deletion evidence.

**Evidence:** no-live-root sweep property; replica lag/grace races; legal hold activation; backup expiration; interrupted sweep recovery.

## G4 — Forge semantics

### FG-015 — Event-sourced issues, pull requests, reviews, and projections

Implement immutable events and deterministic projections with explicit canonical positions.

**Evidence:** replay equivalence; projection lag; schema evolution; stable IDs; authorization revalidation.

### FG-016 — Branch protection and merge queue

Evaluate one pinned snapshot, bind review/status/CODEOWNERS evidence, use synthetic queue refs, and invalidate stale results.

**Evidence:** target movement races; bypass evidence; batched queue failure; flaky/retried checks; merge/ref/PR atomicity.

### FG-017 — Webhook and GitHub API compatibility subset

Implement the registered REST/webhook subset with stable pagination, errors, signatures, delivery IDs, and documented divergences.

**Evidence:** contract fixtures against GitHub behavior where legally/technically applicable; replayable endpoint corpus; abuse limits.

### FG-018 — Git LFS service

Implement batch upload/download/verify, resumability, quotas, retention roots, and optional locks.

**Evidence:** official clients; interrupted transfer; digest mismatch; dedup/tenant isolation; GC safety.

## G5 — Agent-native system

### FG-019 — Intent Run and capability broker

Implement sponsor/agent identities, attenuated capabilities, amendments, revocation, and hard budgets.

**Evidence:** privilege-widening negatives; expiry/revocation races; audience confusion; budget exhaustion; audit receipts.

### FG-020 — Context Packet service

Produce provenance-preserving, position-pinned sparse context with explicit omissions and authorization-safe progressive retrieval.

**Evidence:** no unauthorized result; deterministic generation under fixed inputs; source span integrity; budget truncation receipts.

### FG-021 — Sparse COW agent workspace

Materialize immutable base plus run-owned overlay with lazy authorized fetch and structured-concurrency lifecycle.

**Evidence:** no host escape; no credential residue; cancellation through quiescence; reproducible manifest; destructive tool containment.

### FG-022 — Evidence-Carrying Change and verifier policy

Bind proposals, contexts, tools, checks, omissions, claims, non-claims, and machine-enforced independence classes.

**Evidence:** forged receipt negatives; shared-state verifier downgrade; stale-base revalidation; failed/skipped check preservation.

## G6 — Search, graph, CI, and hosted service

### FG-023 — Progressive code/forge search

Implement lexical first results, semantic/graph refinement, source position receipts, deterministic ordering, and graceful degradation.

**Evidence:** relevance corpus; latency/quality artifacts; stale generation behavior; authorization filtering; explanation fidelity.

### FG-024 — Repository/ownership/dependency graph projection

Build immutable generation shards from canonical events/objects and expose position-aware queries.

**Evidence:** replay/rebuild; edge provenance; incremental/full equivalence; malformed-language input limits.

### FG-025 — CI execution trust boundary

Implement runner identity, sandboxing, immutable inputs, secret broker, cache trust domains, artifact provenance, and cancellation.

**Evidence:** escape/metadata/secret attacks; cache poisoning; untrusted fork policy; reproducible receipt; kill/restart.

### FG-026 — Hosted multitenancy and quota accounting

Implement tenant isolation, per-resource quotas, abuse controls, billing evidence, noisy-neighbor protection, and operator override logs.

**Evidence:** cross-tenant probes; quota races; billing reconciliation; admission under overload; reversible statistical controls.

### FG-027 — Multi-node metadata replication and failover

Move the reference mutation kernel onto the selected consensus/transactional substrate with repository epoch fencing.

**Evidence:** partitions, pauses, clock anomalies, stale leaders, rolling upgrade, backup restore, bounded RPO/RTO artifacts.

### FG-028 — Import/export and migration

Import Git/GitHub-compatible source, prove object/ref/forge closure, support incremental cutover and reversible export.

**Evidence:** large/rewrite-heavy fixtures; LFS/releases/issues/PR mappings; dual-run comparison; rollback.

## Release gates

No public alpha until FG-001 through FG-012 and the core portions of FG-014 pass their fault and differential evidence. No “GitHub replacement” claim until the supported rows of `GIT_COMPATIBILITY_MATRIX.md` are implemented and versioned. No “self-healing” claim until at least one registered object class completes an end-to-end corruption/restore lane. No “open source” claim until the license decision is completed.
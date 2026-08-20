# FrankenGit Architecture

This is a condensed topology and ownership map. Canonical mutation and recovery semantics are defined by [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md); evidence requirements are defined by [`VERIFY_SPEC.md`](VERIFY_SPEC.md).

## 1. Architectural rule

FrankenGit separates three categories that conventional forges often blur:

1. **Canonical truth:** immutable objects/events plus the ordered metadata state machine that determines current refs, forge positions, policy, outcomes, and retention roots.
2. **Materializations:** disposable Git repositories, packs, worktrees, indexes, CI checkouts, and caches derived from canonical truth.
3. **Projections/intelligence:** web views, search, graph, notifications, analytics, and agent context derived from canonical truth and carrying explicit source positions.

A materialization or projection may be stale, incomplete, corrupt, or unavailable without becoming an alternative source of truth.

## 2. Component topology

```text
Humans / Git clients / agents / CI / mirrors
                     |
        SSH + smart HTTP + REST/webhooks
                     |
      authentication + coarse admission
                     |
      capability and budget enforcement
                     |
  Git upload-pack / receive-pack gateways
                     |
     quarantine + object graph validation
                     |
   per-repository fenced mutation sequencer
                     |
    pinned snapshot + deterministic policy
                     |
       serializable metadata transaction
          /                         \
 RCR/outcome/roots/outbox      immutable staged bytes
          \                         /
       canonical object/event storage
                     |
     capsules + backups + repair registry
                     |
 materializers / event projections / search / graph
                     |
 Git views, web UX, merge queue, CI, agent packets
```

## 3. Canonical mutation ownership

The canonical mutation kernel owns:

- one `TxId` identity derivation;
- transaction seals and key-reuse mismatch refusal;
- immutable `TxnOutcomeRecord` values;
- writer epoch fencing;
- one pinned repository snapshot per attempt;
- expected-old ref validation and force semantics;
- deterministic policy input/decision records;
- RCR parent/epoch/sequence continuity;
- atomic ref and forge-event roots;
- transactional outbox publication;
- canonical retention-root updates.

The mutation linearizes at one serializable metadata commit. Immutable bodies may be staged beforehand but are not canonical roots until referenced by that commit.

## 4. Git compatibility boundary

The Git gateway is split by actual Git services:

- upload-pack for clone/fetch, including protocol v2 commands where negotiated;
- receive-pack for push;
- SSH and smart-HTTP transports;
- native SHA-1/SHA-256 typed object identities;
- pack/delta/object validation under strict resource budgets;
- atomic push, expected old refs, push options, hidden refs, signatures;
- shallow/partial clone and promisor semantics;
- LFS as a separate content API and retention domain.

Git subprocesses may serve as early oracles/adapters, but they do not own canonical repository state.

## 5. Storage layers

### Immutable object/event layer

Stores native Git objects or canonical immutable envelopes, forge events, evidence, manifests, index generations, artifacts, package blobs, and backup blocks. Placement is content-addressed and idempotent.

### Metadata layer

Stores current repository head/RCR pointer, seals, outcomes, writer epochs, policy pointers, authenticated root pointers, outbox cursors, quotas, memberships, legal-hold activation, and other mutable current state. It requires transactional replication and fencing.

### Materialization cache

Stores rebuildable packs, indexes, bare repositories, workspaces, commit graphs, bitmaps, and projection shards. Cache eviction and corruption cannot delete canonical truth.

## 6. Capsules and recovery

A repository capsule is a signed root-last checkpoint for one exact RCR. Its unsigned body binds ref, forge-position, object-manifest, segment-manifest, retention, policy, and registry roots. Signatures and placement attestations are outside the capsule identity.

Recovery starts from a trusted capsule/RCR and replays later RCRs/events. A stale capsule is still a valid historical checkpoint but never current-state authority.

## 7. RaptorQ boundary

RaptorQ protects registered immutable byte classes only. Decode occurs in quarantine and reconstructed bytes must pass the original digest, Merkle, Git-OID, length, and structural checks. Mutable metadata correctness never depends on fountain-code reconstruction.

## 8. Forge/event model

Issues, pull requests, reviews, protections, queue transitions, releases, and policy changes are immutable canonical events. Deterministic projections build UI/read models. An RCR can bind a forge-event batch to a ref mutation, eliminating split commit states.

The outbox drives webhooks, CI, indexing, notifications, and billing at least once with stable delivery identities. Projection or delivery failure does not roll back canonical history.

## 9. Agent plane

Intent Runs provide attenuated capabilities and hard budgets. Context Packets are source-position-pinned and provenance preserving. Sparse workspaces have immutable bases and COW overlays. External effects go through a broker with idempotency and receipts. Evidence-Carrying Changes preserve tests, tools, omissions, claims, non-claims, and verifier independence.

## 10. Scale strategy

The design scales independent work before weakening semantics:

- repositories shard naturally;
- upload, pack validation, immutable object writes, materialization, search, graph, and CI parallelize;
- hot objects and packs cache regionally;
- large immutable records segment and stream;
- background compaction/checkpoint/repair are budgeted;
- one logical sequencer per repository remains the correctness oracle.

A future parallel canonical path must prove observational equivalence for overlapping invariant keys; it is not assumed from disjoint ref names.

## 11. Failure model

The architecture explicitly handles:

- duplicate/retried requests and ambiguous disconnects;
- process/node crash at every publication phase;
- stale writer after failover;
- object-store timeout/partial write/listing lag;
- corrupted/missing immutable placement;
- projection lag and rebuild;
- cancellation during validation, commit, materialization, and effects;
- slow/malicious Git clients and pack bombs;
- compromised CI jobs and prompt-injected agent context;
- quota exhaustion and noisy neighbors;
- rolling upgrades and mixed format versions.

Each subsystem publishes typed refusals and evidence rather than relying on panic or implicit retry.

## 12. Initial crate/service boundaries

Names are provisional until first final-abstraction slices land:

- foundation types/canonical codec/crypto registry;
- Git object and pack core;
- Git protocol gateway;
- transaction/reference model;
- metadata sequencer;
- immutable object/event store;
- policy engine and evidence records;
- materializer;
- capsule/backup/repair;
- forge events/projections;
- search/graph;
- agent protocol/workspace/effect broker;
- CI execution boundary;
- hosted control plane;
- conformance/fault laboratory.

No empty crate should be created merely to match this list. A crate appears with its first complete vertical slice and evidence.
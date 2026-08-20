# Initial Public Issue Backlog

**Status:** proposed G0/G1 backlog
**Last updated:** 2026-08-19

This backlog converts the first critical path into issue-sized, evidence-bearing work. It is intentionally dominated by schemas, models, fixtures, and recovery rather than UI scaffolding.

Suggested labels:

- `area:truth`, `area:git`, `area:repair`, `area:agent`, `area:security`, `area:verification`, `area:ops`;
- `type:spec`, `type:model`, `type:implementation`, `type:research`, `type:counterexample`;
- `gate:G0`, `gate:G1`;
- `risk:critical`, `good-first-counterexample`.

Each issue should copy the change requirements from [CONTRIBUTING.md](../CONTRIBUTING.md) and link the affected claim/invariant.

---

## Dependency sketch

```text
FG-001 terminology/claim registry
  ├─> FG-002 canonical codec
  │     ├─> FG-003 Git object identity
  │     │     └─> FG-004 object envelope/segment
  │     │            └─> FG-012 local object store
  │     ├─> FG-005 RefTxn identity
  │     │     └─> FG-006 Repository Commit Record model
  │     │            ├─> FG-007 atomic ref/event model
  │     │            ├─> FG-008 capsule model
  │     │            └─> FG-013 single-node commit store
  │     ├─> FG-009 capability model
  │     └─> FG-010 evidence format
  ├─> FG-011 deterministic simulator
  └─> FG-018 Git compatibility registry

FG-004 + FG-008 + FG-012 + FG-013
  ├─> FG-014 import/export vertical slice
  ├─> FG-015 push/fetch vertical slice
  ├─> FG-016 clean-room recovery/doctor
  └─> FG-017 RaptorQ reconstruction slice
```

---

## FG-001 — Create executable terminology and claim registries

**Labels:** `gate:G0`, `area:verification`, `type:spec`, `risk:critical`

### Objective

Represent every constitutional claim and project term in machine-validated data rather than prose alone.

### Acceptance

- schema for claim ID, statement, scope, owner, status, evidence level, falsifier, dependencies, and artifacts;
- initial rows for all invariants in `ARCHITECTURE.md` and `VERIFY_SPEC.md`;
- terminology registry matching `docs/TERMINOLOGY.md`;
- validator rejects duplicate IDs, unknown statuses, missing falsifiers, broken dependencies, and unregistered normative terms;
- generated Markdown is byte-deterministic;
- no implementation claim starts above E0/E1 without attached evidence.

---

## FG-002 — Specify the canonical codec and golden-vector envelope

**Labels:** `gate:G0`, `area:truth`, `type:spec`, `risk:critical`

### Objective

Freeze the rules used to hash and sign truth-plane structures.

### Acceptance

- canonical encoding profile and schema-version/domain-separation rules;
- unknown required/optional field semantics;
- unsigned-body versus signature/receipt envelope convention;
- golden vectors for valid and invalid encodings;
- independent minimal decoder or cross-language verifier plan;
- mutation tests prove semantically equivalent but noncanonical bytes are rejected or normalized before identity;
- no floats or platform-dependent values in initial canonical schemas.

---

## FG-003 — Build exact Git object framing and identity corpus

**Labels:** `gate:G0`, `area:git`, `type:implementation`, `risk:critical`

### Objective

Parse, frame, hash, and round-trip Git blob/tree/commit/tag objects exactly for declared SHA-1 and SHA-256 profiles.

### Acceptance

- streaming, checked-arithmetic parser with byte/object/depth budgets;
- exact OID computation over canonical Git framing;
- fixtures from ordinary Git plus malformed/adversarial corpus;
- algorithm-tagged identities;
- collision-risk policy hooks for SHA-1;
- differential results against supported Git versions;
- no untrusted-input panic or unbounded allocation.

---

## FG-004 — Specify Franken Object Envelope and deterministic segment v1

**Labels:** `gate:G0`, `area:truth`, `area:repair`, `type:spec`, `risk:critical`

### Objective

Define the immutable storage unit around exact Git objects without changing their bytes.

### Acceptance

- envelope body/signature identity rules;
- deterministic microsegment ordering, record framing, indexes, Merkle footer, and digest;
- source-block partition and encryption-profile fields;
- random-access lookup and complete segment verification;
- corruption, truncation, duplicate, mixed-domain, and nondeterministic-builder tests;
- explicit size/latency hypotheses and a loose-object/pack baseline.

---

## FG-005 — Formalize RefTxn identity, idempotency, and typed refusals

**Labels:** `gate:G0`, `area:truth`, `type:model`, `risk:critical`

### Objective

Make one command identity map to one permanent terminal result.

### Acceptance

- canonical intent body, signature, idempotency key, and `TxnId` derivation;
- same key/different body always returns `IDEMPOTENCY_CONFLICT`;
- permanent mapping survives checkpoint/compaction;
- exact read/write/invariant-key semantics;
- atomic multi-ref operations and force-push policy inputs;
- temporary status unavailability is distinct from a terminal result;
- property tests for replay, duplicate, expiry, stale epoch, and signature variation.

---

## FG-006 — Model Repository Commit Record and authority domains

**Labels:** `gate:G0`, `area:truth`, `type:model`, `risk:critical`

### Objective

Define the one canonical linearization artifact for ref-only, forge-only, and combined effects.

### Acceptance

- body/receipt schema and ID derivation;
- authority-domain and commit-position semantics;
- reserved-position/gap/abort recovery rule;
- immutable ref-delta, canonical-event, policy/evidence, durability, outbox, and capsule children;
- exact commit point and stale-writer fence;
- no deployment-global sequence assumption;
- model proves every accepted record has one predecessor/order in its domain.

---

## FG-007 — Prove atomic ref and forge-event effects

**Labels:** `gate:G0`, `area:truth`, `area:verification`, `type:model`, `risk:critical`

### Objective

Prevent a merge decision, release, or protected deployment from detaching from the ref effect it authorized.

### Acceptance

- combined transaction model with expected aggregate versions;
- crash before commit exposes neither effect;
- crash after commit reconstructs both without a projector;
- outbox retry cannot duplicate canonical events;
- stale ref or aggregate version conflicts deterministically;
- pull-request merge example and counterexample corpus;
- all small-state schedules explored under deterministic faults.

---

## FG-008 — Specify Repository Capsule v1 and root-last publication

**Labels:** `gate:G0`, `area:truth`, `area:repair`, `type:model`, `risk:critical`

### Objective

Create a compact, independently verifiable root for one recoverable repository generation.

### Acceptance

- unsigned body/signature envelope and capsule ID;
- predecessor, ref root, commit/event positions, manifests, policy/key epochs, retention, and durability witness;
- historical placement witness distinguished from live placement catalog;
- current-pointer and recovery semantics;
- root-last crash matrix;
- metadata, sampled, full, reconstruction, export, and application verification levels;
- no client clock or signature encoding affects canonical order/identity incorrectly.

---

## FG-009 — Model capability attenuation and authority-free repository content

**Labels:** `gate:G0`, `area:agent`, `area:security`, `type:model`, `risk:critical`

### Objective

Ensure no agent, workflow, integration, or child task can expand authority from untrusted text.

### Acceptance

- capability schema with subject, audience, selectors, expiry, budget, parent, and caveats;
- attenuation proof/checker;
- replay, audience, revocation, and confused-deputy cases;
- repository/issue/tool text represented as untrusted data channel;
- child delegation cannot widen any selector or quota;
- red-team fixtures for prompt-injected capability requests and secret access.

---

## FG-010 — Specify evidence records and Evidence-Carrying Change v1

**Labels:** `gate:G0`, `area:verification`, `area:agent`, `type:spec`

### Objective

Bind engineering claims to reproducible artifacts instead of prose assertions.

### Acceptance

- claim, command/procedure, input, environment, output, outcome, scope, verifier, and invalidation fields;
- immutable artifact identities and redaction policy;
- requirement-disposition completeness check;
- distinction among pass, fail, refusal, and indeterminate evidence;
- independent verifier relationship;
- generated human and compact-agent views over the same bytes.

---

## FG-011 — Build deterministic state-machine and fault simulator skeleton

**Labels:** `gate:G0`, `area:verification`, `type:implementation`, `risk:critical`

### Objective

Explore transaction, cancellation, crash, partition, and recovery interleavings before distributed code exists.

### Acceptance

- explicit seeded scheduler and virtual clock;
- fault points at every durable action/yield;
- crash, duplicate, reorder, delay, loss, partition, stale read, disk-full, corruption, cancellation, and key/policy rotation primitives;
- state hashing and replay trace minimization;
- oracles for ref/event atomicity, idempotency, fencing, root-last, and quiescence;
- exhaustive small-state and randomized larger campaigns in CI.

---

## FG-012 — Implement local immutable object store and placement catalog

**Labels:** `gate:G1`, `area:truth`, `type:implementation`, `risk:critical`

### Objective

Persist admitted envelopes/segments under immutable keys with explicit verification and no bucket-listing correctness dependency.

### Acceptance

- put-if-absent and conflicting-put incident behavior;
- exact range read and full verification;
- quarantine versus admitted catalog state;
- live placement catalog separate from capsule witness;
- scrub, suspect, repair-candidate, and deletion states;
- crash and filesystem-corruption campaign;
- adapter behavior report suitable for future object stores.

---

## FG-013 — Implement single-node authority-domain commit store

**Labels:** `gate:G1`, `area:truth`, `type:implementation`, `risk:critical`

### Objective

Persist Repository Commit Records, ref roots, aggregate versions, permanent idempotency results, and capsule pointers atomically on one node.

### Acceptance

- observable behavior matches the G0 reference model;
- atomic ref-only, forge-only, and combined records;
- fencing/incarnation/cell epoch even in single-node format;
- crash after every write/fsync boundary;
- permanent idempotency compaction/checkpoint;
- deterministic recovery and doctor output;
- no direct projection mutation path.

---

## FG-014 — Complete ordinary-Git import/export vertical slice

**Labels:** `gate:G1`, `area:git`, `type:implementation`

### Objective

Import a real repository into canonical state and export a fresh ordinary Git repository with exact visible history.

### Acceptance

- refs, tags, symbolic refs, object format, modes, and object bytes preserved for supported tier;
- initial capsule and recovery roots generated;
- delete source repository before export;
- reference `git fsck` and deterministic ref comparison;
- unusual names, encodings, large blobs, deep history, and dangling-object policy fixtures;
- export requires no FrankenGit runtime to inspect source history afterward.

---

## FG-015 — Complete clone/fetch/push vertical slice

**Labels:** `gate:G1`, `area:git`, `area:truth`, `type:implementation`, `risk:critical`

### Objective

Serve and mutate the canonical repository through ordinary Git for the first declared compatibility tier.

### Acceptance

- protocol negotiation and bounded pack/object admission;
- exact object-before-ref durability;
- atomic multi-ref push;
- status retry by transaction identity;
- generated pack verified against requested reachable closure;
- stale worker and concurrent-disjoint/conflicting push fixtures;
- differential client matrix and packet traces;
- deletion of materialized bare repo during read traffic causes latency/rebuild, not wrong refs.

---

## FG-016 — Build clean-room recovery and doctor command

**Labels:** `gate:G1`, `area:ops`, `area:repair`, `type:implementation`, `risk:critical`

### Objective

Prove recoverability from canonical state rather than from a privileged filesystem snapshot.

### Acceptance

- fresh host with only declared canonical object/commit/capsule/key inputs;
- rebuild ref state, event state, idempotency map, and ordinary Git export;
- verify capsule chain, manifests, transactions, event batches, retention roots, and placement health;
- sampled and full modes;
- typed insufficient-recovery report;
- machine-readable signed/hashed evidence bundle;
- reproducible destructive drill script.

---

## FG-017 — Implement one registered RaptorQ reconstruction slice

**Labels:** `gate:G1`, `area:repair`, `type:implementation`, `risk:critical`

### Objective

Close the first real permeation-map row for immutable repository segments.

### Acceptance

- deterministic source-block/symbol identities and parameters;
- source plus repair placement policy;
- arbitrary erasure, duplicate, corrupt, mixed-object, truncated, and excessive-symbol tests;
- bounded cancellation-safe encode/decode;
- exact digest/Merkle/record/Git-OID verification after decode;
- no mutation of canonical placement until verification;
- measured comparison with full replication and fixed erasure-code baseline;
- destructive reconstruction evidence, not only round-trip tests.

---

## FG-018 — Seed the executable Git compatibility registry

**Labels:** `gate:G0`, `area:git`, `area:verification`, `type:research`

### Objective

Define exactly what “Git compatible” means for G1.

### Acceptance

- supported Git client versions/platforms and object formats;
- operation matrix for init/import/clone/fetch/push/atomic push/delete/symref/tag/shallow/partial/signature behavior;
- repository-shape corpus;
- expected wire/object/ref outcomes;
- explicit unsupported and deferred cells;
- harness can run ordinary Git as oracle and preserve packet/object evidence;
- compatibility badge/report generated only from passing registry rows.

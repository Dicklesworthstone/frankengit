# CALM Coordination Registry and Obligation-Typed Effects

**Status:** normative architecture profile  
**Version:** 1.1  
**Last revised:** 2026-08-20

FrankenGit distinguishes operations that can converge safely without coordination from operations whose meaning depends on absence, replacement, uniqueness, ordering, or revocation. It also represents every effect that can be abandoned by cancellation as an explicit obligation with a terminal disposition.

These two ideas are mutually reinforcing:

- the CALM registry says **where coordination is semantically necessary**;
- obligations say **who owns unfinished effect work and how it closes**.

## 1. CALM rule

A monotone computation may proceed coordination-free when adding information cannot invalidate an earlier result. Non-monotone operations require an ordering or coordination boundary.

FrankenGit does not use “eventual consistency” as a blanket architecture choice. Every operation named in this document’s tables has a checked-in classification in `registries/calm_operations.tsv`, and the closed class vocabulary is exactly:

- `monotone_with_authentication`: grow-only information whose union cannot invalidate earlier results, admitted only after identity/authorization verification;
- `monotone_scoped`: grow-only within one locally authorized scope (for example a verified cache); discardable without correctness loss;
- `commutative_but_bounded`: algebraically mergeable state with declared bounds, overflow behavior, and reset/regime semantics; inherently retractable observations (such as availability) belong here, never in a monotone class;
- `local_deterministic`: pure deterministic computation over pinned inputs; produces ordering or advice, never shared truth;
- `ordered_projection`: publication through a subordinate monotone anti-rollback authority (for example generation activation);
- `head_cas_required`: meaning depends on absence, replacement, uniqueness, or revocation; only the repository authority head can decide it;
- `exclusive_external_effect`: one externally observable side effect owned by an outbox obligation with stable idempotency.

An operation classified in a class this vocabulary does not define is a registry defect. The row names its proof argument, authority owner, replay semantics, and forbidden shortcuts.

## 2. Coordination-free operations

Examples that are monotone after identity/authentication checks:

- put an immutable Git object under its verified identity;
- add an immutable repair symbol or placement receipt;
- add a scrub, benchmark, conformance, or verification artifact;
- add an append-only audit/evidence record;
- cache a verified object or pack view inside an already authorized scope;
- publish a candidate search/graph generation body before activation;
- add a Context Packet candidate before final bounded selection;
- add a direct `TxId` outcome pointer that exactly matches canonical decision history;
- warm a materialization from an authenticated authority head.

Authentication, quotas, and resource reservations still apply. “Coordination-free” means no global order is needed for the logical union; it does not mean anonymous writes are accepted.

Peer and piece availability hints are deliberately **not** in this class: a peer departing or dropping a piece retracts earlier positive facts, so availability is `commutative_but_bounded` state with explicit reset/regime semantics (see §4), never a grow-only union.

## 3. Coordinated operations

Operations that depend on replacement, absence, uniqueness, revocation, or current policy require authority:

- move/delete a ref;
- assign a terminal outcome to a sealed `TxId`;
- merge/close/reopen a PR when state transitions are exclusive;
- activate a policy, search, graph, compaction, or checkpoint generation;
- revoke or widen a capability;
- remove a retention/legal-hold root;
- publish one package version where immutability/uniqueness is promised;
- advance repository authority head;
- charge a non-idempotent external account;
- release a globally exclusive lock/lease whose current owner matters;
- publish a destructive GC sweep;
- rotate a key in a way that retires old decryptability.

These operations flow through head CAS, a subordinate anti-rollback authority, or an external idempotent effect protocol.

## 4. Commutative but bounded operations

Some updates are algebraically mergeable but cannot grow without limit:

- counters with escrowed quota domains;
- set additions with cardinality caps;
- telemetry sketches;
- availability/health summaries;
- agent progress observations;
- piece availability maps;
- cache popularity estimates.

Their registry row specifies:

- algebra/lattice;
- bound/compaction rule;
- overflow behavior;
- whether approximation is allowed;
- whether result can influence canonical policy;
- reset/regime semantics.

No unbounded CRDT metadata is allowed to become an operational denial-of-service vector.

## 5. Conflict-absorbing lattices

Non-canonical replicas use conflict-absorbing states instead of last-writer-wins. For transaction observation:

```text
          Conflict
          /      \
   Committed    Refused
          \      /
          Reserved
              |
           Unknown
```

Joining `Committed` and `Refused` yields `Conflict`, which is sticky evidence and blocks service until canonical authority is consulted. Timestamp choice cannot erase contradictory terminal facts.

Similar lattices may represent:

- object verification: unknown → observed → verified/rejected → conflict;
- placement: absent → staged → verified/retired → conflict;
- runner result: unknown → running → succeeded/failed/cancelled → conflict when incompatible terminals appear;
- review evidence: absent → submitted → accepted/revoked with explicit policy ordering.

The canonical repository head is not a CRDT. Lattices improve diagnosis and projection convergence around canonical truth.

## 6. Obligation model

An obligation follows the normative lifecycle: `Reserved -> Committed -> Acknowledged`, or `Reserved -> Aborted` (reserve/commit remain the two-phase effect boundary; acknowledgement is the separate external-observation record). Commit makes the effect canonically owned; acknowledgement separately records that the external recipient observed it. A committed obligation may therefore outlive its region only as an explicit unacknowledged-effect record, never as silently dropped work:

```rust
trait Obligation {
    type CommitReceipt;
    type AbortReceipt;
    type AckEvidence;

    fn commit(self, receipt: Self::CommitReceipt) -> CommittedObligation<Self::AckEvidence>;
    fn abort(self, receipt: Self::AbortReceipt) -> SettledObligation;
}

impl<A> CommittedObligation<A> {
    fn acknowledge(self, evidence: A) -> SettledObligation;
}
```

Effects with no external observer (for example a local placement write) acknowledge trivially at commit. Effects with an external recipient (webhooks, CI dispatch, billing) remain `Committed` until the acknowledgement evidence arrives; retry after commit is idempotent and cannot duplicate the canonical effect.

Public obligation and committed-obligation types are `#[must_use]`. Dropping a reserved obligation without an explicit transfer, commit, or abort — or dropping a `CommittedObligation` without acknowledgement or an explicit unacknowledged-effect record — is a correctness failure in lab/test profiles and a typed containment event in hardened production profiles.

### 6.1 Resource algebra

Obligations carry graded resources such as:

- bytes;
- objects/pieces;
- CPU time;
- memory;
- file descriptors/sockets;
- network egress;
- money/quota;
- secret exposure duration;
- failure-domain slots;
- human approval capacity.

Combining obligations composes their grades. Splitting requires a conservation proof. A child region cannot mint authority or budget from nothing.

## 7. Core FrankenGit obligations

### 7.1 `ObjectAdmissionPermit`

Reserved after quota and object-class checks. Commits only after bytes, native OID, strong digest, length, and structure verify. Aborting releases staging/quota reservations.

### 7.2 `PreparedTxnSlot`

A preparation lane reserves a combiner slot. Commit transfers ownership to a decision-batch attempt; abort records why no candidate was published.

### 7.3 `HeadCasAttempt`

Binds expected authority version, candidate head, decision batch, credentials, and deadline. It commits with the store’s winning version token or aborts with a lost-CAS/failure receipt. A lost CAS is normal control flow, not an exception that may leak candidate state.

### 7.4 `OutboxEffectPermit`

Owns one external effect delivery. Reserve records idempotency key and precondition RCR. Commit stores the exact downstream acknowledgement. Abort/retry preserves ownership until policy marks terminal failure or human intervention.

### 7.5 `SecretLease`

Binds secret class, consumer, delivery handle, allowed effect, expiration, and revocation. Region closure revokes and drains any process/channel that could still use it.

### 7.6 `WorkspaceLease`

Owns overlay, mount/materializer, subprocesses, lazy object credentials, temp outputs, and final snapshot. Commit publishes a workspace/evidence result; abort tears down and records incomplete outputs.

### 7.7 `RunnerSlot`

Owns sandbox capacity, image/toolchain, network policy, cache namespace, logs, artifact outputs, and child processes. Cancellation does not return until reaping/finalization or explicit non-cooperative containment.

### 7.8 `RetentionPin`

Protects canonical objects during open PR, merge queue, migration, backup, legal hold, active seal, or restore. Release is coordinated because absence enables deletion.

### 7.9 `RepairPermit`

Owns decode budget, source symbols, candidate output, verification, placement write, and authority publication. Decoder success cannot auto-commit the permit.

### 7.10 `ContextBudgetPermit`

Owns token/byte/search/graph/model budget and authorization scope for one Context Packet. Commit emits complete inclusion/omission receipts; abort preserves partial evidence without presenting it as a complete packet.

### 7.11 `BillingReservation`

Reserves a bounded charge before costly hosted effects. Commit binds actual usage; abort releases unused amount. Statistical estimates may size the reservation but cannot silently bill beyond it.

## 8. Structured-concurrency regions

Every long-lived operation has one ownership region:

- request/session;
- push/fetch transfer;
- repository decision preparation;
- materializer catch-up;
- agent Intent Run;
- CI job;
- graph/search generation build;
- compaction;
- scrub/repair;
- webhook delivery;
- backup/restore;
- local release run.

Region close is:

```text
request cancellation
  -> stop new admissions
  -> propagate cancellation
  -> drain two-phase primitives
  -> settle obligations
  -> run masked/budgeted finalizers
  -> reap subprocesses/mounts/sockets
  -> publish terminal region receipt
  -> quiescent
```

A function returning while an owned task can still push, write, use a secret, upload an artifact, or charge money violates the contract.

## 9. Two-phase primitives

Covered effect paths use reserve/commit:

- queue send;
- output file publication;
- object promotion;
- authority CAS attempt;
- artifact/release publication;
- secret delivery;
- package version creation;
- runner allocation;
- repair placement;
- webhook dispatch.

The reserve phase is cancellation-safe and produces no externally committed effect. The commit phase is intentionally small and either infallible after reservation or returns a receipt whose ambiguity can be resolved by idempotency lookup.

Inherently partial I/O publishes its boundary. `write_all` over an arbitrary socket is not magically cancellation-safe; the protocol layers sequence numbers, hashes, resumability, and receiver acknowledgements around it.

## 10. CALM registry examples

| Operation | Class | Why | Authority |
|---|---|---|---|
| Put verified Git object | `monotone_with_authentication` | adding immutable identity cannot invalidate prior objects | object admission capability |
| Add repair symbol | `monotone_with_authentication` | enlarges recovery set | repair capability |
| Cache verified pack | `monotone_scoped` | local optimization only | cache grant |
| Add review comment event | `head_cas_required` | entity sequence and permissions matter | repository authority head |
| Move branch ref | `head_cas_required` | replacement/expected-old semantics | repository authority head |
| Activate search generation | `ordered_projection` | old/new choice and anti-rollback | generation authority |
| Remove legal hold | `head_cas_required` | absence permits deletion | repository authority head |
| Deliver webhook | `exclusive_external_effect` | external side effect; at-least-once/idempotency | outbox obligation |
| Add telemetry observation | `commutative_but_bounded` | mergeable but retained window is bounded | telemetry profile |
| Merge peer availability map | `commutative_but_bounded` | retractable observations need reset/regime semantics | availability profile |
| Rank Context candidates | `local_deterministic` | ordering only, not truth | context planner |

## 11. Deterministic verification

The deterministic lab lane must verify, before any related claim advances past proposal:

- every obligation settles;
- loser races drain;
- cancellation at every reserve/commit boundary;
- no budget/authority is duplicated during split/transfer;
- CALM-classified monotone operations converge under reorder/duplicate/drop;
- coordinated operations fail under intentionally removed coordination, proving the registry row is load-bearing;
- conflict lattices never collapse incompatible terminals;
- non-cooperative subprocess/I/O behavior is contained and named;
- crashpacks contain region tree, obligation graph, capabilities, budget state, decision IDs, and replay seed.

## 12. Statistical controls

Conformal/e-process or no-regret systems may tune:

- queue/batch size;
- retry wait;
- path race width;
- repair overhead;
- cache/prefetch budget;
- context expansion;
- scrub priority.

They may not reclassify a non-monotone operation as coordination-free, mint obligation resources, suppress a settlement failure, or override hard safety bounds. Promotion occurs through identity-bound policy epochs with deterministic fallback.

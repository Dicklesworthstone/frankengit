# Agent Control Plane Effect Authorization

**Status:** companion implementation contract; not repository authority  
**Owning architecture:** [`AGENT_CONTROL_PLANE_ARCHITECTURE.md`](AGENT_CONTROL_PLANE_ARCHITECTURE.md)  
**Protocol:** [`AGENT_PROTOCOL.md`](AGENT_PROTOCOL.md) §6 and §9  
**Implementation ledger:** [`AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`](AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md)  
**Owning crate:** `crates/fgit-agent`

## 1. Purpose

Capability authentication and attenuation answer one question:

> Did an issuer authorize this exact non-widening capability ancestry?

They do not answer another:

> Is every link still valid under current repository policy at the instant the effect becomes consequential?

The Agent Protocol requires high-value operations to answer both questions at effect time. The implementation therefore composes four distinct final-abstraction layers:

```text
sealed capability ancestry
    -> VerifiedCapabilityChain

exact authenticated authority read + complete Intent Run
    -> CapabilityRevocationReadRequest
    -> CapabilityRevocationReceipt

verified chain + fresh revocation receipt + exact effect request
    -> CapabilityEffectAuthorization

request-time authorization
    -> RevocationAuthorizedEffectGrant
    -> RevocationAuthorizedOutboxEffect
    -> fresh dispatch-time authorization
    -> RevocationAuthorizedDeferredOutboxEffect
```

None of these objects publishes repository state or becomes an authority source. Revocation evidence may refuse an effect; it may not mint capability, widen scope, move a ref, close a task, or rewrite the authority head.

## 2. Exact named-position revocation read

`CapabilityRevocationReadRequest` binds:

- the exact `AuthorityReadReceiptId`;
- repository ID;
- authority-head ID and generation;
- numeric `RunId`;
- complete `IntentRunCommitment`;
- logical request instant;
- explicit maximum age;
- hard row ceiling.

The read adapter receives this complete request. A response is admitted only when it names the exact request and returns:

- a nonzero revocation-generation commitment;
- a logical observation not earlier than the request;
- no more rows than both the request and system limits;
- a nonzero reader/decoder profile;
- canonically ordered, duplicate-free capability identities;
- an evidence root;
- a freshness deadline that does not overflow logical time or exceed run expiry.

The receipt retains the complete authenticated authority read. A head ID or generation alone is not interchangeable with that read event.

### 2.1 Freshness

The interval is half-open:

```text
observed_at <= effect_time < valid_until
```

A receipt used exactly at `valid_until` is stale. No grace period, wall-clock guess, cache timestamp, or “recent enough” heuristic exists outside the committed maximum age.

## 3. Complete capability ancestry

`VerifiedCapabilityChain::verify` receives the root-first sealed chain and issuer key. It refuses:

- empty key material;
- an empty chain;
- more than the hard link limit;
- repeated capability identities;
- authenticator mismatch;
- absent or substituted ancestry;
- parent-tag mismatch;
- operation amplification;
- quota amplification;
- validity-window widening;
- unknown operation-class bits;
- unrepresentable canonical framing.

The chain identity commits every link's:

- capability ID and parent;
- operation set;
- resource quota;
- validity interval;
- depth;
- parent tag;
- authenticator.

Verifying only the leaf is not equivalent. Revocation of any ancestor invalidates the leaf for a new high-value effect.

## 4. Exact effect authorization

`CapabilityEffectAuthorization` binds one exact high-value `EffectRequest` to:

- the verified chain identity;
- leaf capability identity;
- revocation receipt identity and generation;
- exact authority read;
- numeric run and complete run commitment;
- effect ID and parent effect ID;
- operation class;
- full resource cost vector;
- canonical input commitment;
- authorization instant;
- derived exclusive validity deadline.

Authorization rechecks:

1. the operation belongs to the revocation-gated class set;
2. run, receipt, and authority read are identical;
3. the receipt is fresh;
4. the run remains open;
5. the leaf remains inside its validity window;
6. no ancestry identity appears in the revocation set;
7. run and leaf both authorize the operation;
8. the leaf quota dominates the request cost;
9. the resulting validity interval is nonempty.

The deadline is the minimum of revocation freshness, run expiry, and leaf expiry.

## 5. Request acceptance is not irreversible dispatch

For an external effect, these are separate boundaries:

```text
request accepted
    -> run budget reserved

outbox reserved
    -> typed obligation created

outbox dispatched
    -> downstream-visible effect may have happened

reconciliation
    -> committed responsibility is acknowledged, failed, or escalated
```

A proof fresh during request acceptance may be stale before dispatch. Returning the raw `ReservedOutboxEffect` from the production checked broker would therefore create a time-of-check/time-of-use bypass.

The public `RevocationCheckedEffectBroker` instead returns `RevocationAuthorizedOutboxEffect`. That value exposes only:

- its initial authorization;
- exact effect request;
- effect identity;
- abort-before-dispatch.

It does not expose the raw dispatch method.

`dispatch_authorized_outbox` constructs a new `CapabilityEffectAuthorization` from:

- the broker's exact complete run;
- a newly supplied verified chain;
- a newly supplied revocation receipt;
- the retained exact effect request;
- the actual dispatch logical instant.

It additionally requires the same verified chain identity and leaf capability that authorized initial acceptance. Only then may the typed outbox obligation commit.

## 6. Cleanup asymmetry

Revocation stops new consequential work. It must not prevent responsibility cleanup.

Therefore:

- a refused or stale dispatch returns the still-live `RevocationAuthorizedOutboxEffect`;
- that reservation may be aborted without another revocation read;
- a committed dispatch retains both request-time and dispatch-time authorizations;
- the deferred obligation may enter ordinary stable-key reconciliation even after later revocation;
- acknowledgement, terminal failure, escalation resolution, cancellation, and containment remain available because they reduce or resolve debt.

This is the same lifecycle asymmetry used elsewhere in the control plane:

```text
continue work
    -> freshness and authority required

stop, abort, reconcile, contain
    -> must remain available after expiry or revocation
```

## 7. Effect record and journal identity

`EffectRecord` carries both:

```text
run_id
run_commitment
```

`RunId` is a coordination handle. `IntentRunCommitment` binds the complete machine scope:

- exact authority-read event or explicit legacy basis;
- allowed operation classes;
- resource budget;
- expiry.

The broker computes the commitment before budget moves. Journal replay establishes the numeric and complete run identities from its first acceptance and refuses any later row that differs.

A same-ID run with another budget, expiry, operation set, or authority read cannot be merged into one replayed effect inventory.

## 8. Complete-run reconciliation and cancellation

`RunReconciliationReport` v2 commits the complete run identity in both its report header and every effect row. It rejects a same-ID/different-commitment record before authority, operation, lifecycle, or resource interpretation.

The public cancellation facade v2 commits the same run identity. It validates:

- latest situation;
- active claim when present;
- initial reconciliation report;
- supplied run;
- final reconciliation report.

A report produced for another complete run cannot request or finish cancellation merely because the numeric `RunId` matches.

## 9. Refusal ordering

The implemented ordering preserves the most useful diagnosis and prevents side effects before identity is known:

### 9.1 Revocation read

```text
bounds/time
-> exact run and authority
-> adapter profile and adapter result
-> request identity
-> generation/time/row validation
-> canonical receipt
```

### 9.2 High-value authorization

```text
operation class
-> complete run and exact authority
-> freshness
-> run/capability validity
-> ancestor revocation
-> operation scope
-> quota
-> canonical authorization
```

### 9.3 Broker admission

```text
effect-ID duplicate
-> complete run identity
-> run/capability time window
-> run scope
-> capability scope
-> capability quota
-> run budget reservation
-> journal append
```

### 9.4 External dispatch

```text
dispatch-evidence capacity
-> fresh exact-request authorization
-> exact chain and leaf continuity
-> authorization window
-> typed obligation commit
-> journal transition
```

No refusal before the obligation commit is allowed to consume the reservation. A refusal after commit retains the deferred obligation for reconciliation.

## 10. Threats closed by this slice

The implementation directly addresses:

- revoked root with apparently valid leaf;
- stale cached revocation decision;
- revocation read from another repository/head/read event;
- same numeric run ID with changed machine scope;
- altered request cost or input under a reused effect ID;
- request-time proof reused after expiry;
- capability chain swapped between reservation and dispatch;
- raw outbox dispatch bypass from the checked broker;
- dispatch refusal that loses the reservation;
- journal replay that merges effects from distinct complete runs;
- final cancellation report substituted from another complete run.

## 11. Explicit non-claims

This slice does not provide:

- a concrete canonical revocation registry or policy-event schema;
- a durable revocation index, cache, or invalidation transport;
- a production adapter reading revocations from the authority-selected policy state;
- durable codecs or migrations for the new receipts and authorizations;
- process, workspace, secret, credential, tunnel, upload, or VM reaping;
- a general action-packet executor;
- network, secret-provider, runner, forge, and publication host integration;
- later-head ancestry proof;
- canonical repository publication;
- a stable CLI, native API, JSON/NDJSON, or MCP representation;
- independent batch-verification closure.

The revocation reader trait is storage-neutral by design. An in-memory test reader is not a production revocation service.

## 12. Focused source tests

The source tree contains public-path oracles for:

- deterministic chain and authorization identity;
- revoked ancestor refusal before broker state moves;
- stale freshness refusal at the exclusive deadline;
- same-ID complete-run substitution refusal;
- raw high-value fallthrough refusal on the checked broker;
- malformed reader profile, row bounds, duplicate revocations, and empty issuer key;
- request-time authorization expiring before external dispatch;
- ancestor revocation between reservation and dispatch;
- reservation recovery and abort after dispatch refusal;
- fresh dispatch proof followed by ordinary acknowledgement reconciliation;
- effect record complete-run identity;
- journal replay refusal across same-ID/different-commitment runs;
- reconciliation refusal across same-ID/different-commitment runs;
- cancellation request and final-report complete-run substitution refusal.

Test source is not a test result.

## 13. Verification requirements

Before this slice is represented as mechanically verified, a revision-bound local or designated batch lane must record at least:

```text
cargo fmt --all --check
cargo test -p fgit-agent --all-targets
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

The evidence must retain exact source revision, toolchain, dependency constellation, command outputs, and every later source edit. Hosted GitHub Actions are not required and are not substitute evidence.

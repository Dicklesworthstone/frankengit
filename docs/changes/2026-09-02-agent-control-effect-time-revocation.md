# 2026-09-02: Effect-time capability revocation and irreversible-dispatch gating

## Scope

This wave closes the library-level gap between authenticated capability ancestry and effect-time revocation required by [`../AGENT_PROTOCOL.md`](../AGENT_PROTOCOL.md) §6.3.

The preceding capability implementation proved non-widening ancestry and cryptographic authenticity but had no object binding current revocation state to an exact repository position. The ordinary effect broker also retained only numeric `RunId` plus an authority receipt, and a raw outbox reservation could be dispatched after any request-time check became stale.

The completed slice adds:

1. bounded exact-position revocation reads;
2. verified complete capability-chain identities;
3. exact-request high-value authorization;
4. a checked broker that separates low-risk and revocation-gated work;
5. a proof-carrying external-effect reservation whose raw dispatch method is inaccessible;
6. a second fresh authorization at the actual downstream-visible dispatch boundary;
7. complete-run identity in effect records, journal replay, reconciliation, and public cancellation.

## Named-position revocation evidence

`CapabilityRevocationReadRequest` binds:

- exact `AuthorityReadReceiptId`;
- repository and authority-head identity;
- numeric run and complete `IntentRunCommitment`;
- request logical time;
- nonzero maximum age;
- bounded row limit.

A reader observation is admitted only when it names the exact request, uses a nonzero reader profile and revocation-generation commitment, respects time and row bounds, and contains duplicate-free revoked capability identities.

The resulting `CapabilityRevocationReceipt` uses the half-open freshness interval:

```text
observed_at <= effect_time < valid_until
```

Use at `valid_until` is stale.

## Verified ancestry and exact effect authorization

`VerifiedCapabilityChain` invokes the existing authenticator and attenuation verifier, then commits every root-first link and refuses empty keys, excessive depth, duplicate capability identities, malformed ancestry, amplification, and canonical-framing failure.

`CapabilityEffectAuthorization` binds that chain and revocation receipt to one exact effect request:

```text
complete Intent Run
verified chain and leaf capability
revocation receipt and generation
effect and parent identities
operation class
full cost vector
canonical input commitment
authorization instant and exclusive deadline
```

Every ancestor is checked against the revocation set. A valid leaf is insufficient when its root or another parent was revoked.

## Request acceptance versus irreversible dispatch

External-effect lifecycle stages are intentionally distinct:

```text
request accepted
-> budget reservation
-> typed outbox reservation
-> irreversible downstream dispatch
-> reconciliation / acknowledgement / failure / escalation
```

A request-time authorization can expire before dispatch. The public checked broker therefore returns `RevocationAuthorizedOutboxEffect`, not the raw outbox reservation. The value can be aborted, but it has no direct dispatch method.

`dispatch_authorized_outbox` reconstructs a new authorization for the retained exact request at the actual dispatch time. It requires the same verified chain and leaf capability used at initial acceptance and a fresh revocation receipt. Only then may the typed outbox obligation commit.

Every pre-commit refusal returns the live reservation. A resource or journal refusal after commit retains the deferred obligation. Cleanup is never lost.

## Cleanup asymmetry

Revocation prevents new consequential work but does not prevent responsibility reduction.

The implementation deliberately permits:

- abort of an undispatched reservation after revocation;
- stable-key reconciliation after dispatch;
- acknowledgement;
- terminal failure;
- escalation resolution;
- cancellation and containment.

This matches the control plane's existing rule that expiry and revocation stop continuation without disabling cleanup.

## Complete-run effect identity

`EffectRecord` now carries both `RunId` and `IntentRunCommitment`. The broker computes the commitment before budget movement.

Effect journal replay establishes both identities from the first accepted row and refuses later rows with another numeric or complete run. A same-ID run with another authority read, operation set, resource budget, or expiry cannot be replayed as one effect inventory.

`RunReconciliationReport` moved to its v2 identity domain and commits the complete run in both the report header and every effect row. Complete-run mismatch is refused before authority, operation, lifecycle, or resource interpretation.

The public cancellation facade moved to v2. Request construction verifies the latest situation, active claim, initial reconciliation report, and supplied run use one exact commitment. Completion separately verifies the final report uses the same commitment.

## Source tests added or strengthened

The source tree now contains focused public-path oracles for:

- deterministic exact-position revocation receipts;
- revoked ancestor refusal before broker budget or journal state moves;
- stale revocation refusal at the exclusive deadline;
- same-ID/different-run authorization refusal;
- low-risk/high-value path separation;
- malformed reader profile, row bound, duplicate revocation, and empty issuer-key refusal;
- request-time proof expiring before external dispatch;
- ancestor revocation between reservation and dispatch;
- reservation recovery and abort after dispatch refusal;
- fresh dispatch proof followed by acknowledgement reconciliation;
- effect-record complete-run retention;
- journal replay refusal across same-ID/different-commitment runs;
- complete-run reconciliation refusal;
- cancellation request and final-report substitution refusal.

Existing handoff, cancellation, and receiver-acceptance fixtures were migrated to the new effect-record identity.

Test source is not a test result.

## Identity revisions

The following identities changed deliberately rather than silently reinterpreting old bytes:

```text
RunReconciliationReport          v1 -> v2
public RunCancellationIntent     v1 -> v2
public RunCancellationCompletion v1 -> v2
```

New v1 identities were introduced for:

```text
CapabilityRevocationReadRequest
CapabilityRevocationReceipt
VerifiedCapabilityChain
CapabilityEffectAuthorization
```

`EffectRecord` and journal event persistence remain library values without a registered durable codec. A future codec must version the added complete-run field and preserve migration refusal rather than decode older rows as though they carried it.

## Files

Substantive source and focused test changes include:

- `crates/fgit-agent/src/capability.rs`
- `crates/fgit-agent/src/effect_authorization.rs`
- `crates/fgit-agent/src/effect_dispatch.rs`
- `crates/fgit-agent/src/broker.rs`
- `crates/fgit-agent/src/reconcile.rs`
- `crates/fgit-agent/src/run_cancellation.rs`
- `crates/fgit-agent/src/lib.rs`
- `crates/fgit-agent/tests/effect_authorization.rs`
- `crates/fgit-agent/tests/effect_dispatch.rs`
- `crates/fgit-agent/tests/effect_run_identity.rs`
- `crates/fgit-agent/tests/cancellation_run_identity.rs`
- migrated reconciliation, handoff, handoff-acceptance, and cancellation tests.

The focused implementation contract is [`../AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md`](../AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md).

## Explicit non-claims

This wave does not implement:

- a canonical revocation event/body schema;
- concrete revocation reads from authority-selected policy state;
- a durable revocation index, cache, invalidation stream, or backend adapter;
- durable codecs and migrations for the new objects;
- host integration for network, secrets, runners, forge mutation, or publication;
- process, workspace, credential, tunnel, upload, or VM reaping;
- a complete action-packet executor;
- later-head ancestry witnesses;
- canonical repository publication;
- robot CLI, native API, or MCP surfaces;
- independent batch verification or Bead closure.

The storage-neutral reader trait and in-memory test readers are not represented as a production revocation service.

## Verification boundary

The implementation environment used for this wave did not provide a local FrankenGit checkout, Cargo, rustc, rustfmt, Clippy, `br`, or `bv`. No mechanical result is claimed for the latest revisions.

The designated verifier must run at least:

```text
cargo fmt --all --check
cargo test -p fgit-agent --all-targets
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

Hosted GitHub Actions were not consulted and are not substitute evidence.

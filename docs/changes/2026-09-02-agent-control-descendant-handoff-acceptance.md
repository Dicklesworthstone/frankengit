# Descendant-head handoff acceptance

**Date:** 2026-09-02  
**Area:** `fgit-authority`, `fgit-agent` Agent Control Plane  
**Status:** implementation and focused source tests landed; revision-bound mechanical and independent verification remain pending

## Problem

`fgit-authority` had gained a bounded exact proof that the current authority head descends from one historical head, but `AgentHandoffAcceptance` still accepted only an identical source/receiver head. A receiver observing a valid later head therefore had no proof-carrying acceptance path.

The existing receiver check also trusted numeric `RunId` plus authority receipt without comparing the complete `IntentRunCommitment` retained by the receiver situation. A same-ID run with changed scope, budget, expiry, or authenticated read could reach attenuation checks as though it were the situation's run.

## Implemented authority relationships

Receiver acceptance now recognizes a closed relation:

```text
SameAuthenticatedHead
DescendantAuthenticatedHead
```

Same-head acceptance preserves the existing behavior.

Descendant acceptance requires an `AuthorityHeadAncestryReceipt` whose:

- repository matches source and receiver;
- ancestor head and generation equal the source capsule authority position;
- descendant head and generation equal the receiver run authority position;
- descendant token equals the receiver's exact backend version token;
- hop count equals the complete generation distance.

Generation comparison alone remains insufficient.

## Complete receiver identity

The receiver run is re-committed before authority or attenuation interpretation. The receiver situation must retain that exact `IntentRunCommitment`.

The accepted value now stores:

```text
receiver RunId
receiver IntentRunCommitment
authority relation
optional AuthorityHeadAncestryReceipt
```

A same-ID run with another authority read, operation scope, budget, or lifetime receives a typed identity refusal before ordinary scope arithmetic.

## Atomic current-authority driver

Added synchronous and asynchronous host surfaces:

```text
accept_handoff_at_current_authority(...)
accept_handoff_at_current_authority_async(...)
```

They perform one coherent operation:

```text
read and authenticate current HeadKey
    -> bounded predecessor walk to capsule source head
    -> require receiver head/generation/token == exact current read
    -> immediately consume same-head or descendant proof
```

This prevents a host from proving ancestry against one slot or store and accepting a receiver from another. A byte-identical head body with a different store-issued token is refused before acceptance.

## Identity migration

`AgentHandoffAcceptance` moved from v1 to v2.

The v2 commitment adds:

- complete receiver run commitment;
- authority relation;
- optional ancestry receipt identity.

An old v1 acceptance must not be decoded or migrated as though it had proven receiver run identity or descendant ancestry.

## Focused source tests

New public-path source tests exercise:

- later-head refusal without ancestry;
- deterministic descendant acceptance;
- retained ancestry and complete receiver-run identity;
- wrong-ancestor proof refusal;
- same-body cross-store token substitution refusal;
- same-ID/different-scope receiver refusal;
- atomic current-head proof consumption;
- synchronous/asynchronous semantic parity.

These are source-level test oracles, not observed results.

## Rejected shortcut: weakening task transfer

The current task mutation/persistence protocol binds one authenticated-read basis to predecessor and successor. Descendant handoff acceptance does not make it sound to remove that equality check.

A cross-head task transfer needs a new two-authority-basis envelope retaining:

```text
source authority read and active lease
source capsule and acceptance
ancestry receipt
receiver authority read and complete run
exact predecessor and successor task state
one-shot persistence and authenticated reread evidence
source cancellation projection
receiver activation evidence
```

No cross-head task ownership mutation is claimed in this change.

## Verification boundary

The execution environment did not provide a local checkout, Cargo, rustc, rustfmt, Clippy, `br`, or `bv`. No mechanical result is claimed.

Required evidence remains at least:

```text
cargo fmt --all --check
cargo test -p fgit-authority --all-targets --no-fail-fast
cargo test -p fgit-agent --all-targets --no-fail-fast
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check --no-fail-fast
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

Hosted GitHub Actions are not substitute evidence.

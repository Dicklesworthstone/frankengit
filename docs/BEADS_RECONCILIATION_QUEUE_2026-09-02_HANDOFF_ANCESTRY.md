# Beads reconciliation queue: descendant-head handoff acceptance

**Date:** 2026-09-02  
**Status:** non-authoritative operator handoff; not Beads state  
**Repository:** `Dicklesworthstone/frankengit`  
**Starting revision:** `d6ca39a68cd1845053669ec5546e7b7cb36e6fa7`  
**Implementation and documentation boundary before this handoff:** `3f50179062e6c8e68d372a737bef40107947c0e2`

## Why this file exists

The execution environment used for this slice had GitHub connector access but no local checkout, `br`, `bv`, Cargo, rustc, rustfmt, or Clippy. The live multi-megabyte `.beads/issues.jsonl` ledger was not edited by hand, and connector search did not identify one unambiguous owning Bead.

This document carries exact evidence and suggested operator actions to a later environment that has the repository's actual tracker and verification tools. It is not a task transition, verification receipt, or source of repository authority.

## Implemented slice

The Agent Control Plane now supports receiver-side handoff acceptance at either:

```text
SameAuthenticatedHead
DescendantAuthenticatedHead
```

Descendant acceptance requires an authority-layer `AuthorityHeadAncestryReceipt` that matches:

- source repository, head identity, and generation from the capsule;
- receiver repository, head identity, and generation from the receiver run;
- receiver exact backend version token;
- complete generation-distance hop count.

Receiver acceptance also recomputes and retains the complete `IntentRunCommitment`; same numeric `RunId` with another authenticated read, operation scope, budget, or expiry is refused before attenuation checks.

The acceptance identity moved from v1 to v2 and commits the closed authority relation, complete receiver run, and optional ancestry receipt identity.

A synchronous and asynchronous host driver now performs one coherent operation:

```text
read + authenticate current HeadKey
    -> bounded predecessor walk to capsule source
    -> require receiver head/generation/token == exact current read
    -> immediately consume same-head or descendant proof
```

This prevents a proof obtained from one current slot or store from being paired with a receiver authenticated by another.

## Focused source tests present

- later receiver head refuses without explicit ancestry;
- exact descendant proof enables deterministic acceptance;
- ancestry receipt and complete receiver run are retained;
- proof for another ancestor is refused;
- byte-identical head body from another store is refused by exact token;
- same-ID/different-scope receiver run is refused before attenuation checks;
- current-slot proof acquisition and acceptance are atomic at the public host boundary;
- synchronous and asynchronous drivers have the same semantics.

Test source is not a test result.

## Explicitly absent boundary

Descendant-head acceptance is not durable task ownership transfer.

The existing task mutation and persistence envelope binds one authenticated-read basis to predecessor and successor. It must not be weakened after an ancestry proof. A cross-head transfer requires a new two-authority-basis envelope retaining at least:

```text
source AuthorityReadReceiptId and active lease
source capsule and acceptance identities
AuthorityHeadAncestryReceiptId
receiver AuthorityReadReceiptId and IntentRunCommitment
exact predecessor and successor task generations
one-shot CAS / flush / authenticated reread evidence
source cancellation projection
receiver post-transfer activation evidence
```

No cross-head task mutation, receiver plan adoption, capability issuance, or canonical publication is claimed.

## Incremental revisions

1. `e3d418f35d33ea8a555a670969680f3f257b9af3` — accept handoffs at proven descendant heads
2. `1c95f18bd13cfd2c2d03df82eba8bf6dd7a35b0e` — pin descendant-head handoff acceptance
3. `89c7bbc8e5b27c474def3bfae66402c39e1fdfb7` — consume current-head ancestry atomically
4. `69706cb956c250d6c3cee416ef99639872ca51d2` — expose current-authority handoff driver
5. `80b9805c6a8dc9122296faa5b0d417393069ee95` — pin atomic current-authority handoff
6. `71637ff0ec2a3cd68a4353280a7e9a6e2e375f41` — keep handoff drivers lint-clean
7. `b7c2ba738ef86b1da082b3d9b9c294319b12a8f2` — define descendant-head handoff acceptance
8. `bcb6ad5b58c242494aaa75a54daee9a4ef535fbd` — reconcile descendant handoff continuity
9. `098eae83ff9d558692249dd26cb343bbea98c0a7` — reconcile descendant handoff status
10. `a5a49dc5544190220584666e92638e324322802f` — record descendant-head handoff acceptance
11. `212359a193fa4d88c74caa84c17b5413323d298e` — record descendant-head handoff acceptance in changelog
12. `3f50179062e6c8e68d372a737bef40107947c0e2` — integrate descendant handoff architecture

The operator must refresh `main` before verification and use the final descendant of these revisions, including this handoff commit.

## Required live-graph procedure

From a clean current checkout:

```bash
br ready --json
br list --json
br search "handoff ancestry descendant authority Agent Control Plane" --json
```

For each plausible owner:

```bash
br show <issue-id> --json
```

Choose an owner only when its acceptance contract and dependency position clearly cover receiver handoff acceptance or the broader Agent Control Plane lifecycle. If more than one issue plausibly owns the work, do not guess; record the ambiguity or create/link a narrowly scoped follow-up through normal `br` commands.

## Required revision-bound verification

At the exact current source revision:

```bash
cargo fmt --all --check
cargo test -p fgit-authority --all-targets --no-fail-fast
cargo test -p fgit-agent --all-targets --no-fail-fast
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check --no-fail-fast
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

Retain:

- tested commit SHA;
- pinned Rust toolchain;
- `Cargo.lock` identity;
- complete command outcomes;
- first load-bearing failure output;
- any source edit after the result.

The focused tests that must be observed include:

```text
handoff_descendant_acceptance
handoff_current_authority
handoff_acceptance
```

## Suggested progress comment

> Implemented proof-carrying receiver handoff acceptance at the same authenticated head or an exact bounded descendant. Acceptance v2 retains the receiver `IntentRunCommitment`, closed authority relation, and optional `AuthorityHeadAncestryReceipt`; sync/async host drivers authenticate the current `HeadKey`, prove ancestry, bind the receiver's exact current slot token, and consume the proof atomically. Focused source tests cover missing ancestry, wrong ancestor, cross-store token substitution, same-ID altered receiver scope, and sync/async parity. Cross-head durable task transfer remains explicitly out of scope pending a two-authority-basis persistence envelope. Tested revision and command evidence: <attach exact results>.

## Safe tracker update

After successful local verification, attach the exact evidence through the owning issue's normal `br` update/comment workflow. Preserve the repository's lifecycle distinction: implementation evidence may justify `in_progress` or the policy-defined verification-pending state, but not `verified` or `closed` unless the designated independent gate has completed.

Then flush tracker state only through:

```bash
br sync --flush-only
```

## Stop conditions

Do not mark the owning Bead verified or closed when any of the following holds:

- formatter, compiler, test, Clippy, registry, docs, constitution, or fast lane is nonzero;
- the tested revision predates a source edit;
- the owning issue is ambiguous;
- only source-test presence or hosted workflow status is available;
- descendant acceptance works but complete receiver-run or current-token binding fails;
- sync and async driver semantics differ;
- a proof for the wrong ancestor, repository, descendant, store, token, or hop count is accepted;
- cross-head task transfer is claimed without the separate two-authority-basis persistence protocol;
- the designated independent batch verifier has not produced the required receipt.

GitHub-hosted Actions are not required and must not be substituted for the repository-owned local or designated batch evidence.

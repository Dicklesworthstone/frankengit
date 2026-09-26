# Exact-version fast-forward PR merges

Implementation slice for `frankengit-root-doctrine-x2mv.4.20`.

`NativeMergeIntent::fast_forward_only` requests a merge of an existing PR to
its already-admitted source tip. The caller supplies the PR number/version,
source and target branch names, and both observed native tips. Admission never
refreshes these coordinates, fabricates a merge commit, or falls back to a
force update or two-parent merge.

## Identity and publication

The request seals `forge/merge.method = fast-forward-only/v1` in addition to
the existing native event commitment. The ordinary constructor remains
`NativeMergeMethod::MergeCommit` and retains its original semantic bytes.
Changing methods under the same idempotency key is a changed request, not a
retry. Resource ceilings and the current authority head do not enter identity.

The existing native merge driver owns the seal, outcome recovery, current
source/target checks, exact PR version/lifecycle checks, full Ref + Forge +
Outbox fold, and conditional authority-head publication. One successful decision
moves the target to the exact source tip and marks the same PR merged in one
RCR. Its pending delivery is not an acknowledgement. Terminal retries resolve
before freshness checks and cannot republish or move a later target backwards.

The canonical native event format is unchanged. A fast-forward records
`merge_commit == source_tip` and `base_tip == target_tip_before`. These native
coordinates describe the result, not an authorization proof. The explicitly
sealed method selects its validator. Existing projection implementations default
to refusing the new method until they implement `validate_fast_forward_async`.
The embedded node implements it through its existing verified materializer.

## Verification boundary

The independent native-object walker hashes and parses the complete source
closure. It proves ancestry through commit parent headers, including non-first
parents; tree equality, fabricated outgoing-edge metadata, gitlinks and mere
local object existence cannot establish ancestry. Every resulting dependency
must already belong to the authority-selected closure. The existing object,
edge, byte, deadline and cancellation ceilings remain in force.

Divergent or reverse ancestry receives a canonical `NonFastForwardRefused`.
Missing dependencies and exhausted execution budgets remain unavailable, not
fabricated terminal merge decisions. Equal tips are outside this mutating
profile and fail construction. The ordinary two-parent validator is unchanged.

Mandatory review protection is still checked on every publication attempt.
This method does not create an approval or successful CI check. The source tip
must have the exact candidate reviews required by current repository policy;
without them a protected branch refuses. No existing bundle, workspace, or
review-gated entry point silently opts into this method.

## Source tests and non-claims

`crates/fgit-admission/tests/native_fast_forward.rs` covers both native hash
formats, deep and second-parent ancestry, divergent/reversed history, fabricated
edges, missing/corrupt objects, exact resource boundaries, interruption at every
checkpoint, disjoint merge methods, and unchanged legacy seal construction.

`crates/fgit-node/tests/native_fast_forward.rs` uses the real embedded backend
for atomic ref/PR/outbox publication, unchanged object identity, reopen/retry,
stale versions, unselected staged tips, method/key mismatch, retryable resource
exhaustion, and mandatory-review refusal.

These tests are authored, not executed in the implementation environment.
Rust compilation, rustfmt, Cargo tests, native-client E2E and repository gates
remain required at an exact revision. This is not squash/rebase merge, an
unbounded-history claim, a production-readiness claim, or a completed bead.

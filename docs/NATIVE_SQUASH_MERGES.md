# Native squash merges

Squash combines an existing pull request's reviewed result into a commit whose
only parent is the exact target tip. It uses FrankenGit's native merge planner,
pack handling and coupled Ref + Forge + Outbox publication path. The source
branch remains at its original tip.

Commit style is separate from tree semantics. The native options APIs support
both `PathMergeV1` and `ExactRenamesV1` with `MergeCommitStyle::Squash`.
The local command below selects the existing bounded `path-v1` profile.
Existing preparation and publication entry points default to two-parent merges.

## Prepare and inspect

Preparation reads both branches at one authenticated head and writes an
artifact. It does not stage objects, seal a request, grant approval or change
repository authority. Publication requires an existing open PR at an exact
positive version, with the same source and target coordinates.

```bash
fg merge prepare "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main ./squash.bundle \
  --trusted-local \
  --profile path-v1 \
  --method squash \
  --object-format sha256 \
  --source-ref refs/heads/topic \
  --author 'Operator <operator@example.invalid>' \
  --timestamp 1791676800 \
  --message 'Squash topic into main' \
  > ./squash-receipt.json
```

Select `--object-format sha1` for a SHA-1 repository; SHA-1 remains the default.
The author, optional committer, timestamp and message are explicit inputs.
A clean receipt includes `method: "squash"`, the pinned source head, both
original tips, common base, resulting tree and exact candidate identity.
The usual create-only artifact and node-shutdown rules still apply.

The candidate has one `parent` line naming target-before. Both original tips
remain bundle prerequisites: the resulting tree can reuse source-side blobs
even though source is no longer a commit parent. The review environment needs
both histories. Read-only PR bundle inspection includes the actual commit body,
actual parents and target-to-candidate content comparison.

A fast-forwardable branch still receives squash construction. If a one-commit
source already has exactly the selected tree, parent and complete metadata
bytes, native hashing can reproduce the source commit identity. This is valid
only with the same one-target-parent shape; it does not change the explicitly
sealed publication method. An already integrated source remains a no-op, and
conflicts produce no candidate or bundle.

## Publish the exact candidate

After inspecting and reviewing the artifact, use its coordinates unchanged:

```bash
fg merge apply "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main ./squash.bundle \
  --trusted-local \
  --method squash \
  --principal "$PRINCIPAL_ID" \
  --idempotency-key "$IDEMPOTENCY_KEY" \
  --source-ref refs/heads/topic \
  --expected-source "$EXPECTED_SOURCE" \
  --expected-target "$EXPECTED_TARGET" \
  --merge-base "$MERGE_BASE" \
  --expected-commit "$CANDIDATE_COMMIT" \
  --pull-request "$PULL_REQUEST_NUMBER" \
  --expected-version "$PULL_REQUEST_VERSION"
```

The PR version must be positive. `--expected-version 0` remains available only
for the legacy two-parent merge-receipt stream. Unknown or duplicate method
options refuse; omitting `--method` preserves the existing `merge-commit`
behavior. Supplying a squash bundle with that default method fails its
two-parent check rather than silently selecting another method.

Every publication independently verifies:

- current source and target refs and the exact open PR version;
- a single candidate parent equal to target-before;
- native identity, object kind and closure of the candidate and source history;
- a common base reached through actual commit parents from both original tips;
- current mandatory protection and, where requested, exact-candidate reviews.

Candidate and source history share one deduplicated validation walk. Object,
edge, individual-byte, total-byte and cancellation limits apply to that whole
walk, including source-only dependencies. Object presence in storage alone
does not authorize a source outside the selected repository history.

## Exact-candidate reviews

`fg pr review` binds the exact candidate commit and original PR subject.
Use the same command for squash reviews; it needs no method flag because the
native commit identity already commits to the complete parent list and tree.
Approval of a different two-parent candidate cannot approve a squash commit,
even if their resulting trees match.

To require named reviewers in addition to current mandatory protection:

```bash
fg merge apply-reviewed "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  "$PULL_REQUEST_NUMBER" \
  --trusted-local \
  --method squash \
  --principal "$PRINCIPAL_ID" \
  --idempotency-key "$REVIEWED_ATTEMPT_KEY" \
  --expected-version "$PULL_REQUEST_VERSION" \
  --source-ref refs/heads/topic \
  --target-ref refs/heads/main \
  --source-tip "$EXPECTED_SOURCE" \
  --target-tip "$EXPECTED_TARGET" \
  --merge-base "$MERGE_BASE" \
  --candidate "$CANDIDATE_COMMIT" \
  --policy-epoch "$POLICY_EPOCH" \
  --bundle ./squash.bundle \
  --require-reviewer "$REVIEWER_ID"
```

The same current-review checks apply to withdrawal, stale votes, PR edits,
branch movement, policy changes and author/submitter exclusion. Review
inspection neither imports the candidate nor publishes a merge.

## Atomicity and recovery

The target-ref update, PR merge event and pending outbox obligation are
published with the same exact-predecessor authority-head CAS. There is no
intermediate ref-only publication. The source ref is unchanged, and a pending
outbox obligation does not claim delivery acknowledgement.

The semantic request includes the scoped field
`forge / merge.method = squash/v1`. Existing two-parent seals retain their
bytes, and the existing fast-forward marker retains its value. No canonical
forge event or review encoding changes are required.

Retry the original artifact coordinates, method, principal and idempotency
key after uncertainty. An exact retry recovers its original committed or
refused terminal result, including after restart. Changing the method or
candidate under the same key is a different sealed request and refuses.
Known terminal outcomes remain distinguishable from cleanup and transport
failures.

## Native API surface and current limits

The method-aware entry points are:

- `prepare_merge_with_options(..., profile, style)` in `fgit-forge`;
- `OneNode::prepare_merge_bundle_with_options_in(..., profile, style)`;
- `OneNode::prepare_pull_request_bundle_with_options_in(..., profile, style)`;
- `OneNode::apply_merge_bundle_with_method_durable_in(..., method)`;
- `OneNode::apply_reviewed_merge_bundle_with_method_durable_in(..., method)`.

`fgit_node::NativeMergeMethod` exposes the publication method to callers
without requiring them to add a direct admission dependency. Custom admission
projections must explicitly implement the squash validation hook; the default
refuses publication.

Automatic squash uses the existing bounded merge rules and conflict behavior.
The explicit conflict-resolution constructor retains its two-parent contract.
A squash candidate never claims Git `ort` equivalence or execution of project
tests.

Regression source covers both hash formats, native bytes, method separation,
source-only closure validation, combined budgets, cancellation, atomic
publication, stale tips/versions, exact reviews, retry and restart. Cargo
validation for this change was blocked by a full shared filesystem before
first-party compilation; the execution service subsequently disconnected.
The added Rust tests are not reported as executed.

See [native preparation](NATIVE_MERGE_PREPARATION.md),
[bundle publication](MERGE_BUNDLE_COMMAND.md), and the
[exact-candidate review workflow](EXACT_CANDIDATE_REVIEW_WORKFLOW.md).

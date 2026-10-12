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
sealed publication method. An already integrated source remains a no-op.
Automatic preparation reports conflicts without a candidate or bundle; resolve
them explicitly before inspection and publication.

## Resolve conflicts while retaining squash

The native resolver supports squash using the same exact PathMergeV1 conflict
set as a two-parent merge. Submit one choice for every conflict and preserve
the selected input tips and unique base:

```bash
fg merge resolve "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main ./resolved-squash.bundle \
  --trusted-local --profile path-v1 --method squash \
  --source-ref refs/heads/topic \
  --expected-target "$EXPECTED_TARGET" --expected-source "$EXPECTED_SOURCE" \
  --merge-base "$MERGE_BASE" \
  --author 'Operator <operator@example.invalid>' \
  --timestamp 1791676800 --message 'Resolve and squash topic' \
  --file src/example.rs 100644 ./resolved-example.rs
```

Base, ours (target), theirs (source), deletion and exact regular-file bytes are
available. Side choices retain their exact object identity and mode; a missing
side requires explicit deletion. All actual conflicts must be resolved, and
clean paths cannot be overridden. Binary and empty files keep their exact
bytes. The conflict discovery and reconstruction passes share existing budgets.

The receipt records `method: "squash"`; the resulting commit has only the target
parent. Inspect that exact candidate, collect any required independent reviews,
and carry `--method squash` into publication below. Choosing ours may leave the
target tree unchanged while still creating the explicitly selected squash
commit. See [native conflict resolution](NATIVE_MERGE_RESOLUTION.md) for the
complete path grammar, limits and create-only artifact rules.

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

## HTTP, MCP and browser workflow

The HTTP preparation endpoint accepts `method=squash` alongside the existing
exact PR subject and commit metadata. `profile=path-merge-v1` and
`profile=exact-renames-v1` remain independent choices. The response identifies
its method even for conflicts and no-op results. Carry that method into
`POST .../pulls/{number}/merge` with the exact bundle and required reviewers.
Review and inspection HTTP forms omit the selector; native inspection verifies
the actual commit parents, and reviews bind the actual commit identity.
Reviewed publication independently validates and seals the selected method,
then returns it in the terminal receipt.

For a conflicted PathMergeV1 preparation, submit all exact path choices to
`POST .../pulls/{number}/resolve` with `method=squash`, the same PR subject,
merge base and metadata. The response reports `state: "resolved"` and
`method: "squash"`. The resolver accepts the method but retains its existing
PathMergeV1 tree profile; a profile override is rejected.

With MCP, call `frankengit_source_candidate` with
`operation: "prepare_pull_merge"` and `method: "squash"`. A clean result includes:

- `inspection_arguments`: pass directly to `frankengit_source_candidate`.
  They pin the preparation head and bundle digest and retain the selected method.
- `candidate_arguments`: use with `frankengit_pull_review`, adding the caller's
  review version, decision and durable key. These arguments contain no method.
- `publication_arguments`: use with `frankengit_pull_merge_reviewed`, adding
  the caller's durable key and required reviewers. These arguments include
  `method: "squash"`.

`operation: "resolve_pull_merge"` accepts the same method plus explicit conflict
choices and merge base. It constructs and natively inspects the resolved bundle
in one request, then returns all three argument objects with the same separation
between inspection, review and publication. Its inspection template also retains
the original inspection limits.

The inspector returns the verified parent list and a matching publication
template. An explicit squash assertion remains squash when its candidate
identity equals the source tip. Read, review and merge grants remain separate;
a candidate result supplies no authenticated sponsor or approval.

In the pull-request browser, select **Squash (one target parent)** before
preparing. The client verifies the returned method and inspects the exact
candidate. Exported candidate receipts preserve the selection and require
native reinspection when imported. Review requests remain method-free, while
staged merge requests preserve squash in their exact request bytes and recovery
key. Editing the selection cannot change an already staged request. A terminal
receipt that contradicts its method leaves the outcome uncertain and retains
the original request for recovery or exact retry.

For a conflicted squash, the browser enables the existing per-path resolution
editor. The client fixes the original subject, base, metadata and selected
method before reading file bytes. It verifies the returned method and every
resolution's exact path, side, mode and content identity, then requires native
inspection of the one-target-parent candidate. Changing the method cancels an
in-flight candidate selection. A resolved candidate still needs a separate
review and a newly confirmed publication request.

See the [HTTP preparation API](HTTP_CANDIDATE_PREPARATION_API.md),
[HTTP reviewed merge API](HTTP_REVIEW_MERGE_API.md),
[MCP candidate API](MCP_PULL_CANDIDATES.md),
[MCP inspection API](MCP_PULL_INSPECTION.md),
[HTTP conflict resolution](HTTP_CONFLICT_RESOLUTION_API.md) and
[MCP conflict resolution](MCP_PULL_RESOLUTION.md) for complete field and grant rules.

## Native API surface and current limits

The method-aware entry points are:

- `prepare_merge_with_options(..., profile, style)` in `fgit-forge`;
- `OneNode::prepare_merge_bundle_with_options_in(..., profile, style)`;
- `OneNode::prepare_pull_request_bundle_with_options_in(..., profile, style)`;
- `prepare_resolved_merge_with_style(..., limits, style)` in `fgit-forge`;
- `OneNode::prepare_resolved_merge_bundle_with_style_in(..., limits, style)`;
- `OneNode::prepare_resolved_pull_request_bundle_with_style_in(..., limits, style)`;
- `OneNode::apply_merge_bundle_with_method_durable_in(..., method)`;
- `OneNode::apply_reviewed_merge_bundle_with_method_durable_in(..., method)`.

`fgit_node::NativeMergeMethod` exposes the publication method to callers
without requiring them to add a direct admission dependency. Custom admission
projections must explicitly implement the squash validation hook; the default
refuses publication.

Automatic squash uses the existing bounded merge rules and conflict behavior.
Explicit conflict resolution supports both styles under PathMergeV1, including
manual binary content and whole-side choices. Its original entry points retain
their default two-parent contract through wrappers.
A squash candidate never claims Git `ort` equivalence or execution of project
tests.

Regression source covers both hash formats, native bytes, method separation,
source-only closure validation, combined budgets, cancellation, atomic
publication, stale tips/versions, exact reviews, retry and restart. Resolved
squash regressions add all conflict choices, exact byte/parent receipts, shared
resolution budgets, an empty target diff, and the HTTP/MCP review-to-publication
lifecycle. Test source alone does not establish a native execution pass.

The focused browser suite uses the actual client modules and WebCrypto with
controlled DOM/HTTP fixtures:

```sh
node --test --test-concurrency=1 \
  tests/browser/pulls-squash.test.mjs \
  tests/browser/pulls-resolution.test.mjs \
  tests/browser/pulls-resolution-view.test.mjs
```

It covers method preservation, exact resolution choices, substituted response
refusals, file-read cancellation and separate publication confirmation. This
client suite does not establish live server or native admission behavior.

See [native preparation](NATIVE_MERGE_PREPARATION.md),
[bundle publication](MERGE_BUNDLE_COMMAND.md), and the
[exact-candidate review workflow](EXACT_CANDIDATE_REVIEW_WORKFLOW.md).

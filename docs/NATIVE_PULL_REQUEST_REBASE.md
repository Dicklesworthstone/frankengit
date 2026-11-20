# Native pull-request rebase-and-merge

The bounded native PR workflow can prepare, inspect, review and land a linear
rebased series. It implements the rebase-and-merge method in comprehensive-plan
§25.7 through the existing repository authority, not a source-branch rewrite
followed by a separate PR close.

## What publishes

An exact existing open PR supplies its original source and target branches,
tips, content version and policy epoch. Preparation replays the explicitly
selected source suffix `(upstream, source]` onto the target. The supplied
upstream must also be an ancestor of the target. The native planner preserves
each original author header, message and encoding, and uses the explicitly
supplied committer and timestamp. Original signatures are not copied to
rewritten bytes.

The artifact names the **target** branch and has the target tip as its sole
bundle prerequisite. Preparing and inspecting it stage no objects, acquire no
publication seal and move neither branch. Landing advances only the target,
records the PR's native merge event and enqueues its delivery obligation in one
RCR and one successful predecessor-head CAS. The source branch remains at its
original tip.

`NativeMergeMethod::Rebase` is explicitly sealed as `merge.method=rebase/v1`.
Existing merge-commit, squash and fast-forward seals retain their bytes. The
same principal/key cannot select a different method or different reviewed
coordinates. Known terminal results retain the existing recovery behavior:
an identical retry can recover after later branch changes or restart without
re-reading a discarded candidate bundle. An uncertain return is not evidence
of non-commit.

## Prepare and inspect

Obtain the positive PR version, branch names and tips using `fg pr show` and
the current policy epoch using `fg pr reviews`. Pass these inspected values
explicitly; preparation refuses if they no longer describe the same current
subject. For example, with the named shell variables set to those values:

```bash
fg pr prepare-rebase "$STORAGE" "$TENANT" "$REPOSITORY" "$PR" "$BUNDLE" \
  --trusted-local --profile path-v1 --expected-version "$VERSION" \
  --source-ref "$SOURCE_REF" --expected-source "$SOURCE_TIP" \
  --target-ref "$TARGET_REF" --expected-target "$TARGET_TIP" \
  --policy-epoch "$POLICY_EPOCH" --upstream "$BASE" \
  --committer 'Maintainer <maintainer@example.invalid>' --timestamp "$TIMESTAMP" \
  --empty stop

fg pr inspect-rebase "$STORAGE" "$TENANT" "$REPOSITORY" "$PR" "$BUNDLE" \
  --trusted-local --expected-version "$VERSION" \
  --source-ref "$SOURCE_REF" --expected-source "$SOURCE_TIP" \
  --target-ref "$TARGET_REF" --expected-target "$TARGET_TIP" \
  --policy-epoch "$POLICY_EPOCH" --upstream "$BASE" --candidate "$CANDIDATE"
```

Preparation returns the candidate ID and original-to-rewritten step mapping.
Its destination must not already exist; output uses the existing no-clobber
bundle publisher after explicit node shutdown. `--source-ref-hex` and
`--target-ref-hex` preserve non-UTF-8 branch names.

Inspection independently validates the complete bundle and returns exact
native commit bodies, the old-source-to-candidate comparison and every
parent-to-child comparison in chronological order. A temporary change that is
removed by a later rewritten commit therefore remains visible. Path filters
and merge-base comparison mode are not supported by this inspection profile.
All comparisons share one finite review budget; truncated results do not
become a complete inspection receipt.

## Review and land

Use the existing exact-candidate review command with `--method rebase`:

```text
fg pr review ... --method rebase ...
fg merge apply-reviewed ... --method rebase ...
```

Run those commands with `--help` for their complete principal, original retry
key, PR subject, review-stream version, policy epoch and reviewer arguments.
`fg merge apply --method rebase` is also available and still enforces canonical
repository protection. Neither command invents an approval or bypasses required
checks, reviewer quorums, author exclusion or current ref policy. Preparation
and inspection receipts are not write authorization.

Review submission uses `admit_rebase_candidate_review_durable_in`, which
inspects every commit before storing the existing exact-candidate vote. The
vote remains bound to the original PR subject, common base and actual final
candidate ID. That ID commits to the entire ordered parent chain; it does not
merely identify a final tree. Withdrawal and immutable historical vote recovery
keep their existing semantics.

Path-specific protection uses the union of changes across **every** rewritten
commit. Adding a protected path and removing it later still selects its review
rule. A private series-proof marker prevents another projection from replacing
this witness with only a final-tree comparison.

## Boundaries and refusal behavior

- Both the original suffix and rewritten candidate series contain 1–256
  single-parent commits. A narrower caller limit remains effective. Native
  preparation clamps the generic preparation allowance to this series ceiling.
- Candidate commit bodies have a cumulative 16 MiB ceiling. Existing aggregate
  object, tree, edge, byte, output, policy and request-lifetime limits also apply.
  Each intermediate tree is validated, even when a candidate commit was already
  present in the selected closure.
- The original common base and both branch tips must belong to the selected
  canonical history. Original-source history is unavailable as an implicit
  external delta base: bundle unpacking and coverage first prove target-only
  prerequisites before source bytes become available for review.
- Merge commits in the original suffix or rewritten chain refuse. A conflict
  or a newly empty change under `--empty stop` returns a stopped preparation and
  no bundle. `drop` omits newly empty steps; `keep` retains them. An entirely
  dropped series refuses instead of claiming a merge with no target movement.
- Current PR, source, target, policy, checks and reviews are revalidated during
  admission and CAS replanning. Stale input is not silently refreshed.
- Queue-required branches continue to refuse this direct path. Native queue
  candidate construction has no rebase profile in this slice.

The delivered clients include the trusted-local CLI/native APIs and the
authenticated HTTP workflow. The PR browser offers **Rebase and merge** with an
explicit upstream and empty-commit policy. It prepares the candidate, sends the
entire bundle through the separate series inspector, verifies each returned
native commit identity and parent chain, and displays every intermediate change.
Original authors/messages are displayed from those exact commit bytes. Display
clipping is explicit; the complete bounded inspection remains downloadable.
Imported candidate receipts always undergo native reinspection, and an uncertain
review or merge retains the original method, command, bundle and recovery key.

HTTP uses `prepare-rebase` and `inspect-rebase` under
`/api/v1/pulls/{number}/`. Both require Git-read and PR-read on the same token.
The existing review and merge endpoints require their existing write grants and
explicit `method=rebase`; merging also enforces the target-ref write ceiling.
The [preparation](HTTP_CANDIDATE_PREPARATION_API.md),
[inspection](HTTP_CANDIDATE_INSPECTION_API.md), and
[review/merge](HTTP_REVIEW_MERGE_API.md) guides specify exact fields and receipts.
Browser preparation supports the direct path profile; conflicts stop without a
partial candidate or automatic change of method. The browser retains its
16 MiB bundle and 8 MiB response limits, and uses one cumulative display budget
across the series. This does not widen the service's loopback deployment or
credential model.

MCP clients use `frankengit_source_candidate` with
`operation: "prepare_pull_rebase"` or `"inspect_pull_rebase"`. These require
ordinary source-read and PR-read grants together and return separate explicit
inspection, review and publication arguments. The existing review and merge
tools accept `method: "rebase"` with their existing write grants; preparation
does not grant either permission. The MCP profile deliberately caps bundles
at 24 KiB and applies its smaller aggregate reply and inspection limits. See
[MCP preparation](MCP_PULL_CANDIDATES.md),
[MCP inspection](MCP_PULL_INSPECTION.md), and
[MCP writes](MCP_PULL_REQUEST_WRITES.md) for schemas and recovery behavior.
Sponsored read-only agent credentials cannot invoke these operations.

The dedicated rebase planner constructs the replay; publication validates the
independently reviewed series, its content, topology and original ancestry.
Publication does not claim to reproduce an arbitrary supplied author's replay
algorithm, resolve conflicts automatically, preserve merge topology, or meet
an unexecuted Git differential or performance target.

## Ownership and verification

This extends the existing PR workflow owner
`frankengit-root-doctrine-x2mv.4.20`, native admission and publication primitives
`PUB-001`/`PUB-002`. It adds no authority store, event codec, dependency or registry
claim promotion. The original bead's remaining acceptance and ownership are
unchanged.

Regressions live in `fgit-admission/tests/native_rebase_merge.rs`,
`fgit-node/tests/native_rebase_merge.rs`,
`fgit-node/tests/native_pull_rebase_http.rs`, the path-review verifier tests,
CLI parser/receipt tests and `tests/browser/pulls-rebase.test.mjs`. They
distinguish native validators, file-backed TCP integration and browser
protocol/DOM peers; authored tests alone do not qualify an executed native gate.

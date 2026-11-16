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

The delivered clients are the trusted-local CLI and native APIs. Existing HTTP,
browser and MCP parsers do not advertise a new rebase-and-merge operation.
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
`fgit-node/tests/native_rebase_merge.rs`, the path-review verifier tests and CLI
parser/receipt tests. They distinguish native validators, file-backed integration
and client parsing; authored tests alone do not qualify an executed native gate.

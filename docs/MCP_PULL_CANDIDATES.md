# Exact pull-request candidates over MCP

The trusted-local MCP profile can prepare an actual merge-commit or squash candidate
with `frankengit_source_candidate`, `operation: "prepare_pull_merge"`. Both
`--allow-source` and `--allow-pulls` are required. Its static operation catalog
states this conjunction; the handler enforces it before parsing or node work.
Source-write, review-write and merge-write grants do not imply either read grant.
This is an operator-sponsored local surface, not an IntentRun capability issuer
or the complete FG-096 / x2mv.4.24 agent execution path.

## Prepare the recorded PR, not newer branch tips

Supply the exact positive decimal strings `number`, `expected_version` and
`policy_epoch`; `expected_source` and `expected_target` native commit IDs; and
both full branch names, each as either its UTF-8 `source_reference` /
`target_reference` field or lossless `_hex` alternative, never both.
Native reference names remain bounded to 1,024 bytes.
All commit metadata is explicit: `author`, `committer`, `timestamp` (an exact
positive decimal string) and `message_hex`. These strings never authenticate a
principal. An optional `expected_head` pins the returned native snapshot.

`merge_profile` is either `path-merge-v1` (default) or `exact-renames-v1`.
The latter recognizes only the native planner's unique exact-content regular-file
moves, not similarity heuristics, copies or directory rename inference. Neither
profile executes hooks, attributes or external merge drivers.

`method` independently selects `merge-commit` (the default) or `squash`. The
first records the ordered target/source parents; squash records exactly the
target parent and keeps the merged tree. Empty, unknown or duplicate methods
are rejected. Neither choice falls back to a fast-forward. Explicit conflict
resolution remains two-parent and rejects a method selector.

The native PR selector validates the open PR, recorded version, policy epoch,
branch pair and exact tips, and fences source construction to the same head.
A changed PR, moved branch or different construction head refuses rather than
refreshing submitted coordinates. The optional head pin is checked against the
native result before any result is returned, not against an unrelated head read.

Three completed outcomes are distinct:

- `clean` returns a bounded complete bundle, native merge base, commit and tree,
  exact ordered parents, exact commit bytes, and three separate argument objects:
  `candidate_arguments` for review, `inspection_arguments` for inspection, and
  `publication_arguments` for the selected method.
- `conflicted` returns exact raw paths, native conflict classes and base/ours/theirs
  entry identities and modes. Candidate, tree, parents, bundle and arguments are
  null. A root-level path, when present, is explicitly labelled `root_path`.
- `already_up_to_date` has no candidate or bundle. It does not close the PR or
  manufacture a merge event.

Resource exhaustion, ambiguous merge bases, unsupported automatic semantics,
missing source and cancellation are errors, not successful partial candidates.
`complete` describes the bounded preparation result; `candidate_available` is
separately false for conflicts and already-integrated history. Every preparation
result identifies its selected `method`, including conflicts and no-op results;
all three argument objects are null when no candidate is available.

## Separate inspection, review and publication

Preparation is not a full-tree review or an approval. The existing native
`inspect_pull_request_bundle_in` surface owns inspection of the actual uploaded
merge result; the PR source-side diff alone does not establish that result.

For a clean candidate, `candidate_arguments` uses the shared input vocabulary of
`frankengit_pull_review` and `frankengit_pull_merge_reviewed`. It contains the exact
PR/version/policy/branch/tip/base/candidate coordinates and original bundle chunks.
It contains no retry key, review decision, reviewer identity, required reviewer
set, or head pin. The caller must inspect the actual artifact and independently
choose the review/publication operation, sponsor, original key and its required
review preconditions.

Use `inspection_arguments` directly with `frankengit_source_candidate`. It adds
`operation: "inspect_pull_merge"`, the selected `method`, exact returned snapshot
and bundle digest. A squash artifact that happens to reproduce the source
commit therefore retains its explicit squash intent during inspection.

For `frankengit_pull_merge_reviewed`, use `publication_arguments` and add the
caller-owned `idempotency_key` and nonempty `required_reviewers` list. This object
adds the exact method to the shared candidate coordinates and original bundle.
The publication tool defaults an omitted method to `merge-commit`; a squash
caller must preserve `method: "squash"`. The native publication driver rechecks
actual parent shape, current reviews and protection, and seals the method into
retry identity. Review arguments omit method because the vote binds the commit.

No read changes a ref, imports an object, seals a request,
records a vote, or grants permission to merge. A clean automatic candidate may
still be refused by current publication policy.

## Bounds and validation

The returned bundle remains at most three nonempty 8 KiB chunks (24 KiB decoded),
matching the existing review and merge tools. Complete candidate arguments reserve
4 KiB of the 64 KiB request limit for the RPC envelope, caller-owned key and named
reviewer set; optional review text still shares the global request budget.
Oversized artifacts are refused rather than truncated.

Preparation permits at most 4,096 commits, 100,000 tree entries, 64 conflicts,
1,024 newly generated objects, and 1 MiB of generated object bodies (256 KiB by
default). The named `max_commits`, `max_tree_entries`, `max_conflicts` and
`max_output_bytes` fields may narrow these ceilings. Native graph-edge, depth,
source-read, content-merge and request-context budgets remain in force. Metadata
identities are at most 1,024 bytes each; message bytes are at most 4 KiB. The
complete tool result remains at most 2 MiB.

Tests cover strict independent coordinates, explicit metadata/profiles/bounds,
raw byte encodings, non-candidate result integrity, template compatibility, and
persisted SHA-1/SHA-256 protocol preparation with exact-head repetition, unchanged
authority/object placement, conflicts, stale inputs and separate read/write grants.
The squash tests additionally carry real candidates through preparation,
inspection, independently sponsored review, method-bound publication and restart.
These Rust test definitions are not a passing execution claim. Run them on the
pinned toolchain and record the actual revision and result.

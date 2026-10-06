# Exact pull-request candidates over MCP

The trusted-local MCP profile can prepare an actual two-parent merge candidate
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

The native PR selector validates the open PR, recorded version, policy epoch,
branch pair and exact tips, and fences source construction to the same head.
A changed PR, moved branch or different construction head refuses rather than
refreshing submitted coordinates. The optional head pin is checked against the
native result before any result is returned, not against an unrelated head read.

Three completed outcomes are distinct:

- `clean` returns a bounded complete bundle, native merge base, commit and tree,
  ordered target/source parents, exact commit bytes, and `candidate_arguments`.
- `conflicted` returns exact raw paths, native conflict classes and base/ours/theirs
  entry identities and modes. Candidate, tree, parents, bundle and arguments are
  null. A root-level path, when present, is explicitly labelled `root_path`.
- `already_up_to_date` has no candidate or bundle. It does not close the PR or
  manufacture a merge event.

Resource exhaustion, ambiguous merge bases, unsupported automatic semantics,
missing source and cancellation are errors, not successful partial candidates.
`complete` describes the bounded preparation result; `candidate_available` is
separately false for conflicts and already-integrated history.

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
review preconditions. No read changes a ref, imports an object, seals a request,
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
The implementation environment lacks Cargo, rustc, rustfmt and a built fg: these
Rust tests are authored but not executed. No native passing gate, full agent-day,
performance or bead-closure claim is made.

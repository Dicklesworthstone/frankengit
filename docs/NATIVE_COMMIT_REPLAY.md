# Native cherry-pick and revert preparation

`fg cherry-pick prepare` and `fg revert prepare` construct one reviewable native
commit from an exact historical change. They reuse the existing path-based
merge planner, verified object reader, single-parent candidate validator,
pack writer, and create-only artifact publisher. They do not invoke Git,
create another worktree or database, or mutate repository authority.

The output is a normal single-parent candidate bundle. Review it with
`fg workspace inspect`, then deliberately publish it with `fg workspace apply`.
The latter remains ordinary source-update admission, not PR merge publication,
and does not acquire the exact-candidate review gate merely because the input
was prepared here. Repository-wide mandatory protection remains unfinished.

## Prepare one selected change

```bash
fg cherry-pick prepare "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main ./picked.bundle \
  --trusted-local --profile path-v1 \
  --source-ref refs/heads/topic \
  --expected-target "$TARGET_BEFORE" --expected-source "$SOURCE_TIP" \
  --commit "$SELECTED_COMMIT" \
  --author 'Operator <operator@example.invalid>' --timestamp 1788883200 \
  --message 'Apply the selected change'
```

`--commit` may identify a historical commit, not only the source tip. The node
first proves that it is reachable from the explicitly selected source branch.
Changes introduced by later source commits are not applied. The target may
have unrelated history: replay is a three-way application of one change, not
merge-base selection between two branches.

Both current branch tips must match their supplied expectations and come from
one authenticated authority head. An optional `--expected-head` accepts the
`alg:<code>:<hex>` snapshot token returned by earlier commands and rejects a
changed snapshot. A raw object merely present elsewhere in the admitted object
set is not enough to authorize historical selection.

SHA-1 and SHA-256 are inferred from the explicit native IDs. Mixed formats and
zero IDs refuse; there is no separate `--object-format` argument to override
those identities. Source and target may be the same branch, particularly when
reverting an older commit. Both must be fully qualified branch refs. Caller
visibility may narrow, but never override, canonical hidden-ref policy.

## Revert without rewriting history

```bash
fg revert prepare "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main ./reverted.bundle \
  --trusted-local --profile path-v1 \
  --source-ref refs/heads/main \
  --expected-target "$CURRENT_TIP" --expected-source "$CURRENT_TIP" \
  --commit "$COMMIT_TO_REVERT" \
  --author 'Operator <operator@example.invalid>' --timestamp 1788883201 \
  --message 'Revert the selected change'
```

Cherry-pick merges the selected parent's tree, the current target tree, and the
selected commit's tree. Revert swaps the selected commit and its parent in
that comparison, applying the inverse while retaining unrelated target work.
Both produce a commit whose only parent is the exact current target. A revert
appends history; it does not reset a ref to an earlier commit.

A merge commit requires `--mainline <n>`, with a positive, one-based position
in its stored parent order. The position is not a branch name or a guess about
which parent mattered. A single-parent commit defaults to position one. A root
commit accepts no mainline and compares against the canonical empty Git tree.
Invalid mainlines fail before a candidate is emitted.

## Conflicts, no-change results, and metadata

The existing path-v1 planner recursively combines directory and regular-file
changes and preserves native modes and unchanged objects. Its binary,
modify/delete, type, mode, opaque-entry, and attribute-dependent conflicts stay
explicit. It never invokes a merge driver or silently inserts/strips conflict
markers. Conflicts return raw path bytes and actual base/ours/theirs identities
and modes, with no partial commit or bundle. For revert, base means the
selected commit and theirs means its selected parent, not another branch.

If the resulting tree equals the target tree, the command returns `no_change`
and creates no empty commit. That is a net-content observation, not proof that
the selected change previously appeared in the target's history.

Author, committer, timestamp, and message are explicit construction inputs.
The committer defaults to the supplied author, never to ambient Git settings.
This is not a claim of upstream cherry-pick's metadata-preservation behavior.
Author/committer headers are claims, not authenticated identities. Timestamps
are positive integral Unix seconds, bounded by signed 64-bit range, with UTC
encoding. Supply exactly one of `--message` or `--message-file`; the latter
preserves raw bytes, CRLF and missing final newlines. Messages must be nonempty,
NUL-free, and at most 64 KiB. Input files must be bounded regular files under
the authorized local operator's control, not symlinks or devices.

`--target-ref-hex` interprets the positional target name as lowercase hex;
`--source-ref-hex <hex>` replaces `--source-ref`. Neither permits lossy Unicode
normalization or broadens access. JSON escapes controls and preserves exact
message bytes in `message_hex`.

## Complete target-only bundles

A replayed source commit is not a parent of the new commit. Therefore a bundle
containing only newly constructed objects could omit a source-only blob or
subtree the planner reused, producing a candidate that works locally but fails
in a destination with only target history.

The node independently validates both the target's full native closure and the
candidate's full closure. It packs the exact set difference: candidate objects
absent from target history, whether constructed or borrowed from source history.
Its single prerequisite is the target commit. Source commits and unused later
source objects are not secretly required or added. The receipt distinguishes
`generated_objects`, `pack_objects`, and `borrowed_objects`.

Every constructed object is strictly verified, and the candidate's sole parent
and all reachable native dependencies are independently checked before packing.
The existing compressed no-delta writer provides deterministic output. Root
reversal includes the actual empty-tree bytes when they are needed. Objects
remain in memory or the returned artifact; preparation never stages them in
the node's object fabric, creates a seal, or advances refs, forge or outbox state.

## Review and explicitly publish

Use the candidate ID returned in the preparation receipt, after independently
checking that receipt and artifact against the intended operation:

```bash
fg workspace inspect "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main ./picked.bundle --trusted-local \
  --expected-base "$TARGET_BEFORE" --expected-commit "$CANDIDATE_COMMIT"

fg workspace apply "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main ./picked.bundle --trusted-local \
  --principal "$PRINCIPAL_ID" --idempotency-key "$PUBLICATION_KEY" \
  --expected-base "$TARGET_BEFORE" --expected-commit "$CANDIDATE_COMMIT"
```

These are existing single-parent inspection/publication commands. Publication
retains its own current policy, expected-old, seal and authority-CAS checks.
A stale target never becomes permission to force a ref. An identical publication
retry recovers its historical outcome rather than rolling back a later change.
The current workspace-apply CLI is Linux-gated; the preparation and inspection
commands do not acquire that host-tool gate. Remote authentication remains a
separate integration responsibility; `--trusted-local` is not a credential.

The output path must be absent. The node is explicitly closed before the shared
artifact writer synchronizes a temporary file and publishes it with a create-only
hard link. Existing files, directories, and symlinks are never overwritten.
Unsupported filesystem operations refuse rather than using an overwrite-rename
fallback. A failure after visibility retains that fact. Receipt write/flush
failure distinguishes whether a complete bundle was already published; it does
not suggest that the repository was mutated by preparation.

Exit 0 means `prepared` or `no_change`; exit 3 means conflicts, with a complete
conflict report and no bundle; exit 2 means an input, infrastructure, budget,
shutdown, artifact, or output error. Conflict exit 3 is not a canonical mutation
refusal: preparation submits no mutation. `approval_granted` and
`published_to_repository` remain false.

## Bounds and applicability

The inherited profile allows at most 4096 history commits, 16384 parent edges,
100000 tree entries, depth 64, 4096-byte repository paths, 64 content merges,
1 MiB per text merge input, 128 conflicts, 10000 generated/packed objects, and
32 MiB of generated/packed expanded bytes. Source-read work shares the existing
128 MiB cumulative byte ceiling. Native closure validation retains its separate
object, edge and byte budgets. The CLI can lower history and output ceilings
with `--max-commits`, `--max-edges`, and `--max-output-bytes`; invalid or excessive
limits refuse rather than disabling checks.

This is one-commit path-v1 replay, not a complete Git sequencer or rebase engine.
It does not implement ranges, continue/abort state, automatic rename/copy
inference, custom drivers, attribute interpretation, or automatic conflict
resolution. Existing `fg merge resolve` is a two-parent merge workflow, not a
replay-conflict continuation. New candidates require explicit review; neither
preparation nor artifact inspection authorizes their own publication.

## Verification status

Fifteen Rust test functions are registered: eight core replay tests, three
embedded-node integration tests, and four CLI tests. They cover both native
hash formats, historical selection, exact single-parent metadata, root and
mainline semantics, inverse binary/mode/deletion changes, no-change outcomes,
conflicts, bounded work, visibility, source-only borrowed objects, inspection,
publication, reversal, stale snapshots and retry without rollback.

```bash
python3 scripts/e2e/commit_replay_smoke.py --self-test
python3 scripts/e2e/commit_replay_smoke.py --git-oracle /absolute/path/to/git
python3 scripts/e2e/commit_replay_smoke.py --fg /absolute/path/to/fg
```

The checker self-test executed and rejected 50 corrupted reports or bundles.
The isolated Git 2.47.3 oracle executed for SHA-1 and SHA-256: independently
constructed bundles verified and fetched into target-only repositories, exact
candidate bytes and absent source commits were checked, and real cherry-pick /
revert operations reproduced independently expected trees. These are fixture
and bundle-format checks, not executions or conformance claims for FrankenGit.

Python compilation/help, Rust lexical/delimiter checks, and exact local versus
GitHub blob checks were performed. Cargo, rustc, rustfmt, Clippy and a built
`fg` were unavailable. Rust compilation, all native tests, and the complete
fresh-process binary campaign were not run. The campaign fingerprints its
supplied binary and does not substitute a Python implementation for it. No
bead is closed and no passing native gate is claimed by this source integration.

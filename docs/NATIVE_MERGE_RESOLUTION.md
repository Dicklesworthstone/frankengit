# Explicit native merge conflict resolution

`fg merge resolve` fills the gap between a conflicted `merge prepare` result
and an inspectable, publishable merge candidate. It reuses the existing native
merge planner, verified object reader, candidate validator, pack writer and
create-only artifact publisher. It does not run Git, a merge driver or user
code, stage objects, seal a transaction, move refs, append forge events or
create an approval. Publication remains a separate `fg merge apply` operation.

## Resolve the exact conflict

Supply the independently selected target/source commit identities and their
unique best merge base, plus exactly one choice for every conflicted path:

```bash
fg merge resolve "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main ./resolved.bundle \
  --trusted-local --profile path-v1 --source-ref refs/heads/topic \
  --method squash \
  --expected-target "$TARGET_BEFORE" --expected-source "$SOURCE_COMMIT" \
  --merge-base "$MERGE_BASE" \
  --author 'Operator <operator@example.invalid>' \
  --timestamp 1788883200 --message 'Resolve the reviewed merge conflicts' \
  --file src/example.rs 100644 ./resolved-example.rs
```

`--method squash` constructs a commit with the exact target-before tip as its
only parent. Use `--method merge-commit`, or omit the flag, for the existing
ordered target/source two-parent commit. The selected method changes the
commit's parent list; it does not change the conflict set, resolution choices,
merge base or resulting tree. Fast-forward is not a resolution method.

The command fails without creating a candidate if any other conflict remains.
There is no implicit side choice or blanket `--all-ours`. Alternatives
to supplying a file are `--ours path`, `--theirs path`, `--base path`, and
`--delete path`. Each has a `-hex` spelling for raw repository path bytes,
including `--file-hex <hex-path> <100644|100755> <local-file>`.

`ours` means the target-before side and `theirs` means the incoming source.
A side choice preserves that entry's exact native identity and mode, including
a whole directory, symlink or gitlink in a type conflict. Symlinks and gitlinks
are not followed. Selecting a nonexistent side is an error, not shorthand for
deletion; use `--delete` to express that intent. A new file resolution must
explicitly choose a regular-file mode: `100644` or `100755`.

Manual bytes may be empty or binary and retain CRLF, invalid UTF-8 and a missing
final newline. No marker removal, text normalization, implicit chmod, attribute
interpretation or external command occurs. A file that still contains conflict
markers remains those exact bytes; preparation does not certify its correctness.
The input file must be a stable regular file under the local operator's control.
Final symlinks, devices and oversized inputs are rejected. This is not a hostile
filesystem race-isolation guarantee.

The native hash format is inferred from the required commit identities.
An optional `--object-format sha1|sha256` must agree. Both current visible
branch tips must still equal their supplied identities. A changed branch is
refused, not silently rebased; the supplied merge base must be uniquely best.
Unrelated histories and multiple best bases retain their existing refusals.

## Conflict-only, all-or-nothing construction

The automatic `PathMergeV1` planner is the conflict oracle. Resolution first
recomputes its actual conflicts at the exact input commits, checks that every
and only those paths have a choice, then reconstructs through the same planner.
A clean path cannot be changed through this interface. Duplicate paths,
ancestor/descendant overlaps, absent sides and unconsumed choices refuse.
A merge with no conflicts belongs to `merge prepare`, not `merge resolve`.

The second pass must reproduce each conflict's kind and exact base/ours/theirs
entries before consuming its resolution. Both passes retain the same source,
resource counters and generated-object map. Graph discovery happens once;
tree/content discovery and reconstruction share a single total budget rather
than receiving two fresh allowances. Clean automatic merges and unchanged
siblings are retained. Native object identities deduplicate repeated emission.

The resulting commit follows the explicit method: target-before is its sole
parent for squash, or its first parent followed by source for merge-commit.
Both original tips remain bundle prerequisites, because the resolved tree can
reuse source-side objects even when source is not a commit parent. The existing
production validator independently hashes and traverses the complete candidate
and source closure before the shared pack writer emits its bundle. Original
objects come from the authenticated repository selection; new objects remain
in memory and are not imported into node storage.

Resolution currently uses `PathMergeV1`. Selecting squash does not enable
`ExactRenamesV1`, infer renamed conflicts or synthesize a virtual merge base.

## Inspect before applying

The JSON receipt has type `merge_resolution`, profile `path-resolved-v1`, the
explicit `method` (`merge-commit` or `squash`), and
`published_to_repository: false`. It records exact input commits, source
reference names as hex, the observed authority head, resulting tree/commit,
complete bundle SHA-256 and counts, and a deterministic raw-path-ordered list
of original conflicts, choices and resulting entries. Modes in those conflict
entries are numeric, as in the existing preparation receipt.

Review the saved bytes with `fg merge inspect`, supplying the same source,
target and base and the returned `candidate_commit`. The inspector compares
the target parent against the actual result, including manual changes. Only
then use the separate `fg merge apply` with the receipt's same `--method`,
reviewed coordinates, principal, idempotency key and PR version. Squash requires
an existing open PR at a positive version. Use `fg pr review` and
`fg merge apply-reviewed` when collecting and requiring exact-candidate votes;
review binds the commit identity without a method flag, while publication
retains the selected method. Resolution does not approve itself, waive policy,
freeze repository state or change the apply command's retry semantics.

The node is explicitly closed before artifact publication. Output is a new
regular bundle created through the existing synchronized temporary-file and
non-overwriting hard-link procedure. Existing files, directories and symlinks
are not replaced. Receipt write/flush failures after artifact creation preserve
the known candidate identity and path in the error. Exit 0 means a complete
candidate was created; exit 2 is an error, never evidence of repository commit.
Consumers must require a complete JSON document and successful exit.

The native APIs accept the style as their last argument:

- `prepare_resolved_merge_with_style(..., limits, style)` in `fgit-forge`;
- `OneNode::prepare_resolved_merge_bundle_with_style_in(..., limits, style)`;
- `OneNode::prepare_resolved_pull_request_bundle_with_style_in(..., limits, style)`.

The existing entry points without `with_style` remain wrappers for
`MergeCommitStyle::TwoParent`, preserving their candidate bytes. The node's
branch-level API additionally accepts an optional exact authority-head
precondition. Its PR API rechecks the exact open PR and policy subject. The CLI
currently exposes only the mandatory native tip/base pins; its `source_head`
is an observation, not a capability.
The caller must already be authorized as a local operator. Ref visibility can
narrow canonical policy; path choices cannot grant access or reviewer authority.

## Bounds and verification

The existing upper preparation profile remains 4,096 commits, 16,384 parent
edges, 100,000 visited tree entries, depth 64, 4,096 path bytes, 64 content merges,
128 conflicts, 10,000 generated objects and 32 MiB generated payload bytes.
Manual file inputs are at most 1 MiB each; their combined bytes and paths are
at most 32 MiB. The two passes consume the same counters, so resolution may
refuse a case whose single automatic discovery pass fits. The verified source
owner also bounds each original read by node policy/32 MiB and cumulative reads
by 128 MiB. Existing native-closure and pack bounds apply independently.
CLI input is bounded before repository opening and JSON receipts are at most
4 MiB. Limits are enforced rather than silently omitting unresolved work.

Regression source covers both methods and object formats; exact commit parents
and native object bytes; nested conflicts with clean changes; mode/raw/binary/
empty data; whole-side type choices; explicit deletion; missing, duplicate and
clean-path choices; shared budgets; cancellation; visibility/stale pins;
stage-free inspection; exact-candidate review; and coupled publication/retry.
The legacy two-parent entry points are compared with explicit TwoParent
construction. Choosing ours can produce an empty target diff while still
constructing the explicitly selected squash commit.

```bash
python3 scripts/e2e/merge_resolution_smoke.py --self-test
python3 scripts/e2e/merge_resolution_smoke.py --fg /absolute/path/to/fg
```

The fresh-process campaign uses independent Python fixture/pack helpers to
calculate exact expected native blobs, trees and commits. It checks all
side/delete/file choices in both formats and both methods, inspects actual
candidates, rejects stale/invalid requests, opens a real PR, and exercises
coupled apply/retry with a fingerprinted binary. The helper self-test validates
its fixtures and rejects corrupted receipts, including a missing or substituted
method. That mode tests the checker, not FrankenGit's Rust implementation.
Use the built native binary campaign and Rust test suites for engine and
publication validation; source parsing alone is not a native test pass.

See [native squash merges](NATIVE_SQUASH_MERGES.md) and the
[exact-candidate review workflow](EXACT_CANDIDATE_REVIEW_WORKFLOW.md) for method
selection and the separate review/publication contract.

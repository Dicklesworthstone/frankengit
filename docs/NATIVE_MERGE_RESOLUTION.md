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
  --expected-target "$TARGET_BEFORE" --expected-source "$SOURCE_COMMIT" \
  --merge-base "$MERGE_BASE" \
  --author 'Operator <operator@example.invalid>' \
  --timestamp 1788883200 --message 'Resolve the reviewed merge conflicts' \
  --file src/example.rs 100644 ./resolved-example.rs
```

The command fails without creating a candidate if any other conflict remains.
There is no implicit first-parent default or blanket `--all-ours`. Alternatives
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

The resulting commit uses target-before as its first parent and source as its
second parent. The existing production validator independently hashes and
traverses the complete candidate closure before the shared pack writer emits
its bundle. Original objects come from the authenticated repository selection;
new objects remain in memory and are not imported into node storage.

## Inspect before applying

The JSON receipt has type `merge_resolution`, profile `path-resolved-v1`, and
`published_to_repository: false`. It records exact input commits, source
reference names as hex, the observed authority head, resulting tree/commit,
complete bundle SHA-256 and counts, and a deterministic raw-path-ordered list
of original conflicts, choices and resulting entries. Modes in those conflict
entries are numeric, as in the existing preparation receipt.

Review the saved bytes with `fg merge inspect`, supplying the same source,
target and base and the returned `candidate_commit`. The inspector compares
the target parent against the actual result, including manual changes. Only
then use the separate `fg merge apply` with the reviewed coordinates, principal,
idempotency key and PR version. Resolution does not approve itself, waive policy,
freeze repository state or change the apply command's retry semantics.

The node is explicitly closed before artifact publication. Output is a new
regular bundle created through the existing synchronized temporary-file and
non-overwriting hard-link procedure. Existing files, directories and symlinks
are not replaced. Receipt write/flush failures after artifact creation preserve
the known candidate identity and path in the error. Exit 0 means a complete
candidate was created; exit 2 is an error, never evidence of repository commit.
Consumers must require a complete JSON document and successful exit.

`OneNode::prepare_resolved_merge_bundle_in` additionally accepts an optional
exact authority-head precondition. The CLI currently exposes only the mandatory
native tip/base pins; its `source_head` is an observation, not a capability.
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

Thirteen Rust test functions were added: seven pure planner tests, two embedded
node tests and four CLI tests. They cover both object formats; nested conflicts
with clean changes; mode/raw/binary/empty data; whole-side type choices; explicit
deletion; missing, duplicate and clean-path choices; shared budgets; cancellation;
visibility/stale pins; stage-free inspection; and canonical apply/retry. Existing
automatic preparation and publication tests are retained.

```bash
python3 scripts/e2e/merge_resolution_smoke.py --self-test
python3 scripts/e2e/merge_resolution_smoke.py --fg /absolute/path/to/fg
```

The fresh-process campaign uses the existing independent Python fixture/pack
helpers, calculates exact expected native blobs, trees and commits, checks all
side/delete/file choices in both formats, inspects actual candidates, rejects
stale/invalid requests, and exercises real apply/retry with a fingerprinted
binary. The helper self-test was executed against the retrieved helper blob
`50953d2b68f759baaed4ae8a3142597ae985cd3b` and rejected 56 corrupted receipts.
That tests the fixtures and checker, not FrankenGit's Rust implementation.

Rust compilation, native tests, the full binary campaign, rustfmt and Clippy
were not run in this editing environment: Cargo, rustc and a built `fg` are
absent. Source/lexical checks and GitHub blob verification are not a native test
pass or bead closure. Rename inference, virtual-base synthesis, custom drivers,
durable reviewer approvals and broader forge completion remain outside this
explicit conflict-resolution profile.

# Verified source copies and renames

The existing `fg_source_changes.mjs draft`, `prepare`, and `inspect-candidate`
commands also accept explicit `copy` and `rename` operations. They reuse the
selected-source package, exact-patch encoder, independently derived whole-tree
root and ordinary candidate format described in [SOURCE_CHANGE_AUTHORING.md](SOURCE_CHANGE_AUTHORING.md).

```json
{
  "schema": "frankengit-source-changes-v1",
  "changes": [
    {
      "operation": "rename",
      "from_path_hex": "7372632f6d61696e2e7273",
      "path_hex": "6c69622f6d61696e2e7273"
    },
    {
      "operation": "copy",
      "from_path_hex": "72756e2e7368",
      "path_hex": "62696e2f72756e2e7368",
      "executable": false
    }
  ]
}
```

This renames `src/main.rs` to `lib/main.rs` and copies `run.sh` to `bin/run.sh`.
`path_hex` is always the destination; `from_path_hex` is the original source.
These are repository byte paths, never local filesystem paths. Both sides are
validated before asynchronous work. Sources must be selected regular files with
complete verified bytes. Destinations must be absent under the independently
selected commit, proved from the complete needed parent trees. A missing source
body or an omitted parent tree is not absence. No proof is fetched implicitly.

Copies preserve the source. Renames lower to an exact deletion plus an exact
creation in the same candidate, not native similarity hints or a production Git
subprocess. An optional boolean `executable` changes the destination mode only;
otherwise the original mode is preserved. Content is copied byte-for-byte,
including empty files, CRLF and missing final newlines. This profile continues
to refuse NUL-bearing binary content, symlinks, gitlinks and directory moves.
No content-edit fields may accompany a relocation.

All relocations read the original pinned source. Several copies may share one
source. Chains, swaps, overwrites, duplicate destinations, repeated removal of
one source, file/ancestor collisions and another edit to a relocation source
are refused. Copying a source that is also being renamed is refused rather than
selecting an implicit operation order. This bounded external change-set is not
the general sequential TreeFS intent evaluator.

The existing 32-effect authoring limit remains: a copy uses one destination
slot; a rename uses two. Every relocation charges its full source and destination
bytes, even when several copies share a blob. The 1 MiB per-file, 4 MiB retained
before/after, 1 MiB patch and original proof/tree/time limits still apply. All
source and destination names share the 32 KiB input path budget. A 17-rename
request therefore refuses before source hashing, while 16 independent renames
can use exactly 32 effects. Use the returned `effects` for the native selection:
copy sources are not write targets; rename sources are.

The reviewed manifest retains each explicit relocation's source/destination,
original blob, original mode and destination mode, plus the existing absence
witness. Different choices change the reviewed draft hash. Earlier requests
without relocation fields retain their previous manifest bytes. Preparation
and offline inspection recompute the expected root and reject omitted removals,
wrong content/modes or unrelated changes.

`bash scripts/verify_source_changes.sh` includes the focused relocation tests.
They exercise both native hash domains, actual Git-applied patches, complete
production imports and HTTP native-schema peers. Those peers are not Rust `fg`;
passing this lane is not native authorization, admission, pack closure or
full-workspace verification. No repository publication occurs in these commands;
publication still requires the separate original-principal/candidate consent and
one-shot journal workflow.

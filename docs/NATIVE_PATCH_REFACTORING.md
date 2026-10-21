# Atomic native file refactoring through fg patch

`fg patch prepare --profile exact-tree-v1` exposes the existing native regular-file
relocation engine. It composes explicit moves, exact text edits, ordinary binary
literal/delta edits, file creation/deletion and executable modes into one candidate.
It does not infer renames from equal content or similarity scores and never runs
Git, a source script, a host tool or an external merge driver.

```sh
fg patch prepare NODE TENANT REPOSITORY refs/heads/main refactor.patch candidate.bundle \
  --trusted-local --profile exact-tree-v1 --workspace-id WORKSPACE_ID \
  --expected-base BASE_OID --author 'Author <author@example.invalid>' \
  --timestamp TIMESTAMP --message 'Reviewed refactoring'
```

## Original coordinates and one result

A rename names `rename from` and `rename to` explicitly. A regular source must
exist at the exact selected base, and the destination must be absent. Both
endpoints retain the native read/write checks before content fetch. Existing
paths never become available because another section deletes or moves them.
Chains, swaps, cycles, duplicate endpoints, ancestor overlap, copies, symlinks,
gitlinks and compressed *edited* rename records remain refused. A pure binary
move needs no content hunk and preserves exact original bytes; edited text moves
may also change executable mode. Quoted raw paths are decoded without Unicode
normalization. Similarity percentages do not authorize an edit.

Every section must validate before a candidate bundle exists. An invalid later
file cannot publish half a move or leave a partially changed repository. The
native exporter preserves unmodified siblings and prunes directories emptied by
the explicit edits. Its sorted receipt reports both source deletion and target
creation, including their native blob IDs and resulting modes. A move is one
input file section but two path effects; existing parser/exporter bounds are not
increased or reinterpreted.

The original `exact-v1` remains text-only. `exact-binary-v1` accepts compressed
binary edits but still refuses rename records. Only the explicit new profile
admits moves. Existing unfiltered receipt fields and the apply API are unchanged;
the preparation receipt names the selected profile.

## Publication and recovery

Preparation does not move any ref, publish a forge event, or authorize a merge.
Inspect the exact bundle, then use ordinary `fg patch apply` with the independent
base/candidate, principal and original idempotency key. The normal quarantine,
protection, sealed admission and expected-old CAS remain the publication engine.
Fresh-process retries recover the original decision; they do not replay the
refactoring against a new source. Missing output is not evidence of non-commit.

This is the trusted-local owner surface, not remote authorization or a hostile
filesystem sandbox. File/output/read budgets and request-owned native execution
remain unchanged. No dependency, runtime or first-party unsafe boundary is added.

## Native checks

`cargo test --locked -p fgit-cli --bin fg patch_command::tests` checks explicit
profile selection and forbidden near twins. `fgit-node`'s `workspace_patch` and
`workspace_binary_patch` integration targets exercise the reused native engines.
With prebuilt `FG_BIN`, `scripts/e2e/suites/smokes/patch_refactor_native.sh` drives
actual fresh fg processes in SHA-1 and SHA-256. Independent Python encoders and
bundle inspection verify the whole tree, byte-exact moves, modes and siblings;
negative cases cover occupied destinations, bad identities, late-file failures,
chains, exact resource boundaries, wrong reviewed commits and stale source.
No mock node or Git subprocess participates. These are focused functional
checks, not full-workspace, release, physical-power-loss or hostile-isolation gates.

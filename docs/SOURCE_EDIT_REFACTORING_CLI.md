# Explicit file-refactoring patches from private local plans

`node scripts/fg_source_refactor.mjs compile` authors bounded native
`exact-tree-v1` patch input by default. It reuses `compileSourceReplacements`' encoder,
original-file checks, binary framing and limits; it does not apply a patch, read
a repository, publish a branch or infer a rename. Existing `fg_source_patch.mjs`
compile/splice commands and replacement profiles keep their previous behavior.

```sh
node scripts/fg_source_refactor.mjs compile \
  --plan-file /private/edit/refactor.json \
  --output /private/edit/refactor.patch
```

The plan and referenced files must be private regular files, with canonical
absolute local paths under owner-private `0700` directories. The destination
must be absent. The patch is linked create-only, synchronized, read back and
hash-checked. No shell command, network endpoint, credential or native executable
is accepted by this authoring command.

## Closed versioned plan

The plan schema is `frankengit-source-refactoring-v1`. The following is a shape
example; supply the independent full lowercase SHA-1 or SHA-256 blob ID rather
than the descriptive string below. Modes are JSON integers (`33188` is `100644`,
`33261` is `100755`), not octal strings.

```json
{
  "schema": "frankengit-source-refactoring-v1",
  "object_format": "sha256",
  "changes": [
    {
      "path_hex": "7372632f746f6f6c",
      "destination_hex": "6c69622f746f6f6c",
      "before": {
        "file": "/private/edit/original",
        "blob": "FULL_INDEPENDENT_LOWERCASE_NATIVE_BLOB_ID",
        "mode": 33188
      },
      "after": { "mode": 33261 }
    }
  ]
}
```

`path_hex` and `destination_hex` above name `src/tool` and `lib/tool`.
`destination_hex` makes a move explicit; it is never inferred from equal bytes.
For a move, both sides are required. Omitting `after.file` preserves the original
bytes and permits a separate executable-mode change. Supplying `after.file`
selects an exact text replacement while moving the file. Its complete original
blob ID and every new byte are committed into the output patch. Header paths
are losslessly quoted from raw bytes, without Unicode normalization.

Without `destination_hex`, a row retains the ordinary replacement schema:
`before: null` creates, `after: null` deletes, and two sides modify a file.
Every present side names its private `file`; original sides also require `blob`.
Thus one patch may combine explicit moves with text edits, ordinary binary
edits, executable modes, additions and deletions. The complete plan is checked
before the final output file is created.

Unknown keys, duplicate JSON members, ambiguous numeric spelling, invalid modes,
non-native IDs, wrong preimages, same-path no-ops, duplicate endpoints and ancestor
overlaps refuse. Every move source and destination participates in the same
original-coordinate namespace check. Deleting or moving one path does not make
it available to another section: chains, cycles, swaps and occupied-in-batch
move targets are not accepted.

## Binary and resource boundaries

Pure binary moves need no binary member: their unchanged bytes are selected by
exact original/result identities. They therefore do not transmit the whole file
body in both directions. A binary move whose bytes change is refused by the default `exact-tree-v1`,
including when only `--binary` is supplied. Explicit `--profile exact-tree-binary-v1`
together with `--binary literal|delta|delta-runs` opts into the new
[native binary refactoring path](NATIVE_BINARY_REFACTORING.md). Its receipt uses
`frankengit-source-refactoring-binary-v1`; existing defaults and encodings do not
change. The plan schema remains the same and still grants no native authority.

Ordinary same-path binary edits inside the batch require explicit `--binary
literal`, `--binary delta` or `--binary delta-runs`. Those options retain the
existing encoding algorithms and budgets. Text moves do not select compressed
binary syntax merely because a neighboring ordinary file uses it.

The existing bounds are unchanged: 32 input file sections; at most 64 affected
paths when every section moves a file; 32 KiB aggregate endpoint bytes; 4,096 bytes
and 64 components per path; 1 MiB per body; 8 MiB each of original and result
bytes; 1 MiB patch output and 131,072 records. A move counts both its original
and result image against the respective allowances. File-backed reads enforce
the remaining cumulative allowance before allocating a body. The JSON plan is
limited to 512 KiB. `--max-patch-bytes` may tighten but never increase the ceiling.

`--timeout-ms` is a positive integer up to 300,000, defaulting to 30,000.
Cancellation and timeout checkpoints precede final output ownership. Once
publication starts, synchronization/readback completes or reports uncertainty;
cancellation cannot justify deleting or overwriting an ambiguous output.

## Receipt and native preparation

The receipt names the exact plan SHA-256, exact patch SHA-256 and length, hash
format, file-section and affected-path counts, move count, byte totals and selected
binary profile. It states `preimages_verified: true`, but also explicitly states:

- `source_membership_verified: false`;
- `destinations_absent_verified: false`;
- `publication_attempted: false`.

An offline patch compiler cannot prove that a source exists, that its mode is
current, or that a destination is absent in the selected repository. Native
`fg patch prepare` with the matching explicit native profile must verify those
facts against the independently pinned source. Use `--expected-result-tree` to bind the complete
intended result, including untouched siblings, then inspect the exact resulting
bundle. Only ordinary `fg patch apply` with the reviewed commit, expected base,
principal and original idempotency key can publish. The plan and compiler receipt
are not substitutes for native evidence or authorization.

Exit `0` means the patch and receipt were produced. Exit `2` is an input or
pre-publication failure. Exit `4` means a result was retained or publication may
have started; stderr carries `retained_result` or `publication_unconfirmed` with
its independent hashes. A missing stdout response is not permission to overwrite
or automatically choose a new destination. Both concurrent and repeated writers
retain the creation-only boundary.

## Focused verification

```sh
node --test tests/operator/source_edit_refactoring.test.mjs \
  tests/operator/source_edit_refactoring_cli.test.mjs \
  tests/operator/source_edit_refactoring_git_oracle.test.mjs
```

The tests exercise the actual Node CLI, private files, competing processes and
broken stdout. A separately invoked installed Git is a **test-only oracle**, not
a product dependency. Each forward/reverse application starts in an independent
repository, verifies desired novel objects are absent before application, and
compares the whole resulting tree against independently calculated bytes in both
Git hash formats. This does not certify native Rust integration, remote source
preparation, hostile-host isolation, full operator qualification, release gates
or physical-power-loss recovery.

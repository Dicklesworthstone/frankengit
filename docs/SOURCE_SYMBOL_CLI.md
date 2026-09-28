# Native Rust declaration search from `fg`

`fg search --symbols` exposes the existing `rust-declaration-heads-v1`
reader over an imported FrankenGit repository. The storage root is the node
store, **not** a working tree or a `.git` directory. The operator must already
be authorized for whole-repository reads and explicitly pass `--trusted-local`.
Path, name, kind and source-pin options narrow a read; they do not grant access.

```sh
fg search --symbols "$STORE" "$TENANT" "$REPOSITORY" refs/heads/main \
  --trusted-local --name Repository --match prefix --kind struct --path crates
```

Names are case-sensitive ASCII identifiers, without a raw identifier's `r#`
prefix. Exact match is the default. Supported kinds are `function`, `struct`,
`enum`, `trait`, `type`, `module`, `union` and `macro`. Repeat `--kind` or `--path`
to select several. `--path-hex` preserves non-UTF-8 repository path bytes.
Specify `--object-format sha256` for a SHA-256 repository; SHA-1 is the default.

The JSON includes the authenticated `snapshot_token`, native commit/tree,
repository commit record, raw name/path/excerpt bytes as hexadecimal, and
one-based line/byte-column plus zero-based byte offsets. A raw identifier's
name span excludes `r#`. Work counters and exclusions remain explicit.
Reuse `snapshot_token` as `--expected-head` and `source_commit` as
`--expected-commit` to demand the same snapshot on another invocation. Neither
pin prevents another writer from advancing the repository after the read.

Only regular `.rs` files are parsed, including executable regular files.
Symlinks and gitlinks are not followed. Other languages are counted but not
parsed. This is declaration-head retrieval, not compiler name resolution:
attributes and macro bodies are opaque, macro-generated declarations are not
expanded, and all cfg branches are searched. No source code is executed.
Malformed or unsupported Rust source returns an error, including `path_hex`
and a byte offset, rather than silently becoming an empty answer.

## Existing persisted declaration tables

```sh
fg search --symbols --indexed-current "$STORE" "$TENANT" "$REPOSITORY" refs/heads/main \
  --trusted-local --name Repository --match prefix --kind struct \
  --max-index-bytes 33554432
```

This explicitly selects the existing native revalidated-index reader. It
requires a previously built symbol generation; this command does not build,
refresh or activate one. The native owner APIs
`OneNode::build_source_symbol_index_local_in` and its guarded variant remain
the construction boundary. An absent index is an error even when an on-demand
scan of the same source would succeed. There is no implicit scan fallback.

The node authenticates current visibility and verifies the current native
commit/tree before consulting the old index. A repository metadata-only
change can reuse the old generation when its tenant, repository incarnation,
ref, native hash domain, commit and tree still match. Changed code, hidden or
missing refs, integrity failures and exhausted budgets refuse.

The response deliberately has both `current_source` and `indexed_source`.
`distinct_index_provenance` reports whether they differ; the old source is
never relabelled as a new generation. `generation.token` and `generation.number`
identify the queried tables. Repeat them as `--minimum-generation` and
`--minimum-number` to set an ancestry floor. Both options must be supplied
together. A floor is not an exact generation selector or a retention pin.
Generation numbers and work counters use decimal JSON strings, preserving
all `u64` values.

## Bounds, completion and failure

Both profiles validate arguments before opening the store. Defaults come from
the existing source reader, including 200 returned matches, 20,000 files,
8 MiB per source file, 64 MiB total source bytes and bounded syntax work.
`--max-matches` can be raised to 4,096. The indexed profile separately bounds
payload bytes to at most 32 MiB. Its source-byte/file ceilings apply to
referenced index documents, not to a new source scan. The JSON output has a
16 MiB ceiling; source and index integrity checks stay with their owners.

Exit `0` means a complete answer, including a genuine empty result. Exit `3`
means at least one additional match exists beyond the returned prefix;
`complete` is false and `truncated_reason` is `match_limit`. There is no cursor
or `--after` option: narrow the query or raise the bounded match limit. Exit
`2` means argument, source/index, node shutdown or output failure. Shutdown
must complete before a successful JSON receipt is written. A broken output
stream can contain a partial write, but it cannot yield a successful exit.
Neither mode publishes canonical repository state or index state.

## Regression coverage and validation status

`crates/fgit-cli/tests/source_symbols_cli.rs` invokes the real `fg` binary over
native loose-object imports in both Git hash domains, and exercises persisted
index reads after a real authenticated HTTP issue mutation. It covers raw
filenames, executable `.rs` files, symlink/gitlink exclusion, exact/prefix/kind
selection, raw identifiers, opaque macro/string contents, snapshot refusals,
missing indexes, resource bounds and malformed-source diagnostics. Unit tests
cover argument validation, token round trips, distinct provenance, integer
rendering, completion, shutdown and broken-output behavior.

The implementation environment had no Cargo, rustc or rustfmt. These Rust
tests have **not** been compiled or executed here; no passing native gate or
bead closure is claimed. Independent fixture checks used installed Git to
verify both valid and malformed-source repositories with `fsck --strict` and
exact source-byte reads in SHA-1 and SHA-256. JSON format layouts and whitespace
were checked separately; neither check substitutes for Rust execution.

On a provisioned checkout, the focused native commands are:

```sh
cargo test -p fgit-cli --bin fg source_search::symbols
cargo test -p fgit-cli --test source_symbols_cli
```

Run the owning source-symbol/node suites and repository verification entrypoint
as well before treating this change as validated. The broader source-index
scalability limits and verification debt in
`docs/REALITY_CHECK_AND_BRIDGE_PLAN.md` remain open.

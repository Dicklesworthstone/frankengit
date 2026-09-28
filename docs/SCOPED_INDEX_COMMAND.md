# Native scoped-index operator command

`fg-index-scope` builds, queries and recovers the explicit path-scoped lexical
indexes described in [SCOPED_SOURCE_INDEXES.md](SCOPED_SOURCE_INDEXES.md). It
opens an EXISTING repository node, authenticates its authority head and uses
the native scoped APIs; it does not create a repository or call external Git.
All commands require `--trusted-local`. This is an operator interface, not an
HTTP permission or a grant derived from a search prefix.

Build the binary using the repository's pinned toolchain:

```bash
cargo build --locked -p fgit-node --bin fg-index-scope
```

The command source and regression tests were added in an environment without
Rust/Cargo. The commands below describe the implementation; they are not an
observed end-to-end pass or a claim that the workspace compiles.

## Build only the selected code subtree

```bash
mkdir -m 700 "$CANDIDATE_DIR"
fg-index-scope build "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main --trusted-local --prefix crates/fgit-node \
  --candidate-file "$CANDIDATE_DIR/node-index-first.json"
```

Use the repository's actual hash format. Repeat `--prefix` for a union, or use
`--prefix-hex` for exact non-UTF-8 repository path bytes. This creates a distinct
scope history, not a replacement for the whole-repository index. An existing
scope requires `--predecessor-token` with its exact prior index token and a NEW
candidate-record filename. `--expected-head` and `--expected-commit` optionally
pin canonical source. The source can move after selection; a build receipt
names its original source, not guaranteed freshness when stdout is delivered.

An unrelated oversized tracker or fixture outside the union is not read as a
source blob. Every selected regular file must still fit the existing limits;
a failure never silently drops that file. Narrow the union rather than claim
whole-repository coverage. Build limits can be reduced with `--max-file-bytes`,
`--max-source-bytes`, `--max-files`, `--max-entries` and `--max-depth`.

## Search, paginate and retain independent floors

```bash
fg-index-scope search "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main --trusted-local --prefix crates/fgit-node \
  --term needle --channel content --limit 100
```

Terms are whole ASCII words, folded and ANDed within `content` or `path`.
Repeat `--term` or use `--term-hex`. Optional `--filter-prefix` and
`--filter-prefix-hex` further restrict the query INSIDE the indexed union; they
do not select a different index. Work and payload reads can be narrowed with
`--max-work` and `--max-payload-bytes`.

Output explicitly states `coverage: "explicit-path-union"`,
`whole_repository: false`, the canonical `scope_prefixes_hex`, and scope SHA-256.
`complete_within_scope` is not a negative answer about the rest of the repository.
All counters, including document IDs, generation numbers, offsets and cursors,
are decimal JSON strings. Preserve their exact values rather than round them.
Paths and terms are hex, so raw name bytes never become terminal control text.

To continue a page, repeat the identical scope, terms, channel and query
filters, then pass the returned `next_after` as `--after`, `snapshot_token` as
`--expected-head`, `source_commit` as `--expected-commit`, and `index_token` /
`index_number` as `--index-token` / `--index-number`. Both parts of a checkpoint
are mandatory. `--minimum-index-token` / `--minimum-index-number` retain an
independent anti-rollback floor, including when reading an older exact generation.
A bare cursor refuses before opening the node. This interface, like the native
API, carries explicit repeated query inputs, not a signed query-bound cursor.

Every query authenticates current visibility before index disclosure. Metadata
changes can make the scoped index stale; there is no automatic refresh, source
scan, revalidation, fallback, retry or checkpoint reset. Whole-tree CLI/HTTP and
browser readers remain separate and unchanged.

## Write-ahead candidate record and recovery

Before any index payload staging or head update, the build's native barrier
writes the original candidate token with the namespace, repository incarnation,
full reference bytes, canonical scope, supplied source pins and predecessor.
It exclusively creates the named file with mode 0600, synchronizes its contents
and synchronizes the parent directory before native publication may proceed.
An existing filename, partial write or synchronization failure refuses without
allowing this invocation's index effects. Suspect files remain for inspection;
the command never overwrites, deletes, takes over or resets a candidate record.

The parent must already be a real private 0700 directory under trusted operator
control. This durable-record profile is Unix-only; unsupported hosts refuse
build rather than weaken it. It is not a hostile-same-user filesystem sandbox,
a lease or protection against independent changes to ancestor directories.
A record is NOT evidence that publication happened, even after a crash.

```bash
fg-index-scope recover "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main --trusted-local --prefix crates/fgit-node \
  --candidate "$ORIGINAL_CANDIDATE_TOKEN"
```

Copy the original token and exact scope from the retained record, checking its
namespace and incarnation against the node. Recovery never publishes or retries.
`active` and `superseded` establish membership in the selected verified history
and exit zero. `uninitialized` and `not_in_selected_history` emit JSON and exit 2;
they do not prove an earlier write was canceled. Failure exits 1. A missing or
hidden current ref still prevents disclosure, including during recovery.

Each command waits for its existing finite native request to settle and shuts
down the node before writing stdout. Default OS termination is not a cooperative
drain protocol; after interruption inspect the candidate record and use recovery.
Output or shutdown failure does not roll back a confirmed index. Keep the record
even after a successful build. Simultaneous server/operator access still needs
native backend integration evidence; this command adds no new locking authority.

The focused authored coverage includes parser refusals, lossless u64 boundaries,
exclusive filesystem records and real-process build/search/recovery over native
TreeFS/Fsqlite fixtures. It does not establish native test passes, crash safety
under power loss, whole-repository scale, automatic maintenance or index GC.

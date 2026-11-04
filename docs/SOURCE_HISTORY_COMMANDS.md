# Native history and line provenance

`fg log` and `fg blame` read native Git history directly from an authenticated
FrankenGit node. They reuse the same verified object owner as source review and
merge preparation. No checkout, external Git process, transaction seal, object
staging, ref update, forge event or outbox mutation is part of these operations.

## Commit history

```bash
fg log "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local --limit 50
```

The `topo-oid-v1` profile visits the complete reachable commit DAG. Every child
precedes all its parents. When multiple commits are ready, ascending native
object ID breaks the tie. This is deliberately not timestamp ordering: a
commit's author and committer timestamps cannot reorder causal ancestry.
Original parent order is retained inside each record.

The report includes the selected native tip, authenticated authority head,
exact commit bodies, trees and parents, total reachable commit count, and
`next_after`. Continue using the same ref, object format and limits, the
returned numeric offset, and the first page's `snapshot_token`:

```bash
fg log "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local --after 50 --limit 50 --expected-head "$SNAPSHOT_TOKEN"
```

Both the CLI and node API refuse an unpinned nonzero offset. An authority change
returns `SnapshotMoved` instead of splicing two histories. The token is an exact
precondition, not an authentication credential or a self-contained cursor.
Each invocation traverses the bounded DAG before slicing its page; pagination
does not pretend to make an otherwise over-budget history complete.

### Recent first-parent history on larger repositories

```bash
fg log "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local --first-parent --limit 50
```

The explicit `first-parent-prefix-v1` profile reads the selected tip and follows
only the first parent recorded in each commit until the requested page is full
or a root is reached. A repository can have more than 4,096 ancestors and still
return its recent first-parent history. Side-parent bodies, trees and blobs are
not read by this traversal. Original parent headers remain in each returned
record, and all of those headers count against the existing edge budget.

The report includes `root_reached`, `visited_commits`, `visited_parent_edges`,
the logical visited `metadata_bytes`, and `next_cursor`. It deliberately has no
`total_commits`: older ancestry has not been traversed. `complete: true` means
the requested page completed, not that the entire history was read or that a
later page is guaranteed to succeed. Missing or corrupt objects encountered
on the visited chain still refuse instead of truncating the page.

```bash
fg log "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local --first-parent --limit 50 --cursor "$NEXT_CURSOR"
```

The cursor binds the original authority head, exact raw reference, native tip
and numeric offset. It is a selection precondition, not an authentication
credential. Every continuation rechecks current visibility and the exact head,
then walks again from the authenticated visible tip. A cursor cannot directly
select another branch's object. A changed head, even after a forge-only write,
requires explicitly restarting the read; no automatic refresh mixes pages.

Skipped prefix and returned page share the unchanged per-call limits: at most
4,096 visited commits, 16,384 parent headers and 4 MiB of logical commit bodies,
with at most 64 KiB per commit enforced before the node's body allocation. A
deeper continuation can therefore exhaust its budget. This profile provides
bounded recent-history access, not constant-cost arbitrary-depth pagination.
`--max-commits` and `--max-edges` can still select narrower bounds. Metadata byte
accounting describes visited native bodies, not total physical I/O.

`--first-parent` cannot be combined with a path filter or `--after`; use its
returned cursor. Default log, path history and blame retain their existing
profiles. Both native hash formats and raw reference bytes are supported.
The same explicit profile is available through
[HTTP `source/log`](SOURCE_HISTORY_HTTP.md),
[MCP `frankengit_source_log`](MCP_SOURCE_HISTORY.md), and the
[browser history view](BROWSER_SOURCE_HISTORY.md). These adapters share the
canonical `fgfp1` cursor codec with the CLI. They retain their own response and
metadata ceilings; a cursor never enlarges a receiving interface's budget.

### History of one exact path

```bash
fg log "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local --path src/lib.rs
```

`--path` (raw bytes) or `--path-hex` selects `scope: "exact_path_changes"`:
only the commits whose `(mode, native object ID)` entry at that exact path
differs from at least one stored parent, plus a root that contains it. This is
unsimplified history over the same bounded DAG and order: merges keep their
real parents, and there is no rename, copy or first-parent inference.
Directories compare subtree IDs; symlinks and gitlinks are opaque leaves. A
never-present path returns a complete, empty page (`total_commits: 0`), not an
error. `path_hex` echoes the filter and is null for the unfiltered log. The
same native reader serves HTTP `source/log?path_hex=…` and MCP
`frankengit_source_log` with `path_hex`. `scripts/e2e/source_history_smoke.py`
exercises unchanged, changed and absent paths through the binary.

## Line attribution through merges

```bash
fg blame "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local --path crates/example/src/lib.rs \
  --line-start 20 --line-end 40
```

Line intervals are **zero-based and half-open**. Omitting the interval selects
all lines. An empty file has zero lines. A missing final LF, CRLF and invalid
UTF-8 remain exact bytes; no newline or encoding normalization is performed.
Only the selected line content is emitted, not an implicit full-file payload.

The `exact-lines-all-parents-v1` attribution profile now uses the bounded
`line-frontier-v1` traversal through the native node, CLI, HTTP and MCP:

1. Read the selected commit and file, then track only the requested lines.
   Read an ancestor when its contents are needed to resolve those lines;
   unrelated older history does not have to fit the commit budget.
2. For each active commit, resolve the same raw path in its parents, preserving
   their original order. Compare regular-file lines with the existing bounded
   Myers engine. Identical blobs bypass content diff and reuse cached bytes.
3. Propagate a line to the first parent with an exact equal-line mapping. Lines
   unmatched in every parent originate at the current commit. A merge may thus
   attribute some lines to its first branch, others to its second branch, and
   manually resolved additions to the merge itself.
4. Before returning, check that every attributed origin slice exactly equals
   its selected output slice. Return the unique origin commits and their exact
   native bodies alongside the current and original blob/line/byte coordinates.

The report's `traversal` identifies this contract. `graph_commits` counts the
commits actually visited, including parents examined to decide that a line was
new. It is not a total reachable-history count. Empty ranges read the selected
file without an ancestry scan; a tip-origin range can finish after inspecting
the immediate parents even when a much longer history precedes them. Older
lines still require their ancestry and can exhaust the existing limits.

The pure forge `history::blame` API retains `full-dag-v1` as an explicit
compatibility path and attribution oracle. `history::blame_frontier` returns
the same exact line/origin coordinates when both algorithms complete, while
their traversal counts and comparison work can differ. The node continues to
own source selection, current visibility and snapshot checks for either API.

Frontier traversal memoizes each ordered parent/current blob correspondence
and charges all comparisons against one aggregate `max_diff_work` budget.
All parent headers of each visited commit count against `max_edges`, including
duplicate headers and unvisited parent bodies. Cached blob bytes, line spans,
commit/path records, active routes and correspondence payloads share the
logical cache limit. Every encountered dependency, cancellation, cycle or
resource refusal fails the whole range; no partial attribution is returned.

The parent-order rule also applies to octopus merges. Duplicate parent headers
remain in raw metadata but do not duplicate graph dependencies or line work.
Line attribution is deterministic for the stated diff profile and limits; the
actual `MyersTrace`/`MyersLinearRefinement` path and work bound are reported.

This profile does not guess renames or copies, ignore whitespace, execute
attributes or text conversion, or implement Git's presentation heuristics.
A file absent or non-regular in a parent is a same-path boundary; a missing
object is an error, never a boundary. NUL-containing content encountered in a
comparison refuses binary blame. Symlinks and gitlinks are not followed.

## Identity, disclosure and output

Both commands require `--trusted-local`: the caller must already be an
authorized local operator. The node also applies caller-supplied ref visibility
and canonical hidden-ref policy. Neither command is a remote authentication
service or path-capability broker. A path/range is a query filter, not a grant.
Only ancestors reached from the selected visible tip are traversed; unrelated
admitted objects are not added merely because they exist in the repository.

`--object-format sha256` selects SHA-256; SHA-1 is the default. `--ref-hex`
interprets the positional ref as lowercase hexadecimal. Blame accepts exactly
one of `--path` or `--path-hex`. Ref names must point directly to commits;
annotated-tag peeling and arbitrary caller-supplied starting OIDs are not part
of this interface. `--expected-head` may also pin an initial log or blame query.

JSON has explicit profile, scope, source-tip and authority-head fields. Commit
bodies and selected content are hex, plus escaped text when valid UTF-8. Each
blame row contains current byte/line coordinates and `origin_commit`,
`origin_blob`, `origin_line`, `origin_byte_start`, and `origin_byte_end`.
Byte and line ends are exclusive. The origin table is unique and ordered by
native ID; log records instead follow the declared topological order.

Author, committer, signature and message headers are original **claims**. A
native object hash verifies those bytes, not the named person's identity.
Reports explicitly say `author_headers_authenticated: false`. These are
unsigned derived reads, not approvals, provenance attestations or publication
capabilities. Control and bidirectional-formatting characters use the existing
safe JSON escaping rather than becoming terminal commands.

## Failure and resource boundaries

The fixed upper profile is 4,096 commits, 16,384 parent edges, 100,000 visited
tree entries, depth 64 and 4,096 path bytes. Blame admits at most 1 MiB and 20,000
lines per compared blob, 32 MiB of logical cache payload, and 128 distinct
content comparisons. Frontier blame shares at most 1,000,000 work units across
all comparisons; each diff retains the 512,000 trace-cell ceiling. The explicit
full-DAG core compatibility API retains its original per-diff work budget and
blob/span cache accounting. Metadata output is at most 64 KiB per commit and
4 MiB per report. Log
pages contain 1 through 100 records. The shared native object owner separately
limits individual reads to node policy/32 MiB and cumulative reads to 128 MiB.
JSON is capped at 64 MiB.

`--max-commits` and `--max-edges` narrow graph bounds. Blame additionally exposes
`--max-blob-bytes`, `--max-lines`, `--max-comparisons` and `--max-diff-work`.
These flags cannot raise the fixed ceilings. Parent-edge limits are independent
of native header-count limits, so a one-edge graph may still have ordinary tree,
author and committer headers.

Missing or corrupt history, cycles, invalid paths/ranges, unsupported tree modes,
resource exhaustion and cancellation return errors instead of successful partial
history or fabricated line origins. Checkpoints surround reads and bounded work;
an individual finite synchronous hash/diff is not claimed to be preemptible at
every instruction. No detached context or replacement budget finishes a query.

The node is explicitly closed before result output. Exit 0 means the complete
requested page or line range; exit 2 means no successful result. Output failure
may leave an incomplete JSON prefix. Consumers must require successful exit and
a complete JSON document, not merely a prefix containing `complete: true`.

## Implementation and verification

`fgit-forge::history` owns the pure graph/page/attribution algorithms.
`OneNode::read_commit_history_in` and `OneNode::blame_source_in` own authenticated
selection through the existing private `SelectedSource`. The CLI validates,
invokes those operations, closes, checks response bindings, and renders.
No new dependency or lockfile entry is required.

The core tests cover both hash domains, merge-parent order, shifted lines,
exact bytes, ranges, empty files, missing final LF, malformed objects, selected
source refusals, cache reuse, bounds and every cancellation checkpoint. Frontier
cases additionally compare generated DAGs against the unchanged full-DAG oracle,
force late convergence at an already processed ancestor, exercise touched cycles
that stop line propagation, and use a real 100,000-commit irrelevant tail.

The standalone core runner compiles the actual production history modules and
source contracts with the real types, crypto and diff libraries. It needs the
pinned toolchain and cached workspace dependencies, and writes into a private
caller-selected target directory:

```bash
CARGO_TARGET_DIR=/data/frankengit-targets/history-core \
  python3 scripts/test_history_core.py
```

This core lane excludes the node, authority selection and transports. Embedded
node, CLI and HTTP tests separately cover visibility, exact head pins, unchanged
canonical state and output/transport failure. Core execution does not stand in
for those integration lanes.

```bash
python3 scripts/e2e/source_history_smoke.py --self-test
python3 scripts/e2e/source_history_smoke.py --fg /absolute/path/to/fg
```

The real-binary campaign builds its own native-object fixtures, checks exact
commit bodies and every originating line slice, exercises pagination and raw
paths, and compares canonical state before and after reads. It fingerprints the
provided executable. `--self-test` exercises fixture construction and the
checker only; it does not execute FrankenGit.

The frontier work-count cases establish avoided ancestry reads in the pure
history algorithm. They do not remove the native source owner's independent
object-selection, storage or authentication ceilings, and are not end-to-end
latency measurements. Broader Git presentation compatibility, unbounded
histories, rename/copy attribution and remote authorization remain outside
these explicit profiles.

# MCP commit history and line provenance

`fg-mcp` adds two source-read tools using the node's existing authenticated
history engine. Both require `--allow-source`; PR and issue access do not imply
source access. The same launch-bound repository/incarnation, strict JSON,
stdio session and explicit shutdown rules remain in force. Neither tool runs
Git, a shell, repository scripts or a checkout operation.

## Commit DAG pages

Call `frankengit_source_log` with:

```json
{"reference":"refs/heads/main","limit":5}
```

The complete bounded reachable graph is ordered child-before-parent; native ID
order breaks ties among ready nodes. This is not a timestamp sort or a
first-parent-only log. Original parent order and exact native commit body bytes
are returned in `parents` and `body_hex`. The adapter rechecks each returned
commit's native object hash. Author, committer and signature headers remain
untrusted metadata; `author_authenticated=false` is explicit.

`limit` is a JSON integer in 1..20 (default 5). `after` is a canonical unsigned
decimal string (default `"0"`), representing an offset in the pinned ordered
graph. Nonzero offsets require the preceding page's `snapshot_token` as
`expected_head`. Every page reports `total_commits`, `next_after` and `complete`.
A missing ancestor, corrupt object or traversal limit is an error, not a short
successful page. Exactly-at-end requests produce an empty completed page;
beyond-end offsets refuse. A new publication invalidates the strict head pin.

With `path_hex` (exact repository path bytes), the page lists only the commits
whose entry at that path differs from at least one stored parent, plus a root
containing it, over the same graph and order. It is unsimplified (real merge
parents, no rename inference) and reports `path_hex`; a never-present path is a
complete empty page. It is served by the same node reader as `fg log --path`
and HTTP `source/log?path_hex`, and the adapter accepts a filtered page that
starts below the tip only when a path was requested.

## Recent first-parent pages

The same `frankengit_source_log` tool accepts an explicit bounded prefix profile:

```json
{"reference":"refs/heads/main","first_parent":true,"limit":5}
```

`first_parent: true` invokes the node's existing `first-parent-prefix-v1`
reader, also used by `fg log --first-parent`. It reads the visible tip and
follows only each commit's stored first parent until the requested page is
full or a root is reached. Recent pages therefore work on histories exceeding
the complete-DAG traversal ceiling. Side-parent identities stay in `parents`
in their original order; their bodies, trees and blobs are not traversed.

This result has `profile: "first-parent-prefix-v1"`,
`scope: "first_parent_chain"`, `root_reached`, `visited_commits`,
`visited_parent_edges`, `metadata_bytes` and `next_cursor`. It has no
`total_commits` or `next_after`: unread ancestors have not been counted.
`complete: true` means the requested page completed. It does not imply that
the root was reached, or that the next page will fit within the same budget.
Exact commit body hashes, first-parent chain order, cursor bindings, and
reported work are checked before the adapter emits success.

Continue using the returned cursor and the same raw reference:

```json
{
  "reference":"refs/heads/main",
  "first_parent":true,
  "limit":5,
  "cursor":"<next_cursor from the preceding page>"
}
```

The canonical `fgfp1` cursor binds the authority head, reference bytes, native
tip and offset. It is a selection precondition, not an authentication
credential or a direct object selector. Continuation still selects the current
visible reference, checks the exact head and tip, and re-walks the prefix from
that tip. An optional `expected_head` must agree with the cursor;
`expected_commit` must agree with the cursor tip before any node I/O; it remains
a comparison pin against the selected source. Any authority change, including a
forge-only publication, refuses the old cursor rather than silently refreshing
it. A caller must explicitly start a new read. No historical object is made
readable merely by putting its ID into a cursor.

First-parent mode cannot combine with `after`, even `"0"`, or `path_hex`.
A cursor without `first_parent: true` refuses. The flag accepts only the JSON
boolean `true`; explicit `false` refuses. Omitting it retains the
complete-DAG/path-history behavior. Blame accepts neither first-parent field.

The existing MCP bounds remain: `limit` is 1..20, `max_commits` can narrow
1..4096, and the skipped prefix plus returned page share at most 16,384 parent
headers and 128 KiB of logical commit metadata. All parent headers count,
including those whose bodies are not followed. Each commit is bounded to
64 KiB before node allocation. Work counters are canonical decimal strings
and describe logical visited objects, not physical I/O. Deep continuations
can still exhaust these bounds; this is recent-history access, not
constant-cost pagination to arbitrary depth.

The same operator `--allow-source` grant owns this mode. Pull-request access
does not grant history, and the closed sponsored-agent source profile continues
to exclude both history tools.

## Exact line ancestry

Call `frankengit_source_blame` with:

```json
{
  "reference":"refs/heads/main",
  "path_hex":"7372632f6d61696e2e7273",
  "first_line":"0",
  "limit":100
}
```

Line indexes are zero-based. `first_line` is an unsigned decimal string and
`limit` a JSON integer in 1..200 (default 100). Nonzero starting lines require
`expected_head`. The endpoint first asks the native engine for an empty range
to learn the exact file length, then obtains the requested range from that same
head. The upper bound clamps at EOF, so a 100-line request works on a short
file. A publication between the two reads refuses rather than mixing a size
from one file version with attribution from another. At most two bounded native
reads occur per call. Both share the request's existing runtime/storage budgets.
The empty-range size probe uses the native line frontier and reads no ancestor
bodies. The requested attribution then traverses only the ancestry those lines
need, keeping current source authorization and the exact head pin.

The result carries `bytes_hex`, absolute byte ranges, `first_line`, `end_line`,
`total_lines`, `next_first_line` and `complete`. Every returned line has exact
origin commit/blob/line/byte coordinates, and the referenced origin commits
appear once in native-ID order with exact body bytes. The adapter checks payload
partitioning, ranges, native hash domains and complete origin-record coverage
before emitting success. `attribution_complete=true` concerns the returned
range, not the rest of the file.

The native engine follows exact same-path line matches through **all parents in
stored parent order**, including merge parents. It does not guess renames,
copies, whitespace-equivalent lines or human authorship. CRLF and missing final
LF remain byte-exact; binary blame, missing paths and incomplete/corrupt history
refuse. `human_authorship_proven=false` and `merge_permission=null` prevent
provenance from being presented as authentication or merge approval.

Results identify `traversal: "line-frontier-v1"`. `graph_commits` is a decimal
count of commits actually visited, including examined parents that did not
contribute lines. It is not the repository's total history size. A recent
line can resolve without scanning a much older tail, while older origins can
still exhaust the commit budget. Exact ordered blob-pair comparisons are
memoized and share one aggregate `max_diff_work` ceiling per native call.
The compatibility core API retains `full-dag-v1` as the complete-DAG oracle;
the MCP endpoint selects frontier traversal through the existing native owner.

## Selection and bounds

Both tools accept exactly one of `reference` (full UTF-8 `refs/...` name) and
`reference_hex` (raw bytes). `path_hex` is a raw relative repository path, never
a host path. `expected_commit` is an optional nonzero native-ID comparison pin;
it does not select arbitrary objects or bypass current hidden-ref policy.
`expected_head` always compares the authenticated current head. No retained
historical view or automatic latest-tip refresh is substituted.

Optional `max_commits` narrows native traversal to 1..4096 commits. Blame also
allows `max_blob_bytes` (1..1,048,576) and `max_diff_work` (1..1,000,000). The other
native edge, tree, comparison, line and cache ceilings remain unchanged.
Metadata returned in a call is bounded to 128 KiB before hex encoding and each
commit body to 64 KiB. For first-parent history the 128 KiB budget also counts
the skipped prefix, even though only the page's bodies are returned. Blame
content is bounded to 64 KiB per returned page; a
long-line page exceeds this with a `blame_page_byte_limit` error, not truncation.
The final encoded tool result has a separate 2 MiB ceiling. Reduce page size or
narrow the request when these limits refuse. Bounds are not indexed-history or
performance claims.

All 64-bit IDs, offsets and counters are decimal strings. Source bytes stay hex;
no lossy Unicode conversion is performed. Complete answers are assembled before
protocol success. Tool failures never invent a terminal transaction outcome, an
empty repository, authenticated authorship or permission to publish.

## Verification boundary

Unit tests cover argument and limit rejection, source grant requirements,
cryptographically bound raw commit bodies, DAG page shapes, exact cursors,
line partitions, missing origin records, byte caps and hash-domain mismatches.
A real-node scenario creates native commits, closes and reopens both SHA-1 and
SHA-256 nodes, uses MCP log and blame calls, verifies line origins, paginates
short files, rejects stale heads and confirms unchanged authority after reads.
First-parent regressions additionally seed 4,097-commit native histories in both
hash domains, read and continue them through the MCP protocol across node
reopen, and pair permitted pages with narrower-budget, substituted-cursor,
source-pin and forge-only-head-change refusals. Source-grant and sponsored
catalogue tests keep this mode within the existing access profile.
The pinned `nightly-2026-08-31` toolchain is available. Native checks were
attempted but terminated by host memory/resource exhaustion before source
validation; these Rust tests remain unexecuted. This is not passing compiler
or test evidence. The intended package test command is:

```sh
cargo test --locked -p fgit-cli --bin fg-mcp
```

This remains a trusted-local read slice, not remote authentication, a full agent
effect broker, broker-backed mutation or a claim that FG-096 is complete.

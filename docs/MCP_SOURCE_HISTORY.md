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
commit body to 64 KiB. Blame content is bounded to 64 KiB per returned page; a
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
These Rust tests are written but unexecuted in this development environment,
which has no Rust compiler or Cargo. The intended package test command is:

```sh
cargo test --locked -p fgit-cli --bin fg-mcp
```

This remains a trusted-local read slice, not remote authentication, a full agent
effect broker, broker-backed mutation or a claim that FG-096 is complete.

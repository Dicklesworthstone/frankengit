# Native source history over HTTP

This is the bounded one-repository source gateway's history profile, composing
`OneNode::read_commit_history_in`, `OneNode::read_first_parent_history_in` and
`OneNode::blame_source_in` with the existing
authenticated listener. It is not a separate history database, an arbitrary-object
API, or hosted IAM. The broader native API work remains FG-048b; these slices
do not complete that broader scope.

## Commit log

`POST {repository-route}/api/v1/source/log` accepts an
`application/x-www-form-urlencoded` body. Like source browsing and search,
POST carries a bounded **read query**, not a mutation. Query strings and
`Git-Protocol` headers are refused. Fixed-length and chunked bodies use the
existing bounded form decoder.

Required fields are `object_format=sha1|sha256` (matching the repository) and
`ref` (a full native reference name). The ref is resolved from one authenticated
current authority snapshot; canonical hidden-ref policy still applies. A raw
commit ID cannot select an object. Optional `expected_commit` compares against
the selected ref tip and is never a grant to read that object.

`limit` is 1 through 100, default 50. `after` is a zero-based offset in the
complete bounded topological traversal. A nonzero offset requires
`expected_head`, set to the previous response's exact `snapshot_token`.
`max_commits`, `max_edges`, and `max_metadata_bytes` may lower the native
reader's defaults (4096, 16384, and 4194304 respectively), never raise them.

Example bodies:

```text
object_format=sha1&ref=refs%2Fheads%2Fmain&limit=25
object_format=sha1&ref=refs%2Fheads%2Fmain&limit=25&after=25&expected_head=alg:1:<64-lowercase-hex-digits>
```

The JSON response identifies the tenant, repository incarnation, object format,
source authority head, snapshot token and selected native commit. `commits`
contains exact native IDs, trees, original parent order and `body_hex`, the
lossless native commit body including author, committer, message and any
signature headers. These headers are untrusted claims: the response explicitly
sets `author_identity_verified` to false. It does not certify human authorship,
signature validity or review approval.

`ordering` is `child-before-parent-native-id-v1`: child-before-parent
(topological) order, with native-ID order among ready nodes, **not timestamp
order**. `total_commits` describes the entire successfully traversed graph.
`next_after` is null at its end. `page_complete` applies only to the requested
page; it does not claim that all history fits into that response. A valid offset
exactly at the graph's end returns an empty complete page. Missing ancestors,
corruption, limits or cancellation are errors, never a silently truncated page.

### Bounded recent first-parent history

The same log route accepts the explicit `first_parent=true` mode. It reads the
visible tip and follows only the first stored parent until the requested page
is full or a root is reached. Recent pages therefore work on repositories whose
total ancestry exceeds the full-DAG profile's 4,096-commit ceiling. Side-parent
headers remain in each exact commit record and count against the edge budget;
their bodies, trees and blobs are not read by this traversal.

```text
object_format=sha256&ref=refs%2Fheads%2Fmain&first_parent=true&limit=20
object_format=sha256&ref=refs%2Fheads%2Fmain&first_parent=true&limit=20&cursor=<opaque-next-cursor>
```

The response retains the ordinary source coordinates, snapshot token, exact
`object_id`/`tree`/ordered `parents`/`body_hex` records and read-only fields. Its
distinct closed profile is:

| Field | Meaning |
| --- | --- |
| `type` | `source_first_parent_log` |
| `schema_version` | `1` |
| `profile` | `first-parent-prefix-v1` |
| `ordering` | `stored-first-parent-v1` |
| `page_complete` | The complete requested page was read; not a claim that all history was traversed. |
| `after`, `limit` | The cursor's skipped prefix length and requested page bound. |
| `root_reached` | The visited first-parent chain reached its root. |
| `visited_commits` | Skipped prefix plus returned commits, charged to this request. |
| `visited_parent_edges` | Every parent header in those visited commits, including side parents. |
| `metadata_bytes` | Logical native commit-body bytes visited, including the skipped prefix. |
| `next_cursor` | An opaque continuation, or null when the root was reached. |

This profile has no `total_commits` or `next_after`: it does not traverse older
history to compute a total. It retains `author_identity_verified=false`; parent
order and exact native metadata establish neither human authorship nor review
approval.

The shared `fgfp1` cursor binds the exact original authority head, raw reference,
native object format, selected tip and offset. It is the same canonical token
used by `fg log --first-parent` and MCP. It is a selection precondition, not a
credential. Every request authenticates independently, rechecks current ref
visibility and the exact head, then starts from that authenticated visible tip.
Substituting a cursor's object cannot authorize an unrelated object read. A
moved authority head, including a forge-only write with an unchanged tip,
returns 409; restart explicitly instead of combining snapshots.

The skipped prefix and page share the ordinary per-call limits: 4,096 commits,
16,384 parent headers and 4 MiB of logical commit metadata, with a 64 KiB body
ceiling enforced before the native commit allocation. `max_commits`, `max_edges`
and `max_metadata_bytes` may lower these limits; `limit` remains 1–100, default
50. Continuing farther into history repeats the prefix work and can exhaust a
limit even when an earlier page succeeded. The cursor does not provide
constant-cost arbitrary-depth pagination or a guarantee that the next page can
complete within the selected budgets.

`first_parent` accepts only `true`. It cannot be combined with any `after`
field, including `after=0`, a path filter, `max_tree_entries` or
`max_cached_bytes`. `cursor` without this mode is refused. Unknown, duplicate,
oversized or noncanonical fields and cursor/ref/format/pin conflicts return
400. The ordinary log and exact-path profiles keep their existing behavior.

## Line provenance

`POST {repository-route}/api/v1/source/blame` uses the same form framing,
`object_format`, `ref`, `expected_head` and `expected_commit` fields. It additionally
requires `path_hex`, the lowercase hexadecimal encoding of a repository-relative
byte path. This preserves non-UTF-8 names without allowing NULs, traversal,
absolute paths, empty components or host-filesystem access. Symlinks are not
followed and gitlinks are not traversed.

Optional `line_start` and `line_end` select a **zero-based, half-open** interval.
Start defaults to zero; omitted end means through the file's last line. A range
can be empty, including at the end of the file. Keep `expected_head` unchanged
when reading several ranges as one snapshot; omitting it explicitly requests
the current state again. Line ranges narrow output, not object authority or the
underlying correctness checks and work bounds.

Example bodies for `src/lib.rs`:

```text
object_format=sha1&ref=refs%2Fheads%2Fmain&path_hex=7372632f6c69622e7273
object_format=sha1&ref=refs%2Fheads%2Fmain&path_hex=7372632f6c69622e7273&line_start=20&line_end=40&expected_head=alg:1:<64-lowercase-hex-digits>
```

The `exact-lines-all-parents-v1` profile follows exact same-path line matches
through all parents. At a merge, the first stored parent with an exact matching
line wins; an unmatched line belongs to the merge commit. It does not guess
renames or copies, normalize whitespace, infer a person, or verify authorship.
The returned origin is a native commit identity, not a verified human identity.

The `source_blame` response binds the same authority/commit identity as log,
plus the tree, blob, path, total line count and requested interval. `content_hex`
contains **only the requested lines**, preserving CRLF and non-UTF-8 content.
`content_byte_start` is their absolute offset in the selected blob. Every line
includes its absolute target byte span and origin commit, blob, line number
and byte span. `origins` contains unique native-ID-ordered records for exactly
the returned lines' origin commits, including exact `body_hex` metadata.
`range_complete` means the requested interval was completely attributed; it
does not imply that the whole file was returned. `graph_commits`, `comparisons`
and `algorithms` describe the bounded derivation, not an authorization decision.

`traversal: "line-frontier-v1"` follows only ancestry needed to attribute the
selected lines. `graph_commits` is the count actually visited, including a
parent examined to establish a newly introduced line; it does not count unread
history. A short range can therefore complete in a repository whose total DAG
exceeds the commit ceiling. Older origins still require bounded ancestor reads.
Ordered blob-pair correspondence is cached, and `max_diff_work` is shared
across all comparisons in one native call. The exact line and merge-parent
precedence rules remain unchanged. Missing required objects and touched cycles
refuse; unrelated unread history is outside this result's validation claim.

All nine native resource dimensions can be lowered, never raised. Their default
ceilings are `max_commits=4096`, `max_edges=16384`, `max_tree_entries=100000`,
`max_blob_bytes=1048576`, `max_lines=20000`, `max_cached_bytes=33554432`,
`max_comparisons=128`, `max_diff_work=1000000`, and `max_metadata_bytes=4194304`.
All limits are positive. Binary content is a typed 409 refusal; missing paths
return 404, invalid or out-of-file line ranges return 400, and exhausted native
resource bounds return 413. Missing required objects and corrupt ancestry are
not treated as file creation, an attribution boundary or empty success.

## Authorization and failure boundaries

The operator must enable the existing source gateway, and a credential must
have explicit Git `read` scope. Receive, issue, PR, review and outcome scopes do
not imply history-read permission. Authorization and route matching happen
before request-body consumption. Credentials retain the existing rotation,
incarnation binding, request quotas, loopback-only and external-TLS boundaries.
Already admitted requests retain their bounded grant; instantaneous revocation
of in-flight work is not claimed.

The first-parent mode uses this same history grant. Sponsored agent
`SOURCE_READ` credentials remain excluded from history; their bounded current
commit/source-package profile does not acquire ancestor access through a log
option or cursor.

Reads reject `Idempotency-Key`, never seal a request, publish a ref or forge
event, stage candidate objects, or create a terminal transaction. Responses
carry `read_only=true`, `transaction_created=false` and `published=false`.
An I/O failure does not require transaction recovery for this read operation.

Malformed forms, duplicate/unknown fields, invalid ranges and unpinned log
continuations return 400; absent/hidden references return indistinguishable
404s. A moved snapshot or expected tip returns 409. Exhausted native resource
or response bounds return 413. Backend corruption or unavailable required
objects returns a nondisclosing failure, not a successful empty history.
A complete bounded JSON body is constructed before sending success; hex
expansion is charged before allocation. The response ceiling is the smaller
of the listener's bound and 8 MiB. Serialization checks cancellation between
records and byte chunks. Native work remains bounded by the reader and its
request context; these cooperative checkpoints are not preemptive deadlines.

Snapshot tokens pin **current** reads; they do not keep old heads accessible.
Any authority movement, including an unrelated issue event, invalidates an old
continuation. Restart with the new head rather than silently mixing pages. The
response's `source_commit`, `ref_hex`, limits and offset/range make the selection
explicit; callers must keep that selection unchanged when paging.

## Verification scope

`crates/fgit-node/tests/source_log_http.rs` exercises the real listener, imported
native objects, exact commit bodies, both hash formats, chunked framing,
end-of-history, bounds, read-only key absence, explicit scope separation,
credential rotation, disabled service, wrong routes, authority movement and
restart. `crates/fgit-node/tests/source_blame_http.rs` adds exact line ranges,
origin spans and records, CRLF, empty files/ranges, binary and path refusals,
resource exhaustion and the same authenticated restart/revocation boundaries.
Focused module tests cover closed input, byte encoding, output bounds,
partial/duplicate pages, corrupted records and inconsistent line attribution.

`crates/fgit-node/tests/source_log_first_parent_http.rs` adds the actual listener
path for both native hash formats, cursor continuation/reopen, exact metadata,
request scopes before ingress, rotation/disable, authority movement, shared
prefix budgets and a 4,099-commit merge graph whose recent page succeeds while
the ordinary DAG profile refuses its unchanged bound. Focused first-parent
module tests cover conflicting options, cursor substitutions, profile fields,
parent-edge/metadata accounting, exact response size, cancellation and corrupt
native records. Existing native history tests retain hidden-reference,
missing-object and cancelled-request refusal coverage.

The pinned Rust toolchain is available. Native checks were terminated by
workspace memory/resource exhaustion before source validation, and the tests
remain unexecuted. No successful compile, test, Clippy, performance, full Git
compatibility or release-gate result is asserted here.

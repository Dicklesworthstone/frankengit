# Native source history over HTTP

This is the bounded one-repository source gateway's history profile, composing
`OneNode::read_commit_history_in` and `OneNode::blame_source_in` with the existing
authenticated listener. It is not a separate history database, an arbitrary-object
API, or hosted IAM. The owning product work remains the native API bridge
(`frankengit-asa3`) and FG-048b; these slices do not complete that broader scope.

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

These implementations were source-reviewed when introduced; Rust tooling was
not available in the editing environment, so no compile, test, Clippy,
performance, full Git compatibility or release-gate pass is asserted here.

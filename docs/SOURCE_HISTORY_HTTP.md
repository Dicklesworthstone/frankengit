# Native source history over HTTP

This is the bounded one-repository source gateway's history profile, composing
`OneNode::read_commit_history_in` with the existing authenticated listener. It
is not a separate history database, an arbitrary-object API, or hosted IAM.
The owning product work remains the native API bridge (`frankengit-asa3`) and
FG-048b; this slice does not complete that broader API scope.

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

Malformed forms, duplicate/unknown fields, invalid ranges and unpinned
continuations return 400; absent/hidden references return indistinguishable
404s. A moved snapshot or expected tip returns 409. Exhausted reader/response
bounds return 413. Backend corruption or unavailable required objects returns
a nondisclosing failure, not a successful empty history. A complete bounded
JSON body is constructed before sending success; hex expansion is charged
before allocation. The response ceiling is the smaller of the listener's bound
and 8 MiB. Serialization checks cancellation between records and byte chunks.

Snapshot tokens pin **current** reads; they do not keep old heads accessible.
Any authority movement, including an unrelated issue event, invalidates an old
continuation. Restart with the new head rather than silently mixing pages. The
response's `source_commit`, `ref_hex`, limits and offset make the traversal
selection explicit; callers must keep that selection unchanged when paging.

## Verification scope

`crates/fgit-node/tests/source_log_http.rs` exercises the real listener, imported
native objects, exact commit bodies, both hash formats, chunked framing,
end-of-history, bounds, read-only key absence, explicit scope separation,
credential rotation, disabled service, wrong routes, authority movement and
restart. Focused module tests cover closed input, byte encoding, output bounds,
partial/duplicate pages and corrupted records.

The implementation was source-reviewed when introduced; Rust tooling was not
available in the editing environment, so no compile, test, Clippy, performance,
full Git compatibility or release-gate pass is asserted by this document.

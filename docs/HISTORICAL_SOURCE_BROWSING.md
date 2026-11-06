# Historical files and directories through a current visible ref

The source API can open the old contents named by ordinary commit-log or
path-history results, without granting arbitrary object-ID lookup authority.
Ordinary operator reads retain their repository-wide source-read profile.
Sponsored HTTP and MCP callers require the independent `source-history-read`
credential operation and the host's source feature switch. Existing metadata
and `source-read` grants do not gain history operations. This is not historical
authorization, hosted IAM, or a general agent capability broker.

## Requests

Use `POST {repository-route}/api/v1/source/historical-tree` for a directory or
`POST {repository-route}/api/v1/source/historical-blob` for a file/range.
The source endpoints must be enabled. An ordinary credential requires its
existing Git `read` scope; a sponsored agent credential requires
`source-history-read`. Neither endpoint is a mutation. `Idempotency-Key` is rejected
by the shared source authentication boundary. GET, URL query parameters,
Git-Protocol headers, unknown/duplicate fields and non-form media types refuse.
Fixed-length and chunked bodies use the existing bounded form decoder.

Both requests require all five selection fields:

```text
object_format=sha1
ref=refs/heads/main
expected_head=alg:1:<64 lowercase hex digits from snapshot_token>
expected_ref_tip=<current source_commit from the same log response>
at_commit=<historical commit object_id from a log row>
```

These are URL-encoded form fields, joined with `&` on the wire. Supply `sha256`
with 64-digit native IDs for a SHA-256 repository; SHA-1 uses 40-digit native
IDs. Native IDs must be nonzero canonical lowercase hex. `expected_head` is the
internal authority-head snapshot token, not a native commit ID.

The tree operation accepts optional `path_hex`, `after_hex`, and `limit`
(default 100, maximum 1000). Omit `path_hex` to list the selected commit's root.
The blob operation requires `path_hex`, and accepts `offset` (default zero)
and `limit` (default 65536, maximum 1048576). Path/cursor bytes use canonical
lowercase hex, preserving non-UTF-8 names. The existing TreeFS path and range
validation applies. A symlink may be read as opaque link bytes, never followed;
a gitlink cannot be used to traverse another repository.

`expected_ref_tip` and `at_commit` are deliberately different fields. The former
pins the current authority-selected ref; the latter names a commit that must be
reachable through its parent edges. In the node API, the inner
`SourceBrowseQuery.expected_commit` is the historical target, not the ref tip.
The new HTTP endpoints do not accept the ambiguous `expected_commit` field.
Existing `source/tree` and `source/blob` semantics remain unchanged.

## MCP historical reads

With `--allow-source`, MCP exposes `frankengit_source_historical_tree` and
`frankengit_source_historical_blob`. Sponsored mode additionally requires
`source-history-read` for each call; the existing trusted-local operator
profile remains available.

Both tools require `reference`, `expected_head`, `expected_ref_tip` and
`at_commit`. The latter two are nonzero lowercase native IDs in the repository's
object format. The tree tool accepts optional `path_hex`, `after_hex` and `limit`
(1..100, default 50). The blob tool requires `path_hex` and accepts `offset`
(decimal string, default zero) and `max_bytes` (1..65536, default 16384).
The ambiguous `expected_commit` field and unknown arguments are rejected.

MCP returns its existing source fields directly in a `historical_source` result,
with `selection: visible-ref-ancestor-v1`, `source_ref_tip`, `at_commit`,
`transaction_created: false` and `published: false`. This differs from the
nested HTTP `source` wrapper shown below. Retain the same head, tip and commit
pins when following `next_after_hex` or `next_offset`. Both adapters use the
same native ancestry validation and current hidden-ref policy. Native work and
response output retain the originally authenticated deadline.

A historical selection may name the current tip; blame and comparison also
disclose current-tip content. The separate history grant controls these API
operations, not a current-versus-old content secrecy boundary. It does not
grant current-source search, indexes, retrieval or agent-context tools.

## Selection and response

The node selects authority once, checks current canonical hidden-ref policy,
checks the exact head and current tip, then traverses native parent edges from
that tip. The supplied historical ID never triggers a direct object read.
Repository-wide object membership alone is insufficient: an admitted commit
on an unrelated branch is not selectable. Second/later merge parents are
eligible; a deterministic breadth-first traversal preserves stored parent
order and de-duplicates visited IDs. Native commit hashes and unambiguous
single-tree/noncontinued-edge headers are verified before any tree/blob read.

The response wraps the established validated source-tree or source-blob shape:

```json
{
  "type": "historical_source",
  "schema_version": 1,
  "selection": "visible-ref-ancestor-v1",
  "source_ref_tip": "<validated current tip>",
  "at_commit": "<validated selected ancestor>",
  "read_only": true,
  "transaction_created": false,
  "published": false,
  "source": {
    "type": "source_blob",
    "source_commit": "<selected ancestor>",
    "source_head": "<current authority selection>",
    "snapshot_token": "<same pinned authority token>",
    "content_hex": "<exact requested bytes>"
  }
}
```

The example omits the other existing source-response fields. `source_rcr`
identifies the selected authority/closure basis, not the historical commit's
creation transaction. Retain all selection fields for directory/range
continuations; a moved head or tip refuses instead of mixing snapshots.

## Bounds and refusal

Ancestry has fixed ceilings: 4096 discovered commits, 16384 parent headers,
64 KiB per commit body, and 16 MiB aggregate commit bytes. The remaining byte
allowance tightens each fabric read before decompression/allocation. Traversal
stops with a verified ancestry witness; it need not read unrelated branches
once the target is reached. Proving absence requires completing the bounded
traversal. Missing dependencies, corrupt objects, ambiguous headers, exhausted
budgets and cancellation are failures, never a false not-found or partial page.

The ancestry bytes also consume the established 64 MiB source-read allowance.
The existing directory/blob phase keeps its separate 132-object bound, object
size ceilings and response limits. The historical wrapper is included in the
response byte budget. Successful responses carry no canonical terminal outcome.
A hidden/missing ref or a proven unreachable target uses the unavailable/not-
found response; a changed selection uses conflict; resource exhaustion uses a
size/work refusal. Backend/corruption failures never expose internal IDs or
storage details through the source API.

## Verification boundary

Regression tests cover both native formats, non-first-parent ancestry,
other-branch exclusion, corrupt/missing/wrong-kind objects, malformed graph
headers, duplicate parents, bounded allocation, checkpoint cancellation,
node byte/range composition, required pins, hostile forms, read-only routing
and whole-response budgets. Tests were added but not executed in the authoring
environment, which had no Rust compiler. No release or conformance claim is
made; run the repository's pinned-toolchain verification before deployment.

# Native indexed source search: operator build and authenticated queries

The `fg-index` local binary and
`POST {repository-route}/api/v1/source/search-index` compose the native source
builder, persisted lexical segments, exact generation selection and authenticated
source service. Existing literal, batch and regex endpoints keep their original
semantics. This is the ASCII-word index, not a substring or regex accelerator.

## Build an existing node's index

Use the repository's pinned/offloaded build lane:

```bash
cargo build --locked -p fgit-node --bin fg-index
```

The binary opens an existing node with the exact tenant/repository/object-format
binding. It does not initialize a repository or accept remote credentials.
Trusted local access to the node root is required. Supply complete native refs.

```bash
fg-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 refs/heads/main build genesis
```

`TENANT_HEX` and `REPOSITORY_HEX` each contain 32 lowercase hexadecimal characters.
Use `sha256` for a SHA-256 node. `genesis` explicitly requires no existing index.
The returned JSON includes `index_token`, `index_number`, `snapshot_token`,
`source_commit` and `root_tree`. An index token is `alg:CODE:LOWERCASE_HEX` in the
registered generation domain, not a native Git OID or authorization capability.

Rebuild using the exact preceding index token, never `latest` or an implicit
refresh:

```bash
fg-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 refs/heads/main build "$INDEX_TOKEN"
fg-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 refs/heads/main recover "$CANDIDATE_TOKEN"
fg-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 refs/heads/main query content needle nested
```

The build enumerates the complete verified tree and stages every index payload
before activating its derived root. It never modifies Git refs or publishes a
repository transaction. Source changes during a build do not change the build's
source stamp; queries can consequently report that index as stale.

An unconfirmed publication prints the original candidate token for read-only
recovery. Recovery distinguishes active, superseded, uninitialized, and absent
from the completely checked selected history; it does not retry a build or cancel
another writer. The command explicitly shuts down its node on operation success
and failure. A shutdown/output error does not undo a confirmed activation. The
binary does not replace the runtime's process-crash/containment obligations.

Local `query` displays the first bounded page (100 results), including exact byte
paths and native blob IDs. A limited result retains `next_after`; use the HTTP
interface for explicitly pinned pagination. No token, path or source text is
interpreted as an instruction. Query patterns are whole ASCII word tokens only.

## Authenticated HTTP requests

Enable the existing source service and use an independently read-scoped token.
The endpoint accepts a nonempty fixed-length or chunked URL-encoded form. It
inherits source authentication, revocation checks, quotas, deadlines and response
limits. Do not send an `Idempotency-Key`; the request creates no transaction.
There is no HTTP build, activation or recovery route in this profile.

Required fields:

| Field | Contract |
|---|---|
| `object_format` | `sha1` or `sha256`, matching the repository. |
| `ref` | Complete visible commit-valued reference. |
| Repeated `term_hex` | 1–32 nonempty whole ASCII alphanumeric/underscore tokens, each at most 128 bytes, encoded as lowercase hex. |

Optional fields:

| Field | Contract |
|---|---|
| `channel` | `content` (default) or `path`; the same channel applies to every term. |
| Repeated `path_prefix_hex` | Up to 128 TreeFS-valid raw path prefixes, 4096 bytes each and 32 KiB combined; slash-component matching. |
| `expected_head`, `expected_commit` | Exact canonical source snapshot token and complete nonzero native commit ID. |
| `index_token`, `index_number` | Exact index identity AND original authority position. Both fields are required when either is supplied. |
| `minimum_index_token`, `minimum_index_number` | Independently retained anti-rollback checkpoint, also a complete pair. |
| `after` | Positive absolute document ID; requires original source head, commit and exact index pair. |
| `limit` | 1–4096 results, default 100. |
| `max_work` | 1–16,777,216 shared query-work units; default the maximum. |
| `max_payload_bytes` | 1–33,554,432 bytes shared by catalog/segment reads; default the maximum. |

```bash
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${FG_READ_TOKEN}" \
  --data-urlencode 'object_format=sha1' \
  --data-urlencode 'ref=refs/heads/main' \
  --data-urlencode 'term_hex=6e6565646c65' \
  --data-urlencode 'term_hex=6e6573746564' \
  --data-urlencode 'path_prefix_hex=646972' \
  "${FG_URL}${FG_REPOSITORY_ROUTE}/api/v1/source/search-index"
```

This queries `needle AND nested` under `dir`. The server normalizes ASCII case,
sorts and deduplicates tokens, and returns that normalized list in `terms_hex`.
Punctuation, non-ASCII tokens, regex syntax and unknown channels refuse; they are
not silently interpreted as another search language. Prefixes only narrow scope.
Source service grants are whole-repository reads, not sparse agent capabilities.

## Responses and continuation

`type: source_search_index`, `schema_version: 1`, and
`profile: ascii-word-postings-v1` identify the response. It carries the repository
namespace/incarnation, canonical source head/RCR/commit/tree, exact index token
and number, and the distinct selected current index head. The latter does not
replace the generation used by the query. Responses explicitly report
`read_only: true`, `transaction_created: false`, and `published: false`.

Each hit contains an absolute `document_id`, lossless `path_hex`, native `blob`,
source `content_bytes`, and one span per normalized term. `query_index` indexes
`terms_hex`; `byte_offset` and `byte_length` refer to original content bytes in
the content channel, or original path bytes in the path channel. These are first
occurrences of each token, not all occurrences or line/column coordinates.

Results preserve increasing document ID and raw path order. `complete: false`
requires an additional matching document beyond the retained page and a
`next_after` equal to the last returned ID. A full page may still be complete.
For continuation, repeat the original normalized query/channel/prefixes, source
pins, exact index pair and returned cursor. Changing the query is a new query;
this protocol does not mint a signed opaque cursor or store a client session.

Corpus counters describe the whole index, not just the filtered prefix.
`segments_read`, `payload_bytes_read`, `generation_bytes_read` and `work_units`
name bounded work, not latency guarantees. Generation ancestry has its own
existing independent limits. Response JSON is fully validated and bounded before
success is written; malformed rows, corruption, missing payloads and budget
exhaustion do not produce partial success or a fabricated empty answer.

HTTP 400 denotes invalid fields, token/position pairs or continuation pins;
413 denotes resource exhaustion. HTTP 409 distinguishes
`source_index_uninitialized`, `source_index_stale`, source pin conflicts and
`index_checkpoint_unavailable`. An authenticated empty index/query instead
returns HTTP 200 with `complete: true` and an empty hit array. Storage corruption
and infrastructure failures remain errors. Authentication and enablement retain
the existing 401/403 behavior.

Every query revalidates canonical current source and hidden-ref policy before
reading an index. This conservative profile requires an exact source-head match:
even a forge-only write invalidates the old index. Rebuild is an explicit local
operation, never a side effect of a query. Same-source rebuilt index generations
can be queried through an older exact index while retaining a newer checkpoint.
The listener's loopback/external-TLS boundary remains unchanged.

## Verification boundary and remaining work

This integration adds five real-node HTTP tests, six protocol/renderer tests and
three operator argument tests, in addition to the ten native builder tests in
`NATIVE_SOURCE_INDEX.md`. HTTP tests exercise the production TCP listener, actual
native imports and node-owned storage, including both hash formats, chunked
requests, exact-generation pagination, independent scopes, resource refusals,
unbuilt/stale indexes and reopened-node state. Protocol fixtures that construct
rows directly are explicitly tests of serialization, not storage correctness.

Rust/Cargo/rustfmt are unavailable in the implementation environment. None of
these Rust tests, compilation, native durable execution, Clippy, full-workspace
or release gates have been executed here. Baseline/blob identity, source-wiring,
JSON-format and whitespace checks are static checks only, not Rust execution.

```bash
cargo check --locked -p fgit-node --all-targets
cargo test --locked -p fgit-node --test source_index --test source_index_http
cargo test --locked -p fgit-node --lib smart_http::server::source
cargo test --locked -p fgit-node --bin fg-index
```

This does not implement incremental document updates, automatic outbox rebuilds,
symbol extraction, semantic ranking, browser indexed-search UI, remote index
administration, or full FG-032 acceptance. The existing full-rebuild resource
limits and unsupported 129-byte words remain explicit constraints, not skipped
content or claims of production readiness.

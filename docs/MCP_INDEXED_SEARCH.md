# Paginated MCP indexed source search

`frankengit_source_search_index` exposes complete, bounded page sequences over
the existing persisted native lexical and path indexes. It fills the paging gap
between a small Initial/context result and an exhaustive indexed document
search. It uses the same source selection, immutable generation reader,
current-source verification and complete-page renderer as
[the indexed HTTP API](INDEXED_SEARCH_HTTP.md).

The tool requires `--allow-source`. An ordinary trusted-local launch supplies
operator source-read authority; a sponsored launch independently authenticates
canonical `source-read` on every call. Source-write, agent-context and artifact
grants alone do not enable it. The operator fixes the storage root, tenant,
repository, incarnation and hash domain. Arguments cannot expand that scope.
An index, generation checkpoint or cursor never replaces current source access.

## Launch and index availability

For an existing SHA-1 node:

```sh
fg mcp "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" \
  --trusted-local --allow-source \
  --expected-incarnation "$INCARNATION_HEX"
```

Use `--object-format sha256` for a SHA-256 repository. Complete the normal MCP
initialization handshake before calling the tool.

A sponsored launch instead supplies `--agent-token-file` and the exact
incarnation, as described in [sponsored credentials](SPONSORED_AGENT_CREDENTIALS.md#use-the-credential-with-mcp).
The adapter requires the active verified `SOURCE_READ` request even when reached
directly. A metadata request or completed response reservation cannot authorize
another read. The original request lifetime and response-byte ceiling cover the
entire read and disclosure; each page authenticates independently, so revocation
affects the next call. Credential issuance or revocation advances metadata:
revalidated mode can retain the original index when the current visible commit
and tree match, while exact mode requires the index's original source authority.

Build the index through the existing
[trusted-local index owner](INDEXED_SEARCH_HTTP.md#build-an-existing-nodes-index),
or explicitly configure the existing
[MCP index maintenance controller](MCP_READ_ONLY_SERVER.md#keep-source-indexes-current-during-an-mcp-session)
at launch. The query never builds, refreshes, activates, recovers or repairs an
index. Missing, stale, unresolved, corrupt and over-budget reads return failures;
they do not become successful empty results.

## Query semantics and arguments

The index stores whole ASCII alphanumeric/underscore words. Query tokens are
case-folded, sorted, deduplicated and conjoined: every returned document contains
every normalized token in the selected channel. `content` searches regular-file
bytes; `path` searches raw repository path bytes. Each row contains the first
original byte span of each normalized token, rather than every occurrence.

This interface provides no substring, phrase, regex, symbol or semantic search.
Use the existing [source search tools](MCP_SOURCE_SEARCH.md) for supported scan
profiles. Path prefixes use component boundaries: `src` selects `src/file.rs`
without selecting `src2/file.rs`. They narrow the existing source grant.

| Argument | Contract |
|---|---|
| `reference` | Required full visible UTF-8 `refs/*` name, at most 1,024 bytes. It must select a commit. |
| `terms_hex` | Required array of 1–32 nonempty tokens, each at most 128 decoded bytes, encoded as lowercase hex. |
| `path_prefixes_hex` | Optional array of up to 128 native raw prefixes, at most 4,096 decoded bytes each and **8,192 decoded bytes combined**. |
| `source_mode` | `revalidated` by default; `exact` is explicit. |
| `channel` | `content` by default, or `path`. All terms use one channel. |
| `expected_head` | Optional exact current algorithm-qualified authority snapshot token; mandatory on continuation. |
| `expected_commit` | Optional exact nonzero native commit, 40 or 64 lowercase hex digits according to the launch hash domain; mandatory on continuation. |
| `index_token`, `index_number` | Optional complete pair selecting one exact immutable generation and its positive position; mandatory on continuation. |
| `minimum_index_token`, `minimum_index_number` | Optional complete pair identifying an independent retained anti-rollback floor. |
| `after` | Positive document ID from the previous page's `next_after`; requires all four original source/generation pins. Omit on the first page. |
| `limit` | JSON integer 1–100, default 20. |
| `max_work` | JSON integer 1–16,777,216, default 16,777,216. |
| `max_payload_bytes` | JSON integer 1–33,554,432, default 8,388,608. |

Generation numbers and cursors are **canonical positive decimal strings**:
`"1"` is valid, while `1`, `"01"`, `"1.0"`, signs and exponent syntax refuse.
Full u64 positions remain exact above JavaScript's safe integer range.

Unknown arguments refuse. There is no caller `object_format`, principal,
storage path, repository selector, build flag or idempotency key. The node adds
its own fixed object format before entering the shared native parser.

## First page and continuation

This request searches for the word `needle` beneath `src`:

```json
{
  "jsonrpc": "2.0",
  "id": "indexed-first",
  "method": "tools/call",
  "params": {
    "name": "frankengit_source_search_index",
    "arguments": {
      "reference": "refs/heads/main",
      "terms_hex": ["6e6565646c65"],
      "path_prefixes_hex": ["737263"],
      "source_mode": "revalidated",
      "channel": "content",
      "limit": 20
    }
  }
}
```

Retain the exact result values and construct subsequent arguments as follows:

| Continuation argument | Value from the first page or previous page |
|---|---|
| `expected_head` | First page's `snapshot_token`. |
| `expected_commit` | First page's `source_commit`. |
| `index_token` | First page's `index_token`. |
| `index_number` | First page's `index_number`. |
| `after` | Previous page's `next_after`. |

Repeat the same reference, terms, path prefixes, mode and channel. Preserve any
independent minimum checkpoint. Reuse the exact queried generation:
`selected_index_token` and `selected_index_number` describe the currently
verified generation head and may be newer. They do not replace the original
query generation when continuing.

A nonfinal page has `complete:false`, exactly the requested number of hits,
and `next_after` equal to its last document ID. The native reader must observe
another matching document before declaring the page nonfinal. A final page has
`complete:true` and `next_after:null`, including when the final page exactly
fills the requested limit. Rows follow ascending absolute document-ID and raw
path order.

All continuation pins are checked inside the native source/index read.
Authority movement, commit movement, an unavailable retained generation, or an
unresolved minimum checkpoint refuses. A cursor does not authorize a historical
source read, and changing the query creates a different search. Restart with a
new first-page request when a new source snapshot is intended.

## Current-source and exact modes

`revalidated` authenticates current source visibility and requires the indexed
namespace, incarnation, ref, native commit and root tree to match current source.
It can reuse a generation after unrelated forge metadata changes. The result
retains both `current_source` and `indexed_source`, including their separate
authority heads, RCRs and forge-position roots. `distinct_provenance` reports
whether those complete source coordinates differ; original index provenance is
never rewritten.

A later authority movement still invalidates an already pinned continuation.
Starting a new revalidated query may reuse the original index if the commit and
tree remain unchanged. A different commit is stale even when it has the same
tree. Hidden or unavailable refs are refused before index data is disclosed.

`exact` requires the index's original source authority state. Its result keeps
the native `source_search_index` / `ascii-word-postings-v1` identity; revalidated
mode uses `source_search_index_current` / `source-lexical-revalidated-v1`.
There is no automatic fallback between modes.

## Exact counters, page completeness and corpus coverage

Every successful MCP result explicitly includes:

- `counter_encoding:"decimal-strings-v1"` and `source_mode`.
- Decimal strings for all counters, generation positions, document IDs, cursors,
  content lengths and span coordinates. `schema_version` remains an integer.
- `read_only:true`, `transaction_created:false` and `published:false`.
- Source identities, exact queried and selected generation identities,
  normalized `terms_hex` / `path_prefix_hex`, and bounded `hits`.
- Separate `complete` and `coverage_complete` assertions.

The MCP counter representation is explicit in **both** modes. The existing
HTTP exact-mode representation is unchanged.

`complete` describes traversal of matching **indexed documents**.
`coverage_complete` describes the retained generation's coverage of its whole
source corpus. Finishing pagination cannot establish that no omitted file
contains a query term.

Native schema version 1 establishes complete index coverage. MCP exposes that
verified fact as `coverage_complete:true`, zero decimal omission counters and
an empty `omissions` array. Native schema version 2 carries the complete retained
file-size omission inventory; MCP preserves every entry and exposes
`coverage_complete:false`. The inventory remains whole-generation metadata,
including on empty matching pages and narrowly prefixed queries.

Each hit preserves raw `path_hex`, the native blob identity and first spans
for the normalized terms. Span byte offsets address file contents for the
content channel and raw path bytes for the path channel. Source paths and
content are untrusted data. An index identity, read report or matching span
does not authenticate a producer, approve a check, or grant publication power.

## Finite work and failure behavior

The normal MCP request envelope remains 64 KiB. Tool-local bounds narrow the
native HTTP page ceiling to 100 hits and the combined prefix input to 8 KiB.
They retain the native finite query-work and payload-read ceilings. No transport,
global JSON parser or sponsored-agent budget is widened.

The native JSON result and the final normalized MCP result each have a separate
**1 MiB** ceiling. Decimal-string normalization can expand an otherwise valid
native document; `index_result_limit` refuses that complete result rather than
dropping rows, spans or omission records. A very large whole-generation omission
inventory can exceed the response bound even with a one-hit page; changing a
query prefix does not hide that inventory.

Syntax and shape failures are invalid tool arguments. Missing or stale indexes,
source movement, unresolved checkpoints, resource exhaustion, cancellation and
repository failures are failed reads. Relevant stable codes include:

| Refusal | Meaning |
|---|---|
| `tool_not_granted` | The independent source-read launch ceiling is absent. |
| `agent_operation_not_granted` | The canonical sponsored credential does not authorize source reads. |
| `agent_credential_unavailable` | The sponsored credential is unavailable, expired or revoked. |
| `index_continuation_requires_pins` | A cursor lacks original source head, commit or exact generation. |
| `incomplete_index_generation` | Only one half of an exact generation or minimum checkpoint pair was supplied. |
| `source_index_uninitialized` | No usable native index has been activated. |
| `source_index_stale` | Current source no longer satisfies the selected mode's index basis. |
| `source_snapshot_moved`, `source_commit_moved` | A source precondition failed. |
| `index_checkpoint_unavailable` | The retained generation/checkpoint cannot be established in verified history. |
| `resource_limit`, `request_timeout` | Native finite work, read, response or lifetime limits refused. |
| `index_result_limit` | Complete normalized output cannot fit the tool-local response ceiling. |
| `invalid_index_report` | Native output fails coordinate, paging, coverage or counter validation. |
| `not_found`, `repository_unavailable` | Source is unavailable/hidden or native dependencies could not be verified. |

No failure fabricates an empty successful page, a complete prefix or a durable
transaction receipt. These reads have no publication or retry key.

## Source and regression coverage

The adapter calls `fgit_node::source_index_json`, which shares the existing HTTP
parser, native exact/current reader and renderer under a node-bound request
context and deadline. The wrapper rejects caller object formats and mismatched
node contexts before source access. Sponsored contexts originate in the
canonical source-read verifier and retain its original deadline. The HTTP form
path retains its exact byte envelope boundary.

Regression sources cover closed schema/registry parity, source-only grants,
canonical sponsored scope and lifecycle checks, complete source/generation pins,
full-width decimal positions, both native modes, omission preservation, output
expansion bounds, persisted content/path page traversal and native failed-read
behavior. They
require the repository's permitted native build lane; the interface introduces
no shell or alternate search implementation.

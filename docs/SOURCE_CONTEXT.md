# Exact source context from Initial retrieval

`source-initial-context-v1` connects persisted Initial retrieval to verified
native source bytes. `OneNode::hydrate_source_initial_local_in` consumes an
`InitialReport` plus `source_retrieval::context::ContextLimits`. It does not
initialize, refresh, publish, or silently change either index generation.

The embedding must already authorize whole-repository reads. A saved report is
not a capability. Hydration reselects current canonical visibility with the
report's exact authority-head and commit pins, checks repository/incarnation/hash
format and the source RCR/tree/forge position, then resolves only selected paths
through the existing bounded TreeFS source. Symlinks and gitlinks cannot become
context files. A source or policy move is a refusal, not an automatic retry.

Candidates are the union of content, path, and available symbol results, deduped
by raw path. Conflicting identities or lengths cannot merge. The first
`max_files` distinct raw-byte paths are selected; `candidate_files` and
`omitted_files` make this deliberate selection visible. Omitted index coverage,
result truncation and unavailable optional symbols remain in the original
retrieval, not replaced by successful empty channels.

Every selected blob is decoded and commitment-checked once per path. Lexical
spans must equal complete ASCII-folded tokens; symbol names and raw-identifier
markers must agree with original source bytes. Path spans address path bytes,
never content offsets. Source spans get bounded byte-radius windows; overlapping
and adjacent windows are merged. Path-only hits get a bounded preamble, including
an empty excerpt for an actual empty file. Excerpts are exact bytes, not UTF-8
normalizations or line/column approximations.

Defaults: eight files, 128 bytes on each side of source spans, 64 MiB total source
allowance, 256 KiB retained excerpts. Hard ceilings: 32 files, 4096-byte radius,
64 MiB source, 1 MiB excerpts, 4096 anchors and 128 merged windows. Before I/O,
source allowance is evenly partitioned over the selected paths; the native blob
allocation ceiling is min(8 MiB, total allowance / selected files). Unused shares
are not borrowed. Authority, commits and directory trees retain their existing
independent shared native-read ceilings. A small excerpt does not authorize an
unbounded source decode. Source counters describe blob reads, not all metadata I/O.

Only the declared file selection is partial. Missing/corrupt backing, false
spans, cancellation, exhausted source/excerpt/window budgets or incomplete
hydration abort the whole response. `complete()` also requires the original
retrieval's full coverage; it never asserts excerpts contain entire files.

Repository text is available through `untrusted_bytes()`. This output is not an
Agent Protocol ContextPacket, run authorization, prompt-injection detector,
compiler-resolved graph, signed proof, durable context archive, or retention pin.

## Authenticated HTTP context

```text
POST {repository-route}/api/v1/source/context-initial
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer <read-scoped credential>
```

The endpoint reuses the complete `search-initial` grammar: `object_format`, full
`ref`, repeated `term_hex`, optional `path_prefix_hex`, exact source pins,
independent lexical/symbol checkpoint pairs, optional/required symbol options,
and aggregate retrieval limits. It adds four optional context fields:

| Field | Default | Range |
| --- | --- | --- |
| `context_max_files` | 8 | 1-32 |
| `context_radius_bytes` | 128 | 0-4096 |
| `context_max_source_bytes` | 67108864 | 1-67108864 |
| `context_max_excerpt_bytes` | 262144 | 1-1048576 |

Zero radius preserves source matches themselves; path-only hits still receive a
two-byte-or-shorter preamble. All fields and both sets of limits are checked
before I/O. The existing `search-initial` endpoint rejects context fields and
remains index-only: requesting context never silently changes that contract.
The source gateway retains independent read scope, source-service enablement,
current credential-file checks, per-principal quota and transaction-key refusal.
No `Idempotency-Key` is allowed because this operation is not a transaction.

Retrieval and hydration run under one session request and one deadline. Source
movement between the phases fails without retrying against a new snapshot. A
response is buffered and bounded in full before sending; source evidence or
byte-budget failure cannot disclose a successful prefix of context files.

```bash
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${FG_READ_TOKEN}" \
  --data-urlencode 'object_format=sha1' \
  --data-urlencode 'ref=refs/heads/main' \
  --data-urlencode 'term_hex=5468696e67' \
  --data-urlencode 'symbol_name_hex=5468696e67' \
  --data-urlencode 'symbol_match=prefix' \
  --data-urlencode 'context_max_files=4' \
  --data-urlencode 'context_radius_bytes=128' \
  "${FG_URL}${FG_REPOSITORY_ROUTE}/api/v1/source/context-initial"
```

The result has type `source_context_initial`, schema 1 and the context profile.
`retrieval` is the original joined response, using the unchanged lexical/symbol
response validators and retaining exact source, generation vector, coverage,
omissions and per-channel query evidence. Its zero source-read counters describe
index retrieval only. **Top-level** `source_blobs_read` and `source_bytes_read`
report actual context source reads. `source_file_limit` reports the fixed
per-selected-path allocation share. `candidate_files`, `returned_files`,
`omitted_files`, `selection: raw-path-prefix` and `complete` expose selection
and coverage without confusing an omitted file with an empty one.

Each `files` entry has `path_hex`, native `blob`, `source_bytes`, typed `anchors`
and ordered `excerpts`. Anchors retain channel, byte offset and byte length;
`path` offsets apply to path bytes. Each excerpt has its original `byte_offset`
and lossless `untrusted_bytes_hex`. Repository bytes never become control fields,
markup, commands, a JSON fragment or authorization. Hex conversion is chunked,
bounded and cancellation-checked; all output shares the existing gateway response
ceiling, including the nested retrieval. Neither a large requested excerpt limit
nor a successful native read overrides that final encoded-response ceiling.

## Verification and scope

Verification uses production-native imports, patch admission, indexes, source
objects and reopen in SHA-1/SHA-256. Tests cover channel deduplication, raw paths,
CRLF/raw bytes, exact-limit/refusal twins, saved-source movement, optional channel
status, empty answers, cancellation, overlap merging, invalid spans and raw IDs.
The HTTP tests execute actual credentialed TCP sessions with framed/chunked bodies,
scope restrictions, invalid fields, retained checkpoint refusal, budgets, revoked
credentials and disabled source service. Existing index-only behavior remains a
permitted twin rather than being rewritten to require context reads.

```bash
cargo test --locked -p fgit-node --lib source_retrieval::context
cargo test --locked -p fgit-node --lib smart_http::server::source::retrieval
cargo test --locked -p fgit-node --test source_context
bash scripts/verify_symbol_index.sh native
```

Compilation and runtime results must be read at the actual revision. Static
blob/whitespace checks do not establish a passing native suite. FG-032 remains
open; agent-run binding and persisted ContextPacket publication remain separate.

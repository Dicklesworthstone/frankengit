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
by raw path. Conflicting identities or lengths cannot merge. By default, the first
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
and aggregate retrieval limits. It adds four optional context budget fields
and one explicit selection profile:

| Field | Default | Range |
| --- | --- | --- |
| `context_max_files` | 8 | 1-32 |
| `context_radius_bytes` | 128 | 0-4096 |
| `context_max_source_bytes` | 67108864 | 1-67108864 |
| `context_max_excerpt_bytes` | 262144 | 1-1048576 |
| `context_selection` | `raw-path-prefix` | `raw-path-prefix` or `context-weighted-rrf-q16-v1` |

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
`omitted_files`, `selection` and `complete` expose selection
and coverage without confusing an omitted file with an empty one.

Each `files` entry has `path_hex`, native `blob`, `source_bytes`, typed `anchors`
and ordered `excerpts`. Anchors retain channel, byte offset and byte length;
`path` offsets apply to path bytes. Each excerpt has its original `byte_offset`
and lossless `untrusted_bytes_hex`. Repository bytes never become control fields,
markup, commands, a JSON fragment or authorization. Hex conversion is chunked,
bounded and cancellation-checked; all output shares the existing gateway response
ceiling, including the nested retrieval. Neither a large requested excerpt limit
nor a successful native read overrides that final encoded-response ceiling.

## Opt-in deterministic document fusion

Use `OneNode::hydrate_source_initial_ranked_local_in(request, report, limits)`
in native code, or add this field to the HTTP request above:

```text
context_selection=context-weighted-rrf-q16-v1
```

The native method returns a `RankedContext` containing the unchanged source
context and a `ContextRanking`. The existing native method and omitted or
explicit `context_selection=raw-path-prefix` keep alphabetical selection and
the old response shape. `search-initial` remains index-only and rejects this field.
Unknown profiles, duplicate selectors and caller-supplied weights are refused.

For each available channel, collapse consecutive hits to distinct raw paths and
assign one-based document ranks in the reader's existing order. Multiple symbol
declarations in one file contribute once and do not push later document ranks
back. For each document, sum the following integer contribution over its channels:

```text
contribution_q16 = floor(weight * 65536 / (60 + document_rank))
weights: content = 1, path = 1, symbol = 2
score_q16 = sum(contribution_q16)
```

Sort by descending score, breaking ties by ascending raw path bytes, then select
at most `context_max_files`. The complete fixed profile owns constants, weights,
rounding, deduplication and tie breaks; changing them requires another profile.
There is no floating-point accumulation or clock-dependent ordering. Identical
native blobs at different paths remain distinct candidates, while conflicting
blob identities for one path fail before deduplication or selection.

**Input channel order is raw-path order, not BM25 or semantic relevance.** This
profile rewards cross-channel agreement and weights an explicitly requested
symbol channel; it is not a measured relevance improvement or compiler resolution.
It ranks only the channel hits actually returned, not hidden, omitted, truncated
or otherwise unsearched source. Changing upstream result limits may change the
candidate universe. The original query, generation vector, coverage omissions,
optional-channel state and truncation remain attached; fusion never upgrades
`complete` or manufactures an unavailable channel's contribution.

For example, a code file with content rank 2, path rank 1 and symbol rank 1
receives `1057 + 1074 + 2148 = 4279` Q16 units. An alphabetical file mentioned
only by content at rank 1 receives 1074. With one context slot, the corroborated
code file is selected instead of the alphabetical distraction. This example is
an arithmetic fixture, not a corpus benchmark.

Ranked HTTP responses set `selection` to the named profile and append `ranking`.
It includes the profile, rank constant, score scale, input order, tie break,
`ranked_over: returned-channel-hits`, `semantic_relevance: false`, and `selected`
entries in priority order. Each entry carries one-based `position`, `path_hex`,
native `blob`, `score_q16`, and per-channel `document_rank`, fixed `weight` and
`score_q16` contributions. The gateway checks identity joins, contribution sums
and order before sending. Excerpts in `files` remain in raw-path order; use the
receipt's selected order for presentation. Both parts share the final response
ceiling. These are auditable derived receipts, not signed or canonical proofs.

All selected paths still pass through the same current-source TreeFS hydrator.
An oversized, unavailable or corrupt winner fails the whole request; ranking
cannot silently substitute a cheaper lower-ranked file. Source shares are fixed
before decoding exactly as for the default strategy. Rank collection admits at
most 1024 input hits per channel and 2 MiB of distinct path bytes, and checkpoints
cancellation throughout the bounded preparation and encoding.

The fusion regressions cover exact arithmetic, duplicate declarations, channel
arrival-order parity, raw-byte ties, conflicting identities, rank/byte ceilings
and cancellation. Native/TCP scenarios require a tight context budget to choose
corroborated code, preserve legacy behavior, reproduce receipts after reopen,
and retain source pins, budget failures, scope, revocation and no-match behavior.
These tests are included in the existing commands below; their presence is not
an assertion that they have run at an arbitrary later revision.

## The same read in process: CLI and MCP

`fgit_node::source_retrieval_json` runs the exact `search-initial` /
`context-initial` implementation (form grammar, validation, one request
deadline across retrieval and hydration, JSON document) without HTTP framing
or credentials; the HTTP routes call the same functions, so the surfaces cannot
drift. The node supplies `object_format`; a caller-supplied one is refused.

- `fg search --initial` / `fg search --context <root> <tenant> <repository>
  --trusted-local field=value...` takes the route fields verbatim (repeat
  `term_hex`, `path_prefix_hex`, `symbol_kind`). Exit 0 is a complete document,
  3 an explicitly truncated channel, 2 a refusal carrying the route code.
- MCP `frankengit_source_initial` and `frankengit_source_context` (source grant)
  take the same fields as JSON (`reference`, `terms_hex`, `path_prefixes_hex`,
  `symbol_kinds` as arrays; limits as integers) and return the node's document
  as structured content, after checking it is read-only and bound to the
  launch's tenant, repository and object format. Request-shape codes are
  invalid arguments; index state (`source_index_uninitialized`, stale or
  mismatched generations) is a failure, never an empty answer.

Neither builds or refreshes indexes. `scripts/e2e/suites/search/initial_retrieval_cli.sh`
builds both indexes with `fg index` / `fg symbol-index` and checks the
complete, truncated, ranked, raw-path and refusal cases through the binary.

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

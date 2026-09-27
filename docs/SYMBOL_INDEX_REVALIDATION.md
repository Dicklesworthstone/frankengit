# Explicit current-source symbol-index reads

The existing `POST /api/v1/source/search-symbols-index` endpoint accepts
`source_mode=revalidated`. It reuses a persisted Rust declaration index after
repository-metadata changes only when the selected native Git commit and root
tree still match. Omitting the field, or using `source_mode=exact`, retains the
strict source-snapshot read and its existing response format.

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $READ_TOKEN" \
  --data-urlencode object_format=sha1 \
  --data-urlencode ref=refs/heads/main \
  --data-urlencode name_hex=5468696e67 \
  --data-urlencode match=prefix \
  --data-urlencode source_mode=revalidated \
  "$REPOSITORY_URL/api/v1/source/search-symbols-index"
```

Here `name_hex` encodes the case-sensitive name `Thing`. Use the repository's
actual object format. Existing name, kind, path-scope, source-byte, result and
work limits are unchanged. A Git-read token and enabled source service are
still required; an idempotency/mutation key is refused on this read route.

## Two sources, not a relabeled index

The response type is `source_search_symbols_index_revalidated`, schema version
1. Its `current_source` names the selected current head, RCR, forge position,
commit and tree. Its `indexed_source` preserves the generation's original
source. Both include tenant, repository, incarnation, reference and hash format.
The nested `result` is the unchanged `source_search_symbols_index` receipt,
including its original source, generation, rows, counters and completion.
Consumers must not treat those nested original coordinates as current-source
coordinates. The original numeric checkpoint representation is unchanged;
consumers must preserve its exact integer value rather than round it.

`expected_head` and `expected_commit`, when supplied, constrain **current**
source. `minimum_index_token` and `minimum_index_number` continue to constrain
the independently selected symbol generation. A client navigating from results
must use `current_source` for current-source pins. A query's result ordering,
case-sensitive name semantics and lack of a symbol continuation cursor do not
change. Combined Initial retrieval remains strict; standalone lexical and
symbol revalidation are separate explicit choices, not combined fallbacks.

## Browser use

On the code-search page, choose **Rust declarations (indexed)** and select
**Revalidate unchanged Git source** under **Indexed source**. Enter an exact
or prefix declaration name and optional kind/path filters, then submit. Strict
mode is still the default. This requires an already-built symbol index and the
same source-read token and service enablement as strict declaration search.

The client validates the complete wrapper, both provenance records and the
unchanged nested strict receipt before accepting any result or checkpoint.
It displays current and original snapshots, RCRs and forge roots separately.
Native commit/tree mismatches and contradictory same-head metadata refuse.
The original numeric symbol generation must be a positive safe integer in this
browser; larger JSON numbers refuse instead of becoming rounded checkpoints.

Changing source mode clears results and download URLs but retains the existing
source pin and independent lexical/symbol checkpoint floors. **Release snapshot**
is an explicit action: it permits a new current source while retaining repository
scope and those floors. A failed strict read never retries as a revalidated read.

Opening a declaration reads the complete file using the CURRENT source pin,
checks its SHA-1/SHA-256 Git blob identity, and reproduces the full declaration
name, raw-identifier notation, excerpt and byte coordinates before preview or
download. These byte checks do not authenticate the source/index authority or
prove declaration classification or search coverage. Reads share a total bounded
deadline; cancellation, mode changes and page exit discard late results.

## Validation and refusal boundaries

Current canonical visibility is checked before index disclosure. The node
verifies native commit/root-tree metadata through its existing bounded source
reader under the same request context. A source move during that check refuses
instead of silently selecting a new basis. Reuse requires equality of tenant,
repository, incarnation, reference, hash format, commit and tree. A different
commit refuses even when the tree is identical. Contradictory RCR/forge
coordinates for the same head refuse as well.

This operation reads native metadata and persisted index payloads, not source
blob contents. Native metadata reads retain their existing independent bounds;
index payload and query-work budgets are not widened. Rendering charges the
wrapper and nested result to one response-byte ceiling. All stages retain the
same request/deadline context and cancellation checks.

An uninitialized, stale, corrupt, missing or checkpoint-inconsistent index
refuses. There is no implicit scan, build, refresh, old-generation fallback or
retry. No repository state, index head or outbox acknowledgement is written.
This is a read-time revalidation observation, not a promise of freshness at
response delivery, compiler name resolution, macro expansion, an independently
verified browser authority proof, or an index-maintenance/GC policy.

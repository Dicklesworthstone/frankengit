# Same-snapshot batch source search

The `literal-bytes-batch-v1` source-read profile searches 1–32 literal byte
strings with one authority selection, one capability-filtered tree discovery,
and one scan of each selected regular file. It is intended for code navigation
and agent context retrieval that would otherwise repeat source reads for each
needle. It uses the existing authenticated repository source service.

This is the bounded model-free scan path under FG-032, **not** a persistent
lexical/symbol index, immutable search-generation activation, semantic ranking,
or completion of FG-032. No throughput or end-to-end latency claim is made.

## Request

`POST {repository-route}/api/v1/source/search-batch` accepts
`application/x-www-form-urlencoded` with fixed-length or chunked HTTP framing.
The listener must enable the source service and the credential must have the
existing `read` grant. Receive/issue/PR/review/outcome grants do not imply source
read access. This inherits the current loopback/TLS-proxy deployment boundary.
Do not send an `Idempotency-Key`: this operation never seals a transaction.

Required fields are `object_format` (`sha1` or `sha256`, matching the repository),
`ref` (a visible commit-valued ref), and 1–32 repeated `needle_hex` values in the
requested order. Each needle is 1–256 bytes encoded as lowercase hexadecimal;
LF-containing needles are refused. Duplicate needles keep separate result slots.

Optional fields are shared across **all** needles:

- `case`: `exact` (default) or `ascii-insensitive`, never Unicode case folding.
- Repeated `path_prefix_hex`: up to 128 raw, slash-component-bounded path prefixes.
  Prefixes narrow the authorized source selection; they never grant access.
- `expected_head`: the previous response's `snapshot_token`; `expected_commit`:
  an exact native commit ID. A changed head/commit returns a conflict rather than
  silently selecting another snapshot. Omitting pins selects current authority.
- `max_matches`: 1–4096 per query, default 200. `max_bytes`: total selected blob
  bytes, at most 64 MiB. `max_file_bytes`: at most 8 MiB. These limits may be
  narrowed, not widened.

Example for a configured loopback endpoint (token supplied by the operator):

```bash
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${FG_TOKEN}" \
  --data-urlencode 'object_format=sha1' \
  --data-urlencode 'ref=refs/heads/main' \
  --data-urlencode 'needle_hex=536f757263655175657279' \
  --data-urlencode 'needle_hex=547265654361706162696c697479' \
  --data-urlencode 'path_prefix_hex=637261746573' \
  --data-urlencode 'max_matches=20' \
  "http://127.0.0.1:8080${FG_REPOSITORY_ROUTE}/api/v1/source/search-batch"
```

Those needles are `SourceQuery` and `TreeCapability`; the prefix is `crates`.
Binary needles and non-UTF-8 paths remain byte-exact through their hex encoding.

## Response and failure semantics

A successful response has `type: source_search_batch`,
`profile: literal-bytes-batch-v1`, and `shared_scan: true`. Tenant, repository,
incarnation, object format, head/snapshot token, source RCR, commit and root tree
are emitted **once** and apply to every result. The response also labels itself
`read_only: true`, `transaction_created: false`, and `published: false`.

`results` is in submitted query order. Each item contains `query_index`,
`needle_hex`, `completion`, `complete`, `returned_matches` and `matches`.
Matches are ordered by raw path bytes and then zero-based byte offset. Rows
include native blob identity, one-based line and byte column, match length,
and bounded raw excerpts with their original byte offsets. Overlaps are retained;
matching never crosses file boundaries. Binary regular files are not silently
skipped. Symlinks and gitlinks are counted only within the selected disclosure
scope, not followed.

`complete` means every selected regular file was searched for that needle.
`match_limit` is emitted only after observing at least one additional match
beyond that query's limit. One busy query cannot label an absent query partial.
`files_read`, `bytes_read` and `bytes_searched` are shared physical-work counters,
not sums of per-query counters. The scan can stop early only when every query
has its own demonstrated `match_limit`.

The batch retains at most 4096 total matches and 2 MiB of combined path/excerpt
bytes. The existing response ceiling is 8 MiB. Any aggregate result, input,
source-byte, capability, cancellation or output failure refuses the whole read;
there is no partial HTTP success or fabricated empty answer. No search result
can move a ref, add a grant, or become repository authority.

## Implementation and verification boundary

`fgit-forge::source_search::batch` owns the bounded sparse Aho-Corasick matcher
and shares the existing verified tree traversal. `OneNode` exposes both
caller-capability and independently authorized local snapshot APIs; single and
batch local reads share one selection implementation. HTTP reuses existing
source authentication, quotas, body framing and byte-exact row serialization.

The Rust regression tests include scalar parity, independent limits, all 32
query bits, suffix/overlap matching, both object formats, actual node reads,
authenticated fixed/chunked HTTP, stale-head conflicts, and reopened-node
read-only behavior. During the implementation session, an independent Python
algorithm model passed 10,940 comparisons against scalar byte-window search.
That is not execution of the Rust implementation. Rust/Cargo were unavailable;
compilation, Rust tests and canonical verification gates remain unverified.

Run the focused Rust checks with the repository's pinned toolchain:

```bash
cargo test --locked -p fgit-forge source_search
cargo test --locked -p fgit-node --test source_search_batch
cargo test --locked -p fgit-node --lib source
cargo clippy --locked -p fgit-forge -p fgit-node --all-targets -- -D warnings
```

Passing these focused checks would still not complete the repository's full,
release, persistent-generation, or semantic-search acceptance requirements.

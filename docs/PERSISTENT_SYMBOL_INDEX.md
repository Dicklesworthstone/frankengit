# Persistent native Rust declaration indexes

`rust-declaration-tables-v1` stores the existing `rust-declaration-heads-v1`
scanner output behind an immutable, source-bound generation. It connects native
TreeFS inventory, per-blob declaration tables, the existing asynchronous
FrankenSQLite authority, a local operator, and an authenticated HTTP reader.
FG-032 remains open. The original `search-symbols` scanning endpoint is unchanged.

## Build, refresh, query, and recover

The operator opens an existing node with the exact tenant/repository/hash-format
binding. It does not initialize repositories, derive credentials from source, or
change Git refs, forge events, repository decisions, or outbox acknowledgements.

```bash
cargo build --locked -p fgit-node --bin fg-symbol-index
fg-symbol-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main build genesis
fg-symbol-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main query prefix Thing
# After a source or forge write, use the exact previously returned index token.
fg-symbol-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main refresh "$INDEX_TOKEN"
# An explicit full rescan remains available; use the newly active token.
fg-symbol-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main build "$REFRESHED_INDEX_TOKEN"
fg-symbol-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main recover "$CANDIDATE_TOKEN"
```

Use `sha256` for that repository format. Assigned tenant/repository identities
are exactly 32 lowercase hexadecimal characters. A generation token has the
registered `alg:CODE:LOWERCASE_HEX` form. `build genesis` requires an uninitialized
symbol index; subsequent builds require its exact predecessor token. `refresh`
requires an existing, exact active predecessor, never `genesis`. There is no
implicit `latest`, force, background maintenance, or retry with a new basis.
Retain each returned token; old tokens remain useful for read-only recovery but
cannot authorize a refresh over a newer active generation.

Builds use one canonical source selection and complete native tree enumeration.
Regular `.rs` files are read through verified TreeFS and checked against their
native SHA-1/SHA-256 blob identities. Executable and empty Rust files are included.
Other regular files are counted but not read; symlinks/gitlinks are counted and
never followed. Source buffers are dropped per file, not retained during async
publication. A match ceiling never truncates an index build. Unsupported source,
missing objects, or resource failure rejects the complete preparation.

### Incremental refresh

Refresh authenticates current ref visibility before selecting the exact active
predecessor. It verifies the predecessor generation's profile, source namespace,
manifest commitment and **every distinct native blob's declaration table**.
Verification is streaming: only one table payload is retained at a time. A
missing, substituted, corrupt, incomplete or cancelled inventory is an error,
not an empty cache and not permission to fall back to an implicit full rescan.

After predecessor I/O, refresh reauthenticates the pinned current source head
and commit, enumerates the complete current native tree, and authorizes each
current Rust path. Matching native blob identities reuse verified tables without
fetching or scanning source blobs. New or modified blobs use the production
scanner. Renamed and copied files reuse tables under their **current** paths;
deleted paths disappear, including deletion of the entire Rust corpus. No old
path visibility, source stamp or declaration can survive merely through reuse.
Tenant, repository, incarnation, format and ref boundaries cannot be crossed.

The resulting canonical manifest and candidate generation ID are identical to
a full rebuild at the same current snapshot and exact predecessor. Work counters
are not part of canonical identity. The operator returns `type: symbol_index_refresh`,
new index token/number, current source token/commit/tree, and:

- `reused_files`: current Rust paths reusing verified predecessor tables;
- `source_blobs_read`, `source_bytes_read`: source I/O for newly scanned paths;
- `predecessor_tables_read`, `predecessor_payload_bytes`: actual predecessor
  verification work, with the manifest included in the byte count.

A forge-only write or unchanged source can therefore refresh with **zero source
blob reads**, while still recording the new source observation. This is not zero
I/O or constant-time maintenance: current tree enumeration, authority reads,
predecessor table verification and generation publication still happen. All
source-file, total-source, file-count, declaration and encoded-data ceilings apply
to the **whole resulting corpus**, including reused files, not only cache misses.

## Publication and recovery

New tables and the complete manifest are staged before the existing generation-
root conditional write. Refresh references already verified immutable tables
instead of restaging them. Namespace keys include tenant, repository, incarnation
and object format; each ref has its own generation head. This derived view is
named `source-rust-symbols`, with schema `source-symbol-index` 1.0 and a named
parser/index profile. Its document directory, declaration-table directory and
source metadata are one canonical manifest, so all four graph payload-root fields
bind that same manifest. They are not four independently materialized graphs,
and no call/reference graph is implied. Table and manifest frames use distinct
schema families in the existing generation identity domain.

Native `build_source_symbol_index_guarded_local_in` and
`refresh_source_symbol_index_guarded_local_in` accept a bounded synchronous
write-ahead callback. Both use the same publisher. The callback receives the
original candidate before any table/manifest put or root write; returning an
error prevents those effects. Refresh verifies the predecessor and prepares the
complete current corpus before this barrier. The unguarded APIs and simple CLI
do not themselves create durable controller progress. Publication errors after
that barrier retain the original candidate, including cancellation before the
first put. Confirmed publication has no following cancellation probe or await.
The CLI shuts down the node on operation success or failure; output and shutdown
failures never imply rollback. Refresh does not write a repository transaction.

Recovery authenticates current ref visibility and checks the original candidate
against generation history without rebuilding or reexecuting publication.
Active, superseded, uninitialized and not-in-selected-history observations are
separate. Negative history observations are not proof of rollback. The caller
must retain its candidate and its own responsibility for unresolved work.

## Authenticated persisted reads

```text
POST {repository-route}/api/v1/source/search-symbols-index
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer <independently read-scoped credential>
```

Required fields are the matching `object_format`, full visible `ref`, and
lowercase-hex `name_hex` for a 1-128-byte ASCII identifier. The name excludes any
raw `r#` prefix. Optional `match` is `exact` or `prefix`, case-sensitively. Repeated
`kind` and `path_prefix_hex` retain the scanning endpoint's closed kinds and
slash-component path rules. Kinds are function, struct, enum, trait, type, module,
union and macro. The same bounded request framing, credentials, revocation,
quotas, service enablement, and transaction-key rejection apply to both routes.
No indexed read builds, refreshes or activates an index; there is no HTTP write
route for symbol indexes.

`expected_head` and `expected_commit` pin the canonical source observation.
`minimum_index_token` AND `minimum_index_number` optionally carry an independent
previously observed generation checkpoint. Both are required together; a higher,
forked, or unavailable checkpoint fails closed. These extra fields belong only
to the indexed route and remain invalid on the scanning route. There is no
historical-index selector or pagination cursor in this initial profile: one
request selects one current immutable generation, with an explicit result limit.

```bash
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${FG_READ_TOKEN}" \
  --data-urlencode 'object_format=sha1' \
  --data-urlencode 'ref=refs/heads/main' \
  --data-urlencode 'name_hex=5468696e67' \
  --data-urlencode 'match=prefix' \
  --data-urlencode 'path_prefix_hex=737263' \
  "${FG_URL}${FG_REPOSITORY_ROUTE}/api/v1/source/search-symbols-index"
```

The reader first authenticates current source and hidden-ref policy. It then
selects and verifies the generation, manifest and each required table. Namespace,
ref, source head/RCR/forge position/commit and table commitments must agree.
Even a forge-only write makes an old index stale; refresh or full rebuild is an
explicit operator action. An uninitialized index, stale index and unresolved
checkpoint return distinct HTTP 409 codes (`symbol_index_uninitialized`,
`symbol_index_stale`, `index_checkpoint_unavailable`). Corruption and missing
backing remain errors, not successful empty results or fallback scans.

Responses identify `type: source_search_symbols_index`, schema 1, both scanner
and index profiles, exact source head/token/RCR/commit/tree, and index token and
number. Rows retain original name bytes, kind, raw-identifier flag, raw path,
native blob, byte offset/length, physical line/byte column and original excerpt.
Result order is raw path then source offset, not dictionary-name order. An
extra matching declaration is required before `complete: false` is reported.
A page exactly filling its limit may still be complete.

`source_blobs_read` and `source_bytes_read` are zero for indexed queries. Source
state materialization still reads authority/closure metadata; table decoding,
manifest verification and generation ancestry are real work. `indexed_files`,
`indexed_declarations` and `indexed_source_bytes` describe the whole recorded
Rust corpus. `tables_read`, `payload_bytes_read` and `work_units` describe index
query work, not fresh lexical scanning, exact elapsed CPU, or a latency SLO.
`max_matches` narrows 1-4096 retained results (default 200). `max_work` narrows the
67,108,864-unit table/lookup model. `max_bytes` and `max_file_bytes` bound the
referenced source sizes even though those blobs are not reread. Native APIs can
also narrow table-read and aggregate payload-byte limits. Budget failure never
returns a partial successful report.

## Scope, bounds and verification

This preserves the scanner's language semantics: ASCII declaration names in
`.rs` files, not compiler name resolution, type checking, cfg evaluation, macro
expansion, imported references or calls. Literal/comment/attribute/macro contents
cannot fabricate declarations. Unsupported code identifiers or malformed scanned
source refuse a build or refresh; they are not silently skipped. Full Rust or
language-server correctness is not claimed.

Tables have at most 20,000 declarations across the complete corpus, 128-byte
names, a 1 MiB encoded-payload ceiling per file and at most 288 original excerpt
bytes per row. The complete profile admits up to 20,000 regular files, 64 MiB of
Rust source, 8 MiB per Rust file, a 1 MiB manifest and 32 MiB total encoded data.
Generation ancestry retains the existing independent bounded read profile.
Retained result names/paths/excerpts additionally share 2 MiB. Missing required
payloads, exhausted bounds or cancellation cannot become a complete empty index.
An actual empty `.rs` corpus instead has a verified initialized empty manifest.

Tables contain name directories, not full source files. Exact/prefix lookups use
those directories after commitment-checked decoding. This avoids source-blob
I/O and lexical scanning at query time, but still reads and decodes each selected
file table. It is not a global postings tree with I/O proportional only to hits.
Refresh reuses complete per-blob tables; it does not incrementally parse edits
inside a changed file. Delta compaction and the existing lexical maintenance
worker are not integrated for symbols yet. There is no browser symbol UI,
multi-language symbol graph or semantic ranking.

The native regression suite compares refresh candidate IDs with a full rebuild
captured before its write-ahead barrier, and compares refreshed query results
with the live native scanner. It covers SHA-1/SHA-256, additions, modifications,
renames/copies, deletion, empty files/corpora, raw paths, storage reopen, independent
checkpoints, whole-corpus ceilings, source pins, original-candidate recovery,
cancellation, malformed source, the operator binary and authenticated HTTP.
Native tests use actual node imports, patch admission, storage, TCP listeners and
operator processes, not substitute backends. Core tests cover incomplete reuse,
substitution/corruption, cancellation, duplicate-blob consistency and namespace
isolation with production codecs and scanner tables.

At commit `974c352209f85d8f26fa61acd04e5d92ee50fdeb`, the actual native lane passed
all-target compilation, 45 forge symbol tests (including the five new reuse
unit tests), 11 native index integration tests, three operator parser tests and
seven symbol HTTP protocol tests. That result applies to the core reuse commit,
not to later native refresh/operator additions. The standalone scanner/table lane
also passed separately. The implementation container has no Rust/Cargo; local
blob identity, source wiring and whitespace checks are static evidence only.
Read each later native result at its actual commit; it cannot be inferred from
a preceding commit or the standalone table suite.

The native script checks the real cross-crate target composition and runs the
forge symbols, native index integration, operator and symbol HTTP protocol tests.
Test debug symbols are omitted to bound linking memory; assertions remain enabled
and tests execute one at a time. These are repository-owned commands, not
hosted-service requirements for correctness or release.

```bash
bash scripts/verify_symbol_index.sh tables
bash scripts/verify_symbol_index.sh native
cargo test --locked -p fgit-forge source_symbols
cargo test --locked -p fgit-node --test source_symbol_index
cargo test --locked -p fgit-node --bin fg-symbol-index
cargo test --locked -p fgit-node --lib smart_http::server::source
```

Full-workspace, compiler-conformance and release gates remain separate. No bead
is closed or full FG-032 completion claimed.

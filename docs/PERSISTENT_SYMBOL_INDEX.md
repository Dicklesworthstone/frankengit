# Persistent native Rust declaration indexes

`rust-declaration-tables-v1` stores `rust-declaration-heads-v1` scanner output
behind immutable, source-bound generations. Native TreeFS inventory, per-blob
declaration tables, FrankenSQLite authority, local operators, and authenticated
HTTP reads use one publication and recovery path. New builds can additionally
publish the `rust-symbol-name-directory-v1` global lookup layout described below.
FG-032 remains open. The original `search-symbols` scanning endpoint is unchanged.

## Build, refresh, query, and recover

The operator opens an existing node with the exact tenant/repository/hash-format
binding. It does not initialize repositories or change Git refs, forge events,
repository decisions, or outbox acknowledgements.

```bash
cargo build --locked -p fgit-node --bin fg-symbol-index
fg-symbol-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main build genesis
fg-symbol-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main query prefix Thing
# Refresh using the exact active index token, not a Git object ID.
fg-symbol-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main refresh "$INDEX_TOKEN"
# A complete rescan remains an explicit option.
fg-symbol-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main build "$REFRESHED_INDEX_TOKEN"
fg-symbol-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main recover "$CANDIDATE_TOKEN"
```

Use `sha256` for that repository format. Tenant/repository identities contain
32 lowercase hexadecimal characters. Generation tokens use the registered
`alg:CODE:LOWERCASE_HEX` form. `build genesis` requires an uninitialized symbol
index; later builds and `refresh` require its exact active predecessor. There
is no implicit `latest`, force, or retry with a different basis. Retain returned
tokens for subsequent operations and read-only recovery.

For explicitly scheduled, checkpointed local maintenance, use
[`fg-index-maintain --symbols`](SYMBOL_INDEX_MAINTENANCE.md). That foreground
controller owns a separate private state directory, bounded passes, write-ahead
candidate persistence, cancellation drain and process-death recovery. It is not
query-triggered maintenance or a remote write grant.

Builds enumerate one complete authenticated native tree. Regular `.rs` files,
including executable and empty files, are checked against native SHA-1/SHA-256
blob identities and scanned. Other regular files are counted but not scanned;
symlinks and gitlinks are counted and never followed. Source buffers are dropped
per file. Match limits cannot truncate an inventory. Malformed or unsupported
source, missing objects, cancellation and exhausted bounds refuse preparation.

### Incremental refresh

Refresh authenticates current ref visibility before selecting the exact active
predecessor. It verifies the predecessor generation, source namespace, manifest,
selected global directory when present, and **every distinct blob's table**.
Table verification is streaming; decoded source-name/kind summaries are retained
instead of source bytes. Missing, substituted or corrupt backing is an error,
not an empty cache or permission to fall back to a full rescan.

After predecessor I/O, refresh reauthenticates the pinned current head/commit,
enumerates the complete current tree, and authorizes current Rust paths. Matching
native blobs reuse verified tables and summaries without fetching or scanning
source blobs. New/modified blobs use the production scanner. Renames and copies
use their current paths, while deleted paths disappear. Reuse cannot cross tenant,
repository, incarnation, format or ref boundaries.

Full rebuild and refresh at the same snapshot, predecessor, implementation and
host limits produce identical manifest/directory bytes and candidate IDs. Work
counters are not canonical identity. Refresh output contains `reused_files`,
`source_blobs_read`, `source_bytes_read`, `predecessor_tables_read` and
`predecessor_payload_bytes`; the last includes manifest and directory verification.
A forge-only write can refresh with zero source-blob reads, but authority reads,
tree enumeration, table verification and publication still occur. All build
ceilings apply to the entire resulting corpus, including reused files.

## Global name directory and compatibility

The directory maps each case-sensitive declaration name to ordered document
ordinals, closed kind tags, and declaration counts. Its commitment binds the
**exact canonical manifest**, including current source observation, raw paths,
native blob identities and table roots. Only complete production scanner tables
or completely verified predecessor tables supply these summaries. Counts must
cover every document's declarations; malformed names, kinds, order, counts and
ordinals refuse. Duplicate candidate documents are removed without changing
raw-path order. Returned spans still come from verified original tables.

Two generation layouts are supported under the same `source-rust-symbols` view:

| Graph schema | Builder profile | Payload-root layout |
| --- | --- | --- |
| `source-symbol-index` 1.0 | `rust-declaration-tables-v1` | All four roots bind the v1 manifest. |
| `source-symbol-index` 1.1 | `rust-symbol-name-directory-v1` | `edges_root` binds the name directory; vertices, evidence and index-manifest roots bind the v1 manifest. |

These are closed schema/profile pairs, not heuristics based on payload presence.
The parser root and all existing table/manifest codecs remain unchanged. The
name-to-document relation is deterministic-derived, not a call/reference graph
or authorization decision. Ordinary HTTP/CLI responses retain their v1 table
and scanner profile fields; they are not a new wire schema.

**New readers support old generations. Old binaries do not support schema 1.1.**
Upgrade readers before publishing an accelerated generation. An explicit build
or refresh can upgrade a legacy index while preserving predecessor/checkpoint
history. Current-index maintenance no-ops do not migrate layouts or advance a
generation merely to add the optimization. There is no automatic downgrade or
rewrite of an acknowledged checkpoint when returning to an older binary.

A directory must fit the existing 1 MiB per-payload and 32 MiB total-index
ceilings, as well as the host authority body limit. If only this additional
payload would exceed those bounds, preparation explicitly selects schema 1.0
and preserves the full legacy corpus. It never truncates names or documents.
Integrity, cancellation and source errors do not take this size-only path.
Once schema 1.1 is selected, its directory is **mandatory backing**: queries,
refresh and current reconciliation fail on missing/corrupt/substituted data
instead of silently reading all tables or rebuilding a replacement.

## Publication and recovery

New tables, the selected directory and the complete manifest are staged before
the generation-root conditional write. Reused tables are already verified
immutable payloads and need not be restaged. Keys include tenant, repository,
incarnation and native format; every ref has a separate generation head. Frames
use distinct schema families in the existing generation identity domain.

Native guarded build/refresh APIs share one publisher. Their synchronous
write-ahead callback receives the exact candidate before any payload put or
root write; callback failure prevents those effects. All source preparation and
predecessor verification precede the callback. Publication errors after this
barrier retain the original candidate, even for cancellation before the first
put. Confirmed publication has no following cancellation probe or await.
The simple CLI does not itself persist durable controller progress; the
maintenance controller does. Output/shutdown errors never imply rollback.

Recovery authenticates current ref visibility and examines original-candidate
generation history without executing another publication. Active, superseded,
uninitialized and not-in-selected-history observations remain distinct. Negative
history observations do not prove rollback or erase unresolved responsibility.
Current reconciliation verifies manifest and selected directory metadata, not
every table; it is not a complete corruption audit.

## Authenticated persisted reads

```text
POST {repository-route}/api/v1/source/search-symbols-index
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer <independently read-scoped credential>
```

Required fields are matching `object_format`, full visible `ref`, and lowercase
hex `name_hex` for a 1-128-byte ASCII identifier without a raw `r#` prefix.
Optional `match` is case-sensitive `exact` or `prefix`. Repeated `kind` and
`path_prefix_hex` retain closed kinds and slash-component scopes: `src` does not
include `src2`. Kinds are function, struct, enum, trait, type, module, union and
macro. Independent credentials, revocation, framing, quotas, enablement and
transaction-key rejection remain required. No read builds or refreshes an index.

`expected_head` and `expected_commit` pin canonical source. The paired
`minimum_index_token` and `minimum_index_number` carry an independent retained
index checkpoint; higher/forked/unavailable checkpoints fail closed. There is
no historical-index selector or pagination cursor. One request selects one
current immutable generation; it cannot mix layouts or source observations.

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

Current source and hidden-ref policy precede index data. Namespace, ref, source
head/RCR/forge/commit and payload commitments must agree. Forge-only writes still
make old indexes stale. Uninitialized, stale and unresolved checkpoints retain
HTTP 409 codes `symbol_index_uninitialized`, `symbol_index_stale` and
`index_checkpoint_unavailable`. Corruption is not a successful empty answer.

Schema 1.1 uses the verified global directory to select only tables matching
name, kind and current query path scope. Schema 1.0 retains table-by-table lookup.
All results retain name/kind/raw-identifier bytes, raw path, native blob, original
byte offset/length, physical line/byte column and excerpt. Ordering is raw path
then source offset, not dictionary name. Only an extra actual match proves
`complete: false`; an exactly filled result limit may still be complete.

`source_blobs_read` and `source_bytes_read` stay zero for persisted queries.
`indexed_files`, `indexed_declarations` and `indexed_source_bytes` describe the
whole recorded corpus. `tables_read` counts actual table reads; no-match directory
queries can return zero. `payload_bytes_read` includes manifest, directory and
selected tables. Directory decoding/selection and table matching share one
`max_work` budget. `max_bytes`, `max_file_bytes` and native `max_files` constrain
the referenced source/table candidates actually read, not skipped nonmatching
files; build/refresh limits still cover the entire corpus. Directory bytes count
toward the shared payload budget even when no table is read. Budget failure
never returns a partial successful report.

The directory itself and manifest are still fully read, verified and decoded.
This removes unrelated per-file table I/O, not all corpus-dependent work. It is
not a paged postings tree with total I/O proportional only to hits, a constant-
time query claim, or a measured latency SLO. Broad prefixes may still select
most tables, and the extra directory can cost more for tiny corpora.

## Bounds, tests and remaining scope

The scanner recognizes source declaration heads, not compiler name resolution,
type checking, cfg evaluation, macro expansion, references or calls. Literal,
comment, attribute and macro-body contents cannot fabricate declarations.
Unsupported code identifiers and malformed source refuse; they are not skipped.
The complete profile retains 20,000 declarations, 128-byte names, 20,000 regular
files, 64 MiB Rust source, 8 MiB per file, 1 MiB payloads and 32 MiB encoded data.
Retained result names/paths/excerpts share 2 MiB; results are bounded to 1-4096.
Generation ancestry has its own bounded read contract. No dependencies were added.

Core tests compare directory routing against the scalar table-query oracle
across exact/prefix/kind/path/result-limit combinations in both native formats.
They cover truncations, corruption, source/path substitution, invalid/incomplete
counts, shared exact work budgets, verified reuse and size-only compatibility.
Native tests cover genuine legacy storage/reopen/upgrade, selected-directory
failure in read/refresh/reconcile, plus existing full-rebuild candidate equivalence,
source changes, cancellation, write-ahead recovery and maintenance restart.
The 35-file native/HTTP corpus requires selective one-table and zero-table reads,
compares results with live scanning, and preserves lookahead, scope and byte limits.
Test presence is not execution evidence; read results at their exact revisions.

```bash
bash scripts/verify_symbol_index.sh tables
bash scripts/verify_symbol_index.sh native
bash scripts/verify_symbol_index.sh maintenance
cargo test --locked -p fgit-forge --lib source_symbols
cargo test --locked -p fgit-node --test source_symbol_directory
```

These repository-owned commands use real production codecs, native storage,
TCP and operator processes; debug-symbol omission does not remove assertions.
The editing environment has no Rust toolchain or network access, so local file
checks cannot establish native execution. Earlier successful scanner, refresh
and maintenance runs do not establish results for directory additions.
In-file incremental parsing, paged postings, compaction, multi-language symbol
graphs, semantic ranking and browser UI remain separate. Full-workspace,
conformance and release gates are not implied. FG-032 is not closed by this slice.

# Persistent native Rust declaration indexes

`rust-declaration-tables-v1` stores `rust-declaration-heads-v1` scanner output
behind immutable, source-bound generations. Native TreeFS inventory, per-blob
declaration tables, FrankenSQLite authority, local operators, and authenticated
HTTP reads use one publication and recovery path. New builds can additionally
publish the `rust-symbol-name-directory-v1` global lookup layout described below.
When a Rust file cannot be indexed by the bounded scanner, builds can retain an
authenticated omission under the versioned profiles described below, while
preserving useful declarations from other files. FG-032 and the broader search
integration bead remain open. The original `search-symbols` scanning endpoint
keeps its existing refusal contract.

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
per file. Match limits cannot truncate an inventory. A local scanner/profile
failure omits the entire affected Rust file with a typed, source-bound reason.
Missing or corrupt objects, authorization failures, cancellation and shared
budget exhaustion refuse preparation before publication.

### Authenticated file omissions

An omission records the current raw path, exact native blob ID and format,
source-byte count, closed reason, and one diagnostic: the source-byte offset
for a scanner failure or the applicable byte limit for a file/table overflow.
Current path authorization and native blob verification precede an omission.
This is part of the immutable manifest commitment, not an operator-provided
skip list or an unverified filesystem warning.

| Reason | Meaning | Diagnostic |
| --- | --- | --- |
| `file_bytes` | The verified source exceeds the selected per-file scanner limit. | `limit`: positive and at most 8 MiB; `byte_offset`: null. |
| `invalid_utf8` | Source bytes cannot be interpreted by the Rust scanner. | `byte_offset`: within the original source; `limit`: null. |
| `unsupported_identifier` | A code identifier is outside the supported profile. | Source offset; null limit. |
| `unterminated_comment` | A comment does not terminate. | Source offset; null limit. |
| `unterminated_literal` | A literal does not terminate. | Source offset; null limit. |
| `unbalanced_delimiter` | A delimiter does not balance. | Source offset; null limit. |
| `depth_limit` | A file exceeds the scanner's local nesting bound. | Source offset; null limit. |
| `name_limit` | A file contains a declaration name exceeding the supported bound. | Source offset; null limit. |
| `table_bytes` | Its complete declaration table cannot fit a 1 MiB payload. | `limit`: 1048576; `byte_offset`: null. |

No declaration from a failed file survives, including declarations recognized
before its failure. Its consumed scanner work and source-fetch bytes remain
charged. Shared work/declaration exhaustion is fatal; it cannot be relabeled as
a local omission. The full current inventory still fits 20,000 regular files,
64 MiB of Rust source including omissions, the existing native fetch/allocation
ceiling, and existing manifest/index byte limits. A blob that cannot be read
within those independent limits still refuses the whole operation. No ceiling
was increased and no metadata list is silently truncated.

Paths in the omission list use strict raw-byte order, have valid `.rs` paths and
nonzero native IDs in the source format, and cannot duplicate or overlap a
successful document. Count, source-byte, path, reason, offset, limit and codec
validation apply again when reading the manifest. Omission records contain no
source text. They describe the **whole recorded Rust corpus**, independently of
the current name/kind/path filter and match limit. Unsupported-language files
retain their separate existing count; this is not whole-repository language
coverage or compiler completeness.

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
source blobs. New/modified blobs use the production scanner. **Previous omissions
are never reusable tables:** explicit refresh reauthorizes, rereads and rescans
their current blobs, even when the blob ID is unchanged. A smaller selected
per-file bound also prevents reuse of an oversized predecessor table; the current
blob is authenticated and explicitly omitted. Restoring the bound or repairing
the source allows a later refresh to restore coverage. Renames and copies
use their current paths, while deleted paths disappear. Reuse cannot cross tenant,
repository, incarnation, format or ref boundaries.

Full rebuild and refresh at the same snapshot, predecessor, implementation and
host limits produce identical manifest/directory bytes and candidate IDs. Work
counters are not canonical identity. Refresh output contains `reused_files`,
`source_blobs_read`, `source_bytes_read`, `predecessor_tables_read` and
`predecessor_payload_bytes`; the last includes manifest and directory verification.
A fully covered corpus can refresh a forge-only write with zero source-blob reads, but authority reads,
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

Four closed generation layouts are supported under the same `source-rust-symbols` view:

| Graph schema | Builder profile | Payload-root layout |
| --- | --- | --- |
| `source-symbol-index` 1.0 | `rust-declaration-tables-v1` | All four roots bind the v1 manifest. |
| `source-symbol-index` 1.1 | `rust-symbol-name-directory-v1` | `edges_root` binds the name directory; vertices, evidence and index-manifest roots bind the v1 manifest. |
| `source-symbol-index` 2.0 | `rust-declaration-omissions-v1` | All four roots bind the v2 manifest with nonempty authenticated omissions. |
| `source-symbol-index` 2.1 | `rust-symbol-omission-directory-v1` | `edges_root` binds the name directory; other roots bind the v2 omission manifest. |

These are closed schema/profile pairs, not heuristics based on payload presence.
The parser root and existing table/directory codecs remain unchanged. A corpus
with no omissions preserves its exact existing v1 manifest bytes and identity.
Only a nonempty omission list selects `source-symbol-manifest` schema 2.0; a v2
frame with an empty list is noncanonical and refuses. After the unchanged v1
payload fields, v2 writes the `rust-declaration-omissions-v1` profile byte string,
u32 omission count, and ordered rows. Each row writes a length-prefixed raw path,
the native-width blob bytes, u64 source length, and a closed u8 reason tag
(1–9 in the table order above), then optional offset and optional limit. Each
optional value uses tag 0 for absent or tag 1 followed by u64 for present; other
tags refuse. The graph schema/profile must agree with the decoded manifest's
coverage class. The
name-to-document relation is deterministic-derived, not a call/reference graph
or authorization decision. All successfully indexed tables retain their existing
profile and exact spans.

**New readers support old generations. Old binaries do not support new schema
versions.** Upgrade readers before publishing an accelerated or omission-bearing
generation. An explicit build
or refresh can upgrade a legacy index while preserving predecessor/checkpoint
history. Current-index maintenance no-ops do not migrate layouts or advance a
generation merely to add the optimization. There is no automatic downgrade or
rewrite of an acknowledged checkpoint when returning to an older binary.

A directory must fit the existing 1 MiB per-payload and 32 MiB total-index
ceilings, as well as the host authority body limit. If only this additional
payload would exceed those bounds, preparation explicitly selects schema 1.0
(complete coverage) or 2.0 (authenticated omissions) and preserves its recorded
corpus. It never truncates names, documents or omissions.
Integrity, cancellation and source errors do not take this size-only path.
Once schema 1.1 or 2.1 is selected, its directory is **mandatory backing**: queries,
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

Schemas 1.1 and 2.1 use the verified global directory to select only tables matching
name, kind and current query path scope. Schemas 1.0 and 2.0 retain table-by-table lookup.
All results retain name/kind/raw-identifier bytes, raw path, native blob, original
byte offset/length, physical line/byte column and excerpt. Ordering is raw path
then source offset, not dictionary name. Only an extra actual match proves
`complete: false`; an exactly filled result limit may still be complete.

Match pagination and source coverage are independent. An omission-bearing HTTP
result uses `schema_version: 2`, `index_profile: "rust-declaration-omissions-v1"`
and the following additional fields, while preserving existing `complete` and
`completion` match semantics:

```json
{
  "coverage_complete": false,
  "coverage_scope": "recorded-rust-files",
  "omitted_files": 1,
  "omitted_source_bytes": 14,
  "omissions": [{
    "path_hex": "62726f6b656e2e7273",
    "blob": "<exact native blob hex>",
    "source_bytes": 14,
    "reason": "unbalanced_delimiter",
    "byte_offset": 14,
    "limit": null
  }]
}
```

This example illustrates the field shape, not a reproducible blob fixture.
Covered results retain exact v1 JSON with no additional omission fields.
Revalidated HTTP keeps its original v1 source wrapper and places the v2 receipt
unchanged in `result`; provenance is never relabeled. The trusted-local indexed
`fg search` serializer likewise selects v2 only for omissions and exits 3 if
either match pagination or source coverage is incomplete. `fg-symbol-index query`
also includes the explicit v2 omission receipt. Build/refresh activation output
remains a publication receipt; query the active index separately to inspect its
reported generation and coverage.

The browser validates both closed profiles, exact ordered omission metadata,
native ID format, diagnostics and aggregate bounds before installing a result
or advancing a retained checkpoint. It shows source omissions separately from
match truncation and renders bounded local pages of escaped raw paths, reasons
and native IDs. Display paging does not perform another query. Combined Initial
retrieval keeps useful available symbol results but sets aggregate `complete`
false when they have omissions. Omission paths and metadata count toward the
same retained-result budget as all other Initial channels; no list is hidden to
make a response fit. Browser file navigation still verifies source bytes only
for selected valid hits, and does not claim a proof of omission correctness.

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
Unsupported code identifiers and malformed Rust files produce explicit whole-file
omissions in persistent builds; the separate live scanner still refuses them.
The profile retains 20,000 declarations, 128-byte names, 20,000 regular
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
Omission regressions cover both native hash formats, canonical v1/v2 separation,
closed reasons and diagnostic validation, whole-file discard, reopen, unchanged
omission rescans, repaired source restoring coverage, narrowed/restored per-file
bounds, shared fatal budgets, full-rebuild candidate equality, authenticated HTTP
disclosure, CLI incomplete status and Initial retained-byte accounting. Browser
wire/DOM tests are fixture-driven and do not establish native execution.

```bash
bash scripts/verify_symbol_index.sh tables
bash scripts/verify_symbol_index.sh native
bash scripts/verify_symbol_index.sh maintenance
cargo test --locked -p fgit-forge --lib source_symbols
cargo test --locked -p fgit-node --test source_symbol_directory
```

These repository-owned commands use real production codecs, native storage,
TCP and operator processes; debug-symbol omission does not remove assertions.
Native execution requires the pinned Rust toolchain and the admitted dependency
closure. Earlier successful scanner, refresh and maintenance runs do not
establish results for later directory or omission changes.
In-file incremental parsing, paged postings, compaction, multi-language symbol
graphs and semantic ranking remain separate. A current-source maintenance no-op
does not rescan unchanged omissions or migrate profiles; use explicit refresh.
These fixed bounds do not establish that every large repository, including this
workspace, can be fully indexed. Full-workspace,
conformance and release gates are not implied. FG-032 is not closed by this slice.

# Incremental native source-index refresh

`fg-index ... refresh INDEX_TOKEN` and
`OneNode::refresh_source_index_local_in` refresh a complete persistent lexical
index without rereading or retokenizing unchanged source blobs. This composes
the existing verified TreeFS inventory, immutable lexical codec and asynchronous
generation authority. It adds no dependency, runtime, database, wire schema or
repository mutation path. FG-032 remains open.

## Operator usage

Build the initial index as before, then refresh against the exact preceding
index token printed by build, refresh or indexed HTTP search:

```bash
cargo build --locked -p fgit-node --bin fg-index
fg-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" \
  sha1 refs/heads/main build genesis
fg-index "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" \
  sha1 refs/heads/main refresh "$INDEX_TOKEN"
```

Use `sha256` for that repository format. Refresh opens an existing node and
requires trusted local access. It refuses `genesis`, `latest`, missing tokens,
and extra force arguments. An uninitialized index requires an explicit build.
A mismatched predecessor is not automatically replaced with the current head.

The successful `index_refresh` JSON receipt contains the exact source
head/commit/tree, new index identity and number, reused/rebuilt document and
source-byte counts, prior rows not reused, old index payload/ancestry bytes read,
and modeled build-work bytes. `prior_documents_not_reused` includes replacements
and renamed paths as well as deletions. These are work counters, not elapsed-time,
throughput or peak-memory measurements. `repository_transaction_created` is false.

Source writes may make the selected source stale while refresh runs. A successful
receipt names what was indexed, not a stronger claim of freshness when printed.
The existing HTTP `/api/v1/source/search-index` reads a refreshed generation
without any endpoint change, after its current source/visibility checks. Even a
forge-only write still invalidates the old source stamp; refreshing that case
can reuse every regular file while producing new source-bound metadata.

## Exact reuse and complete replacement

The node first authorizes the current visible reference before loading any old
index metadata. It pins that exact canonical head and commit into the subsequent
native source selection. A write between those observations causes refusal; the
second observation cannot silently refresh the source precondition. Source
head/RCR/forge position/commit/tree in the successor come from the verified
native selection, not from the caller or old index.

The prior index must be the explicitly named current generation. Every catalog
and every referenced segment is read and verified before reusable postings are
returned, including segments whose old files might later be removed. Missing or
corrupt backing never produces an empty reuse base or an implicit full rebuild.
A full rebuild remains a separately requested operator action.

The shared native TreeFS walker still enumerates the complete current tree with
its existing scope, path, depth, entry and object-read controls. Executable and
empty files count as regular files; symlinks and gitlinks are counted but never
followed. Every discovered regular path is authorized, including reused paths.
Only an exact raw path plus exact native blob identity can reuse postings.
New, changed and renamed paths read their blobs through the verified native
object source. A mode-only regular-file change can reuse its lexical postings,
because that lexical profile does not index executable mode.

All present regular files enter the complete successor inventory. Old paths
not present are removed, replaced blobs lose their former tokens, and new paths
receive their correct path-channel tokens. This is not an old-index union.
Document IDs remain scoped to a generation and are assigned in raw-path order;
insertion/deletion can shift them. Queries must keep their exact original index
and source pins for continuation, as before.

The posting engine inverts each verified segment's posting columns once for
per-document reuse. It retains the original first byte spans and separate path
and content channels. Fresh rows go through the same native identity checker
and ASCII-word tokenizer as full builds. The replacement payloads use the same
canonical segment/catalog format, with no tombstone or migration schema.

Prepared successor payloads are staged before the existing exact-predecessor
root publication. The root CAS makes the complete new generation visible at
once. A racing refresh loses rather than refreshing its predecessor. Git refs,
forge events and repository decisions are not changed by index publication.
Publication uncertainty retains `SourceIndexPublication { candidate, error }`;
use the existing `recover CANDIDATE_TOKEN` operation. Staged bytes, cancellation,
output failures and shutdown failures do not establish rollback. No additional
cancellation check follows a confirmed publication.

## Bounds and scope

Reuse loading shares the existing catalog/segment byte allowance and has to fit
its segment count ceiling. Inverted posting metadata is charged to a separate
64 MiB modeled-size bound; allocator overhead/RSS is not claimed to equal that
number. Each immutable segment remains individually bounded before decoding.
The preparation still obeys 20,000 documents, 64 MiB total source, 8 MiB per
file, 128 segments and 32 MiB encoded index data. Deterministic capacity-only
splitting is bounded to 256 attempts and 256 MiB of modeled source/copy work.

Native source-size limits include reused files. Fetch counters and fetch quota
charges instead count bytes actually read. Unsupported input, such as a 129-byte
word in a new file, refuses the whole preparation. Fresh source buffers and old
posting buffers are dropped before asynchronous successor staging. Async reads
receive the invocation's context and cancellation is checked around bounded
work; dropping a future is not a runtime drain/containment protocol.

This avoids unchanged source-blob I/O and tokenization; it does not claim all
index work scales with changed bytes. It still reads current tree metadata and
the whole bounded prior index, copies postings, re-encodes a complete successor,
and stages its payloads (identical bodies use existing idempotent puts). There
is no measured performance claim, global stable document-ID allocator,
append-only delta/tombstone engine, automatic outbox scheduler, background daemon,
HTTP index-management grant, symbol parser or semantic ranking in this change.
Existing build/query/recovery, source-read authorization, freshness rules and
read-only HTTP semantics remain unchanged.

## Verification boundary

Eleven core Rust tests cover exact canonical equality with fresh rebuilds across
both native object formats; insertion/deletion/replacement/rename; raw paths,
binary and empty content; changed source stamps; prior segment corruption;
cross-scope/store refusal; exact shared budgets; concurrent index advancement;
async suspension and per-invocation contexts; cancellation and unpolled futures.
Their source stamps and async/fault adapters are explicit reference fixtures,
not durable-backend or native-tree completeness evidence.

Eight additional integration tests use the existing actual node, native imports,
TreeFS authoring/admission, file-backed authority and HTTP harness. They cover
same-source refresh/reopen, actual multi-file edits and rebuild comparison,
forge-only staleness recovery through HTTP, reuse-inclusive limits, stale
predecessors, source refusals/cancellation, old-generation continuation/recovery,
mode-only changes, renamed paths, and unsupported new content without partial
activation. One operator test checks explicit refresh arguments. They are tests
of the implementation, not a claim that those scenarios were executed here.

Rust/Cargo/rustfmt are unavailable in this implementation environment. These
20 new Rust tests, compilation, formatting, Clippy, durable execution and
full-workspace/release gates have NOT been executed. Exact baseline/uploaded
blob comparisons, changed-file whitespace and operator JSON-template checks
are static checks only.

Run in the repository's pinned/offloaded build lane:

```bash
cargo check --locked -p fgit-graph -p fgit-node --all-targets
cargo test --locked -p fgit-graph lexical::stored::refresh
cargo test --locked -p fgit-node --test source_index_refresh --test source_index --test source_index_http
cargo test --locked -p fgit-node --bin fg-index
```

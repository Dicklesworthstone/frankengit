# Native source indexing

`OneNode` now composes `fgit_graph::lexical` with the node's verified Git object
fabric and existing asynchronous FrankenSQLite authority store. The node builds
its own source inventory instead of accepting caller-supplied files or stamps.
This is the native source integration for FG-032a, not full FG-032 completion.

## Build, query, recover

`build_source_index_local_in` is an explicitly trusted-local operator API.
It takes a full ref, optional expected source head/commit, explicit predecessor
index ID, and bounded source-read limits. `None` as predecessor requires an
uninitialized index; an existing index requires its exact predecessor. Building
never changes Git refs, forge events, repository decision history or outcomes.
It does write derived payloads and activate a derived generation, so it is not
an operation granted by an HTTP read credential.

The shared native source selector authenticates one repository authority head,
checks canonical hidden refs, resolves the commit and root tree through the
selected closure, and derives the read grants from that same tree. The builder
retains its exact forge position as well as head/RCR/commit/tree. A separate
preliminary source read is not used to manufacture the stamp.

Every selected regular file is enumerated through verified TreeFS. Executable
files are included; symlinks and gitlinks are counted but never followed.
Missing objects, unsupported paths/modes, incomplete scope, oversized words,
cancellation or exhausted budgets fail the entire build. `max_matches` does
not truncate an inventory. Empty regular files contribute path terms; a truly
empty committed tree has an authenticated empty index, not an uninitialized one.
An unborn reference still refuses because it does not select a commit.

Files are sorted by raw path bytes and assigned consecutive positive document
IDs within this generation. Segment capacity alone may trigger deterministic
left-first bisection. No malformed document can be skipped by splitting. At
most 256 build attempts and 256 MiB of input reprocessing are admitted, alongside
the existing 128-segment/32-MiB encoded-index ceilings. Source buffers are dropped
before the asynchronous staging phase. This is bounded whole-tree rebuilding,
not incremental/tombstone indexing or a claim of bounded peak RSS/throughput.

All payloads are staged before the existing generation authority activates the
root. The return carries the exact original source and confirmed activation.
A concurrent source write can make that build stale before it finishes; the
receipt does not pretend to select newer source. Publication failures retain
`SourceIndexPublication { candidate, error }`. Neither this error nor staged
payload existence proves rollback. `recover_source_index_local_in` resolves the
saved candidate through authenticated generation history without rebuilding or
reexecuting publication. No cancellation check follows confirmed publication.

`search_source_index_local_in` is read-only. It authenticates current repository
source and visibility before selecting any index data. The stored source head,
commit, RCR and forge position must match that source selection exactly; otherwise
`SourceIndexStale` is returned. Even a forge-only write invalidates an index in
this conservative profile. It never silently rebuilds, scans files, or substitutes
old-source results for current ones. A missing index reports `Uninitialized`, not
an empty successful query.

An optional exact index activation and independent minimum checkpoint use the
existing `read_at`/anti-rollback machinery. Same-source rebuilds can advance the
active index while a continuation retains the original index. A continuation
with `after` requires its original source head, source commit and index activation.
Terms/channel/prefixes are repeated explicitly; changing them defines another
query, not an automatically validated cursor continuation. Native IDs and spans
remain generation-scoped. The node does not offer historical-source fallback.

Queries read persisted catalogs/postings, not source blobs. Payload, ancestry,
query-work and result ceilings remain independent and shared across segments.
No partial result escapes a resource, corruption or cancellation error. Search
semantics are the existing ASCII-word conjunction profile documented in
`PERSISTENT_LEXICAL_INDEX.md`, not literal, regex, symbol or semantic matching.

These local APIs require an already authorized operator with whole-repository
scope. They do not mint credentials or support persisting a sparse caller's
capability as a whole-repository index. Any remote adapter must independently
authorize repository reads; a query prefix is not authorization. Current ref
visibility is also checked before recovery can disclose generation history.
Retaining an activation does not pin payloads against GC or certify durability
beyond the selected store/generation publication profile.

## Integration and verification

The only new dependency edge is `fgit-node -> fgit-graph`, an existing admitted
first-party crate. The lockfile adds that edge only: versions, checksums and all
283 packages are unchanged. No codec, schema, external dependency, runtime or
store implementation is introduced.

Seven native integration tests in `tests/source_index.rs` cover both Git hash
formats, full inventories, native blob spans, real-node shutdown/reopen, binary
names, independent path/content channels, exact generation continuation,
failed-build atomicity, original-candidate recovery, forge-only staleness and
invalid source selection. Three unit tests cover deterministic capacity splitting,
unsupported-document refusal, empty inventories and cancellation. Integration
tests use the existing actual node/Fsqlite harness; they are not executed here.

Rust/Cargo/rustfmt are unavailable in this implementation environment. Compilation,
all Rust tests, Clippy, real durable execution, full-workspace and release gates
remain unverified. Exact baseline/uploaded Git blob checks, lockfile semantic
comparison and changed-file whitespace checks are not substitutes.

Focused verification in the repository's pinned/offloaded build lane:

```bash
cargo check --locked -p fgit-node --all-targets
cargo test --locked -p fgit-node --test source_index
cargo test --locked -p fgit-node --lib treefs_workspace::source_search
```

Automatic outbox rebuild scheduling, incremental updates, symbol extraction,
semantic refinement, public index-management authorization and the full FG-032
acceptance campaign remain separate unfinished capabilities.

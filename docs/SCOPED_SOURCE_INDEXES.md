# Explicit path-scoped lexical indexes

A whole-repository index still requires every selected regular file to fit its
existing limits. An oversized unrelated file can therefore block a whole-tree
build. The scoped native API instead selects an explicit union of paths and
subtrees BEFORE reading source blobs, then publishes a separately identified
index of every regular file in that union. It does not silently skip a failing
selected file, read an ignore file, or pretend the resulting corpus covers the
whole repository.

This is lexical content/path search under `ascii-word-postings-v1`, not Rust
symbol indexing. File, source-byte, document, segment, posting, query-work and
payload limits are unchanged. A scope containing an oversized file still
refuses; large selected subtrees still need smaller explicit scopes. This is
not automatic sharding, whole-repository coverage, or an index GC policy.

## Native operator API

The [`fg-index-scope` operator command](SCOPED_INDEX_COMMAND.md) exposes build,
search, exact continuation and original-candidate recovery over these methods.
It requires write-ahead candidate recording for builds and emits explicit scope
coverage; it does not change the existing whole-repository command paths.

Construct `fgit_graph::lexical::scoped::LexicalScope` with 1–128 raw-byte paths.
Use `OneNode::build_scoped_source_index_local_in` or its guarded variant to
build/rebuild, `search_scoped_source_index_local_in` to query, and
`recover_scoped_source_index_local_in` for original-candidate read-only recovery.
The scope argument follows the reference argument. All operations require the
caller's existing trusted-local repository authority. A path filter, scope
digest or index checkpoint grants no permission.

Builds enumerate the canonical visible reference through the existing native
TreeFS selector and verify native SHA-1/SHA-256 blob identities. The shared
inventory walker visits ancestor directories necessary to reach each prefix,
not unrelated subtrees. Metadata that must be inspected still consumes its
existing independent bounds. Symlinks and gitlinks are not followed; their
counts refer only to the selected scope. A missing path is an explicitly empty
part of the union. Selected-file failures refuse the complete build.

The default build requires an uninitialized scoped head. A replacement names
its exact predecessor; source head/commit preconditions remain independent.
The guarded build calls the original-candidate barrier after preparation and
BEFORE any payload staging or root publication. Barrier failure prevents those
effects. After the barrier, failure or cancellation can require recovery of
that exact candidate; staged objects alone never prove publication. Confirmed
activation wins over later cancellation. Repository refs, forge state and
outbox acknowledgements are not changed.

Queries return `ScopedLexicalReport { scope, index }`. `index.results.complete`
is completion only within the explicit coverage intersected with query path
filters, never a whole-repository negative result. Document IDs, source byte
counts, first-word spans and content/path semantics are unchanged. Continuation
requires the same scope, exact source head/commit, generation and query. A
minimum generation floor still refuses unresolved or regressed history.

Reads remain strict: even a metadata-only repository change can make the scoped
index stale. There is no implicit build, refresh, revalidation, fallback or
retry. The existing whole-tree HTTP, browser, CLI search and maintenance APIs
keep their original index heads and cannot consume a scoped index by accident.
An explicit scoped rebuild is currently required after source changes.

## Coverage identity and compatibility

Prefix input is bounded to 4096 bytes per path, 64 components, and 32 KiB total
BEFORE copying/deduplication. NUL, empty/dot/dot-dot components and `.git` (ASCII
case insensitive) refuse. Path bytes otherwise retain their original case and
encoding. Raw-byte sorting, deduplication and removal of descendant prefixes
produce one canonical union. Similar siblings such as `src` and `src2` remain
distinct. An empty prefix list refuses rather than becoming a wildcard.

The scope digest is SHA-256 over:

```
frankengit/source-lexical-scope/v1\0
u32be(prefix_count)
for each canonical prefix: u32be(byte_length) || exact_path_bytes
```

There are no newlines in that preimage. The head key uses the existing namespace
key prefix with kind `scoped-head`, followed by SHA-256 of the exact reference
bytes and the complete 32-byte scope digest. The canonical generation view is
`lx-` followed by lowercase RFC 4648 base32 of the complete digest, without
padding (55 ASCII bytes total). Both the selected head and its committed view
therefore bind the scope, including for an empty corpus. Prepared indexes and
selections are distinct scoped types and cannot be passed to full-index APIs.

Original manifest, segment, catalog and generation codecs are unchanged.
Identical immutable payloads can be shared, but distinct scoped heads and
canonical views never merge their generation histories. Existing full-tree
keys, views and result structures are untouched. Keep the original prefix set
with candidate receipts: a digest alone cannot reconstruct coverage. Retaining
a checkpoint is not a GC pin or a retention lease.

## Validation boundary

Focused tests cover canonical coverage identities, separate empty histories,
foreign selections/floors, original-candidate recovery, byte-exact pagination,
unchanged resource ceilings, out-of-scope file exclusion, cancellation, native
storage reopen and actual TCP metadata publication. Graph tests explicitly use
the reference memory authority store; node tests use the existing native node,
TreeFS and Fsqlite support. Authored tests are not evidence that they ran.
No native compilation, test execution, rustfmt, Clippy or full repository gate
was available in the implementation environment. No bead closure or release
readiness is claimed.

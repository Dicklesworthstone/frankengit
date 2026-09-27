# Scoped lexical index reads

Related: `frankengit-root-doctrine-x2mv.4.19`.

The synchronous and asynchronous `LexicalIndexStore` readers use the selected
manifest's authenticated document-path ranges before fetching posting segments.
Existing content/path queries, including native callers behind indexed HTTP
search, gain this behavior without a new query mode or an index rebuild.
For example, `path_prefix_hex=737263` selects the exact path `src` and its
slash-delimited descendants, not `src-old`, `src0`, or `srcfile`.

A segment is skipped only when its complete document-ID interval precedes the
pagination cursor or its complete path interval cannot intersect any requested
prefix. Prefixes are a union; words remain an AND within the selected channel.
No filename decoding, Unicode normalization, case folding of paths, or prefix
successor allocation is used. Intersecting ranges are only candidates: native
segment commitments and the original per-document query predicate still decide
which results may be returned. A gap between two catalog paths is not a hit.

## Authority and completeness

The generation selection, checkpoint floor, store-instance binding, namespace,
reference, manifest, and all metadata catalogs retain their existing checks.
This is not a cache, alternate authority, old-generation fallback, or grant of
source access. All existing node-side current-source and visibility checks still
precede these reads. Manifest and catalog bytes are still read and authenticated.

`complete` remains query completeness at the selected source/index, not an
integrity scrub of every stored segment. An unrelated missing/corrupt segment
need not be accessed for a disjoint path scope, just as a preceding document-ID
range need not be revisited on a continuation. A required segment or metadata
failure still refuses the read; no partial result is relabeled as success.
An unscoped query retains the original segment traversal.

Pagination still uses increasing absolute document IDs. The reader looks ahead
for an actual next matching document, across pruned ranges, before returning a
continuation. An exhausted scope can return a complete empty result with zero
segment reads. Corpus and original source/generation identities are unchanged.

## Resource accounting

Scope planning shares the existing query-work budget across all examined
segments, including ones ultimately skipped. Each prefix comparison reserves
`4 * (prefix byte length + 1)` units before comparing the bounds; this covers
the four possible bounded byte comparisons. Cancellation is checked during
planning. Unscoped queries do not acquire this additional planning charge.

Segment and payload-read limits count the bodies actually read, plus the
existing metadata-byte charge. Before storage I/O, the reader refuses a segment
whose manifest-declared encoded size cannot fit the remaining payload budget.
Actual bytes and native commitments are still checked after the read. Planning
can consume part of a narrow work allowance; limits are never widened or renewed.
This change establishes no measured latency or end-to-end speedup claim.

## Regression target and remaining work

`lexical::stored::scope_tests` exercises both readers through the real codecs and
reference generation authority, with an explicitly simulated async I/O spy. It
covers native hash formats, content/path channels, byte scopes, pagination,
metadata-only queries, exact resource boundaries, corruption, cancellation and
cross-store/ref/namespace refusals. The range property checks use an independent
path-membership oracle. These tests must be compiled and executed on the pinned
repository toolchain; authored coverage is not a passing gate.

This does not implement a cross-segment term dictionary, decoded-segment cache,
large-file exclusion/coverage policy, symbol-source revalidation, in-server
maintenance, or index garbage collection. The broader indexing bead stays open.

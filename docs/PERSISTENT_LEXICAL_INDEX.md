# Persistent lexical source generations

`fgit_graph::lexical` implements `ascii-word-postings-v1`: immutable source
metadata and content/path posting segments with native blob validation, bounded
conjunction queries, persistence and exact generation selection. This is a real
index over supplied source documents, not a loop over the literal source scanner.
It advances FG-032a without declaring symbol extraction, semantic ranking,
progressive refinement or the complete search acceptance campaign finished.

## Document and query behavior

Build `LexicalSegment` from raw-path-sorted, already authorized documents. Each
source blob is checked against its declared SHA-1/SHA-256 identity. Only complete
ASCII alphanumeric/underscore words are indexed; A-Z is folded. High bytes and
punctuation are separators, never Unicode normalization. Content and path are
separate channels. The first original byte span for each term/document is kept
in equally sized, sorted document-ID and offset columns. Source contents are
not retained in the index. A 129-byte word refuses the entire build rather than
silently omitting part of the document. Binary files are not silently excluded.

`LexicalQuery` ANDs 1–32 whole tokens, normalized, sorted and deduplicated. It is
not substring, phrase, regex, symbol or fuzzy search. The rarest posting list is
the pivot; equal counts break ties by normalized term index. Other lists are
intersected by bounded binary search. Results have ascending absolute document
IDs, which also preserves the raw-path order required by the builder. Query
prefixes use slash-component boundaries and confer no read permission.

The caller assigns each segment's first positive document ID. Compaction
concatenates disjoint ordered ID/path ranges without renumbering or overwriting
postings. Partitioning a corpus with the same consecutive IDs, then compacting,
produces the same canonical bytes/root as rebuilding it. This is not a global
cross-generation document-ID allocator, update/tombstone engine or merge policy.
IDs used in continuations are scoped to the exact selected index generation.

Pagination requires a further matching document before returning `complete:
false` and `next_after`. Filling the requested result count alone is not evidence
of truncation. A continuation keeps the exact generation, normalized query and
last returned ID. A caller changing those parameters is issuing another query,
not continuing the same result. The library does not mint an HTTP cursor token.

## Explicit omissions and source coverage

Native builders enumerate every selected regular file and verify its native
blob before deciding whether its body fits the configured per-file indexing
limit. Oversized files can be recorded as `LexicalOmission` rows instead of
aborting the entire build. Each row binds the exact raw path, native blob ID,
verified source-byte count, `FileBytes` reason and applied limit. Paths are
strictly ordered, unique and disjoint from indexed documents. Binary bytes
retain the existing tokenization behavior; no new binary-file exclusion applies.

`PreparedLexicalIndex::with_omissions` and the corresponding scoped/refresh
constructors accept these records from the native source owner. The original
constructors remain strict. Omission-free preparations preserve their original
v1 bytes. Nonempty omissions select `source-lexical-index` schema 2.0 and v2
manifest/evidence frames, bound to `ascii-word-postings-omissions-v1`;
document/posting catalogs and segments retain their existing encoding. Readers
check the matching generation, profile and catalogs before returning results.

`IndexedLexicalReport.coverage_complete` is independent of result pagination.
`results.complete` means the selected postings have no further matching page;
it does not establish coverage of an omitted file. Every page retains the same
authenticated omission inventory, including queries with no matching documents.
The combined indexed-plus-omitted corpus remains bounded to 20,000 files and
64 MiB. Omission metadata and returned hits share the 2 MiB result allowance.
Preparation and manifest decoding reject an omission inventory that cannot
fit that allowance on its own, so it cannot publish an unqueryable generation.
Source corruption, missing objects, host limits, exhausted aggregate budgets
and cancellation remain errors, never omission reasons. This profile only
permits the explicit per-file-size omission; oversized tokens still refuse.

## Persistence and generation lifecycle

`PreparedLexicalIndex::new` consumes complete segments plus the exact source
namespace/ref/head/RCR/forge-position/commit/tree and excluded non-regular count.
Preparation writes nothing. Source coordinates are caller-supplied facts:
verifying blob IDs does not establish authorization or prove the supplied files
exhaust the named tree. The native source owner must establish those properties.

`LexicalIndexStore` derives bounded keys from tenant, repository, incarnation,
object format and the full reference. Payloads are content-addressed in that
namespace. A publish stages segment bodies and distinct document, posting,
evidence and manifest catalogs before invoking the existing generation authority.
The catalogs reference the same segment bodies, with distinct canonical schema
families. Evidence records builder/source/count commitments; it is not an
independent completeness attestation. Existing v1 encodings remain unchanged;
the explicit omission profile uses the versioned metadata described above.
No external dependency, new runtime or competing store is added.

The resulting graph generation is `DeterministicDerived`, bound to the explicit
builder profile and source stamp. Generation CAS, predecessor checks, receipt
validation and ambiguity use the shared `GenerationAuthority` machinery.
`candidate_id` can be saved before publication; `recover`/`recover_async` resolve
that exact candidate from selected history without reexecuting it. Staged-only
bytes do not establish activation. A returned root-publication confirmation is
not converted to cancellation afterward, nor does it promise stronger durability.

`select`/`select_async` authenticate one generation selection and verify the
persisted manifest and all three supporting catalogs. Supplying an exact
activation invokes `read_at`, independently checking an optional newer or older
anti-rollback checkpoint. Continuing an older index never substitutes a newer
manifest. `search`/`search_async` then verify and inspect one selected segment at
a time, sharing byte, comparison-work and result bounds across segments. A
selection cannot be reused on another store instance, namespace or reference.
Metadata counters name the whole indexed corpus, not just a query prefix.

Every async operation receives the invocation's store context. The library has
no blocking adapter, ambient runtime, listing, retry loop, filesystem checkout,
or Git subprocess. Missing/substituted payloads, malformed catalogs, cross-scope
reuse and cancellation refuse the whole read; an authenticated empty index is
distinct from an uninitialized index. Immutable retention remains a separate
owner obligation. Holding a selection does not prevent GC or grant access.

## Bounds and deployment boundary

A segment has at most 2048 documents, 32768 dictionary entries, 65536 postings
and 1 MiB of encoded data. A complete generation has at most 128 segments,
20000 documents, 64 MiB of source data and 32 MiB of encoded payloads. A file is
at most 8 MiB for indexing, a path 4096 bytes and a word 128 bytes. Only the
explicit omission constructors permit per-file-size exclusions, with their
verified bytes still charged to the aggregate budget. Other limits are hard
refusals. Empty indexes contain no segment but still have
all metadata catalogs and a generation root.

Queries retain at most 4096 hits and 2 MiB of result metadata. Their shared work
budget counts token setup, posting comparisons, candidate visits and prefix
checks; it is not a measurement of CPU instructions or a latency guarantee.
Decoding and hashing are independently bounded by payload byte/count ceilings.
Read byte counters include catalog work from selection, rather than granting a
fresh full allowance to each segment. Generation ancestry has its own existing
bounded and reported read allowance. Backends must bound read allocation before
returning a buffer. Live probes bracket bounded work; hashing primitives are
bounded synchronous calls, not forcibly interruptible tasks.

The store is an internal library capability. Its caller must authorize the
entire namespace before retrieving metadata, postings, paths or statistics and
revalidate current visibility at any remote boundary. Existing source HTTP
endpoints are unchanged by this library commit. This is not yet their persistent
index adapter, a cross-repository search service, a full-text language parser,
or a production-readiness claim.

## Verification boundary

Twelve segment tests cover both object formats, exact offsets, distinct channels,
byte paths, prefix boundaries, compaction/rebuild equality, independent scalar
conjunction parity, malformed structures with matching commitments, corruption,
pagination and resource/cancellation twins. Twelve stored-index tests cover real
reference-store payload persistence, exact old-generation reads, lost-root-reply
recovery, staged-only versus empty state, corrupt/missing catalogs and segments,
shared cross-segment budgets, foreign selection reuse, genuine async suspension,
per-call contexts and wrong generation classes. Async/fault adapters are explicit
test doubles; source stamps in these tests are fixtures, not a live node builder.

The pinned nightly graph test lane covers codec compatibility, omission
integrity, scope and refresh behavior, empty and paginated partial coverage,
and exact shared result-budget boundaries. These graph tests do not by
themselves establish native durability, full-workspace or release conformance.
Focused checks in the pinned build lane:

```bash
cargo check --locked -p fgit-graph --all-targets
cargo test --locked -p fgit-graph lexical
```

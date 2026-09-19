# Exact generation reads for query continuation

`GenerationAuthority::read_at` and `read_at_async` resolve an exact previously
selected graph generation. They extend the shared generation machinery used by
FG-032a and plan §27.4: continuing a query must not silently substitute a newer
index when another builder activates a generation.

This is a native read API over the existing generation authority. It introduces
no new database, runtime, dependency, schema or root encoding. It is not a
persistent lexical/symbol index, an HTTP indexing service, a retention pin, or
completion of FG-032. The source-search endpoints are not switched to an index
by this change.

## Exact selection versus minimum freshness

`read_active(view, minimum, limits, live)` selects the current generation and
optionally proves extension of a retained checkpoint. Its `minimum` is a lower
bound, not the precise generation to use for a continuing query.

`read_at(view, expected, minimum, limits, live)` instead requires the exact
`GenerationActivation` in `expected`: both its immutable generation ID and its
original authority generation must match. Its asynchronous sibling additionally
takes the invocation's `AsyncAuthorityStore::Context` as the first argument.
A staged object, a valid ID at the wrong position, a fork, or an unavailable
selected lineage cannot become a successful replacement by the latest index.

The returned `PinnedGeneration` keeps two facts separate:

- `activation()` and `body()` identify the exact requested generation and its
  original source stamp, schema, authority class and payload commitments.
- `selected_head()` identifies the current head observed once for this lineage
  check. It is not the manifest to use for the query's subsequent payload reads.

`generations_read()` and `bytes_read()` report the complete membership/checkpoint
observation, including the current head and immutable backing. They are not the
cost of a direct arbitrary-object lookup.

The body exposes `vertices_root()`, `edges_root()`, `index_manifest_root()` and
`evidence_root()`. These return the digests already committed by the unchanged
body codec. Consumers must fetch and verify the corresponding exact payloads
under their existing authorization; a newer generation's root is not a fallback.
An exact-only graph consumer still calls `body().require_exact()` rather than
borrowing the authority class of the current head.

## Retaining newer checkpoints without changing a query

The optional `minimum` is independent of `expected`. A caller can keep querying
an older immutable generation while retaining a newer anti-rollback checkpoint,
or verify an older floor that requires walking past the query generation.
Both are checked on the same selected predecessor chain before returning any
result. A higher or conflicting minimum refuses even if the query ID was found.

When `minimum` is omitted, the query's own activation is also its checkpoint.
No checkpoint or query state is persisted automatically. The owned result does
not mutate when a later builder advances the head. A fresh `read_at` call may
report a later `selected_head()` while returning the same exact query body.
Multi-view callers must retain their entire explicitly chosen generation vector;
this per-view API does not silently assemble or refresh a mixed vector.

## Security, resources and cancellation

The implementation reuses the existing authenticated head read and bounded
immutable ancestry walker. It verifies each visited body, exact identity,
canonical encoding, view and predecessor position. It retains at most one
additional bounded target body internally and exposes it only after all
checkpoint checks succeed. It never looks up the requested ID outside the
selected chain, lists storage, retries publication, or performs any write.

`GenerationReadLimits` and backend read ceilings are unchanged. The target and
independent floor share one ancestry/byte budget; neither receives an extra
budget. Cancellation checks bracket storage work and final selection. Async
reads receive the current invocation context and can suspend normally. No
provisional manifest escapes cancellation, missing history or resource refusal.

The caller must authorize the scoped head key, view and source before invoking
these primitives, and still verify the content behind the returned roots.
Membership in a selected generation lineage grants neither repository access
nor retention authority. Keeping a `PinnedGeneration` alive does not prevent
GC, satisfy durability obligations, or certify the builder's source facts.
Missing retained data fails explicitly instead of selecting an older/newer body.

## Verification boundary

Twelve Rust regression tests accompany the implementation. They cover exact
manifest/source/root preservation; all original positions in a twelve-generation
chain; sync/async result and counter parity; independent floors above and below
the query; wrong positions; staged forks; absent and substituted backing; exact
resource limits; cancellation; real async suspension; a writer advancing during
the walk; unpolled futures; and exact-versus-statistical authority classes.

They use actual generation encoding and the reference authority store through
explicit test adapters. Their source stamps and payload digests are fixtures,
not outputs of a live graph builder. Rust/Cargo are unavailable in this session:
these Rust tests, compilation, formatting, Clippy, durable FrankenSQLite,
live-node, full-workspace and release checks have not been executed.

An independent Python selection model was executed for 329,152 combinations of
query IDs/positions and optional floor IDs/positions over valid chains of up to
16 generations. All results agreed with a direct membership/position oracle;
1,632 combinations produced successful selections. This checks the abstract
selection logic only, not the Rust implementation, hashing, corrupted storage,
async scheduling or full generation conformance. Changed-file whitespace and
exact uploaded blob identity checks are separate static checks.

Focused checks in the repository's pinned/offloaded build lane:

```bash
cargo check --locked -p fgit-graph --all-targets
cargo test --locked -p fgit-graph generation
```

# Current-source Initial retrieval

`OneNode::search_source_initial_revalidated_local_in` composes the existing
current-source lexical and Rust-symbol readers into one model-free retrieval
result. This is an explicitly authorized whole-repository local read, not an
index builder, remote identity boundary, Context Packet, or retention pin.
The exact-source `search_source_initial_local_in` contract is unchanged.

## Metadata is not source code

An issue, PR, review, or unrelated ref update can advance repository authority
without changing the selected branch's native commit/tree. An index need not
be rebuilt solely for that metadata change. The current readers still verify
namespace, ref, native commit/tree, current visibility and independent index
commitments; a matching tree alone or a historical permission is insufficient.

The combined response keeps the distinction explicit:

- `current_source()` is the single authenticated source used for disclosure.
- `content().source` and `path().source` retain the original lexical provenance.
- An available symbol report retains its own original `source`, which may
  name another head than the lexical index or the current source.

No provenance field is refreshed or relabelled. Both lexical channels query
one identical generation. Path is pinned to content's selected generation and
current source even if maintenance activates a successor. Symbols must join
the same exact current namespace/ref/head/RCR/forge/commit/tree observation.
A move during any successful channel read refuses rather than retrying or
mixing snapshots. Results do not promise freshness at response delivery time.

## Bounds, failures and checkpoint semantics

`InitialLimits` divides total work and index-payload allowances before I/O.
An unavailable optional channel still owns its share. Unused allowances are
not borrowed, and no phase receives a new request/cancellation context.
Generation-ancestry and native authority/object reads retain their own bounds
within that same request. Returned `completed_*` counters cover successful
channels only; they are not total physical-I/O measurements.

Only an uninitialized or stale symbol index may be omitted, and only under
`SymbolPolicy::Optional` without a retained symbol-generation floor. Such a
result is explicitly incomplete. Required symbols, a retained unresolved
floor, corruption, missing payloads, cancellation and other failures abort
the whole response. A missing/stale lexical index always fails. No refusal
triggers literal scanning, index maintenance, or a historical-source fallback.
Result ceilings preserve each channel's native truncation semantics and the
combined retained-result byte limit; no omitted channel becomes zero hits.

## Evidence boundary

Authored persisted-node regressions cover SHA-1/SHA-256 indexes built at
separate metadata heads, unchanged original provenance, strict-reader refusal,
current-source reuse, reopening, actual code changes, optional/required/stale
symbols, unresolved floors, truncation, work/output budgets and cancellation.
The implementation environment lacked Rust tools: these tests, compilation,
formatting and Clippy were not executed here. Static checks do not establish
a passing native gate, an end-to-end speedup, or FG-096 completion.

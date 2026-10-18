# Complete selected-context byte verification

On `/ui/search/`, run a combined Initial search with **Include source excerpts**
enabled. The result now offers **Verify all selected context files**. Review the
full-file byte count and page count, set the verification ceilings, explicitly
consent, and press **Verify complete selected context**. Merely displaying a
result or downloading its original context report performs no verification read.

This is the byte-verification consumer of FG-032 and plan section 27. It does not
complete the broader Context Packet, agent-control, search, or authority work.

## What is checked

`CodeSearch.verifyContext({ maxSourceBytes, maxRequests })` verifies the entire
hydrated selection using the existing authenticated `source/blob` endpoint. All
pages retain the original reference, source snapshot and commit. The source
response validator still checks repository/incarnation, native identity, regular
file kind, page size and continuation. It does not refresh source or generation
pins and does not rerun the search.

The verifier preflights the full selection before I/O, charges each page before
dispatch, then hashes each complete file once with native Git blob framing in its
SHA-1 or SHA-256 domain. All retained excerpts must equal those verified bytes.
Every content/path hit must reproduce its first whole ASCII-word spans. Every
selected declaration must reproduce its complete name, raw-identifier boundary,
excerpt, line and byte column. A source shared by several channels or declarations
is fetched and hashed once per selected path, not once per hit. Path coordinates
remain path coordinates; they do not acquire file line numbers.

Only a complete successful selection returns a summary. A later failure cannot
publish a successful prefix. One operation deadline and cancellation generation
span every page, hash and witness check. Disconnect, source replacement or query
changes cannot install a late verification result. The page's Cancel action also
clears the selected verification summary. No retries or fallback reads run.

## Bounds and ownership

The source-byte ceiling is at most 64 MiB; the page-request ceiling is at most
1,056. Existing context limits admit at most 32 files, and the original search's
navigation limit (at most 8 MiB per file) still applies. An empty file requires
one page request and verification of its empty native blob. An empty selection
does not enable the verification button or establish absence elsewhere.

The UI defaults to the exact byte/page cost of its selection. These are new,
explicit full-file reads, additional to the source bytes read during hydration.
They are not a claim about total HTTP wire bytes, aggregate server work or wall
clock execution on every host. The host keeps existing response-size bounds.
The verifier holds one full file at a time, owns its hash input before WebCrypto
yields, and does not retain full source bodies in the returned summary.

## What is not proved

The blob identity was originally reported by the server. Matching its digest
checks internal byte consistency; it does not independently authenticate the
commit/tree membership, repository authority head, access control, freshness,
search coverage, declaration classification, macro expansion or compiler meaning.
The summary records these boundaries as explicit false fields. A ranked selection
remains a bounded advisory choice over returned hits, not authorization or proof
that the whole repository was searched. Source text remains untrusted data.

**Download local verification summary** produces a token-free record bound to
the selected source and generation vector. It includes exact checked file IDs,
counts and original verification limits. It deliberately does not include the
full blobs or authenticated membership proofs: `localObservationOnly` is true
and `independentlyReplayableProof` is false. It is not an import format, attestation
or permission grant. Keep it private. The original source-context report remains
unchanged and continues to describe its own verification limits. Repeated exports
revoke prior object URLs; query changes and page disposal revoke the remaining URL.

## Executable evidence boundary

`node --test tests/browser/search-context-verify*.test.mjs` runs the complete
verification module with real WebCrypto and explicit read-host adapters, plus its
actual view with a fake DOM. Tests cover both Git hash domains, byte corruption
outside excerpts, first-word and declaration witnesses, per-file hash deduplication,
empty and multi-page files, cancellation, caller mutation, exact/one-under ceilings,
consent, stale-result rejection and export cleanup. The legacy context suite
remains unchanged except for copying this additional production module into its
explicitly isolated harness.

These are not live Rust-node, real-browser, full Transport/Initial integration,
repository-authorization, full-workspace or hardware failure tests. No bead closure
or wider correctness claim follows from them. The source-only Rust asset route was
updated with its existing allowlist and inertness assertions; compilation requires
the repository's pinned Rust toolchain.

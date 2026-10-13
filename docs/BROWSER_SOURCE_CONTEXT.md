# Browser source context

The existing `/ui/search/` page can request exact source excerpts together with
combined Initial search. Enable **Include source excerpts** under combined search;
choose separate limits for distinct files, radius, source decoding and retained
excerpt bytes. No new access grant, mutation, index build or fallback is used.
The same source observation, generation checkpoints and absolute request deadline
span retrieval, hydration and complete-response validation.

## File selection

Hydration is off by default. When enabled, **Raw-path prefix** preserves the native
compatibility default. **Corroborated documents** explicitly requests
`context_selection=context-weighted-rrf-q16-v1` from the existing
`source/context-initial` endpoint. It is not an index-only search followed by a
second request using independently selected file paths.

Ranked selection uses the fixed native profile in
`crates/fgit-node/src/source_retrieval/context/ranked.rs`. For each channel, the
one-based rank counts distinct returned paths in raw-path order. Content and path
have weight 1; declarations have weight 2. Each contribution is
`floor(weight * 65536 / (60 + document_rank))`. Sum per file, sort by decreasing
score, break ties by raw path bytes, then take the requested file-count prefix.
Repeated declarations in one file contribute once. Native file/excerpt response
ordering remains raw-path ascending regardless of the selection priority.

This is deterministic cross-channel agreement, **not semantic relevance**. It
ranks only returned hits; unavailable channels, index omissions and truncated
results remain explicitly incomplete. A small file-count budget can omit files
with valid matches. Source-byte shares and excerpt bounds do not expand with a
file's score. Ranking does not grant permission or authenticate partial excerpts.

The browser recomputes selection from every returned channel before accepting the
receipt. It checks every winner, score, contribution, channel rank, identity and
tie-break; a plausible total is insufficient. Ranked responses without ranking
evidence, downgrades to alphabetical selection, mixed identities, reordered input
channels and arbitrary weights are refused. Invalid responses do not advance the
source pin or generation checkpoints, and do not trigger retries or fallback.

## Inspection and report export

The priority table shows each selected file's fixed-point score and channel
contributions. The source-file list stays raw-path sorted and labels the priority
separately. Path byte coordinates never become file coordinates. Display clipping
is explicit, and does not remove returned bytes from the downloaded report.

**Download exact source-context report** is a local, explicit action. The report
contains source/repository/generation bindings, selected profile, independent
budgets, completeness and omission counters, exact anchors and excerpt bytes. A
ranked report additionally retains the complete selection receipt and every
returned channel's ordered `(pathHex, blob)` identities, including repeated
symbols and candidates omitted by the hydration file limit. These inputs permit
reproduction of the bounded selection rather than merely trusting its winners.

Reports contain private repository/source data, but no ambient bearer credential.
They are neither signed proofs nor Agent Protocol ContextPackets. Partial source
excerpts remain untrusted data, not instructions or execution authority. Existing
explicit complete-file navigation retains its independent full-blob hash checks.

Changing selection or any query/limit invalidates in-flight results and download
URLs while retaining the existing snapshot pin. Selecting another snapshot is
explicit. Disconnect clears results, revokes download URLs and resets hydration
and ranking to their defaults.

## Verification boundary

`node --test tests/browser/search-context*.test.mjs` runs the decoder and browser
contract tests. Ranking golden values follow native test source at
`9da3ef87c0ccd6ca061a3e6b00a72f9b9c9ba166`, including the exact `4279` corroborated
late-path example and raw-byte ties. Decoder tests use explicit native-schema,
prevalidated Initial fixtures. Controller/view tests execute the production
modules with explicitly substituted shared Transport/Initial dependencies and a
fake DOM. They are not live native HTTP, real-browser, Rust-refinement,
authorization/CAS, or full-workspace acceptance evidence. No bead closure follows
from these tests.

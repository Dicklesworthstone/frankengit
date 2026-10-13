# Exact source context from Initial retrieval

`source-initial-context-v1` connects persisted Initial retrieval to verified
native source bytes. `OneNode::hydrate_source_initial_local_in` consumes an
`InitialReport` plus `source_retrieval::context::ContextLimits`. It does not
initialize, refresh, publish, or silently change either index generation.

The embedding must already authorize whole-repository reads. A saved report is
not a capability. Hydration reselects current canonical visibility with the
report's exact authority-head and commit pins, checks repository/incarnation/hash
format and the source RCR/tree/forge position, then resolves only selected paths
through the existing bounded TreeFS source. Symlinks and gitlinks cannot become
context files. A source or policy move is a refusal, not an automatic retry.

Candidates are the union of content, path, and available symbol results, deduped
by raw path. Conflicting identities or lengths cannot merge. The first
`max_files` distinct raw-byte paths are selected; `candidate_files` and
`omitted_files` make this deliberate selection visible. Omitted index coverage,
result truncation and unavailable optional symbols remain in the original
retrieval, not replaced by successful empty channels.

Every selected blob is decoded and commitment-checked once per path. Lexical
spans must equal complete ASCII-folded tokens; symbol names and raw-identifier
markers must agree with original source bytes. Path spans address path bytes,
never content offsets. Source spans get bounded byte-radius windows; overlapping
and adjacent windows are merged. Path-only hits get a bounded preamble, including
an empty excerpt for an actual empty file. Excerpts are exact bytes, not UTF-8
normalizations or line/column approximations.

Defaults: eight files, 128 bytes on each side of source spans, 64 MiB total source
allowance, 256 KiB retained excerpts. Hard ceilings: 32 files, 4096-byte radius,
64 MiB source, 1 MiB excerpts, 4096 anchors and 128 merged windows. Before I/O,
source allowance is evenly partitioned over the selected paths; the native blob
allocation ceiling is min(8 MiB, total allowance / selected files). Unused shares
are not borrowed. Authority, commits and directory trees retain their existing
independent shared native-read ceilings. A small excerpt does not authorize an
unbounded source decode. Source counters describe blob reads, not all metadata I/O.

Only the declared file selection is partial. Missing/corrupt backing, false
spans, cancellation, exhausted source/excerpt/window budgets or incomplete
hydration abort the whole response. `complete()` also requires the original
retrieval's full coverage; it never asserts excerpts contain entire files.

Repository text is available through `untrusted_bytes()`. This output is not an
Agent Protocol ContextPacket, run authorization, prompt-injection detector,
compiler-resolved graph, signed proof, durable context archive, or retention pin.

Verification uses production-native imports, patch admission, indexes, source
objects and reopen in SHA-1/SHA-256. Tests cover channel deduplication, raw paths,
CRLF/raw bytes, exact-limit/refusal twins, saved-source movement, optional channel
status, empty answers, cancellation, overlap merging, invalid spans and raw IDs.

```bash
cargo test --locked -p fgit-node --lib source_retrieval::context
cargo test --locked -p fgit-node --test source_context
bash scripts/verify_symbol_index.sh native
```

Compilation and runtime results must be read at the actual revision. Static
blob/whitespace checks do not establish a passing native suite. FG-032 remains
open; agent-run binding and persisted ContextPacket publication remain separate.

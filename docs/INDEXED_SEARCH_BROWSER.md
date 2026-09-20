# Indexed-search browser reconciliation

The main browser workflow is described in [BROWSER_INDEXED_SEARCH.md](BROWSER_INDEXED_SEARCH.md).
This supplement records the remaining changes reconciled with that implementation,
not a replacement UI or a claim to its already-landed capabilities.

## Diagnostics and deadlines

The existing read-only transport retains three diagnostic codes only for HTTP 409
from `source/search-index`: `source_index_uninitialized`, `source_index_stale`, and
`index_checkpoint_unavailable`. Diagnostic bodies are bounded to 4096 bytes before
JSON decoding. Server prose is never rendered; malformed or unknown diagnostics
remain ordinary HTTP refusals. The UI gives distinct initialization, reconciliation,
and checkpoint-recovery guidance. HTTP 503 remains an unavailable/verification
failure, not an empty successful query. No automatic scan, rebuild, retry, or older
index fallback is introduced.

A monotonic whole-operation deadline supplements the existing timer. Synchronous
work that prevents the timeout callback from running cannot accept an overdue read.
This detects an overrun at the next checkpoint; it does not preempt synchronous
JavaScript or claim hostile-code isolation.

## Verified content coordinates

After the existing complete native blob and first-token checks succeed, indexed
content spans also display one-based physical lines and byte columns. LF advances
the line; CR and multibyte UTF-8 sequences still count as bytes. One offset-ordered
scan computes every coordinate, then the UI preserves normalized query-term order.
Filename spans remain path offsets and never receive content line coordinates.

The current `openIndexed` and `nextIndexed` APIs, dynamic continuation control,
100-document page limit, all-term previews, source/index pins, retained generation
checkpoint, independent file-navigation limit, and exact downloads are preserved.
The existing HTML, indexed client/protocol, native index, and authorization rules
are not replaced. Original overlapping UI and HTML patch hunks are superseded by
the implementation in `b8db1231` rather than replayed over it.

## Focused execution evidence

```bash
node --test scripts/tests/indexed_search_transport.test.mjs scripts/tests/indexed_search_view.test.mjs
```

The reconciled selected-file fixture passes 46 tests on Node v22.16.0: 16 transport
and 30 mounted-controller tests, with zero failures or skips. These execute the
actual controller/client/transport/validators, with explicit HTTP, DOM, and download
URL fixtures. They cover both native hash domains, pinned continuation, cancellation,
download cleanup, indexed path/content results, and nonempty literal/batch/regex
regressions. Two added coordinate cases reverse lexical versus byte-offset order
and include CRLF and multibyte UTF-8.

Against the original transport/driver, the same 16 transport tests reproduce six
failures. Against the unmodified `b8db1231` UI with the new transport, the first 28
controller tests reproduce five failures: content line/column display, the three
specific diagnostics, and unavailable-index guidance. The two additional coordinate
cases also fail on that baseline.

This fixture is not a full repository checkout. Rust compilation, native index
execution, a live Rust listener, real-browser acceptance, Clippy, full-workspace,
and release verification have not been executed here. Index coverage and authority
signatures remain server claims; file hashing is not an authority-root proof.

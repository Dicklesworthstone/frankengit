# Persistent lexical search in the existing code browser

`<repository-route>/ui/search/` offers **Indexed content words (AND)** and
**Indexed path words (AND)** alongside the existing literal, batch and native
byte-regex modes. These use the existing authenticated `source/search-index`
API and persisted native index, not a browser-built index or a replacement scan.
See `INDEXED_SEARCH_HTTP.md` for operator setup and the native protocol.

## Query and navigate

Connect a source-read token, a complete commit-valued ref and the repository's
SHA-1 or SHA-256 format. Choose an indexed mode and enter one whole ASCII word
per line (or its exact lowercase hex bytes). Words contain only letters, digits
and underscore; A-Z folds to a-z. Terms are sorted and deduplicated and every
term must occur in the selected channel. There is no implicit substring, phrase,
regex, symbol or Unicode-word interpretation. The normalized conjunction is
shown with the results. Optional path prefixes remain lossless byte inputs and
match slash-component boundaries, not arbitrary string prefixes.

Each result is one indexed regular file with its absolute document ID, raw path,
blob identity, file size and the first byte span of every normalized query term.
Path-channel spans are checked against the returned path before accepting the
page. Results contain no invented source excerpts. The page shows the queried
index, observed index head, corpus size, excluded non-regular entries and actual
reported index work/read counts. Those are not relabeled as live source scanning.

Open a result to fetch its complete file in snapshot-pinned bounded pages. Only
regular/executable files are accepted; symlinks are not followed. Every page must
retain the original path, blob, source snapshot, commit, root tree and mode. The
client hashes the complete Git blob in its native domain, then independently
reproduces every first whole-word position in one byte scan. Content and path
positions are deliberately distinct: a filename match never highlights unrelated
content at the same offset. Empty and binary files retain their exact bytes.

Previews escape controls, directional characters and non-UTF-8 bytes. They are
bounded even when a complete large file has been verified. Explicit download
saves those exact bytes as an inert `application/octet-stream` attachment under
a fixed name. Repository strings are never HTML, executable code or URL paths.
Download handles and file buffers are cleared on replacement, cancellation,
query changes, disconnect and page exit.

## Two independent pins and a retained checkpoint

The first successful query selects a canonical source snapshot and an immutable
index identity/authority-position pair. **Next indexed page** sends the original
normalized query, source head, source commit, index token, index number and last
absolute document ID. It does not reread the form or substitute the newest index.
Both document IDs and raw paths must advance. Corpus metadata must stay fixed.
The server's extra-hit guarantee permits continuation only after a full limited
page; an empty next page, repeated result, missing cursor or generation switch
refuses rather than becoming successful completion. Only the current result page
is retained. Native completeness remains a server claim, not a browser proof.

A newer selected index head may be observed while querying the original immutable
index. The latest observed identity/position is retained in page memory and sent
as the minimum checkpoint on following queries and continuations. A lower head
or a different token at the same position refuses. Native generation ancestry
verification remains the server's job; the client does not authenticate these
opaque tokens independently.

Changing the query releases results but retains the source selection. **Release
snapshot** explicitly releases source pins while preserving repository identity
and the observed index checkpoint. Disconnect clears the whole session, including
that checkpoint. There is no persisted cross-session anti-rollback claim. HTTP
conflicts explain the missing/stale-index or unresolved-checkpoint possibilities;
an authorized operator must repair/build/refresh the native index when needed.
Neither an HTTP error nor a missing index produces a successful empty result.
No query builds or refreshes an index, retries automatically, or falls back to
literal/regex scanning. Those other modes remain explicit user choices.

## Limits and authority

The browser admits 1-32 terms of at most 128 bytes, up to 128 prefixes (4096 bytes
each, 32 KiB combined), at most 100 documents per page, 16,777,216 native query
work units and 33,554,432 index payload bytes per request. Users can narrow work
and payload budgets. Complete-file navigation is at most 8 MiB in 64 KiB pages
and can be narrowed separately; an oversized indexed hit remains a result but
cannot initiate a file download above that limit. Each read operation has one
end-to-end deadline across all HTTP pages and verification work, in addition to
per-request transport limits. JSON responses are bounded to 8 MiB.

The existing source-enabled static route serves the added module; each API call
still requires native read authorization and applies current hidden-ref policy.
The search transport permits only bounded bodyful same-origin POST reads, omits
cookies, refuses redirects, and has no idempotency-key, mutation, outcome, build
or index-refresh route. Existing write-capable browser profiles gain no indexed
search operation. No dependency, runtime, new native authority or store is added.
Object hashes and reproduced word positions do not authenticate the source
server, index coverage, authority signatures or other documents.

## Executable evidence and limits

```sh
node --test tests/browser/search-index.test.mjs tests/browser/search-index-view.test.mjs
```

The implementation run passed 82 focused tests: 64 client/protocol cases and 18
mounted-interface/import-route cases. The combined selected-file browser suite
passed 314 tests (232 retained regressions), with zero failures, cancellations or
skips. Both native hash formats, multi-page index/file reads, raw paths, binary
and empty files, first-word semantics, hostile responses, checkpoint forks,
resource limits, cancellation and existing literal/batch/regex behavior are
covered. A real loopback Node HTTP/fetch test checks request encoding and pins
against an explicitly labeled protocol double, not the native Rust server.

All relevant search source baselines were refreshed to their exact GitHub file
hashes. The wider retained browser fixture is not a complete current repository
checkout. HTTP and DOM fixtures are test doubles; no performance improvement,
native index execution or live-browser rendering is claimed. Existing Rust
static-route tests include the added asset but were not executed because
Rust/Cargo was unavailable. Native compilation, live-node/browser integration,
full-workspace tests, Clippy and release acceptance remain unverified. This is a
user-facing lexical slice, not completion of FG-032a or the broader forge bead.

# Browser code search and verified result navigation

`{repository-route}/ui/search/` exposes the existing source search engines as a
read-only browser workflow. It is also linked from the source browser at
`{repository-route}/ui/`. The source service must be enabled; its existing
independent `read` credential grant is still required for every API request.
No new runtime, dependency, object store, admission path or grant is introduced.

This is product integration under FG-032. Persistent indexes, symbol extraction,
semantic ranking, immutable-generation activation and the broader search
acceptance campaign are not implemented or declared complete by this change.

## Workflow

Connect a read-scoped token, a complete native ref such as `refs/heads/main`,
and the repository's SHA-1 or SHA-256 object format. Connect retains the token
only in page memory and clears the password input; it does not issue a source
request. The first successful search selects the current repository snapshot.

Choose **Single literal**, **Batch of literals** (one term per line, up to 32),
or **Native byte regex**. Query bytes can be entered as UTF-8 or lowercase hex.
Batch order and duplicate terms are preserved. Case matching is exact or ASCII
insensitive, never Unicode case folding. Optional path prefixes use slash
component boundaries; `src` does not select `src2`. Prefixes may also be entered
as raw hex, so non-UTF-8 filenames do not require lossy text conversion.

A final separator newline is ignored in batch/prefix textareas. Other spaces
are not trimmed. A newline inside one byte-valued prefix is entered in hex.
Literal terms cannot contain LF; hex input can express CR, NUL and other bytes.
The native regex profile is documented in [SOURCE_REGEX_HTTP.md](SOURCE_REGEX_HTTP.md).
User patterns are never evaluated by JavaScript's regular-expression engine.

The page shows shared physical-work counters and each query's own completion.
`match_limit` is not silently presented as a complete result. Empty complete
results are distinct from request, resource and infrastructure failures. Results
are displayed in local pages of 50 per query; paging retained results causes no
new source request. Server truncation has no invented continuation: narrow the
query/prefix or adjust a bounded limit and search again.

Opening a match uses only the internally retained query/result indices, not a
caller-supplied path or object ID. It loads every page of the exact regular file
at the search snapshot and checks the complete native Git blob ID with WebCrypto
(SHA-1 or SHA-256). Its excerpt and line/byte-column/span are reproduced from
those verified bytes. Literal bytes are checked again against the original
needle. Only after these checks does the page show a source preview and offer an
explicit binary download named `snapshot-source.bin`.

The visible file preview is at most 4096 source bytes. A long regex span retains
its full offsets and explicitly labels a truncated preview; an empty span gets
a visible marker. Source, filenames, excerpts and query labels are DOM text,
not markup. Control and bidirectional-formatting characters are escaped; invalid
UTF-8 remains byte-escaped. Downloads preserve original bytes, not display escapes.

## Snapshot and authority boundaries

Every result and file page carries the same tenant, repository, incarnation,
object format, selected ref, authority-head token, source RCR, commit and root
tree. All subsequent searches remain pinned until the user explicitly chooses
**Release snapshot**. That button discards results and pins without a request;
the next search may select new current state but cannot silently change the
retained repository/incarnation identity. Reconnect explicitly for that change.

Search controls changing invalidates the old result handles and any verified
file while keeping the selected snapshot. Ref/format/token edits disconnect the
old client. Cancel, superseding requests, disconnect and page exit invalidate
outstanding reads and late hash results. File pages or digest completion cannot
resurrect a discarded view. Disconnect clears query text, prefixes, token,
results and source bytes; generated download URLs are revoked when the file view
is discarded or another download is created. Completed user downloads are not
revoked or deleted by the page.

The isolated search transport permits only `POST` to `source/search`,
`source/search-batch`, `source/search-regex`, and `source/blob`. It rejects keys,
outcome recovery, preparation, publication, bundle routes, alternate methods,
cross-origin URLs, redirects and binary artifact responses. Existing PR,
source-authoring, initial-commit and branch profiles do not inherit search
permissions. Source requests omit ambient cookies and use no-store/no-referrer;
query data and tokens are not placed in URLs or persistent browser storage.

Static routes use the existing source switch and CSP/security headers. The
page is unavailable when source is disabled even if issue or PR services are
enabled. Static assets themselves contain no repository content or permission.
The existing server loopback/external-TLS deployment boundary is unchanged;
the client requires HTTPS outside localhost, 127.0.0.1 and IPv6 loopback.

A matched native blob ID establishes consistency of bytes with the returned ID,
not an independent signed authority-root proof. Search completeness and regex
leftmost-longest selection remain native-server claims. The browser validates
response structure, scope, identity, counters and coordinates; it does not
independently replay native search over every repository file.

## Bounds and failure behavior

Patterns/needles are at most 256 bytes; batch size is at most 32. Prefixes are
limited to 128 and 32 KiB combined. A query can request up to 4096 matches; the
browser caps all retained matches to 4096 and combined path/excerpt bytes to
2 MiB. It refuses an excessive response rather than silently discard rows.
The UI defaults to 100 matches per query.

Source work can be narrowed from 64 MiB read bytes, 8 MiB per file and 67,108,864
regex VM steps. JSON responses are limited to 8 MiB with declared and actual
length checks. File reads use 64 KiB pages, an 8 MiB maximum retained file, and a
30-second whole-operation deadline including paging and verification. Runtime
hash operations are not forcibly interrupted; their results are ignored after
cancellation or expiry. Native tree/object/capability/CPU limits still apply.

Malformed or mismatched responses never adopt a new search snapshot. A file
verification failure exposes no provisional source/download. Authentication
failure disconnects; stale snapshots require deliberate refresh. There is no
automatic retry, request replay, idempotency key or write responsibility.

## Verification boundary

The implementation session ran **103 JavaScript tests**: 85 client/protocol
cases and 18 DOM interaction cases. They exercise both object formats, all
three modes, independent batch completion, binary paths/needles, multichunk
files, hash/content/coordinate corruption, strict read-only routing, malformed
requests/responses, bounds, cancellation/supersession/hash races, local result
paging and download cleanup. Test files drive the production client and view;
HTTP source responses and the DOM are explicit test doubles.

```bash
node --test tests/browser/search.test.mjs tests/browser/search-view.test.mjs
```

Three Rust static-handler tests were added for exact source routes, source
enablement, framing/resource refusals and static-page security. Rust/Cargo were
unavailable, so compilation and these Rust tests were not executed. An installed
Chromium smoke attempt was blocked by this environment's browser policy before
loading the loopback page; it is not browser interoperability evidence. Live
native-node/browser execution, visual/accessibility verification, the current
full workspace and release gates remain unverified.

```bash
cargo test --locked -p fgit-node --lib smart_http::server::browser
cargo test --locked -p fgit-node --test source_regex_http
cargo test --locked -p fgit-node --test source_search_batch
```

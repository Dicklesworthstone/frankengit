# Native source-history investigation

Related product bridge: `frankengit-asa3` and comprehensive-plan source/forge
interfaces. This is read-only composition, not a new history authority or a
completion claim for the broader forge.

`HistoryClient` connects the existing source log, exact path log, line blame,
and historical tree/blob endpoints. An explicit reference-open selects one
repository incarnation, native hash format, authority snapshot, and current
ref tip. Every later request retains that selection until an explicit reopen;
no stale page is silently refreshed. A source-read grant is required by the
native gateway. No mutation endpoint, idempotency key, token persistence, or
ambient browser credential is part of this client.

## Read semantics

Log pages retain native child-before-parent order and original parent headers.
Exact path filtering includes changes against any parent and does not claim
rename following or simplified history. A filtered path can have zero matches;
an empty full ancestry cannot be fabricated as a successful empty repository.
Pagination applies the original filter and authority head before disclosure.

The client recomputes each returned commit's native SHA-1/SHA-256 identity and
checks its tree/parent summary against the exact body. Arbitrary message and
identity bytes are retained, including signature continuation lines. Author
and committer strings are untrusted claims, not authenticated identities.
This does not independently reconstruct the complete server ancestry graph.

Blame preserves zero-based half-open line and byte ranges, including CRLF and
missing final newlines. All returned origin commits are checked, every output
line must have an exact contiguous span, and complete-file results reproduce
the native blob ID. A narrow range is not represented as a complete blob hash
verification. The native all-parent same-path algorithm owns provenance; no
client rename or author heuristic substitutes for it.

Opening a blame origin reads that exact historical commit and path through
the currently selected visible ref, authority head, and ref tip. The server
still owns ancestry/disclosure checks; a digest is never permission. Returned
origin bytes must reproduce the attributed line and its native blob identity.
Historical directory/file continuations retain both the current ref tip and
the historical commit. Symlink payloads are inert bytes; links and gitlinks
are not followed.

## Resource and lifecycle contract

Native history ceilings remain 4,096 commits, 16,384 parent headers, 4 MiB
returned commit metadata, 64 KiB per commit, 20,000 file lines, 1 MiB blame
content, and 128 content comparisons. Client responses are streamed under
8 MiB. Historical file pages are at most 1 MiB and are never presented as an
unread complete file. Bounds are checked before retaining derived records.

All requests are exact same-origin POST reads, without cookies or redirects.
HTTPS is mandatory outside trusted loopback. A new view or explicit cancel
aborts obsolete work; generation checks continue through asynchronous native
hashing. Disconnect clears the token, selected scope, and retained blame.
Read failures never become empty success, mutations, or rollback assertions.

## Verification boundary

Run `node --test tests/browser/history.test.mjs`. These tests use real native
hash computations and actual client/validator modules, but HTTP responses are
explicit doubles. They do not establish live Rust-node ancestry, browser
rendering, authorization deployment, full-workspace, or release conformance.
No production Git subprocess or dependency is introduced.

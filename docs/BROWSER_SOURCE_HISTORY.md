# Native source-history investigation

Related product scope: FG-050 Web UI and comprehensive-plan source/forge
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

### Recent first-parent history

Choose **Recent first-parent chain — large repositories** before connecting or
explicitly reopening a reference. This uses `source/log` with
`first_parent=true` immediately; opening does not first require a complete DAG
read. **All parents** remains the default view. The API client equivalent is
`client.open(ref, objectFormat, { first_parent: true })`.

The recent view follows only the first parent stored in each commit. Merge
records still show every original parent, but side-parent histories are not
included. Each page reports the visited prefix's commit count, parent-header
count and logical metadata bytes, and whether its root was reached. It makes no
claim about the total reachable history. The client checks every native commit
hash, decoded parent order, first-parent link, root boundary and work counter
before displaying the page.

**Next first-parent page** retains the validated opaque cursor and applied page
size, even if the form is edited. Its head, raw ref, hash domain, tip and offset
must match the exact selection before a request is sent. The server independently
authorizes that current ref and re-walks its prefix. A cursor does not grant
arbitrary object access or make deep pagination constant cost. Prefix and page
share the existing 4,096-commit, 16,384-parent-header and 4 MiB metadata budgets;
older pages can still refuse. **Restart first-parent pages** starts again at the
same pinned tip; selecting a new head requires an explicit reopen.

Exact-path filtering requires **All parents**. Combining it with first-parent
mode is refused before networking. Existing blame, historical-file and
comparison tools keep their own traversal limits and all-parent semantics;
opening a recent page does not relax those limits. Scoped sponsored-agent
credentials still have no history grant.

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
logical commit metadata (including the skipped first-parent prefix), 64 KiB
per commit, 20,000 file lines, 1 MiB blame
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

## Browser workflow

The source-enabled gateway serves `<repository-route>/ui/history/`, linked
from the current source browser. Connect a source-read token and explicitly
open a full reference. Use the path form for exact file/directory history,
then browse a commit's tree and its immutable file ranges. Byte-valued paths
can be entered as lowercase hex and stay lossless during navigation.

Blame always names the selected current ref tip, not whichever historical
file happens to be on screen. Supply zero-based first/end line coordinates,
with an exclusive end or a blank end for the complete remaining file. Origin
buttons verify the exact old bytes before displaying a historical source view.
Current ref tip and historical commit remain separately labeled.

Blame tables show at most 200 rows at once with local pagination over the
already validated response. Source previews are capped at 64 KiB and commit
previews are narrower; explicit clipping messages and a complete validated
JSON download preserve the distinction between a preview and a full result.
Downloads contain repository data, not credentials. No repository markup is
interpreted as HTML, Markdown, paths on the host, or executable commands.

Static assets use the existing CSP/no-store/same-origin policy and require the
source endpoint switch. Existing PR, issue, initial-authoring, and source-write
gates are unchanged. Three Rust handler tests exercise exact routes, disabled
profiles, framing, body limits and inert assets. The pinned Rust toolchain is
available, but workspace resource exhaustion stopped native checks before
source validation; these Rust tests remain unexecuted.

The focused JavaScript suite is
`node --test --test-concurrency=1 tests/browser/history*.test.mjs` with the
repository's pinned Node version. It includes direct first-parent opening,
cursor/profile conflicts, both native hashes, merge-parent order, malformed
accounting, stale snapshots, cancellation and form-independent continuation.
It exercises actual client, validator and controller modules with HTTP/DOM
doubles, not browser-rendering or native-node deployment evidence.

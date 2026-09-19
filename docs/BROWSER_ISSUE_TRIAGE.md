# Native issue triage in the existing browser

Related integration bridge: `frankengit-asa3`. This extends the landed native
issue browser, not a second UI or a new authoritative issue store.

## Native search client

`IssueClient.search(predicate, { after, limit, head, maxScan })` uses the existing
`POST .../api/v1/issues/search` endpoint. The independent `issues-read` grant and
issue endpoint switch still apply. It never attaches an Idempotency-Key, stages
or dispatches a change, or modifies an unresolved request/recovery receipt.
Search cancellation uses the existing read controllers, not the write controller.

The closed predicate supports `state` (null, open or closed), `opened_by` (a
canonical principal ID), all required `labels`, literal `text` (up to 256 UTF-8
bytes), and `case_sensitive`. Matching folds only ASCII when case-insensitive;
it tests title and body separately and does not search comments. Label sets use
native UTF-8 ordering without mutating the caller's input. The client freezes
its predicate before awaiting transport.

The existing safe-integer browser profile is retained. Result limits are 1..100,
scan limits 1..1000 (default 200), and every nonzero `after` requires the original
snapshot token. The response must echo the exact predicate, snapshot, bounds
and repository identity. Rows, ordering, match membership, stopping reason,
counts, cursor progress and read-only flags are validated before disclosure.
The existing 8 MiB streamed JSON response ceiling remains in force.

A continuation names the last **examined candidate**, not the last matching
issue. A scan-limited page can contain no matches and still have a continuation.
Only `exhausted` means the queried suffix was fully examined; neither another
candidate nor an incomplete page guarantees another matching issue exists.
No count here is a repository-wide total or an authorization decision.

## Browser workflow

The existing `/ui/issues/` page now has a triage form for the native filters and
an explicit per-page scan ceiling. Submit starts a fresh query. Applied filters
are shown with the results so later edits to the form cannot mislabel the page.
The continuation button captures the original predicate, exact snapshot,
last-examined cursor and scan bound, rather than reading the edited form.
Selecting a matching issue opens its canonical history at the same snapshot;
existing comment/edit/close/reopen preparation still uses the displayed version.

Scan and result limits are visibly distinguished from exhausting the remaining
snapshot suffix. A page containing no matches does not hide an available scan
continuation, and it does not assert a repository-wide zero. Snapshots that move
or fail validation are not silently refreshed. New queries, list/history
navigation and the cancel-read button invalidate prior read responses. Cancel
never aborts an in-flight write or discards a pending change. Disconnect clears
private search filters along with existing visible state while preserving the
existing token-free unresolved recovery receipt.

No new static asset route, Rust endpoint, dependency, credential, authority
primitive, receipt format or mutation path is introduced. The previously landed
issue UI remains the implementation; the overlapping draft UI from this session
is intentionally not part of this change.

## Verification boundary

Run `node --test tests/browser/issues-native.test.mjs tests/browser/issues-search.test.mjs tests/browser/issues-triage-view.test.mjs`.
These are API/transport contract doubles, not live authority-service or browser
interoperability evidence. No Rust behavior, dependency, authorization grant,
mutation identity or canonical publication primitive is changed by this client.

The focused run passed 34 Node tests: eight existing native-client cases, 15 new
search-client cases, and 11 new DOM/controller cases. Rust compilation, full
workspace verification, actual browser rendering and live-node interoperability
remain unverified. DOM/fetch doubles do not establish those properties.

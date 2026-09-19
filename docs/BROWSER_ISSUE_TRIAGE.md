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

## Verification boundary

Run `node --test tests/browser/issues-native.test.mjs tests/browser/issues-search.test.mjs`.
These are API/transport contract doubles, not live authority-service or browser
interoperability evidence. No Rust behavior, dependency, authorization grant,
mutation identity or canonical publication primitive is changed by this client.

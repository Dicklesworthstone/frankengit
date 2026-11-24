# Verified PR and issue history coordinates

Native PR list/detail reads and issue list/timeline reads can retain verified
aggregate-history coordinates at an exact authority head. This addresses the
repeated unrelated-payload replay in `frankengit-root-doctrine-x2mv.4.7` without
adding canonical state, a database, an event schema, or a publication path.

## Cold construction and warm reads

The ordinary selected-history reader authenticates the selected frontier
ranges, scans every active outbox payload to detect conflicting duplicate
versions, and follows verified predecessor history when retired versions are
missing. It checks contiguous coverage through each selected frontier before
returning. That complete validation remains the cold-read oracle.

Optional index construction accompanies that same scan. It records only each
selected aggregate/version, a verified event identity, and one batch root
containing that event, plus the exact selected frontier coordinates. It adds no
storage reads and retains no titles, bodies, comments, credentials, grants, or
rendered pages. Only private construction through a successful complete replay
can produce `VerifiedAggregateHistory`.

A warm reader requires the same authority-head identity, repository and store
instance, with complete coverage of all currently selected aggregate frontiers.
It still reads and verifies the selected frontier batches and all selected
historical payload roots. It checks event identities and complete version
coverage against the retained coordinates. An absent or corrupt selected body
is a refusal; cached metadata cannot supply its text. A list index can serve a
subset of its aggregates, including an issue timeline, without retaining or
reusing the earlier output page.

Conflicting versions in another active outbox payload are still detected during
cold construction, even when the selected frontier alone appears complete.
Previously verified unrelated immutable payloads need not be read again at the
same head. A changed head or uncovered selection performs the ordinary replay;
the index never supplies missing history at a different authority position.

## Native integration and custody

The indexed admission APIs are:

- `pull_request::read_page_filtered_indexed_at`;
- `issues::read_page_indexed_at`;
- `issues::read_history_indexed_at`.

Their existing non-indexed counterparts retain the ordinary replay contract.
The new APIs accept optional prior coordinates and a retained-byte allowance,
then return the page and an optional newly verified index. Successful reuse
returns no replacement index. Zero or insufficient optional retention disables
capture without refusing an otherwise valid canonical read.

The node selects and authenticates the live/retained basis before lookup. PR
visibility and labels are reevaluated for the current caller before disclosure.
An index contains no authorization decision. Storage root, tenant, repository,
incarnation and object format also bind node cache custody; equal store-instance
numbers do not establish interchangeable host configurations.

`NodeConfig::with_aggregate_history_index_cache_bytes` sets the total retained
allowance. The default is 16 MiB, divided equally between one PR slot and one
issue slot. Each allowance includes index vector capacities, actual owned path
capacity and conservative entry/allocation overhead. Service children sharing
that configuration can reuse coordinates within the complete storage scope.
Zero disables retention. A fresh configuration or process can rebuild from
canonical data without these indexes.

No cache lock spans storage I/O. Contention or poisoning causes a miss. The node
retains a new index only after the entire page succeeds; cancellation, invalid
pagination and later fold failures do not replace the previous index. A late
read at an older generation cannot evict newer same-scope coordinates. Different
selections at the same exact head may replace each other. Already admitted
readers can temporarily hold an evicted `Arc`, so the allowance bounds cache
custody rather than total process RSS.

## Work and resource limits

The hypothesis is reduced payload I/O: after one complete validation, repeated
reads load the selected frontier/history batches instead of every unrelated
active outbox payload. A shared batch can contain other events, so this bounds
work by selected batch contents, not solely by returned row count.

Canonical forge/outbox maps are still authenticated on each read, and frontier
selection still depends on the aggregate map. Cold reads retain the existing
history, event and byte limits. Page payload limits, current disclosure checks,
request cancellation and request I/O budgets still apply to warm reads. Index
allocation uses checked arithmetic and actual vector capacities; optional
retention does not widen a replay or page budget.

This is process-local exact-head reuse. Persistent indexing, incremental
cross-head maintenance, arbitrary-age cold lookup, removal of canonical map
ceilings, and full history-independent list/search cost remain outside this
increment. It does not close `.4.7`, establish the 50,000-event acceptance
campaign, or claim a measured latency/throughput improvement.

## Regression coverage

Core index tests compare the visitor output with full replay, count payload
reads independently of unrelated history, and exercise conflicting duplicates,
retired history, stale bindings, selected-payload corruption, cancellation and
optional retention limits. PR and issue indexed-reader tests compare complete
pages and timeline windows with their canonical counterparts, including both
native Git hash formats for PRs. Native tests exercise real file-backed nodes,
current visibility, shared configuration/reopen, disabled caches, scope changes
and late pinned readers. Execution results must be reported against the tested
revision; this list is a description of authored coverage.

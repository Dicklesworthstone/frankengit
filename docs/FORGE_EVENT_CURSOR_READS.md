# Forge event cursor reads

Owning work: `frankengit-root-doctrine-x2mv.4.35` and the bounded-read gap
`frankengit-root-doctrine-x2mv.4.7`; plan sections 24 and 31.

## Cursor-scoped history replay

Resuming a nonzero cursor verifies the decision suffix from the selected head
through the complete batch containing that cursor's repository sequence. It no
longer replays unrelated decision batches before that position. Every traversed
predecessor and batch retains the ordinary content-identity and pair checks.
The payload reader still loads and verifies the cursor's own event batch, even
at EOF: a real RCR with an empty batch or an invented event index is not a valid
cursor. A future repository sequence refuses before history I/O.

The replay envelope remains 4,096 examined decision batches and 65,536 examined
RCRs. Refusal-only batches count, and every RCR in the boundary microbatch is
charged even when it precedes the cursor. Cancellation returns no partial page.
An initial read still verifies to genesis. A resumed read is not a whole-history
integrity scan: corruption strictly before its verified boundary is outside
that read, while a missing or corrupt boundary/suffix body still refuses.

The event-history part now costs O(decision suffix), not O(repository age), for
recent-cursor polling. This is a mechanism statement, not a measured latency or
throughput result. It does not by itself remove the node's admission-materializer
cost or implement the indexed O(limit) acceptance. Model-store regressions count
actual authority reads, compare every fixture cursor with full replay, and plant
missing/corrupt bodies and cancellation. They require native execution before
being cited as passing evidence.

## Thin node selection

Both `fg events` and the scoped HTTP/MCP feed now select directly from one
runtime-context-bound authority head read and its authenticated receipt. The
node checks the receipt's key/store binding, the decoded head's repository,
the requested head pin, and the immutable configuration's incarnation and
native object format. Configuration readers preserve supported historical
2.0/2.1/2.2 carriers without interpreting missing bytes as defaults.

The same selected configuration supplies hidden-ref policy. Its commitment is
checked before rules are applied, and any missing, corrupt, mismatched or
cancelled read refuses. A successful earlier request provides no cache fallback.
A policy-free supported configuration is distinct from an unresolved policy.
The event history reader receives the exact same head as the policy reader;
there is no second head lookup between them.

This path no longer materializes refs, Git-object closure, outcomes, retention
or the outbox. Those bodies are not event disclosure authorities. Event reads
still verify their own required decision and event bodies and retain current
cell readiness, request budgets, cancellation, caller grants and output bounds.
This is not a weakening of source publication or an alternative admission path.

Together the two changes bound recent polling by its decision suffix plus
configuration/policy reads, rather than adding a complete source/outbox replay.
Cold initial reads and uncached old-cursor backfills can still be O(history).
The disposable index below accelerates repeated reads of one already-verified
head. There is no long-poll or new canonical format. Cold node opening may have
other initialization costs. The bead remains open until its complete bounded
lookup, real-binary execution and independent verification acceptance is met.

Ten additional authored tests cover exact I/O selection, head pins, independent
repository/incarnation/format bindings, missing/corrupt/replayed configuration
and policy, cancellation at each I/O boundary, forged receipts, historical
configuration, and raw/scoped parity on reopened native SHA-1/SHA-256 nodes.
They have not been run in the toolchain-less editing environment.

## Reusing verified history metadata

The shared node reader used by CLI, HTTP and MCP can retain a
`VerifiedEventIndex` after a successful initial page. Construction uses the
existing authenticated history walk. Its private rows contain committed
repository sequences, transaction identities, policy epochs and event roots;
they contain no event text, credentials, hidden-ref rules or rendered pages.

Both canonical empty-event schemas are recognized by their exact commitments,
and each referenced empty body is verified once during construction. Empty
records are omitted from the searchable rows. A warm page binary-searches the
cursor and reads only its event batch plus the nonempty batches needed for the
page and lookahead. Both paths use the same payload reader, preserving content
commitments, cursor offsets, EOF verification, byte ceilings and cancellation.
The bound concerns event-batch reads, not measured latency or throughput.

`NodeConfig::with_event_history_index_cache_bytes` sets the retention allowance,
16 MiB by default; zero disables it. At most one exact-head index is retained,
shared with service children opened from cloned configuration. Scope includes
storage root, store instance, tenant, repository, incarnation and hash format.
Index capacity and scope overhead are charged. An active reader may retain its
immutable index after eviction; this is a custody allowance, not an RSS limit.
No cache lock spans storage I/O.

Every request authenticates its head and configuration, resolves hidden-ref
policy at that same head, and applies its own grants before disclosure. Missing
policy cannot fall back to an earlier successful read. Selected event bodies
are reread, including the cursor body at EOF, so cached coordinates cannot
conceal missing or corrupt selected payloads.

A changed head or scope misses. An initial read may rebuild; a cold resumed
cursor uses the existing suffix reader without populating optional metadata.
A conservative sequence-based preflight skips builds that cannot be guaranteed
to fit, before any history I/O. Other construction failures never supply a
page: fallback uses canonical reading with the same remaining request budget,
which may already have been partially consumed. Cancellation retains no partial
index. Fresh processes rebuild from canonical history; cursors do not depend
on cache lifetime.

Reference tests in `feed/history_tests/index.rs` compare full pages to canonical
replay and count actual store reads across history lengths, both empty schemas,
corruption, cancellation, stale bindings and memory bounds. Native tests in
`events/tests/cache.rs` cover both hash domains, reopen, discarded caches,
changed heads and per-request grants. These are authored tests, not a passing
execution claim. Persistent indexing, incremental maintenance across changed
heads and the full Bead acceptance remain open.

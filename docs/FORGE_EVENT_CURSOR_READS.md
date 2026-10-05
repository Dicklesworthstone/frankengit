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
Initial reads and old-cursor backfills can still be O(history); there is no
indexed O(limit) claim, long-poll or new canonical format. Cold node opening may
have other initialization costs. The bead remains open until indexed lookup,
real-binary execution and independent verification satisfy its acceptance.

Ten additional authored tests cover exact I/O selection, head pins, independent
repository/incarnation/format bindings, missing/corrupt/replayed configuration
and policy, cancellation at each I/O boundary, forged receipts, historical
configuration, and raw/scoped parity on reopened native SHA-1/SHA-256 nodes.
They have not been run in the toolchain-less editing environment.

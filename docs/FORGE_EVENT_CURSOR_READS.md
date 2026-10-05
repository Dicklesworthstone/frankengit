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


# Durable custody of workflow check proposals

FG-095b now has an explicit custody handoff and a Unix private-file journal.
These are local execution infrastructure, **not canonical forge publication**.
They do not replace the existing authority-selected forge outbox. A journal
receipt is not permission to merge, a required check, or proof of isolation.

## The two custody boundaries

`WorkflowCoordinator::prepare_check_delivery` freezes a bounded, one-run prefix
without removing facts. `deliver_check_facts` calls an operator-configured
`CheckDeliverySink` and settles only after that sink acknowledges the exact
batch. Failed or ambiguous submissions retain the pending prefix. Duplicate,
wrong, or stale acknowledgements cannot remove unrelated facts. Cancellation
before submission performs no handoff; once custody is durably accepted, local
settlement completes even if cancellation has arrived.

A batch binds tenant, repository, run/attempt, native source commit, authority
basis, workflow graph, trust partition, execution profile and exact facts.
Trusted-workflow success/skips remain `ActionRequired`; decoding rejects their
promotion to `Success` or `Neutral`. Bounded decoding checks framing and
integrity, not producer authorization or truth of the evidence references.

The old `drain_check_facts` remains a compatibility-only in-memory transfer:
its caller owns every returned fact. It does not guarantee restart safety.
Do not mix that method with journaling the same run; missing earlier phases
are refused rather than invented during replay.

## Journal integration

`fgit_runner::coordinator::delivery::journal` is available on Unix. The operator
creates a stable private parent directory and supplies a `CheckJournalScope`
with tenant/repository and a unique, independently retained journal-instance
commitment. `FileCheckJournal::create` creates one new 0600 regular file without
overwriting an existing path. It holds an OS advisory exclusive lock, syncs
the header and its parent directory, and refuses symlinks, multiply-linked
files, or group/world-accessible files and immediate parent directories.
Stable operator-controlled paths are a precondition, not a hostile-host claim.

Use `WorkflowCoordinator::journal_check_facts` for custody transfer. It persists
actual referenced evidence **before** the proposal, then acknowledges the
exact coordinator prefix only after the append is synchronized. Command-only
receipts are taken from retained runner receipts and their evidence is verified.
For trusted workflows, pass the matching `PreparedTrustedWorkflow::receipt()`;
`TrustedWorkflowReceipt::job_frame` supplies the unchanged bytes underlying
`job_commitment`. Missing, oversized or mismatched evidence refuses the handoff.
Evidence already persisted during a refused/cancelled attempt is reusable.

For one repository and one trusted prepared run, the essential call is:

```rust,ignore
while coordinator.pending_check_fact_count() != 0 {
    coordinator.journal_check_facts(
        &mut journal,
        MAX_BATCH_FACTS,
        MAX_BATCH_BYTES,
        prepared.receipt(), // None for the command-only path
        &live,
    )?;
}
```

A multi-repository coordinator must choose the journal matching the next batch;
one batch never crosses a run or repository. The matching trusted receipt is
needed for whichever run owns that prefix. The live predicate belongs to the
request/runtime; this API does not spawn a worker or renew a budget.

## Restart and downstream delivery

`FileCheckJournal::open` requires the existing file and exact scope. It scans
one known file, validates the chained records and per-job phase transitions,
and reconstructs bounded indexes of record locations. It does not require the
original coordinator or prepared handles to read retained batches/evidence.
It refuses torn tails, corrupt records, unknown tags, reordered/overlapping
phases, duplicate physical records, missing evidence and conflicting bindings.
It never truncates a damaged tail, silently recreates a journal, or reruns jobs.
A complete append whose response was lost is synchronized on reopen and reused.

`next_batch` returns the oldest pending batch without removing it, rechecking
its record and every referenced evidence body. `read_evidence` retrieves those
bytes for a downstream adapter. `forward_next` performs one submission to an
explicit `CheckDeliverySink`, then synchronizes a FIFO delivery acknowledgement.
The downstream sink must durably deduplicate exact batch identities. Supply
its required evidence using `read_evidence` before submission; the sink trait
carries proposal metadata, not an implicit evidence-upload transport.

An uncertain downstream result leaves the batch pending. A retry resends the
same bytes and id. Exact repeated delivery acknowledgements are harmless;
conflicting receipt roots and out-of-order acknowledgements are refused.
An accepted batch is deduplicated even after delivery; no tombstone is expired
implicitly. Regrouping a failed submission under different batch limits is a
conflicting retry: retain/reconcile the original batch and acknowledgement.

## Durability, integrity and resource profile

The file has a scope-bound header and length-delimited, SHA-256 chained records
for evidence, proposal acceptance and downstream acknowledgement. Appends are
acknowledged only after `sync_all`. Any potentially mutating I/O error or unwind
poisons that journal object; reopen must resolve its state before further work.
Readback detects damaged retained evidence before forwarding a valid proposal.

Persist `journal.pin()` independently when anti-rollback is required and supply
it as the minimum on reopen. The exact length/tail must occur in the verified
history. Without an external witness, a valid older prefix is indistinguishable
from a genuinely older journal. The journal-instance id is not a repository
incarnation id or an alternate authority root.

Defaults are 256 MiB total, 65,536 records including history, and 64 MiB per
evidence body. Hard ceilings are 4 GiB, 1,000,000 records and 64 MiB respectively.
Proposal batches remain bounded to 128 facts / 1 MiB. Index memory is bounded
by record count; evidence is retained on disk and read one bounded record at a
time. Capacity reserves one acknowledgement record per pending batch, so
accepted responsibility can settle even when new submissions are refused.
There is no automatic rotation, compaction, retention expiry or evidence GC.

Synchronous filesystem calls have bounded byte/record envelopes, not hard I/O
latency bounds. The owning runtime must choose an appropriate blocking context;
recovery checks cancellation between records. File locks are advisory. Hostile
same-UID mutation, compromised producers, lying filesystems, loss of an entire
journal volume, and independently verified power-loss durability are not covered.

## Remaining work and verification

A coordinator crash before explicit journal acceptance can still lose work
that only existed in memory. This is not a durable scheduler or process-reaping
journal. Canonical check admission/publication, producer authorization,
current-source/current-policy validation, evidence interpretation and actual
hostile-code isolation remain separate required work. No local receipt alone
can authorize a protected-ref transition.

`delivery/tests.rs` covers bounded handoff, failure/unwind/cancellation and
native-domain/profile framing. `delivery/journal/tests.rs` covers actual private
files, restart without coordinator handles, lost-response deduplication, evidence
custody, FIFO acknowledgements, corruption/truncation/rollback refusal, reserved
capacity, lock/path exclusion, fragmented I/O and sync failures. Fixtures are
labelled; their presence does not claim canonical publication or containment.
The SHA-256 header/frame goldens were independently derived in Python.

These Rust tests have not been compiled or executed in the editing environment
because Cargo/rustc are unavailable. Independent Python framing, torn-prefix,
corruption, rollback-witness, reserve arithmetic and POSIX file-operation checks
passed; they do not establish Rust correctness, native conformance or RPO/RTO.

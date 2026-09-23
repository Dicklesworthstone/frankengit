# Durable local workflow attempt ownership

FG-095b's `execute_trusted_workflow_durable` adds a synced execution-start
record around [journaled job execution](JOURNALED_WORKFLOW_EXECUTION.md).
It closes the local restart window in which a new coordinator could otherwise
rerun work whose terminal observation had not reached durable custody.
It does **not** claim exactly-once external side effects, a distributed
scheduler, canonical check publication, or hostile-code isolation.

## State and ownership

`fgit_runner::coordinator::delivery::journal::attempt` exports
`FileWorkflowAttempt`, `WorkflowAttemptBinding`, `WorkflowAttemptPin`,
`WorkflowAttemptStatus`, `WorkflowAttemptRefusal`, and `RecordedWorkflowReceipt`.

The lifecycle is `Prepared -> Started -> Completed`. The caller must select
one stable owner path for the logical attempt, retain it across retries, and
hold both the owner and custody-journal descriptors throughout execution.
`create` uses an exclusive new private regular file; it never adopts an old
path. `open` requires an existing exact identity and never recreates a missing
file, repairs a torn tail, or clears a prior start. Both use the same private
path checks and OS advisory exclusive-lock profile as `FileCheckJournal`.
Header creation and adoption synchronize the file and its parent directory.

`WorkflowCoordinator::trusted_attempt_binding` derives the expected binding
from the prepared compiled plan and the configured `CheckJournalScope`.
The binding includes repository and journal instance, native source domain,
authority basis, workflow source and semantic graph, run/attempt identity,
trust partition, actor, trigger/idempotency parameters, concurrency intent,
exact effective limits, and logical execution time. Keep the original logical
execution time for every retry; it is part of the observation identity.
The configured journal identity is local ownership, not repository authority.

Pass the owner alongside the journal to
`WorkflowCoordinator::execute_trusted_workflow_durable`. Before execution it
checks the prepared identity, existing pending-run prefix, readiness, caller
liveness, and conservative journal capacity. Initial queued proposals are
persisted first. A `Started` record referencing that journal checkpoint is
then appended and synchronized **before the first executor callback**.

Each completed job still persists its exact normalized evidence and proposals
after cleanup and before the next job starts. Finally the owner synchronizes
the full existing local observation frame and the final journal checkpoint.
Its separate retention flag is derived from the private typed receipt, not an
independent caller assertion. The result is read back before returning.
No new canonical repository schema, dependency, runtime, or implicit secret is
introduced. Existing local observation and check-journal bytes are unchanged.

## Restart behavior

A valid `Prepared` owner has no recorded execution start. It can proceed only
through the same admission, exact queued-prefix, and capacity checks. A retry
must reproduce its original accepted input and queue timestamps; a conflicting
proposal partition is refused rather than invented or silently regrouped.

A `Started` owner with no retained full in-process receipt returns
`ReconciliationRequired`. No user work is run, even when the OS lock has become
available after process exit. A fresh coordinator records an unresolved scope
responsibility and blocks independent jobs too. This is a containment hold,
not proof that the prior job or its descendants were reaped. Host/runtime
reconciliation is required; there is no automatic force/retry/reset operation.

A `Completed` owner returns the saved immutable local observation without
executing jobs or appending another terminal record. The integration checks
that both the start and completion journal pins are actual retained prefixes,
not merely smaller byte lengths. Later downstream acknowledgements are allowed;
a recreated journal, a rolled-back prefix, or a different tail is refused.
The archived result can be returned even when a new caller is cancelled,
because lookup does not launch work. An in-process retained full receipt can
also finish a `Started` owner after a lost final write response, without reruns;
an uncertain file object must first be reopened and verified.

`RecordedWorkflowReceipt` is deliberately an immutable frame plus binding,
journal pin, and containment requirement. It is **not** a decoded scheduler
snapshot, `CheckReceipt`, or protected-ref green check. Reconstructed prepared
handles are fenced from execution, not marked successful by parsing an opaque
archived result. Their newly generated in-memory queue facts are not replayed
into the journal or treated as restored scheduler state. A recovered retention
requirement keeps the coordinator blocked until host reconciliation.
Standalone `completed_receipt` verifies the owner file; a caller using it
outside the coordinator must also verify the referenced custody checkpoint.

## Failure and resource profile

The `FGWA0001` header is 168 bytes. At most two length-delimited SHA-256-chained
records follow: a 41-byte start payload and a completion payload with a bounded
local observation. Completion bytes are limited to 64 MiB. Readers check
lengths before allocation and refuse duplicate, unknown, reordered, corrupt,
trailing, or partial records. Uncertain mutating I/O poisons the owner object;
reopen resolves only valid complete records, without truncating evidence.

Before starting, the integration conservatively budgets the entire workflow's
encoded output, metadata, per-job journal records and downstream acknowledgement
reserves. It holds exclusive mutable access to the journal while executing.
This can refuse a configuration that might have fit smaller actual output;
refusal before work is preferable to consuming settlement space knowingly.
Actual device exhaustion, failed sync, or unbounded I/O latency remain possible.
A later persistence failure stops further work and leaves a recorded start
unresolved instead of issuing a durable-success claim.

Retain `owner.pin()` independently when rollback detection is required, and
pass it as the minimum to `open`. A checksum-valid older Prepared prefix cannot
be distinguished from an original Prepared owner without an external witness.
The same rule applies to the custody journal. Stable private operator paths,
a trusted producer and honest filesystem synchronization are preconditions.
Different owner paths, deleted files, bypassing the durable API, mixed old/new
execution paths, hostile same-UID mutation, or total volume loss are not fenced
by an advisory local file lock. The owning runtime still chooses the blocking
context and supplies current source/policy checks through `live`.

## Tests and unfinished scope

Twenty added Rust regressions cover independent framing goldens, owner locks,
wrong identities, file kinds, every torn nonboundary prefix, corrupt readback,
minimum-pin rollback, capacity refusal, lost completion responses, fresh
coordinator replay, uncertain starts, retained containment, checkpoint ancestry,
changed inputs, and a Linux trusted-shell side-effect/reopen case. Together
with the ten journaled-execution tests, this change sequence adds thirty tests.
They are authored but have **not** been compiled or executed in the editing
environment: Cargo and rustc are unavailable.

Independent Python reference checks passed for 339 prefixes, 338 one-byte
corruptions, phase closure, rollback witnesses, duplicate-terminal refusal,
and actual cross-process POSIX lock/fsync/reopen/no-overwrite operations.
These are format/filesystem reference checks, not Rust integration results,
a hostile sandbox test, a power-loss campaign, or an RPO/RTO guarantee.

The exact queued source inputs still must be supplied by the caller; the owner
stores commitments, not a durable job queue or full scheduler projection.
Automatic recovery/reconciliation of interrupted execution, distributed owner
fencing, canonical check admission/publication, and registered hostile-code
isolation remain unfinished. Local trusted success remains `ActionRequired`.

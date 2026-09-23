# Journaled trusted workflow execution

FG-095b's `WorkflowCoordinator::execute_trusted_workflow_journaled` composes
trusted multi-step execution with `FileCheckJournal` on Unix. It persists the
initial queued proposals before opening the first job scope. After each job's
cleanup, it persists the exact normalized per-job evidence and proposal pair
before the next job may start. The per-job bytes and check conclusions are
unchanged; local successes remain `ActionRequired`, not protected-ref checks.

Supply the same explicit compiled prepared handle and source-scoped executor
used by `execute_trusted_workflow`, plus an already open, repository-scoped
journal. The operator owns stable private paths. All currently pending facts
must belong to this run; unrelated prefixes and foreign journal scopes are
refused without consuming them. No new threads, runtime, dependencies,
canonical repository schemas, or implicit secrets are introduced.

Initial cancellation refuses before any journal transfer or user work. Once a
job has completed, persistence is part of bounded non-cancellable drain; a
cancelled caller does not discard its terminal result. Job cleanup still runs
before persistence. An I/O, capacity, or evidence failure stops subsequent
user work, retains unsettled proposals in memory and holds the run. Earlier
accepted job results remain recoverable from the journal without the original
coordinator. Later jobs are cancelled without opening their scopes. A failed
handoff never yields a successful complete-workflow receipt.

A completed repeated call flushes any remaining matching facts and returns
its original observation without repeating execution or appending duplicate
journal records. An interrupted call with no retained full observation is not
retried by this coordinator. The old non-journaled execution API retains its
behavior through a no-op custody callback.

**This method alone does not fence execution across process loss.** The journal
retains proposals and evidence; its queued facts are not an execution lease.
A new coordinator must not infer permission to rerun a job from an incomplete
proposal stream. A durable attempt owner is required for that boundary.
Canonical check admission, current-source/policy validation, hostile isolation,
and a distributed scheduler remain separate work. Disk calls are byte-bounded,
not a guarantee of hard I/O latency; the owning runtime chooses the blocking
context and the supplied executor must bound cleanup.

The ten new regression tests exercise real private-file reopen/evidence
retrieval, per-job persistence ordering, capacity failures before and after
work, cancelled drain, exact repeat calls, scope/prefix fences, retained
containment, and persistence callback failure/unwind. Executors are explicitly
control-flow fixtures, not containment proofs. Rust compilation and tests were
not run in the editing environment because Cargo/rustc were unavailable.

For a synced start fence and completed-result lookup across restart, use the
explicit [durable attempt owner](DURABLE_WORKFLOW_ATTEMPTS.md) and
`execute_trusted_workflow_durable`. The journaled-only API remains unchanged.

## Per-job launch-fenced alternative

`WorkflowCoordinator::execute_journaled_trusted_workflow` adds an explicit
alternative that synchronizes an InProgress proposal before every job scope.
It uses the same interpreter and custody journal, not another scheduler. It
fences recreated handles against retained attempted history and permits a
surviving process to finish result persistence without executing commands again.
It never promotes a local observation to a canonical check.

The original volatile and per-job journaled paths above remain available. The
separate `execute_trusted_workflow_durable` API and its attempt-owner file also
remain supported for whole-run start ownership and archived-result lookup;
see [DURABLE_WORKFLOW_ATTEMPTS.md](DURABLE_WORKFLOW_ATTEMPTS.md). Choose the
execution profile explicitly before starting a prepared handle. The per-job
launch-fenced path cannot be switched to another profile after selection.

### Ordering and custody

Compile and enqueue a trusted plan as described in
[WORKFLOW_COORDINATOR_EXECUTION.md](WORKFLOW_COORDINATOR_EXECUTION.md). Supply a
created/reopened, scope-matched journal and the same live source/policy predicate
when executing. The coordinator's pending proposals must belong to this run;
flush unrelated runs explicitly beforehand. This API never silently hands off
another run's evidence or chooses a journal on its behalf.

```rust,ignore
let receipt = coordinator.execute_journaled_trusted_workflow(
    &mut prepared,
    &mut source_scoped_executor,
    &mut journal,
    logical_now,
    &live,
)?;
// This is a locally retained observation, not a green check or a merge grant.
let observed_success = receipt.report().succeeded();
```

The execution sequence is:

1. Persist and acknowledge the Queued proposals before attempting user work.
2. Persist the exact InProgress proposal before opening each executor scope.
3. Run the existing job interpreter and finish its cleanup.
4. Persist the exact normalized per-job evidence and Completed proposal before
   the next job or optional observer callback can execute. No later observer
   notifications escape after a custody failure.

A failed launch barrier opens no scope. A failed result barrier stops subsequent
jobs, still lets the interpreter account for their cancellation, and preserves
its normalized report in the prepared handle. The method refuses to return a
durable receipt until every per-job terminal proposal and evidence body has
been read back from the journal. A successful return can describe a failed,
cancelled, timed-out or containment-failed workflow: inspect the report and
coordinator obligations. Local success/skips still propose ActionRequired.

The adapter uses **one fact per batch** throughout. This is deliberate: a
complete append followed by a lost acknowledgement must be retried under the
same partition even if later cancellation facts have joined the pending queue.
Existing journal record formats and evidence bytes do not change.

### Retry and interruption

A prepared handle pins its custody profile before the first journal I/O. It
cannot fall back to the volatile executor after a failed append, switch to a
different journal instance, or retroactively relabel a volatile execution as
launch-journaled. A fresh journal with no retained terminal records cannot
certify an old in-memory receipt even when its operator-supplied scope matches.

After a result-custody error in a surviving process, reopen the same journal as
necessary and retry with the original coordinator and prepared handle. A retained
receipt is reused; commands and observer callbacks do not execute again. The
pending evidence/proposals are settled under the original fixed batch identities.
A larger independently chosen storage envelope can resolve a configured
capacity refusal, but damaged/torn storage is still refused without repair.

After process restart, a recreated handle is refused with Custody(StaleBatch)
when the journal contains any phase beyond Queued for that run. This includes
history already acknowledged downstream: an empty delivery queue is not proof
of non-execution. A known InProgress phase for another run in this single-owner
journal also blocks new execution with Custody(OutOfOrder).

**InProgress means may have started.** A crash between its sync and executor
begin is indistinguishable from one after launch. This API does not guess which
occurred, rerun interrupted jobs, reconstruct arbitrary workflows from hashes,
or assert that old processes were reaped. Use the retained proposals/evidence
for recovery and have the owning host/runtime reconcile uncertain containment.
Queued-only history is not a portable scheduler checkpoint; exact identity,
ordinal, source/policy and FIFO checks still apply to a supplied prepared plan.

### Scope and limits

Only the trusted job-scoped path is integrated. The source-scoped executor
continues to own source verification, workspaces, process isolation and cleanup.
Fork execution remains refused. No secrets or transport endpoints are inferred
from repository text. Canonical check publication remains separate.

Work cancellation is observed by the existing interpreter. Once a job produces
an observation, its bounded local result handoff still runs rather than dropping
that responsibility because the work predicate became false. The finite graph
bounds handoff iterations; journal byte/record/evidence limits still apply.
Filesystem calls are synchronous, not hard-latency-bounded. The owning runtime
must supply the appropriate blocking context and a cleanup/I/O budget.

A launch intent may survive while its result is missing because of process exit,
I/O failure or capacity exhaustion. It then fences replay; it does not promise
recovery of output never persisted. Retained scopes and completed observations
are different: a terminal proposal is not an OS containment acknowledgement.
The host must independently reconcile retained scopes before resuming work.

Stable private paths, advisory locks, independently retained journal instance
identity/minimum pins, and storage durability assumptions are unchanged; see
[WORKFLOW_CHECK_DELIVERY.md](WORKFLOW_CHECK_DELIVERY.md). Recreating or rolling
back the journal, losing its volume, hostile same-UID writers, and using another
unfenced execution path are outside this profile. No once-only or power-loss
conformance claim follows from this adapter.

### Verification

`coordinator/delivery/journal/execution/tests.rs` covers launch/result ordering,
capacity failures, fixed-partition custody retry, retained result readback,
observer unwind, cancellation, mode/scope fences, acknowledged-history replay,
and a separate process-exit/OS-lock recovery case. Most execution is explicitly
fixture-backed; the process-exit helper tests lost process memory, not a hostile
sandbox or canonical admission. These Rust tests require the pinned toolchain.


### Validation status for the launch-fenced change

This patch was prepared against `e064bea72215ad5778e98327adf0938e26979adb`
and reconciled with `daa87647f1f262d1601c4c7d54118bfdbd8506e2`. The existing
per-job journal callback, durable attempt owner and their public entry points
are preserved. There are 18 new Rust regression cases and one subprocess helper.
Cargo and rustc are unavailable in the editing environment: these Rust tests
have not been compiled or executed. Independent Python state/record-boundary
models, POSIX file-lock/process-exit checks, lexical checks and exact Git blob
comparisons are supporting checks, not Rust or full-system conformance evidence.

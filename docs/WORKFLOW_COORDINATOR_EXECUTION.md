# Workflow coordinator execution profiles

FG-095b has two explicit library execution paths. Neither is a complete CI
service, a durable coordinator journal, or canonical forge publication.

## Command-only path

`WorkflowCoordinator::enqueue_run` preflights every job for
`coordinator-command-only-v1`. `execute_job` uses the existing input-capsule and
runner control-plane boundary. It accepts one exactly representable argv
command per job; it does not approximate scripts or multi-step workflows.

## Trusted job-scoped path

Compile source with `fgit_runner::workflow::WorkflowPlan::compile`, then pass
the immutable plan and `WorkflowLimits` to
`WorkflowCoordinator::enqueue_trusted_workflow`. The returned
`PreparedTrustedWorkflow` binds one run, source document, semantic graph,
trust partition, and effective resource profile. Enqueue takes the intersection
of requested run/step deadlines and coordinator ceilings; `limits()` exposes
that exact admitted profile. Compilation covers the entire plan before queue
state or check proposals change. Fork requests are refused before admission.

`execute_trusted_workflow` takes that prepared handle, a `WorkflowExecutor`, a
logical observation time, and a cooperative `live` predicate. It reuses
`WorkflowPlan::execute` for all script and condition semantics. The executor
must be explicitly authorized for trusted work and must own verified source
selection, its job workspaces, and cleanup. A graph or runner label is not an
OS isolation boundary. The supplied predicate must include request cancellation
and any required current-source/current-policy checks.

Execution is serial and follows the compiled dependency order. Each job opens
one scope; its steps share that workspace, with exact script bytes and
`success()`, `failure()`, and `always()` step predicates. Ordinary failure stays
failed after diagnostic steps. Dependent jobs do not start before cleanup.
One run-wide output budget and deadline cover every job, rather than resetting
at job boundaries. `WorkflowExecutor::observe_job` is called once per normalized
job result, after cleanup or a no-execution skip/refusal, before the next job.
It is a derived scheduling notification, not a publication acknowledgement.

The prepared handle cannot switch to the command-only path. Completed repeat
calls return its retained observation without launching work or emitting facts
again. An attempted invocation without a terminal observation is not retried
implicitly. These are in-memory guarantees; a new process does not inherit a
journal, a containment acknowledgement, or a once-only execution guarantee.

## Observations and checks are different

`TrustedWorkflowReceipt` is deliberately not `CheckReceipt`. Its versioned
local frame binds the tenant/repository, selected head and native commit,
run/attempt identity, trust domain, exact workflow source and graph, full
precision time limits, attempts, normalized outcomes, retained output, and
cleanup flags. Per-job commitments can be reproduced with `job_commitment`.
`ActiveRun::job_outputs` retains bounded step observations; `job_receipts`
is not populated with fabricated runner receipts.

Successful and skipped trusted jobs emit `ActionRequired`, never `Success` or
`Neutral`, as their check conclusion. Independent verified check admission and
canonical publication are still needed for a protected ref. Existing check
fact draining remains an in-memory handoff, not proof of durable publication.
The local report is useful execution evidence but cannot certify a sandbox,
secret policy, CPU/memory accounting, source correctness, or a canonical merge.

## Cancellation and containment

A worker cancellation stops later jobs even when the external predicate still
returns true. Cleanup is not skipped, and cancellation/deadline is checked
again after cleanup before a successful observation can escape. Output clamping
cannot conceal explicit containment failure. Forced-stop reasons remain typed
as cancelled/timed-out/output-limited alongside the retention requirement.

A retained scope or uncertain cleanup leaves `workflow_scopes_opened` greater
than `workflow_scopes_closed`. No later work may use that coordinator while the
responsibility is unresolved, including after recording a terminal containment
failure. On unwind, the bridge attempts `finish_job(true)` when a scope might
remain open, returns a typed containment failure, and does not invent a clean
settlement or rerun the attempt. Process-abort recovery and reconciliation of a
retained scope still need the owning runtime/host and durable coordinator work.
Deadlines are cooperative; the supplied executor must bound its own cleanup.
Retained-output limits are not OS disk quotas. No secrets are implicitly issued.

## Regression coverage

`workflow/settlement_tests.rs` covers outcome precedence, cancellation during
cleanup, terminal notifications and ordinary failure controls.
`coordinator/scoped_workflow/tests.rs` covers retained forced stops, multi-step scopes,
dependency/failure predicates, shared budgets, duplicate-call observations,
profile/trust fences, FIFO groups, panic/containment holds and receipt identity.
The Linux `tests/live.rs` case uses the existing `run_trusted_step` implementation
with private file-backed capture to write/read a file across steps and verify
that a dependent job receives a fresh workspace. It is a trusted-process test,
not a hostile isolation or native-repository admission test.

These tests require execution with the repository's pinned Rust toolchain.
Their presence is not a batch-verification result.

# Supervise execution and publication across selected branches

`node scripts/fg_workflow_supervisor.mjs` connects the existing branch watcher
and workflow-check publisher into one bounded, restartable operator. Each lane
selects exactly one repository branch and its original publisher principal.
The controller drains prior publications, executes the selected branch through
the Rust watcher path, and publishes its completed observations. A workflow
failure still reaches the publisher; an unrelated lane can continue.

This is an **external trusted-local Linux operator**, not a native executor,
forge database, sandbox or second publication authority. Node.js 22+ and the
native `fg` executable are required. Every selected revision executes with the
operator account's host privileges. Do not select untrusted branches. Native
trusted-local successes still publish `action_required`, not protected-merge
success. This does not close the required-check authority decision.

## Configuration

Use a private 0600 JSON file with this envelope:

```json
{
  "schema": "frankengit-workflow-supervisor-v1",
  "state_directory": "/srv/ci/supervisor",
  "lanes": [
    {
      "name": "main",
      "publisher": {
        "schema": "frankengit-workflow-check-publisher-v1",
        "watch": {},
        "state_directory": "/srv/ci/main-publication",
        "principal_id": "55555555555555555555555555555555"
      }
    }
  ]
}
```

Replace `watch: {}` with the **complete existing watcher configuration** described
in [TRUSTED_WORKFLOW_WATCH.md](TRUSTED_WORKFLOW_WATCH.md). Replace the example
principal with the original actor selected for native trusted-local publication,
as described in [TRUSTED_WORKFLOW_CHECK_AUTOMATION.md](TRUSTED_WORKFLOW_CHECK_AUTOMATION.md).
This deliberately embeds rather than follows a mutable watch-config pathname.
No implicit branch discovery, principal selection or execution permission exists.

Configure 1–64 lanes with unique lowercase names. Two lanes cannot select the
same store/tenant/repository/ref. Every lane needs separate watcher, run-parent
and publisher directories; all must be disjoint from the supervisor directory,
other lanes' custody, every store and every executable. Different lanes may
share the exact native storage root. Create custody directories as owner-private
0700 directories before starting. The original watcher and publisher enforce
all their existing native-scope, input-selection and immutable journal rules.

```sh
node scripts/fg_workflow_supervisor.mjs once \
  --config /srv/ci/supervisor.json --trusted-local

node scripts/fg_workflow_supervisor.mjs status \
  --config /srv/ci/supervisor.json
```

`once` admits lanes in name order, subject to native-store availability. `status` is read-only and summarizes native
custody instead of copying every historical run. Exit codes are 0 for a settled
pass, 1 for a reported failure/refusal, and 2 for pending or stopped work. A zero
exit code is not a statement that a protected merge is authorized. Publication
counts are historical observations, not a current-branch success verdict.

Budgets can be reduced with `--max-publications` (1–128 per publisher pass),
`--read-timeout-ms` (1–30000), `--dispatch-timeout-ms` (1–660000), and
`--publication-timeout-ms` (1–660000). Each lane has at most two publisher passes
and one watcher pass. `--concurrency` (1–16, default 1) permits independent native
stores to progress in parallel; all lanes sharing a store remain serialized
through both publication passes and execution. A pending or budget-limited pre-publication pass prevents
new execution on that lane; it does not prevent processing another lane.

## Continuous service and bounded parallelism

```sh
node scripts/fg_workflow_supervisor.mjs serve \
  --config /srv/ci/supervisor.json --trusted-local \
  --concurrency 4 --interval-ms 5000

# A bounded run for an external scheduler or a supervised smoke check:
node scripts/fg_workflow_supervisor.mjs serve \
  --config /srv/ci/supervisor.json --trusted-local \
  --concurrency 2 --interval-ms 1000 --max-cycles 3
```

`serve` holds one supervisor owner for the entire service, including the polling
wait and report delivery. It performs complete bounded cycles with a fixed delay
between them, not overlapping timer callbacks. `--interval-ms` accepts 1–3600000
(default 5000); `--max-cycles` accepts 0–1000000 (default 0, run until stopped).
The first admission position rotates each cycle so a fixed lane-name ordering
does not always get priority. A busy store does not prevent admission of a later
lane using an independent store. Each cycle drains all admitted operations
before beginning the next cycle. Sharing a store therefore does not introduce
parallel mutation of the same native publication owner.

The original watcher still decides whether a selected commit is new or already
observed. Polling an unchanged revision returns its native idle observation;
the supervisor does not invent execution retries or new run identities.

A lane that throws an execution/publication error, or reports an unknown
publication, is quarantined for the remainder of that service invocation.
Healthy lanes continue; the affected lane is reported as `recovery_required`.
When every lane is quarantined, the service exits rather than polling forever.
Native custody survives process restart and remains the authority for explicit
recovery. Restarting is not a way to clear uncertain work or bypass child locks.
Ordinary, safely observed workflow failures are still published and do not
quarantine the lane. Known publication-budget backpressure can clear on a later
cycle without automatically resuming an uncertain request.

Each completed cycle emits one bounded JSON line. A final
`workflow_supervisor_service` record contains the cycle count, latest per-lane
observations, quarantined lane names and a failure flag that remains set if any
cycle failed. In-memory service state is bounded by the selected lane count,
not elapsed service time. JSON output is capped at 1 MiB per record. Reporting
waits for the stream's write callback; a stalled reader stops the service after
a 30-second reporting deadline instead of accumulating unbounded output or
starting more executions without reporting the prior cycle.

SIGINT/SIGTERM interrupts the polling wait and stops new native admissions while
already admitted owners drain. If a lane reports unknown containment, no later
execution or publication stage is admitted on any lane; operations already
admitted on independent stores are drained before the supervisor returns.
The supervisor retains its own containment fence even if reporting then fails.

## Custody, interruption and recovery

The supervisor keeps only an immutable configuration binding and its owner lock.
The watcher and publisher retain the original run identities, start records,
native evidence, publication keys and outcomes. Restarting the supervisor never
manufactures a new run namespace, removes history, passes `resume`, or changes
an uncertain request into a successful one. Reordering lane definitions is safe;
changing a bound branch, principal or path is rejected before native work.

One supervisor owner spans the entire pass or continuous service. SIGINT/SIGTERM stops admission of
new work and lets the existing native owner drain the active operation. If that
operation cannot establish containment, the supervisor retains its own lock,
stops subsequent lanes and leaves every child operator's custody intact. No
stale lock is deleted automatically. Inspect native custody and use the existing
watcher reconciliation or publisher recovery tools explicitly; a check outcome
receipt does not prove that a native process was reaped.

Changing the lane set requires stopping the old supervisor and selecting a new,
empty supervisor directory while retaining the original lane directories and
configuration. Do not run a second watcher or publisher service for the same
lane: the existing child locks reject competing ownership, not coordinate it.

## Tests

```sh
node --test scripts/fg_workflow_supervisor*.test.mjs
```

These deterministic tests use the production POSIX custody implementation with
an injected watcher/publisher boundary. They test orchestration, branch isolation,
backpressure, cancellation, custody fencing, bounded parallel scheduling,
service quarantine, reporting backpressure and CLI validation. They do not
replace the existing native workflow execution/publication integration gates.

# Supervisor reconciliation of completed native runs

`fg_workflow_supervisor.mjs reconcile` recovers missing watcher completion
summaries across all configured lanes using their original saved native dispatch
reports. It uses the production watcher validator, not a new execution engine or
an alternative source of canonical repository truth.

```sh
node scripts/fg_workflow_supervisor.mjs reconcile \
  --config /srv/ci-supervisor.json --trusted-local --read-timeout-ms 30000
```

The original supervisor binding must already exist and match exactly. The command
accepts no execution, publication, concurrency, polling or retry options. One
cooperative read deadline covers every lane; it is not restarted per report or
per lane. Cancellation is checked before filesystem work and between bounded
custody records, report validation and immutable summary publication. Filesystem
system calls themselves are not preempted. The default and maximum shared
supervisor reconciliation budget are 30 seconds.

## What can change

Only a previously missing watcher terminal summary may be installed, and only
when the original saved dispatch report validates at the original source,
incarnation, run, graph and execution coordinates. Existing summaries, report
bytes, publication plans, transaction keys and check evidence are not rewritten.
Historical conditional-completion meanings stay supported without upgrading an
old failed observation to success. Repeating reconciliation is idempotent.

No workflow is compiled or executed; no new branch tip is read; no publication
is submitted; no existing publication is retried. The native executable, source
checkout and repository storage can all be unavailable. Original operator
bindings, attempt directories and complete dispatch reports must remain intact.
Publisher status reports only its retained local custody, not a new authority
lookup. Missing, incomplete, corrupt or containment-unproved reports remain
unresolved, rather than permitting an execution replay.

## Locks and partial results

Retained supervisor, watcher, publication and recovery owner locks are reported,
never removed or stolen. A completed report does not establish that a killed
supervisor's remaining processes have been independently reconciled. A retained
owner therefore keeps the aggregate result pending even after its completed
watcher summary is recovered. Normal execution still refuses that owner lock.

Each lane carries its recovered watcher status and retained publication status,
or an explicit error. A corrupt lane does not hide a different valid lane.
Cancellation or an exhausted deadline prevents starting more reads. Results
already installed before a late error remain recoverable; an error is not proof
that no local summary was written. There is no all-lanes atomic transaction.

The CLI emits `workflow_supervisor_reconciliation` with `execution_retried`,
`publication_submitted`, `locks_removed` and `authoritative_check` all false.
Exit 0 means local reconciliation is settled, 1 reports a lane error or retained
publication refusal, and 2 means pending ownership/work or cancellation without
another error. A settled observation does not grant a protected merge. After
independent process/owner reconciliation, the ordinary `once`/`serve` path can
continue using its original execution and publication identities.

## Verification

`tests/operator/workflow_supervisor_reconcile.test.mjs` uses explicit backend
fixtures for orchestration, original-binding refusal, cancellation, deadline
sharing, owner retention and command argument tests. It does not claim native
execution or canonical publication evidence.

The discovered `scripts/e2e/suites/workflow/supervisor_loop.sh` suite takes a
prebuilt native `FG_BIN`. It creates real SHA-1 and SHA-256 repositories, advances
refs through native expected-tip updates, and drives the real supervisor,
watcher, Rust workflow runner, proposal recovery and canonical check publisher.
It exercises conditional matrices, failed-job propagation, publication
backpressure, exact historical publication recovery and repeated idle cycles.
It also terminates its own supervisor with SIGKILL after a native workflow starts,
waits for that finite native execution to finish, removes access to the native
binary and source/storage paths, and reconciles the retained report without
rerunning or publishing any job or clearing any owner lock. It does not claim
physical power-loss behavior, hostile execution isolation, PID-reuse stress,
automatic lock repair or full-workspace verification.

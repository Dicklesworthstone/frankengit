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

`once` visits lanes in name order. `status` is read-only and summarizes native
custody instead of copying every historical run. Exit codes are 0 for a settled
pass, 1 for a reported failure/refusal, and 2 for pending or stopped work. A zero
exit code is not a statement that a protected merge is authorized. Publication
counts are historical observations, not a current-branch success verdict.

Budgets can be reduced with `--max-publications` (1–128 per publisher pass),
`--read-timeout-ms` (1–30000), `--dispatch-timeout-ms` (1–660000), and
`--publication-timeout-ms` (1–660000). Each lane has at most two publisher passes
and one watcher pass. A pending or budget-limited pre-publication pass prevents
new execution on that lane; it does not prevent processing another lane.

## Custody, interruption and recovery

The supervisor keeps only an immutable configuration binding and its owner lock.
The watcher and publisher retain the original run identities, start records,
native evidence, publication keys and outcomes. Restarting the supervisor never
manufactures a new run namespace, removes history, passes `resume`, or changes
an uncertain request into a successful one. Reordering lane definitions is safe;
changing a bound branch, principal or path is rejected before native work.

One supervisor owner spans the entire pass. SIGINT/SIGTERM stops admission of
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
node --test scripts/fg_workflow_supervisor.test.mjs
```

These deterministic tests use the production POSIX custody implementation with
an injected watcher/publisher boundary. They test orchestration, branch isolation,
backpressure, cancellation, custody fencing and CLI validation. They do not
replace the existing native workflow execution/publication integration gates.

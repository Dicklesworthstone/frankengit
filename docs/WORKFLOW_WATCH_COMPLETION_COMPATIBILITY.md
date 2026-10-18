# Workflow watcher completion compatibility

The branch watcher and check publisher share the native dispatch-report validator
in `scripts/operator/workflow_watch.mjs`. Both must distinguish a whole workflow's
completion from the historical all-jobs-succeeded field inside its saved evidence.
Otherwise a successfully completed workflow with an optional `failure()` diagnostic
can be stranded before its observations reach the publication planner.

## Two compatible report forms

The node completion change in `41102c6` permits a whole run to succeed when at least
one job succeeded and every other job either succeeded or was genuinely skipped.
The outer run must also have closed workspaces and no request interruption. A
skipped job has no executed steps and no cleanup failure. Successful jobs require
complete successful step observations and no failure or containment marker.

The nested `execution.succeeded` field was deliberately not changed: it remains
true only when every job succeeded. It is therefore valid for a current run to
have `run.succeeded: true` and `run.execution.succeeded: false` when an optional
job was skipped. The unchanged evidence format and native job conclusions must
not be rewritten to make those fields agree.

The watcher accepts that current form and the previous form, where the same mix
of successful and skipped jobs was reported with both fields false. Old reports
remain failed observations; accepting them does not promote or reclassify them.
The exact input report determines the retained outcome and report commitment.
Configuration, intent, start, run, and publication key derivations are unchanged.

Validation does not accept arbitrary disagreements. Failure, cancellation,
timeout, output exhaustion, refused work, incomplete output, retained workspaces,
executed skipped jobs, or failed cleanup cannot become a successful run. Empty or
all-skipped executions cannot assert successful work. The executed graph must
match the selected workflow definition, including the exact native SHA-256 domain.

## Recovering a stranded completed dispatch

After upgrading the operator, inspect the existing watcher state and reconcile
its original saved native report:

```sh
node scripts/fg_workflow_watch.mjs status \
  --config /srv/watch.json --trusted-local
node scripts/fg_workflow_watch.mjs reconcile \
  --config /srv/watch.json --trusted-local
```

Reconciliation does not execute a workflow, refresh a source pin, publish a check,
change the principal, or remove an owner lock. It can recover a valid completed
report without the original native executable or source store. A missing,
malformed, or containment-unproved report remains unresolved and blocks automatic
execution. Never delete custody to cause replay.

Already retained results remain byte-identical. An old failed observation is not
rewritten merely because the newer completion predicate could classify the same
job outcomes differently. A resumed publisher still uses its original sealed
plan and keys, including the existing old-conclusion compatibility checks.

Whole-run success is not a required-check grant. Skipped jobs keep their own
native outcome, and this change adds neither authority nor acknowledgement of
retained workspace cleanup. The native evidence verifier and canonical check
publisher are unchanged.

## Verification

```sh
node --test tests/operator/workflow_watch.test.mjs \
  tests/operator/workflow_watch_completion.test.mjs
```

The completion suite drives the actual watcher, custody code, and operator CLI
against the existing explicit native-schema process peer. It covers both Git
hash domains, all 49 terminal-state pairs, modern and historical reports,
source-free fresh-process reconciliation, effect deduplication, service and
observer failure, invalid summaries, exact graph binding, and unchanged bounds.
The native peer is not Rust `fg`: these tests do not establish persisted-node
execution, canonical admission, a full publisher/supervisor campaign, or a
complete-workspace pass.

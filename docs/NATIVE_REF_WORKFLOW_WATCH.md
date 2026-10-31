# Native latest-ref workflow triggering

Branch-selected execution is documented in [native branch filters](NATIVE_WORKFLOW_BRANCH_FILTERS.md).

For the current head of a canonical merge queue, use
[`--merge-queue` candidate CI](NATIVE_MERGE_QUEUE_WORKFLOW_WATCH.md). That mode
watches a fixed target and selects the head's PR/source dynamically under one
queue-wide custody scope.


The native node `poll_trusted_ref_workflows_in` composes authenticated decision
history with the existing trusted workflow dispatcher. It is not a wire-push
receipt, a canonical event queue, an authorization service, or a green-check
issuer. The caller is a whole-repository local operator who trusts every selected
script with host-user privileges.

## Selection and identity

One configured `refs/heads/*` branch is observed. Its latest committed net ref
change is selected from verified history, and the current authority head is
rechecked after that scan. Dispatch requires the same observed head and commit.
Import, merge and receive updates all qualify. Matching uses native `on: push`
definitions in the configured directory; a caller-supplied push story is not used.

This is a latest-state profile: intermediate tips that came and went between
polls are coalesced, not reported as tested. A check, comment, checkpoint or change
to an unrelated ref cannot create a new event for this branch. A later return to
an earlier tip is a distinct decision batch and therefore a distinct event.

The watch scope binds tenant, repository, incarnation, raw branch bytes and raw
workflow-directory bytes. Each event binds that scope and its canonical decision
batch. Input selectors, time limits and output settings cannot create a second
execution identity for an already observed event. Changing the explicit parent
or deleting/rolling back records defeats local suppression; retain custody across
restart, backup and restore.

## Execution custody

The existing private run parent contains `watch-<scope-sha256>`. A private stable
`owner.lock` grants one local poll exclusive custody. Each creation-only
`event-<event-sha256>` directory saves `event.json` and establishes directory/file
durability before the ordinary native dispatch can start. The normal dispatch
marker, per-job process ownership, artifact handoff, evidence journals and reports
remain the execution implementation; no subprocess invocation of fg or Git and
no JavaScript supervisor is involved.

For ordinary branch and PR-head dispatch, the dispatcher verifies the exact
observed authority head and source commit before creating permanent event
custody. A source move at that boundary returns `source_moved` with no event or
execution; a later bounded poll may select again. The same immutable snapshot
then supplies discovery and execution. Merge candidates retain custody before
their publication effect. Every failure after custody creation remains subject
to the unresolved-event fence below; source movement never authorizes replay.

A settled marker is written only after the dispatch returned and all observed
workspace/process ownership settled without interruption. It is not a passing
check: an ordinary failed build can settle safely, and zero selected workflows
create no check. A repeated settled event returns `previously_settled` without
executing or claiming its report succeeded. A missing or invalid settlement
cannot be promoted from a process exit, candidate file or report snippet.

Any unresolved event blocks ALL later events in the same watch scope, including
after ref movement and restart. No automatic repair, force retry or record
pruning is provided. Inspect the retained event/dispatch and use the existing
workflow recover/publish commands for completed job evidence. This deliberately
prefers unresolved work over accidental repeat effects. A file lock is not
hostile-code containment, and SIGKILL cannot perform cooperative process drain.

The custody scan is bounded to 1024 retained events; source-history and dispatch
retain their existing finite work/byte limits. Filesystem parents must remain
stable and operator-owned. No directory scan or local marker is repository truth.


## Native CLI

`fg workflow watch <storage-root> <tenant> <repository> refs/heads/main
--trusted-local --workflow ci --input ci --run-parent /private/runs` performs
one native poll. Add `--polls 100 --interval-ms 1000` for a bounded foreground
watch, or select SHA-256 with `--object-format sha256`. Byte-name and artifact
capture/input flags match `fg workflow dispatch`. The global leading
`fg --timeout-secs 300 workflow watch ...` bounds the whole watch, including
idle waits; no poll resets that request budget. Defaults are one poll, 1000 ms
between polls, the native workflow limits, and the configured command deadline.

### Continuous service

Use an explicit service lifetime for sustained trusted CI:

```sh
fg workflow watch NODE TENANT REPOSITORY refs/heads/main \
  --trusted-local --workflow ci --input ci --run-parent /private/runs \
  --continuous --stop-file /private/control/workflow.stop \
  --attempt-timeout-secs 300 --interval-ms 1000
```

The stop file must initially be absent and its parent must already exist. Create
that regular file, or send SIGTERM/SIGINT, to stop admission and drain active
execution. The watcher never deletes or rewrites it; a pre-existing entry refuses
before repository open. A replaced parent, symlink, special file or failed stop
observation stops work with an error. These controls govern the local service,
not repository authorization.

`--continuous` and `--polls` are mutually exclusive. Without an explicit global
`--timeout-secs`, the service has no fixed lifetime deadline. Each attempt still
has a fresh finite request: pending check recovery, one poll/dispatch, and the
resulting check publication share that request's deadline and work budgets.
`--attempt-timeout-secs` accepts 1–3600 seconds and defaults to 300; it is only
available in continuous mode. An explicit leading `--timeout-secs` remains an
absolute limit on the **whole service**, including idle waits, and narrows each
new attempt to the remaining time. No active attempt renews its authority.

The continuous service emits `workflow_watch_ready` with its configured attempt
and optional lifetime limits before any poll or check publication. Its final
summary adds `continuous` and `operator_stopped`. An idle operator stop exits 0;
non-green execution, exhausted deadlines or unresolved custody remain nonzero.
Stop observation runs as an owned child of the node's existing runtime during
synchronous execution and joins before node shutdown. Signal subscriptions and
stop state remain live across attempts and idle intervals.

All existing trust, latest-state/coalescing, permanent event identity, canonical
check publication and restart rules apply. This mode does not increase the 1024
retained-event limit, prune custody, automatically retry interrupted scripts, or
turn trusted-host execution into a sandbox. `--publish-checks` and native PR
selection compose with the same service lifetime. The real-binary
`scripts/e2e/suites/workflow/watch_continuous.sh` campaign exercises successive
source updates, canonical checks, restart suppression, finite attempt/whole-service
deadlines and active process drain in SHA-1 and SHA-256 repositories.

The CLI installs one runtime-owned signal observer for the complete watch.
SIGTERM/SIGINT stop future polls, reach active synchronous native execution,
and leave cleanup/retained journals to their existing owners. An idle watcher
also responds without waiting out its poll interval. Every poll is flushed as
one `workflow_watch_poll` JSON line; the final `workflow_watch_result` separately
records node shutdown, non-green execution, interruption, reconciliation and
operation/cleanup errors. No raw output is accumulated across polls.

A verified source-head race detected BEFORE reservation returns `source_moved`
without creating an event or executing a script. A later bounded poll can select
again. Once an event is reserved, source changes or errors remain unresolved;
this path is never automatically retried. This distinction keeps normal branch
updates from terminating an idle watcher without weakening replay suppression.

An exit of zero means the requested observations completed, not that all history
or any unexecuted workflow has passed. Ordinary failed builds return non-green
and may settle; a restart reports `previously_settled`, not historical success.
Unresolved events stop the loop and require reconciliation. No event, caller run
ID, fixed head or commit may be supplied to override canonical selection.
By default this command does not publish checks or grant merge authority; completed
jobs remain available through the native recover/publish boundary. Explicit
`--publish-checks --principal-id ... --expected-incarnation ...` connects settled
events to canonical checks without rerunning scripts. See
[`NATIVE_WATCH_CHECK_PUBLICATION.md`](NATIVE_WATCH_CHECK_PUBLICATION.md) for the
durable handoff, restart, identity, limits and legacy-state refusal contract.

The discovered `scripts/e2e/suites/workflow/watch.sh` drives the real Rust binary
in both object formats, including new refs observed during polling, restart and
unrelated-update suppression, ordinary failure and unmatched-workflow behavior,
idle deadlines, repeated signals, real child drain and later-event blocking.
It is functional trusted-local evidence, not a pinned Git compatibility campaign,
universal process containment, an all-events queue or a full release gate.

## Native pull-request selection

Optional `--pull-request NUMBER` selects an actual open native PR whose source
matches the explicit watched branch. It uses separate PR/version-scoped custody
and `on: pull_request` definitions, while retaining the same execution and opt-in
check-reporting boundaries. This is current **source-head-only** testing, not a
synthetic merge. See [`NATIVE_PULL_REQUEST_WORKFLOW_WATCH.md`](NATIVE_PULL_REQUEST_WORKFLOW_WATCH.md)
for lifecycle selection, stale recorded PR coordinates, artifacts and recovery.

# Native latest-ref workflow triggering

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

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

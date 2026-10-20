# Trusted workspace execution: source pins and owned process cleanup

`fg workspace run` is an explicit local-owner tool, not a remote agent endpoint
or hostile-code sandbox. Its executable retains host-user privileges. Inputs
and declared output paths limit the sparse copy and candidate export, not all
possible external effects of the executable.

## Exact source before execution

Optional `--expected-head alg:<algorithm>:<digest>` and `--expected-commit <oid>`
flags fence execution to the source the caller reviewed. Both checks run inside
the same authenticated source-selection operation, before creating a workspace
or starting a process. An unrelated canonical event can change the head without
changing the commit: the head fence intentionally refuses that change too. The
commit fence alone permits such a head change while still requiring the exact
native source commit. SHA-1 and SHA-256 identities remain distinct.

The node API `run_trusted_workspace_tool_at_in` exposes the same optional pair;
the existing `run_trusted_workspace_tool_in` remains its unpinned compatibility
wrapper. Source expectations are not approvals, credentials or publication
capabilities. A matching candidate is still only a bundle; publishing it uses
ordinary admission via `fg workspace apply`.

## Completion belongs to the process group

The runner's `run_trusted_command` executes the literal argv without inserting a
shell. It reuses the existing Linux process-group owner used by workflow steps.
The direct child stays waitable until group inspection and signalling finish,
so its numeric PID/PGID cannot be recycled underneath cleanup. The owner never
signals a group after reaping its leader.

A successful leader that leaves group members behind is not a successful tool
execution. Its group is drained, the workspace is retained, and no candidate is
exported. Properly joined children and ordinary nonzero exits preserve their
real exit statuses. Timeouts, signals, and cancellation after spawn also retain
the workspace. Known group members stopping is not proof that every possible
escaped descendant was contained or reaped.

SIGTERM and SIGINT sent to `fg workspace run` request cooperative cancellation.
An owned Asupersync blocking-pool child relays signals into a derived request
while synchronous tool work executes. The shared native context remains usable
for workspace settlement and node shutdown. Repeated signals do not interrupt
that drain. Observer and node cleanup are both attempted and both failures are
retained; a candidate bundle is not written unless execution and cleanup finish.
Signals arriving after completed execution do not imply rollback of effects.
SIGKILL and machine failure remain abrupt failures.

## Recovery boundary

Inspect a retained `workspace-<id>` and any external effects before taking a
new action. Its occupied slot refuses another materialization; an existing
bundle destination also refuses another execution. These are not an exactly-once
external-effect protocol: a successfully removed workspace ID is not a persistent
execution journal, and a missing bundle is not proof that no command ran. Do not
retry a tool automatically merely because a response was lost. The broader
IntentRun/effect-broker integration remains a separate obligation.

## Executed-path regression coverage

`tests/trusted_command.rs` in fgit-runner exercises real argv/status, envelope
refusals, failed spawn, pre-cancel, joined and orphaned children, signal exit,
timeout and cancellation. The node workspace tests reproduce the original
orphan-on-success defect and pair it with proper child joining and source-pin
refusal/success twins.

`scripts/e2e/suites/workspace/lifecycle.sh` drives a prebuilt `FG_BIN` in both
native hash formats. It verifies exact candidate bundle bytes, stale-pin refusal
before host effects, SIGTERM/SIGINT against live nested descendants, repeated
signals, timeout and orphan rejection, retained-slot and bundle-destination
replay refusal, and unchanged canonical refs. Descendant liveness is checked
before test-fixture cleanup. This is Linux trusted-host evidence, not a full
workspace release gate or proof of hostile isolation.

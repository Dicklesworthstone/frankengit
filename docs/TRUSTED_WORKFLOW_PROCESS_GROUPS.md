# Trusted workflow process-group ownership

The Linux foreground workflow adapter now starts each step in a fresh process
group using `CommandExt::process_group(0)`. Cancellation, timeout, output
exhaustion and error cleanup signal that exact group, not merely `/bin/sh`.
The direct child remains owned until cleanup is complete. This applies to the
existing plain, step-context and matrix workflow paths; no new executor or CLI
switch is required.

## Completion and identity

The owner observes direct-child termination with `waitid(WEXITED | WNOHANG |
WNOWAIT)`. Keeping the child unreaped pins its numeric PID and group ID while
cleanup still needs to signal the group. `Child::try_wait` is used only at the
final reap, after all group signalling. No later operation signals that numeric
group ID. A missing child (`ECHILD`) invalidates ownership instead of allowing
signals to a potentially reused ID. The embedding process must not independently
reap the adapter's children or install a competing global child reaper.

A normal shell exit is not sufficient for a passing result. Before reaping, the
adapter inspects the matching process group. Any other group member, even a
zombie, makes the result `containment_failure`; cleanup is attempted and the
workspace stays retained. The shell's original exit code is preserved, so an
exit code of zero may accompany a non-passing containment result. Normal scripts
that wait for their own children keep their existing success/nonzero-exit and
output behavior.

## Bounded drain and failures

Every forced cleanup gets one non-cancellable three-second deadline. It signals
the still-owned group with SIGKILL, also targets the owned direct child, and
checks whether remaining group members can still run. Repeated signals remain
within that deadline and happen before the leader is reaped. The direct child
is reaped; orphaned descendant zombies are NOT claimed as reaped by FrankenGit.
They are distinguished from live descendants and left to their operating-system
reaper. All forced-stop paths still retain the workspace and a non-passing
outcome, including when group members have stopped.

Procfs observation has a 250-millisecond per-scan bound, at most 16,384 directory
entries, and at most 4,096 bytes per stat record. Names in `/proc/<pid>/stat` are
opaque: spaces, parentheses and newlines are not interpreted as field separators
inside the command name. An unreadable, malformed, missing-leader, over-capacity
or timed-out observation refuses rather than claiming complete cleanup. The
normal host procfs must expose the group's members; a filtered or substituted
process view is outside this trusted profile.

Callback unwinding also enters bounded group cleanup through the owning guard.
The coordinator's existing unwind handling still reports unresolved containment;
a destructor does not manufacture a successful job or erase scope obligations.
A failed cleanup is not retried under a fresh deadline on guard destruction.

## Trust boundary and compatibility

This is trusted host-user execution, not VM, namespace, filesystem, network or
hostile-code isolation. Programs that intentionally leave their group, daemonize
or delegate to another service remain outside group containment. They must not
be selected as ordinary trusted foreground scripts. There is no subreaper,
process-global signal-handler change, `/proc`-discovered arbitrary-PID signalling,
new runtime, first-party unsafe code, or new dependency version. The runner
explicitly requests the `process` feature of existing rustix 1.1.4 (DEP-118),
already present in the admitted feature closure; Cargo.lock is unchanged.

The existing report format, graph identity, check-evidence encoding and authority
publication rules are unchanged. A retained or containment-failure job cannot
become a passing workflow merely because its shell exited zero. The broader CI
product-loop bead remains incomplete; this does not provide an unrestricted
hostile runner or claim complete descendant reaping.

## Verification

`crates/fgit-runner/tests/workflow_process_group.rs` uses finite real Linux
processes to exercise child/grandchild cancellation, timeout, orphaned success,
signal termination, output exhaustion, clean joined-child behavior, unrelated
group isolation, pre-spawn cancellation and liveness-callback unwind. Existing
workflow, condition, matrix and runner-library tests remain applicable. These
focused tests alone do not establish persisted-node end-to-end or full-workspace
verification.

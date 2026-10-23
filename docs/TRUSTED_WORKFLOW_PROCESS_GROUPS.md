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

Normal completion inspects procfs once under the step or command's **remaining
absolute execution deadline**, checking request cancellation throughout. It does
not impose a shorter completion timer or discard a partial scan and restart it
when the host deschedules the observer. The step, job and workflow limits still
bound the operation; observation does not reset any execution budget. A request
cancelled or timed out during that scan transfers to the independent forced
drain, retains its workspace and preserves the interruption even if the caller's
liveness predicate later returns true. The same rule applies to trusted shells
and directly configured foreground commands.

Forced cleanup inspects under its original three-second drain deadline. Every
scan admits at most 16,384 directory entries and at most 4,096 bytes per stat
record. These work bounds apply to normal completion too. Names in `/proc/<pid>/stat` are
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
workflow, condition, matrix and runner-library tests remain applicable. Private
procfs fixtures test exact entry/record limits, caller deadline and cancellation,
missing leaders and zombie distinctions. A deterministic clock advances beyond
the former observation windows during a scan and checks that no progress is
discarded while the caller budget remains. Separate real-child tests verify that
repeated WNOWAIT observations retain the leader, competing reaping invalidates
ownership, and interruption of terminal observation drains both public execution
adapters without turning a zero exit into a pass. These tests do not claim that
an arbitrarily starved host can complete within a finite caller or drain budget.

The discovered `scripts/e2e/suites/workflow/process_groups.sh` campaign drives a
prebuilt `FG_BIN` against persisted SHA-1 and SHA-256 nodes. It tests joined
children, orphaned zero-exit shells, signal termination and request-deadline
cancellation of grandchildren. The campaign checks that later independent and
`always()` jobs do not run after containment loss, retained reports recover
without execution, occupied attempt IDs cannot replay, and removing the source
directory does not invalidate durable recovery.

Every terminal job observation also traverses the existing canonical publication
path. Failed containment publishes failure, cancelled successors publish cancelled,
and joined foreground jobs retain their normal success behavior. Graph, native
source and evidence identities must match; exact publication retries return
byte-identical results without changing refs or acknowledging workspace cleanup.
These are actual binary tests, not injected runner or authority implementations.
They do not establish hostile isolation, physical power-loss recovery, maximum-host
scaling, or complete-workspace validation. Use the existing matrix and step-context
suites to check their broader execution/publication paths as well.

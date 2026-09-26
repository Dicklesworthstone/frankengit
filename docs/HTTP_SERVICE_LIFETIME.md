# Continuous HTTP service and explicit draining shutdown

Owning work: `frankengit-root-doctrine-x2mv.4.8` (listener-lifetime slice).

## Operator interface

The existing `fg serve-http` defaults are unchanged: a bounded run retires on
its configured request count or idle window. A continuously running service is
an explicit choice:

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file /run/frankengit/http-credentials \
  --allow-receive --max-in-flight 4 \
  --continuous --stop-file /run/frankengit/http.stop
```

`--continuous` and `--stop-file` must appear together. The chosen stop file must
initially be absent, and its parent must already exist and remain operator-owned.
Do not select a path writable by repository content or an untrusted user.
A prior stop request refuses startup before opening the repository or binding the
listener. The service never creates, reads the contents of, or removes this file.

Creating the regular stop file requests shutdown:

```sh
touch /run/frankengit/http.stop
```

The accepting thread polls the control with a 50 ms minimum interval between
filesystem inspections. The first poll is immediate. This is not a preemption
bound on filesystem I/O or scheduler delays. Detection stops new acceptance; it
does not discard requests already accepted. Those requests complete or refuse
within their existing ingress, processing, response and cleanup envelopes.
The service joins their workers before returning its transport receipt. The CLI
then shuts down the node and emits `smart_http_drained` only after success.
A mutation's lost response or shutdown is never treated as proof of non-commit.

In continuous mode, SIGTERM (what a service manager sends to stop a service)
and SIGINT (Ctrl-C) request the same drain as the stop file, and stderr says
so once. The handlers are installed through the runtime's signal support only
when continuous serving starts, so a bounded run keeps the default behaviour.
A signal is latched like a stop file; a second signal during the drain does
not cut it short. A platform that cannot install the handlers keeps the default
behaviour and prints why, leaving the stop file as the drain control
(`scripts/e2e/suites/node/http_signal_drain.sh`).

An unreadable stop-control directory, directory replacement detected on Unix,
symlink, socket or other non-regular control entry causes a draining error, not
silent continued service and not a fabricated successful drain. A detected stop
is latched. Removing the file afterward cannot restart acceptance. Remove a
retained stop file explicitly before a later invocation; startup does not do so.

Continuous mode refuses explicit `--max-sessions` or `--idle-timeout-secs` flags
rather than silently ignoring them. It keeps all request timeouts, object and
wire limits, in-flight limits, independent endpoint ceilings and credential
scopes. It does not enable receives or metadata APIs by itself. Both static
Git-only credentials and the reloadable scoped credential table are supported.
The readiness record adds `lifetime: "bounded" | "continuous"`.

## One lifetime, not repeating bounded windows

The two modes enter the same accept loop. Continuous mode does not simulate an
unlimited listener by repeatedly calling the bounded entry point: that would
reset mutation, read and recovery quotas, and restart receipt accounting.
One profile and one set of quotas remain live until stop. The request queue and
retained worker handles remain bounded by the existing in-flight limit.
A machine-sized lifetime counter refuses before overflow instead of wrapping.

Library callers can use `OneNode::serve_smart_http_until_stopped` for static
Git-only credentials, or `OneNode::serve_repository_http_until_stopped` for a
reloadable credential file and independent endpoint flags. Their stop callback
runs only on the accepting thread and must be bounded, nonblocking and nonpanicking.
`Ok(true)` retires acceptance; an error reaches the same draining epilogue.
Unwinding callback panics are converted to errors. A panic-abort build cannot
recover an aborting panic. The caller remains responsible for node shutdown
once the serving method returns.

## Verification obligations

New unit regressions cover bounded compatibility, continuous operation beyond
old count/idle limits, stop while slots are occupied, control errors and unwinding
panics, counter overflow, control-file startup/polling/refusal behavior, and CLI
option/scoping validation.

The native campaign requires an already-built executable:

```sh
FG_BIN=/absolute/path/to/fg scripts/e2e/suites/node/continuous_http.sh
```

For SHA-1 and SHA-256 repositories it drives stock pushes before and after 1,024
connections, a known active upload RPC across stop, complete drain accounting,
pre-existing-stop refusal, and credential revocation/restoration without restart.
The active-child test waits for the actual `100 Continue` before requesting stop,
then supplies the body and requires the final ref response. It does not infer
acceptance merely from a connected socket. Failure artifacts are retained.

The implementation-preparation environment had no Rust toolchain or built `fg`.
Rust compilation, Rust tests, rustfmt, Clippy and this native campaign were NOT
run. Python syntax and shell syntax were checked, and the campaign's exact
ls-refs request builder was exercised against upstream Git 2.47.3 for both
object formats. That validates a fixture, not FrankenGit execution. No gate pass,
verified serving claim or bead closure follows from those checks.

## Boundaries

This change does not replace the existing per-connection node opening strategy,
add TLS, organization IAM, hostile-filesystem confinement, handlers for signals
other than SIGTERM and SIGINT, instant cancellation of admitted work, or a
hosted supervisor. The stop-file
parent is operator-owned. Unix checks parent identity; portable std does not
expose comparable directory identity on every other platform. A killed or aborted
process is not a successfully drained service.

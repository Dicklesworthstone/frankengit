# Foreground index command deadlines

A leading `fg --timeout-secs SECONDS` now reaches lexical, symbol and scoped
index build, refresh, query and recovery, and foreground index maintenance.
Nested commands and hyphenated aliases share the same boundary. Standalone
compatibility binaries and callers that supply no override retain their original
finite Database or BackgroundController policy.

The optional deadline starts once at command entry, before opening the node.
Native readiness and index work use runtime-owned contexts bounded by remaining
command time, while keeping the original class's poll/cost limits and node-root
ceiling. Parsing, opening and preparation consume that time; later stages do not
renew it. This is cooperative cancellation, not preemption of blocking OS calls.

Foreground maintenance shares one absolute deadline across refs, passes and idle
waits. Each new attempt receives only the remaining time. Expiry stops new work,
drains the original native operation and retains its candidate/recovery records.
An expired invocation exits nonzero even if an earlier pass completed. Confirmed
activations remain confirmed. Once native work and node shutdown settle, the
foreground lock can release; a new explicit resume uses the existing checkpoint.
The independent in-server maintenance controller's lifetime is unchanged.

Cleanup has its own bounded budget and is attempted after success and failure.
An expiry or output error never means a previously published index was rolled
back. Recover the original candidate when its publication outcome is unresolved.
Index publication remains derived state and creates no canonical ref mutation.

The native `operator_index_deadlines.sh` suite exercises both Git hash formats,
all index command aliases, one-nanosecond refusal/permitted twins, exact candidate
recovery, maintenance expiry during a long idle interval and clean resume. Its
Python driver's optional `--baseline` mode reproduces the old bug: lexical and
symbol index activation succeeds despite an expired one-nanosecond global budget.

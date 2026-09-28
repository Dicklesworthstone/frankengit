# Continuous raw Git and SSH service

## Operator interface

Both native Git transports can remain available across an arbitrary number of
sessions and idle periods. Select continuous operation explicitly:

```sh
fg serve "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:9418 \
  --continuous --stop-file /run/frankengit/git.stop --max-in-flight 4

fg serve-ssh "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:2222 \
  --host-key-file /run/frankengit/host-key \
  --deploy-keys-file /run/frankengit/deploy-keys \
  --continuous --stop-file /run/frankengit/ssh.stop --max-in-flight 4
```

The repository must already be initialized. Each stop file must be absent in an
existing operator-owned directory. The host key and deploy-key file use the
existing `serve-ssh` formats. Continuous operation does not grant write access:
raw Git still requires an explicit `--receive-principal`, and SSH still requires
`--allow-receive` plus a matching deploy key with write scope.

`--continuous` and a nonempty `--stop-file` must appear together. Continuous mode
refuses an explicit `--max-sessions`; `--max-in-flight` remains in the range 1–16.
Without these new flags, raw Git still defaults to one session and one in-flight
client, and SSH retains its existing bounded defaults. The bounded raw Git
human-readable completion line remains compatible with the bring-up script.

## Stop and drain

Create the selected regular file, send SIGTERM, or send SIGINT to request drain.
Signals are installed before the readiness record. If signal registration is
unavailable, the executable reports the reason and the stop file remains the
available drain control. A second signal does not abandon already accepted work.

All three server commands reuse the same stop-file controller. It never reads
file contents, creates the file, removes it, or modifies it. A preexisting entry
refuses startup before repository open or listener bind. Parent identity changes
on Unix, unreadable control paths, symlinks, directories and special entries fail
closed through the draining error path. Detection is latched. A stopped service
does not resume if the file is subsequently removed.

The accepting thread inspects stop state even when every worker slot is occupied.
On stop it closes its owned listener before joining accepted children. New peers
therefore see a closed listening socket during drain, while already accepted
sessions retain their normal protocol and admission behavior. Accepted pushes
may still commit. Loss of a client response never proves that a push did not
commit; use the native report-status and canonical repository state.

The configured ingress, processing, terminal-response and cleanup envelopes
bound accepted work. Raw Git and SSH both retain the existing flags:

```text
--session-timeout-secs
--session-secs-per-mib
--session-max-extension-secs
--receive-max-input-mib
--receive-max-expanded-mib
--pack-max-expanded-mib
```

SSH identification, authentication and command selection have the pre-command
60-second idle ceiling and the accepted session's absolute deadline. Once a Git
command is authorized, I/O uses the remaining absolute session budget, without a
60-second idle ceiling. Git data delivered to the native reader can earn the
configured finite work extension; SSH control packets and window traffic do not
restart or extend it. The native terminal writer can install its separate
response deadline after admission. This permits legitimate quiet pack generation
while bounding silent peers, control traffic and blocked channel windows.

A stop-file inspection interval of 50 ms is a polling interval, not a guarantee
about filesystem latency or scheduler delay. The drain envelope depends on the
selected session/work limits; continuous mode does not introduce a universal
fixed-duration force kill.

## Readiness and receipts

Continuous raw Git emits `git_daemon_listening` with `schema_version: 1`,
the bound `address`, `repository_incarnation`, `receive_enabled`, and
`lifetime: "continuous"`. Bounded raw Git keeps its existing human-readable
completion output. SSH emits `ssh_listening` in both modes with
`lifetime: "bounded" | "continuous"`, its identity fields and `allow_receive`.

After the service drains and node shutdown succeeds, continuous raw Git's
`git_daemon_drained` or SSH's `ssh_drained` carries `accepted`, `completed_transports`,
`refused_transports` and `lifetime`. Every accepted child is counted exactly
once:

```text
accepted = completed_transports + refused_transports
```

These are transport and cleanup observations. They do not replace a push's
canonical outcome. Stop-control, listener, scheduling, pooled-node cleanup or
receipt-output failure returns an error instead of inventing a successful drain.

## Library ownership

`OneNode::serve_guarded_git_daemon_until_stopped` and
`OneNode::serve_ssh_until_stopped` consume their `TcpListener`. The bounded
entry points retain their borrowed-listener signatures. A shared accept loop
preserves one set of quotas, writer gates, repository-incarnation-pinned node
lanes and counters across the entire service lifetime. Finished child handles
are reaped continuously, so retained handles stay bounded by the in-flight limit.

The callback runs on the accepting thread and must remain bounded and
nonblocking. `Ok(true)` stops acceptance; errors and unwinding panics close
acceptance and reach the common drain path. Native session unwinding also
preserves explicit node cleanup and refusal accounting. Abort or process kill
cannot provide a successful drain. The library caller shuts down its owning
node after the serving method returns.

## Verification commands

The owning Rust tests exercise both object formats, held atomic push drain,
continued acceptance without a stop, refused future connections, control errors
and panics, invalid limits, bounded handle retention, and SSH deadline behavior.
The discovered stock-client campaign is:

```sh
FG_BIN=/absolute/path/to/fg scripts/e2e/suites/node/continuous_git_transports.sh
```

It is designed for 70 push/fetch/fresh-clone cycles per transport, followed by
held atomic pushes, their no-signal twins, SIGTERM/SIGINT/stop-file shutdown and
canonical restart checks. A 30-second base with work scaling disabled gives this
campaign a 120-second signal-to-exit assertion. That assertion is a test setting,
not an operator-independent production timeout.

The execution environment disconnected during implementation. The reconstructed
source and campaign need fresh Rust formatting, compilation, unit tests and real
stock-client execution; prior fixture syntax checks do not establish a pass for
this revision.

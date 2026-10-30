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

## Live SSH deploy keys

On Unix, `--deploy-keys-file` selects a live authorization source in both bounded
and continuous service modes. The server validates the complete file at startup
and again before each Git command, after the peer proves possession of its SSH
key and before a successful exec reply or repository data. The listener retains
the source path, not a cached grant table. A relative path is anchored to the
startup working directory.

Each non-comment row has three whitespace-separated fields:

```text
<64-hex-character-Ed25519-public-key> <32-hex-character-principal-id> <scopes>
```

Scopes are `read`, `write`, or a comma-separated combination. `write` does not
imply `read`; pushing also requires the server's `--allow-receive` flag. Blank
lines, full-line `#` comments and whitespace-separated trailing `#` comments are
accepted. The complete UTF-8 file is limited to 64 KiB and 256 unique public keys.
Repeated public keys, even identical rows, and any malformed row refuse the
whole file. A valid first row never hides an invalid later row.

Use a regular file in an operator-owned directory, with no group or other
permission bits (`chmod 600`). Symlinks, directories, FIFOs and other special
files are refused. The reader opens without following a final symlink or waiting
for a FIFO writer, reads only the finite byte envelope, and checks the opened
file and named path for changes. This profile relies on trusted parent directories
and local filesystem availability; it does not impose a kernel-level deadline
on a stalled filesystem operation. The session checks its remaining deadline
and peer connection before and after authorization, and discards a late result.

Replace the whole table atomically to rotate or revoke keys. For example, with
`PUBLIC_KEY_HEX` and `PRINCIPAL_ID_HEX` already selected:

```sh
umask 077
key_dir=/run/frankengit
next=$(mktemp "$key_dir/deploy-keys.XXXXXXXX")
printf '%s %s %s\n' "$PUBLIC_KEY_HEX" "$PRINCIPAL_ID_HEX" read,write > "$next"
chmod 600 "$next"
mv -- "$next" "$key_dir/deploy-keys"
```

That replacement authorizes only the listed key. Preserve other rows explicitly
when they should remain authorized. An empty or comment-only replacement revokes
all keys. A missing, unreadable, oversized, unsafe or malformed replacement
refuses subsequent commands; the server never falls back to its previous grants.
A later valid replacement restores access without a restart. A concurrent file
change can refuse that attempt, so use a fresh command after completing the
replacement.

A connection that proved its SSH key before the replacement still consults the
current file when it selects a Git command. An already authorized command keeps
its selected principal and completes under its existing bounded lifetime; file
replacement does not retroactively cancel a push or establish its outcome.

Inline `--deploy-key --principal --scopes` remains an explicit static profile.
It cannot be combined with `--deploy-keys-file`, and changing an inline grant
requires replacing the configured service. File-backed authorization returns an
unsupported-platform refusal outside Unix; the static API remains available.
This operator-controlled table supplies live deploy-key authorization, not a
hosted account, organization or team administration service.

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
--pack-cache-mib
```

The pack computation cache defaults to 64 MiB across a service's request
children. `--pack-cache-mib` accepts 0..65536 MiB; zero disables retention.
It changes disposable memory retention, not the request's selected objects,
work limits or publication authority. Smart HTTP accepts the same option.

SSH identification, authentication and command selection have the pre-command
60-second idle ceiling and the accepted session's absolute deadline. Once a Git
command is authorized, I/O uses the remaining absolute session budget, without a
60-second idle ceiling. Git data delivered to the native reader can earn the
configured finite work extension. For upload-pack, the exact selected expanded
bytes earn their bounded allowance after disclosure, filtering and size checks,
before body reads. Ingress and selected work share the same extension cap;
repeating a selection cannot add duplicate credit. Transfer poll/cost quotas
remain unchanged. SSH control packets and window traffic do not earn work time.
The native terminal writer can install its separate response deadline after
receive admission or for one terminal upload refusal. A refused upload's
response phase permits bounded window-control reads needed to send its error;
it does not reopen Git input, handshake I/O, or expired pack work. This permits
legitimate quiet pack generation while bounding silent peers, control traffic
and blocked channel windows.

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

`./scripts/verify.sh continuous-serve` runs the owning Rust tests. It then
builds `fg`, runs the campaign in both hash domains, and runs the SSH
compatibility suite with its quiet-command regression.

It is designed for 70 push/fetch/fresh-clone cycles per transport, followed by
held atomic pushes, their no-signal twins, SIGTERM/SIGINT/stop-file shutdown and
canonical restart checks. A 30-second base with work scaling disabled gives this
campaign a 120-second signal-to-exit assertion. That assertion is a test setting,
not an operator-independent production timeout.

## Executed evidence (2026-09-28)

The source was reconstructed after its executor disconnected, and was committed
(7847acca) unformatted, uncompiled and unrun. It has since been executed:

- It compiles (`cargo check -p fgit-node -p fgit-cli --all-targets` at
  `bd45641f`). Eight of its files were rustfmt-formatted in `e98c2d05`, with no
  code change.
- The owning Rust tests pass at `bd45641f`:
  - the fgit-node `ssh::` and daemon supervisor tests, 22/22;
  - `tests/guarded_git_daemon`, 10/10, including the three continuous tests;
  - the `fg` serve-command tests, 28/28.
- The first run of the stock-client campaign found one harness defect.
  `GIT_PROXY_COMMAND` was given a command line, which Git cannot exec, because
  it runs the proxy without a shell. It was fixed in `f4560746`; the relay and
  every assertion are unchanged.
- The runs used a release `fg` built at `bd45641f`, OpenSSH 10.2p1 and git
  2.55.0 on a shared, loaded host:
  - the discovered suite passed 11/11 in the SHA-1 domain;
  - the same campaign with `--format sha256` passed all four acceptance lines
    for both transports;
  - together that is 840 sequential stock sessions.
- In each of the four transport and format runs:
  - SIGTERM during the held atomic push let the push complete;
  - the drain receipt settled 217 accepted = 217 completed;
  - the process exited 2.5–3.5 s after the signal;
  - a connection attempted during the drain was refused (ECONNREFUSED) while
    the server and the held push were still alive.
- Planted negative: the suite fails against `fg` built at `b8b79a11`, before
  this change, because that binary refuses `--continuous`.

These are one agent's local runs, not a batch-verification result. The
signal-to-exit times were measured with the campaign's 30-second session base on
small repositories. They are not a production drain bound.

# Guarded raw Git serving

The **`fg serve` executable** now selects the guarded raw TCP receiver. This is
an executable switch-over, not merely the addition of an unused node API. It
connects native receive framing to the same continuing admission coordinator as
Smart HTTP. Upload-pack still delegates to the existing native upload engine
without consuming its greeting. No second ref database, Git engine, executor,
transaction identity, or publication mechanism is introduced.

These are committed interfaces and regression tests, not an executed Rust
acceptance result. Compilation and the focused tests below remain required.

## Invocation and trust boundary

The existing command shape is retained:

```sh
fg serve "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:9418 \
  --receive-principal "$PRINCIPAL" \
  --max-sessions 100 --max-in-flight 4 \
  --session-timeout-secs 30
```

Without `--receive-principal`, receive is refused before advertisement or PACK
intake. **Raw git:// authenticates no remote principal.** Enabling this option
assigns its operator-selected identity to every connecting writer. Bind to a
trusted loopback/tunnel deployment; this is not bearer authentication, SSH, TLS,
or multi-user IAM. The existing Smart HTTP gateway is the separate credentialed
transport. This change does not make an untrusted raw TCP listener safe.

The repository must already exist. Its canonical configuration selects the
native object format. Existing expected-incarnation, receive byte-envelope,
selected-pack and work-scaling options remain explicit; unknown, duplicate,
incomplete or overflowing options refuse rather than silently select defaults.
There is no fallback to the old receiver after a guarded-serving failure.

The guarded service supports **1..1,000,000 sessions**, **1..16 concurrent
connections**, and at most **64 commands per receive**, matching the admission
limit before retaining a longer command list. Session/concurrency defaults remain
one. Command-prefix retention is bounded to 4 MiB; PACK reads use 16 KiB scratch
chunks. The native scanner and quarantine retain their own bounded storage;
this is not disk-spooled admission or a zero-copy claim.

## Receive sequencing

The existing parser first verifies the bounded greeting and exact repository
route. Receive then requires the configured principal, shared principal quota,
and an intake-eligible cell. Discovery uses the existing direct-ref projection
and current canonical visibility; it does not require a resolvable fetch HEAD.

Commands and packs feed the real native receive machine. A complete PACK trailer
ends ingress without waiting for client EOF. Bytes beyond the trailer in the
same read refuse. EOF before the trailer, corruption, invalid commands and
resource exhaustion do not yield a successful handoff.

After ingress, the node starts independent finite server-work clocks and selects
a **fresh authenticated authority basis** for production quarantine. The earlier
advertisement is not reused as the validation witness. An intervening unrelated
publication therefore does not by itself invalidate otherwise current client
expected-old conditions. Publication admission still rechecks the exact basis
and current policy: a later race cannot turn the advertisement into authority.

`admit_receive_session_durable_in` owns all command decisions. Non-atomic pushes
bind their complete semantics and each wire-order child key before publication,
and persist the existing recovery descriptor. Continuation retains the exact
validation witness and advances only across this session's verified preceding
committed or refused decision. Atomic pushes remain one sealed transaction.

## Terminal decisions versus transport errors

Report-status is emitted only from authenticated canonical outcomes. A stale
first command may therefore return `ng` while valid later commands return `ok`;
it must not poison later commands merely by advancing the authority head.

An infrastructure failure after entering admission emits a terminal pkt-line:

```text
ERR receive outcome unknown; retry identical commands or recover the original key
```

It does **not** manufacture per-ref rejection records. Some commands may already
be committed. The typed stream API retains `ReceiveInterrupted`, its known
completed prefix, stable mapping and underlying error. Unknown commands are not
classified as refused. If admission finishes but report delivery fails,
`ReceiveResponse` retains the complete `AdmissionResult`. Failed best-effort
error delivery does not replace the admission error with an I/O-only verdict.
A failure before this invocation enters admission says so; it cannot undo a
previous attempt's decisions.

The per-connection native API is `OneNode::serve_guarded_git_daemon_stream`.
It returns `Some(AdmissionResult)` for a fully delivered receive result and `None`
for upload. Call it only from an owned blocking lane and retain its typed error.
`OneNode::serve_guarded_git_daemon_bounded` owns accepted blocking tasks, opens
children pinned to this repository incarnation, shares quota, and joins all
children through shutdown. It returns transport counts, **not proof that refused
connections published nothing**. Receive cleanup is bounded by both 64 KiB and
one second, even when a peer continues sending. Acceptance stops at the selected
session count, not an invented idle timeout.

## Retry and recovery compatibility

The raw retry selector is unchanged: its input is the existing domain prefix,
exact repository path, separator, and original command-section bytes including
pkt-line framing. PACK representation is excluded. Admission alone derives the
transaction identities. Changing capabilities, expected-old values or original
wire order changes the raw selector; a high-level client rebuilding a different
push is not necessarily retrying the same request.

`recover_receive_session_in` can recover guarded non-atomic raw sessions from
the original synthesized key under the operator principal. Atomic sessions use
`recover_transaction_in`. The key is **32 binary digest bytes**, not the UTF-8
bytes of its printed hexadecimal form. The native API accepts those exact bytes;
local outcome CLI hex input supports exact per-transaction/per-command selection.
Do not put a hex rendering into an HTTP Idempotency-Key header and claim it
selects the same key. Whole-session HTTP recovery remains ASCII-header scoped.

The fault regression recovers a real committed first command and an undecided
second command after restart, then retries through the typed HTTP adapter using
the same binary key. The typed adapter test is not a claim about header encoding.

## Remaining compatibility entry points

The binary dispatch now uses `guarded_git_server::run`. Historical library calls
to **`fgit_cli::run` with `serve`**, **`OneNode::serve_git_daemon_*`**,
**`receive_loopback_pack_durable_in`**, and the old generic/basis-bound admission
entry points have not been redirected. Embedders must choose the guarded APIs;
those historical paths still need their coordinated error/signature migration.
This pass does not apply or complete the earlier receive-unification bundle.

## Focused verification

```sh
cargo test -p fgit-node --lib smart_http::receive_session::daemon
cargo test -p fgit-node --test guarded_git_daemon --test receive_transport_parity
cargo test -p fgit-node --test smart_http_non_atomic --test smart_http_atomic \
  --test smart_http_session_binding --test receive_session_http
cargo test -p fgit-cli --bin fg guarded_git_server
cargo test -p fgit-cli --test guarded_serve
```

The tests use actual TCP, native quarantine and embedded authority, including
mixed outcomes, duplicate clients, publication during upload, restart, partial
outcome recovery, invalid packs, disabled receive, and the actual `fg` binary
routing. Their committed assertions have **not** been compiled or executed in
the editing environment. Independent checks against pinned Git 2.47.3 exercise
fixture PACK bytes and success/ERR response grammar only, not FrankenGit.

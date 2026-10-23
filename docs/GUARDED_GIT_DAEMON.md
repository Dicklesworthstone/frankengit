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

`--pack-max-expanded-mib <non-zero>` sets the selected-pack write envelope
(frankengit-e6jj). This is the total expanded object bytes one upload-pack
response may emit, 4096 MiB by default; the 32 MiB per-object ceiling is
separate. The pack streams (frankengit-8xyq). Each object is loaded, verified,
delta-searched against the preceding candidates and written to a private
scratch file under the storage root, unlinked as soon as it is created (on
Unix; elsewhere it is removed when the response ends), and read back to the
client in bounded chunks. Server memory is the candidates, not the pack: at
most 32 entries and 128 MiB of their bodies
under the served `git-pack-compressed-v5` profile, plus their search indexes,
the current object and its at most two client-held bases. The envelope bounds
work and scratch disk. It was 128 MiB, and a memory bound, while packs were
built in memory.

Measured with a release fg of 25ba1840 built on ba7f09a3, on one commit of
1 MiB random blobs, one `fg serve` session per clone, default flags:

| repository | clone | received pack | server peak RSS |
| --- | --- | --- | --- |
| 160 MiB | 18.5-18.7 s | 167,804,125 B | 102-110 MiB |
| 500 MiB | 57.1 s | 524,387,130 B | 108 MiB |

Before this change the 160 MiB clone needed `--pack-max-expanded-mib 512` and
peaked at 537-540 MiB (release fg 9f15cfb5), taking 18.8 s at the same host
load. Every 160 MiB clone, before and after, received the identical pack
(`pack-6ecbf0f4...`). This is one corpus shape: its blobs do not delta, so the
window holds bodies and indexes but finds no bases. The byte bound itself is
exercised by the opt-in XL lane (`first_push.sh`, `FG_E2E_LARGE_PUSH=1`): 24
blobs of about 14 MB, a 314 MiB count window, clone under the default envelope
(FG-HH37-PUSH-036, -058).

Before the ref advertisement, every session walks the visible closure of the
advertised refs. It reads and verifies every commit, tree and tag body, but
reads only the stored header (kind and exact size) of a blob reached through
a tree or tag (frankengit-8xyq). A blob body is read and verified only when a
pack selects it. The envelope bounds the commit, tree and tag bytes of this
walk. So `ls-remote`, and a fetch that needs only a small pack, do not depend
on blob bytes: a repository larger than the envelope is still advertised and
incrementally fetchable.

A request whose pack exceeds the envelope is refused after the advertisement,
on the side band. git prints it and then stops, for example under
`--pack-max-expanded-mib 128`:

```text
remote: pack needs 134217845 bytes of objects, over this server's upload envelope (128 MiB of objects); the operator can raise it with fg serve --pack-max-expanded-mib
fatal: early EOF
```

The first figure is where the writer crossed the limit, not the full pack
size.

A repository whose commit, tree and tag bytes alone exceed the envelope is
refused before any advertisement, with one `ERR` packet such as, under
`--pack-max-expanded-mib 128`,
`ERR repository exceeds this server's upload envelope (128 MiB of objects, 32 MiB per object); the operator can raise it with fg serve --pack-max-expanded-mib`.
A stock client prints it as `fatal: remote error: ...` (git:// and SSH).
Smart HTTP refuses that case with its existing status mapping and does not
yet carry the message.

`--processing-timeout-secs <non-zero>` sets the server-work budget a push gets
after its pack trailer: quarantine, delta resolution, policy and publication.
The default is 300 s, and the session flags never extend it. The ingress clock
(`--session-timeout-secs` plus its bounded admitted-byte extension) ends at the
complete trailer. Processing then gets its own full finite allowance, including
writer-capacity wait, quarantine, policy and authority work. Database contexts
inherit the remaining processing time rather than restarting it. A long upload
needs enough ingress time; a long admission needs enough processing time.
The final response has one fresh finite network allowance. Expiry after
admission starts preserves an unknown outcome unless authority supplies the
actual terminal result; retry identical commands or recover their original key.
Receive used to place each object
with its own file and directory fsync, about 20 ms per object, so at the
defaults a 24,000-object push was refused at about 300 s with
`CancellationInProgress`. It now stages through batched placement, and syncs
each batch's staged files concurrently (frankengit-pc9g). A 6,000-object push
takes about 5 s, and a 24,000-object push 17.5 s at the defaults (release-perf
`fg`, development host).

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

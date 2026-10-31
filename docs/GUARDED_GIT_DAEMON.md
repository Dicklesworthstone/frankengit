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

`--pack-max-blob-mib <non-zero>` sets the per-blob serving/export ceiling on
`fg serve`, `fg serve-http`, `fg serve-ssh` and `fg export`. For example,
`--pack-max-blob-mib 96` permits selected blobs up to 96 MiB; the default remains
32 MiB. All paths use the same checked decimal parser and refuse zero,
malformed, duplicate, missing or overflowing values before opening the node.
The selected byte count must also fit the finite compression-work envelope.

Embedded callers use `NodeConfig::with_selected_pack_blob_limit(maximum_blob_bytes)`,
for example `.with_selected_pack_blob_limit(96 * 1024 * 1024)`. This separate policy
also admits the corresponding stored file plus bounded envelope/framing bytes,
without widening eager-import, receive, or metadata parser ceilings. The total
pack envelope (`--pack-max-expanded-mib` or `with_selected_pack_byte_envelope`)
remains independent.

Above 32 MiB, that explicit configuration selects `git-pack-compressed-v6`, its
thin variant, or `git-pack-compressed-no-delta-v2` according to the negotiated
request. A selected blob above 32 MiB is read from one checked file descriptor
and compressed in fixed 16 KiB input chunks. Its exact length, native Git
identity and stronger payload commitment must all verify at EOF before the
private pack can be promoted or sent. Each read checks both the outer session
and Database budget; only the completed verified body earns read-work credit.
Large blobs are whole base entries, clear the delta candidate window, are not
retained as client-held thin bases, and bypass compressed-entry caching. Small
objects preserve the previous profile's bytes; commit/tree/tag and untyped
ref-root reads retain the original buffered limit, at most 32 MiB. Independent
pack size, output, compression-work and deadline limits still refuse explicitly.

`--pack-cache-mib <0..65536>` sets a separate byte budget for retained pack
computations, 64 MiB by default (frankengit-grvl). The same flag is accepted by
`fg serve-http` and `fg serve-ssh`. Zero disables retention. A service and its
independently reopened request children share the cache; a process restart
starts cold. Repeated or overlapping fetches can reuse deterministic compressed
entries and delta outcomes, while every request still authenticates its own
authority head and computes its permitted object selection. The cache does not
make an object or base reachable or bypass work limits. Its capacity is separate
from each request's delta window and output spool, and is not a total process
RSS limit. `NodeConfig::with_pack_cache_bytes` exposes the same control to
embedded callers, and `OneNode::pack_cache_stats` reports shared cache activity.
No new wall-time, CPU, or peak-RSS improvement is claimed here.

Network upload-pack also supplies verified tree-entry basename hints to the
existing pack ordering policy. Related versions can then share the bounded
delta window even when their native IDs are far apart. This adds no blob-body
reads and does not change the selected object set, limits or local-export
ordering. Served pack bytes can change. The
[visibility contract](UPLOAD_PACK_VISIBILITY_AND_TAGS.md#verified-basename-grouping-for-served-packs)
defines raw-byte hashing, multiple-name ties and the component-only evidence.
It does not establish a new cold-clone throughput result or persistent reuse
of stored deltas.

The following measurements predate this computation cache:

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
incrementally fetchable. The per-object payload ceiling also applies only
when a pack selects a blob reached through one of those typed edges. An
oversized blob therefore does not prevent `ls-remote`, an up-to-date fetch,
`blob:none`, or a `blob:limit` filter that omits it. A full clone or an explicit
lazy want for that same blob still receives the typed object-size refusal
before any pack bytes are emitted. Header reads remain independently bounded
by the fabric's stored-file and envelope profiles and verify namespace, OID,
kind and exact stored length. Commit, tree, tag and untyped ref-root bodies
retain their existing parsing limits. Filtering changes no retention root.

After negotiation, Git, SSH and HTTP prepare the exact requested object set
from the verified visible graph before reading its bodies (frankengit-1tl9).
Want/have subtraction, shallow boundaries, filters, explicit lazy wants and
include-tag handling all run before the aggregate and per-object checks.
The same private selection drives pack construction. A refused request earns
no extra work time, and a filtered fetch earns none from objects it omits.
Blob bodies still require complete native and fabric verification before any
completed pack is sent.

A request whose pack exceeds the envelope is refused after the advertisement.
Native Git and SSH hold the final negotiation/packfile prefix until preparation
succeeds. A public resource failure is one plain Git `ERR` packet before that
prefix, without depending on progress output or sideband negotiation. The
aggregate diagnostic retains this form under `--pack-max-expanded-mib 128`:

```text
ERR pack needs 134217845 bytes of objects, over this server's upload envelope (128 MiB of objects); the operator can raise it with fg serve --pack-max-expanded-mib
```

The byte count above is illustrative. Network preflight reports the complete
selected expanded total; it does not need to read the selected blob bodies to
discover that refusal. Intermediate negotiation responses remain immediate,
including when the client waits for one before sending the next round.

An admitted selection also earns a finite work allowance from its expanded
bytes. The work clock is the original base plus
`min((admitted_client_bytes + selected_expanded_bytes) * per_byte, max_extension)`.
The existing session flags select the base, rate and cap. Repeating a selection
does not accumulate duplicate credit; the largest admitted selection and
ingress share one cap. The Transfer context keeps its remaining poll/cost
quotas and priority. A stopped, cancelled or expired context cannot be revived,
and flat scaling still has no extension. Successful preflight does not remove
the pack-output, compression-work, memory-window or storage limits.

A selected-pack work timeout or build refusal has one fresh, finite terminal
write allowance on Git and SSH, bounded by the configured base session timeout.
It can deliver the diagnostic after computation expires without reopening Git
input or computation. SSH can accept the control packets needed to drain that
write window within the same allowance; retries do not restart it. HTTP already
starts a separate finite response phase at its first write.

These changes address late limit discovery and the clone work-clock mismatch.
They do not make cold clones reuse stored pack representations or establish a
new throughput/RSS result for the original large repository in frankengit-1tl9.

For selected-pack failures after negotiation, Smart HTTP sends one bounded Git
ERR packet in an HTTP 200 upload-pack response. This covers the selected-object,
pack-output and delta-window limits, named Database/Transfer exhaustion, and the
pack-work session timeout. Quiet clients can display the cause without requesting
progress output. An aggregate size refusal names the upload-envelope option; a session
timeout names the session and work-scaling options. No negotiation prefix or pack
byte precedes this error. The original typed refusal remains the server result
even if the peer has gone away or the bounded response write fails.
Storage errors, object identifiers and authority details do not cross this
diagnostic boundary. Cancellation and the configured response-size limit still
apply.

Git and SSH use that same public resource allowlist and bounded text, before
the final prefix. Their existing terminal-write allowance also covers an ERR
after work expires. Unclassified failures keep the transport's existing
behavior; arbitrary generic pack-builder text is not promoted to this ERR
path. Authored native regressions cover both hash formats, every supported protocol,
raw/sideband clients, exact successful pack bodies, unchanged authority,
intermediate negotiation and failed diagnostic writes. The native node and SSH
cases have not been executed for this change. Eleven existing generic transport
and clock tests passed in isolated byte-identical-source validation, including
loopback TCP tests. That result does not execute native resource classification,
OneNode or SSH, or establish a pinned-client or large-history performance result.

HTTP upload work also uses the same bounded, sticky peer-reset probe as raw Git.
It checks at most once per 100 ms without consuming queued input. An observed
socket reset/error cancels subsequent work checkpoints and stays cancelled;
ordinary EOF remains inconclusive because clients may finish the request with
a write-side half-close and continue reading their pack. The finite work
deadline still bounds that case. Receive admission and outcome recovery retain
their separate cancellation semantics.

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
connections**, with at most **16,384 non-atomic commands** or **4,096 atomic
commands** per receive. The parser enforces both ceilings before retaining a
PACK body, including stricter operator-selected limits. Session/concurrency
defaults remain one. Command-prefix retention is bounded to 4 MiB; PACK reads use 16 KiB scratch
chunks. The native scanner and quarantine retain their own bounded storage;
this is not disk-spooled admission or a zero-copy claim.

The durable non-atomic receive coordinator publishes up to 64 independent
command decisions per authority-head CAS, with a 1 MiB canonical batch-byte
bound. Commands retain their individual seals, transaction IDs and outcomes,
and successful earlier commands affect later commands in original wire order.
An atomic receive still makes one all-or-nothing decision. Sessions through
4,096 commands retain their v1 identity and 1 MiB recovery carrier; larger
sessions bind two to four canonical chunks and the full wire-order permutation
in a 4 MiB v2 carrier. This unsealed binding is not another transaction or state
authority. Replicated non-atomic push-option work is capped at 16 MiB, including
retained headers for empty options; long names or large option lists can reach
a byte/work limit before the command-count ceiling. A known pre-admission count
refusal reports the observed minimum, actual configured maximum and a remedy
in a Git `ERR` packet. An interruption after admission starts retains unknown
outcomes for any commands without authenticated terminal evidence.

The node's default authority profile permits 262,144 immutable bodies, with
all key/body/count checks still enforced. This fits the staged-body bound for
one fresh uncontended 16,384-command receive. Existing history and speculative
CAS work share that capacity. `NodeConfig::with_authority_limits` selects a
different finite profile; command capacity does not promise enough remaining
storage, deadline or work budget for every request.

## Receive sequencing

The existing parser first verifies the bounded greeting and exact repository
route. Receive then requires the configured principal, shared principal quota,
and an intake-eligible cell. Discovery uses the existing direct-ref projection
and current canonical visibility; it does not require a resolvable fetch HEAD.

Commands and packs feed the real native receive machine. A complete PACK trailer
ends ingress without waiting for client EOF. Bytes beyond the trailer in the
same read refuse. EOF before the trailer, corruption, invalid commands and
resource exhaustion do not yield a successful handoff.

After ingress, the node starts independent finite server-work clocks and
finishes bounded structural pack validation before acquiring writer capacity.
DEFLATE decoding, entry framing and the native pack checksum therefore run
outside the one-writer gate. A non-cloneable `ReceiveQuarantine` owns the checked
entries while the request waits; raw pack bytes have been discarded. Corruption
is refused before waiting for a writer, and cancellation before handoff drops
that private quarantine without staging objects or creating a session seal.

Only after acquiring the permit does the node select a **fresh authenticated
authority basis** for native object identity, visible-source connectivity and
policy validation. The earlier advertisement is not reused as the validation
witness. An intervening publication during structural work or the capacity wait
therefore does not by itself stale the validation basis. Publication admission
still rechecks the exact basis and current policy. Immutable object staging and
authority writes remain inside the existing writer envelope; this split is not
cross-session combining or a claim of measured throughput improvement
(`frankengit-root-doctrine-x2mv.4.9`). HTTP and the shared raw Git/SSH coordinator
use the same native quarantine owner.

Structural preparation uses the existing per-pack input, expanded-byte, object
and work ceilings and the server's `--max-in-flight` bound. With multiple
clients enabled, more than one waiting request can retain decoded entries;
operators must budget that memory against the expanded-byte envelope, not only
compressed input size. The default remains one in-flight client.

`admit_receive_session_durable_in` owns all command decisions. Non-atomic pushes
bind their complete semantics and each wire-order child key before publication,
and persist the existing recovery descriptor. Continuation retains the
validation witness and advances across complete verified publications belonging
to this session, with every command's own terminal identity preserved. A retry
recovers already decided commands and publishes only the remainder. Staging
failure before a group's CAS publishes none of that group; an interruption
between groups does not undo earlier decisions. Atomic pushes remain one
sealed transaction.

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

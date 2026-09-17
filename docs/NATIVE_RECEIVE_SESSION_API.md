# Guarded native receive sessions

`OneNode::receive_pack_session_durable_in` accepts native receive-pack bytes
without an HTTP envelope. It shares the continuing coordinator with Smart HTTP.
This is an embedding API, not an authentication service. The subsequently added
[guarded raw TCP service](GUARDED_GIT_DAEMON.md) uses the same admission entry
point and is now selected by the `fg serve` executable.

## Entry points

- `receive_pack_session_durable_in` owns native parsing, production quarantine,
  and session admission. The caller supplies a node-owned authenticated
  `MaterializedAdmission`, `ReceiveContext`, parser/admission limits, the native
  bytes, a cancellation callback, and an authenticated `LoopbackReceiveSession`.
- `admit_receive_session_durable_in` accepts an already validated private
  `BasisBoundValidatedReceive` and owns the node publication gate plus the same
  continuing coordinator. The embedding owns authentication and intake/quota
  checks before this lower-level entry point.

The public error family retains the existing `NodeSmartHttpRefusal` name for
compatibility. Native calls do not construct HTTP requests or responses.
Smart HTTP's existing internal entry point now delegates to the public admission
entry point; it no longer owns a separate copy of those node-level gates.

## Identity and publication

Use the original authenticated tenant/repository/principal scope and client key.
The complete native command list and its original wire order are significant to
non-atomic session retry binding. The coordinator preflights the whole request
and every child key before the first child is sealed or published, and persists
the existing recovery descriptor. It does not mint new transaction identities
or introduce another descriptor format.

Every command retains the validator's authority-basis witness. Between commands,
continuation accepts only the session's verified preceding decision. A refusal
can therefore be followed by valid commands without erasing the witness after a
commit. An unrelated concurrent publication does not authorize stale evidence.
Atomic input remains one transaction and one terminal decision.

A raw session can be retried over HTTP, and vice versa, only when the principal,
original key, semantic commands, options and original wire order match. Changing
transport framing does not create a fresh operation. Whole-session recovery is
available through `recover_receive_session_in`; atomic input uses the ordinary
`recover_transaction_in` API. Those recovery calls read existing evidence and do
not require a replacement pack. Binary native keys must not be confused with
the bytes of their printed hex encodings in ASCII-only HTTP headers.

## Intake and cancellation

Authentication precedes quota, cell-intake and format checks. The callback and
authority budget are checked before retaining native bytes. Input is fed to the
existing receive machine in at most 16 KiB slices, with a checkpoint before each
slice; no second whole-request buffer is introduced. The native machine retains
its own bounded transaction quarantine. The transport remains responsible for
bounding any input buffer it constructs before calling this API.

Full framing and native validation precede session admission. Invalid/truncated
packs do not create a session descriptor. Admission limits can fail after valid
objects have been staged; staging alone is neither publication nor a descriptor.
StagingOnly may retain validated work but cannot pass the publication gate.

During awaited admission, a stopped callback cancels the owning authority
context. The same future is still driven to its actual result. There is no early
return from the polling closure and no cancellation-by-dropping shortcut. A
terminal result wins over late cancellation. Callers must own this future through
completion, and run synchronous native validation on their runtime's appropriate
blocking/work lane. This API does not add an executor or background task.

## Interrupted results and transport reporting

`ReceiveInterrupted` retains the transaction mapping, authenticated completed
wire-order prefix, and exact underlying admission failure. Commands not in that
prefix have unknown outcomes: an interrupted authority operation may already
have published. An empty prefix is not evidence that no command committed.

Do not turn this error into an all-ref rejection report. In particular, sending
`ng` for a ref with a known committed outcome contradicts the authority result.
A transport must preserve ambiguity, retain the error for recovery, and avoid
writing a second response after any final response has begun. This embedding API
returns structured results; the guarded TCP binding owns its network response
and emits a fatal unknown-outcome record for interrupted admission.

## Deliberate migration boundary

The `fg serve` executable now selects `serve_guarded_git_daemon_bounded`, whose
receive lane invokes the shared guarded admission entry point. Upload-pack
continues through the existing native implementation. See
[the raw-service contract](GUARDED_GIT_DAEMON.md) for its caps and trust boundary.

Historical library calls to `fgit_cli::run` with `serve`, the old
`OneNode::serve_git_daemon_*` methods, `receive_loopback_pack_durable_in`, and the
generic/basis-bound admission entry points are NOT redirected. Embedders must
select the guarded APIs explicitly. Their full coordinated migration, and the
earlier exact-blob-pinned migration bundle's rebase, remain separate work.

## Verification

The committed regression targets are:

```sh
cargo test -p fgit-node --test receive_transport_parity --test guarded_git_daemon
cargo test -p fgit-node --lib smart_http::receive_session
cargo test -p fgit-node --test smart_http_non_atomic --test smart_http_atomic \
  --test smart_http_session_binding --test receive_session_http
cargo test -p fgit-cli --test guarded_serve
```

The parity tests exercise actual production quarantine and embedded authority in
both native hash formats, including mixed create/delete sessions, cross-adapter
retries, changed-session rejection, atomic refusal, restart, malformed packs,
limits and early authentication/cancellation. The bounded-intake unit tests
exercise the native framing machine, not a substitute parser. The TCP regression
includes a real interrupted committed prefix; the executable test launches `fg`.
These tests have not been compiled or executed in the editing environment because
its Rust toolchain is unavailable. Independent Git fixture/protocol checks are
not FrankenGit runtime or admission verification.

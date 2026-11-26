# Legacy fetch negotiation rounds

The shared `fgit-wire::LegacyUploadPack` state machine handles Git protocol
v0/v1 fetches on raw Git, SSH and HTTP. A connection can carry several have
batches before the client asks for its pack. The ordinary Git 2.54.0 client
starts with a window of 16 haves, sends a flush, and pipelines another window
before waiting for a reply. Refusing that first have flush prevents a valid
incremental fetch from reaching `done`.

These rules follow the pinned Git 2.54.0 source at
`94f057755b7941b321fd11fec1b2e3ca5313a4e0`:
[`fetch-pack.c::find_common`](https://github.com/git/git/blob/94f057755b7941b321fd11fec1b2e3ca5313a4e0/fetch-pack.c)
and
[`upload-pack.c::get_common_commits`](https://github.com/git/git/blob/94f057755b7941b321fd11fec1b2e3ca5313a4e0/upload-pack.c).
The [Git pack protocol](https://git-scm.com/docs/pack-protocol) specifies the
same exchange.

## Connection behavior

The want-section flush moves the machine into have negotiation. It emits
actual requested shallow updates when a provider is enabled. It does not
emit an early negotiation NAK.

| Input | Plain ACK mode | Multi-ACK modes |
|---|---|---|
| First authorized common have | One `ACK <oid>` immediately | `ACK <oid> continue` or `ACK <oid> common` |
| Later authorized common have | No additional ACK | Another mode-specific ACK |
| Have-batch flush | `NAK` while no common object is known; otherwise silent | `NAK`, optionally preceded by a justified detailed `ready` |
| Explicit `done` with a common object | Pack handoff; the first ACK already answered negotiation | Unqualified `ACK <last-common>`, then pack handoff |
| Explicit `done` without a common object | `NAK`, then pack handoff | `NAK`, then pack handoff |

An ordinary have flush leaves a connection waiting for another batch or
`done`. It preserves the same wants, ordered unique haves, options and
immutable repository view. A complete packet stream at EOF is not proof of a
completed fetch: the connection adapter still requires terminal negotiation
before serving a pack.

A flush before any want retains its separate advertisement-only meaning.
Delimiter and response-end markers remain invalid in legacy negotiation,
and packets after a completed or ended session refuse.

## Negotiated no-done

A caller may advertise `no-done` with detailed multi-ACK. The state machine
finishes at a have flush only when every exact wanted tip is already in the
client's have set and is independently common in the authorized repository
view. Shallow, deepen, deepen-since and deepen-not controls prevent this early
handoff. This conservative test does not infer reachability from an unrelated
common object or from the client's assertion alone.

When ready, the response is detailed `ACK ... ready`, `NAK`, an unqualified
final ACK, then one pack handoff. Without `no-done`, the ready response still
waits for explicit `done`. Native raw Git/SSH capability advertisement is
unchanged by this correction.

## HTTP and outer envelopes

Each HTTP request owns a fresh machine. Its have flush finishes that request's
negotiation round without requiring a pack. The caller checks
`finish_stateless_http_round` against the complete body before releasing
output. An initial resolved shallow exchange can also end at its want flush;
an arbitrary wants-only or unterminated have stream cannot end by EOF.

`git fetch-pack --stateless-rpc` adds an outer pkt-line envelope around these
inner HTTP body bytes. `StatelessRpcUploadPack` validates the outer terminator
and the inner round independently. The outer flush never invents an inner
flush or `done`. A captured initial shallow request therefore returns its
provider's shallow information without requesting a pack.

## Scope and resource limits

The repository's negotiation checkpoint runs before each legacy transition.
This includes empty rounds, unknown haves and the final pack handoff. A
refused checkpoint produces no ACK or pack event and does not install the
packet's wants, haves, capability flags or terminal state. The adapter retains
its original request deadline and cancellation scope.

Have limits remain cumulative over the connection. Duplicate haves retain their
original order and do not spend another distinct-object slot. Decoder calls
retain their existing packet-count and pending-byte caps; flushes do not renew
the cumulative want/have limits or the session deadline. No advertisement,
authorization rule, pack selection, canonical state or publication authority is
added by a negotiation response.

## Regression coverage and evidence boundary

`crates/fgit-wire/tests/legacy_connection_negotiation.rs` covers both hash
formats and both legacy versions with 16-have windows, repeated unknown
rounds, immediate single ACKs, multi-ACK completion, conditional no-done,
multiple wanted tips, shallow controls, cumulative limits, refused live-scope
checks, fragmented/pipelined bytes and outer-envelope boundaries. Existing
wire-protocol, object-format and large-have-set expectations use the same
pinned ACK timing. The stateless HTTP and shallow-response suites preserve
their independent round contracts.

At base `b428f1ed25425086da12d449a6304ac5d6176426` plus this change,
`cargo test --locked -p fgit-wire --all-targets --jobs 2` passed 471 tests with
zero failures and six existing ignored oracle-dependent tests. All 13 new
legacy-negotiation regressions executed. The run used the repository's pinned
`nightly-2026-08-31` toolchain, with debug information and incremental compilation
disabled to fit the bounded temporary build workspace. Formatting and diff
checks also passed.

The added expectations were checked against the pinned source; this run did
not execute a new stock-Git differential transcript or raw/SSH socket test.
No prior transport or Tier A qualification count is extended by these
constructed native wire tests.

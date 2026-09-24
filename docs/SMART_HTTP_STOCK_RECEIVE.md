# Stock Git receive discovery and retry URLs

Owning work: `frankengit-root-doctrine-x2mv.4.8`. This is the stock-receive
compatibility slice, not closure of the serving-lifecycle or full transport bead.

## Native listener path

An authenticated GET to `{repository-route}/info/refs?service=git-receive-pack`
without an explicit `Idempotency-Key` receives a bodyless, non-cacheable 307
redirect to:

```text
{repository-route}/.fgit-receive/{64-lowercase-hex-characters}/info/refs?service=git-receive-pack
```

The identifier comes from 32 fresh bytes of Asupersync OS entropy. The ordinary
Git client retains that discovery-selected base for its subsequent receive RPC.
The adapter recognizes only receive discovery and receive RPC below that base,
normalizes the repository route, and supplies `fg-http-v1-{identifier}` as the
bounded retry key. The redirect also reports this key in its `Idempotency-Key`
response header. Other endpoints below an attempt URL are refused.

Every redirected discovery and RPC authenticates independently. The identifier
is public routing/idempotency data, not a bearer capability, an approval, a
policy snapshot, or an authority receipt. Revoked credentials and disabled
receive service still refuse. Existing credential-file incarnation checks,
mutation quotas, pack quarantine, native semantic sealing and authority-head
publication remain in force. Forwarded headers confer no authority.

Explicit-key clients retain their original route and behavior. On an attempt
URL an explicit key must match the URL-derived key exactly; conflicting,
duplicate, empty and hop-by-hop keys are refused. Original and synthesized
headers both obey byte/count limits. Body bytes and transfer framing are copied
unchanged; there is no new pack buffer or content-derived transaction key.

## What constitutes a retry

Reusing the same attempt URL and same authenticated principal retains the
same native retry namespace across reconnects and listener restarts. No mutable
in-memory session table must survive. The canonical admission protocol, not the
URL adapter, detects a different sealed request under an existing key.

A fresh discovery is a new attempt, even when the eventual ref commands happen
to be identical. This is essential for create/delete/recreate: the later create
must not recover an old successful create without actually recreating the ref.
Starting a new `git push` invocation normally starts new discovery; it is **not**
automatic recovery of the preceding invocation's terminal decision. Recovery of
that exact decision requires retaining its attempt URL or reported key and
using the existing authenticated outcome/retry interfaces.

This listener remains an operator-selected loopback profile. This change does
not add TLS, organization IAM, unlimited serving, or a protocol-v2 push service.
It does not change the native transaction identity formula or any canonical
schema.

## Verification

Focused adapter, authorization and resource tests:

```sh
cargo test -p fgit-node --lib smart_http::server::stock_receive
```

The native integration campaign requires an already-built `fg` and drives its
actual HTTP listener, not a substitute server:

```sh
FG_BIN=/absolute/path/to/fg scripts/e2e/suites/node/stock_http_receive.sh
```

For each SHA-1/SHA-256 repository it covers ordinary create/delete/recreate
without an Idempotency-Key header, distinct discovery attempts, independent
authentication, conflicting-key refusal, delete-only publication, restart and
exact terminal replay, atomic multi-ref push, clone-back identity/fsck, and
read-only refusal. The key replay twin recreates the branch first: retrying an
old deletion must recover its earlier acknowledgement without deleting the
newly recreated branch. Every listener must drain. Failure artifacts are
retained, and the shared harness records the suite's terminal result.

The separate `scripts/tests/smart_http_discovery_oracle.py` uses
`git-http-backend` only in a development test. It establishes the Git client's
redirect behavior, **not** FrankenGit server or canonical-admission behavior.
At introduction, its exact source blob `df44672653f36d30c468888082ad19094b708cc4`
passed with installed Git 2.47.3 both normally and under Python `-O`; each run
performed three successful pushes through three distinct attempt URLs. These
are unpinned client observations, not pinned conformance evidence.

The introducing session had no Rust toolchain. The Rust tests, native campaign,
rustfmt, Clippy and complete verification lanes were not run. The native
campaign must pass at an explicitly recorded source revision and binary digest
before this slice is credited as verified. No bead closure is claimed here.

# Protocol-v2 negotiation without a pack

Native upload-pack advertises the Git protocol-v2 `wait-for-done` feature
through raw Git, the shared SSH Git-command path and smart HTTP. This enables
the request shape used by an ordinary Git client's negotiation-only operation:

```sh
git -c protocol.version=2 fetch --negotiate-only --negotiation-tip=HEAD origin
```

The client sends `command=fetch`, `wait-for-done` and its bounded `have` list,
without any `want`. The server returns an `acknowledgments` section followed
by a flush. It acknowledges only client-supplied IDs common to the selected
visible closure, in first-seen request order. Repeated haves do not repeat
ACKs. If none are common, the response contains `NAK`. Hidden-only, deleted-only
and never-stored IDs are indistinguishable and are not echoed.

## Request and session behavior

A waiting request never emits `ready`, a shallow or wanted-ref section, or
a pack request. This also applies when the client supplied wants and every
wanted tip is already common. A waiting request can start pack construction
only when it includes `done` and at least one authorized want. The bounded profile
continues to refuse `done` without wants; it does not invent an empty pack for
a negotiation-only request.

V2 arguments can place haves before `wait-for-done`. The complete no-want
request is validated before any acknowledgment escapes. Missing negotiation
capability, duplicate `wait-for-done`, invalid OIDs and resource exhaustion
remain typed refusals.

A persistent Git/SSH connection may carry several independent negotiation
commands and then end, or send a fresh normal fetch. Each completed waiting
command clears its wants, wanted refs, haves, shallow controls, filter,
capabilities and pack options. The packet decoder remains intact, including
a partial following command. EOF after completed negotiation is successful;
an incomplete following command or frame still refuses.

Each HTTP RPC remains one complete request. Its body and trailing-byte
validation finish before a response is available. A subsequent RPC selects
a fresh authenticated repository view. A persistent connection retains its
one immutable upload view, as other commands on that connection already do;
this is not an immediate revocation guarantee for established sessions.

## Authority, resource and cancellation boundaries

Negotiation reuses the same `UploadPackRepository::is_common` predicate as
ordinary fetch. Object-store presence, prior admission and a client-supplied
OID never confer disclosure permission. It publishes no repository state and
does not acquire the pack-materialization path.

Existing have-count, OID-width, packet and aggregate response ceilings apply.
A live repository checkpoint runs while accepting haves, while checking each
ACK candidate and before completing a response, including empty/unknown-only
rounds. Visibility wrappers delegate the checkpoint to the original owner;
native views retain their existing session deadline. Waiting rounds do not
renew it.

## Source references and verification scope

The implementation follows the protocol's
[wait-for-done contract](https://github.com/git/git/blob/v2.54.0/Documentation/gitprotocol-v2.adoc)
and the pinned client's have-only request in
[`negotiate_using_fetch`](https://github.com/git/git/blob/v2.54.0/fetch-pack.c).
This is the upload-pack/transport scope of plan section 18 and FG-018, with
cross-transport acceptance remaining under the existing transport campaign.

Regression sources are
[`v2_negotiation_only.rs`](../crates/fgit-wire/tests/v2_negotiation_only.rs)
and the native
[negotiation tests](../crates/fgit-node/src/upload_visibility/tests/ref_in_want/negotiation.rs).
They cover both native hash formats, packet fragmentation, successive rounds,
exact final pack bodies after a waiting request, retained hidden/deleted
objects, restart, HTTP visibility changes, inclusive resource limits and live
cancellation checkpoints. Source review, tree-sitter Rust syntax parsing and
`git diff --check` completed. Native tests were authored but could not be compiled
or executed: the initial environment lacked a required offline dependency,
and the restored execution environment has no Rust toolchain. Syntax parsing
does not type-check or execute Rust. These tests do not add to historical
executed compatibility totals or establish a native or differential passing gate.

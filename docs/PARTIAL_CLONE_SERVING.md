# Partial-clone serving through the native node

The bounded raw Git-daemon profile now applies partial-clone filters to the
actual outgoing pack and supports authorized lazy object requests. This extends
[the exact-head visibility and tag boundary](UPLOAD_PACK_VISIBILITY_AND_TAGS.md);
it does not add smart HTTP, SSH authentication, shallow history or a new
canonical storage format.

## Client behavior

Against an initialized, imported and serving node, ordinary Git clients may use:

```sh
git -c protocol.version=2 clone --no-checkout --filter=blob:none \
  git://127.0.0.1:9418/22222222222222222222222222222222.git partial
```

The same bounded service supports protocol v0/v1. Git records received filtered
packs as promisor packs on the client. Subsequent explicit object requests use
normal upload-pack negotiation and the native pack writer; there is no foreign
Git process in production and no alternative object-disclosure route.

The server supports `blob:none`, `blob:limit=<n>`, `tree:<depth>` and `combine:`
conjunctions, including percent-encoded compound terms. Blob-size suffixes
`k`, `m`, and `g` (and uppercase forms) use checked binary scaling. Oversized,
overflowing, malformed, over-nested or over-budget filters are typed refusals.
Sparse filters and shallow controls do not silently fall back to full packs:
unsupported production semantics remain typed refusals. Shallow support is not
advertised by this profile.

## Selection and authorization

A private complete visible-graph proof retains the verified native kind, body
length and local edges while it performs its existing bounded traversal.
Filtering uses those immutable facts, not a physical-store inventory or a
caller-provided graph. The filter does not create access permission.

After ordinary want-minus-have selection, the server applies the requested
predicate and then the negotiated `include-tag` expansion. Automatically followed
tags therefore cannot reintroduce a referent omitted by the filter. Blob limits
are exclusive: a limit of N includes blobs smaller than N. Tree depth uses the
minimum distance from all selected commit root trees, with each root at depth
zero; a longer path encountered first cannot hide a shared shallow subtree.
Compound filters intersect their predicates.

Explicitly requested objects bypass omission predicates, matching Git's
provided-object semantics. A partial client's `have` commit does not prove that
an explicitly requested blob or tree is present. The selector restores such
lazy object roots (and the required local subtree for a tree request), but only
inside the already-verified visible scope. An explicit have of the same object
still excludes it. Commit history is not blindly restored as a lazy subtree.

Legacy advertisements include `allow-reachable-sha1-in-want` and `filter`.
The historical `sha1` spelling applies to the negotiated native object format,
including SHA-256. The legacy wire machine admits a non-advertised want only
when the server supplied this capability **and** the repository authorizes that
identity. Client capability text cannot grant itself access. Without the server
capability, the existing `WantNotAdvertised` behavior remains intact.
Protocol v2 advertises `fetch=filter` only for adapters whose supplied service
capabilities enable filtering.

Every new connection selects current visibility again. A prior partial clone
is not perpetual permission to retrieve an object after its last visible ref
is removed. Physically retained, historically admitted, hidden-only and foreign
gitlink objects do not acquire disclosure authority through filters or promises.
Canonical admission and retention remain complete and unchanged. No additional
signed omission manifest is transmitted by the standard Git wire protocol;
this change does not claim a durable promise service independent of current
repository authorization.

## Bounds and evidence

Selection checks cancellation and work/node bounds and installs its output list
only after the whole selection succeeds. Pack planning and writing retain their
native checksum, selected-object, byte, delta and deadline limits. No dependency,
lockfile, schema or Beads closure is introduced by this implementation.

The existing profile still eagerly verifies the complete visible graph before
advertising. Filtering reduces transferred object data; this implementation does
not claim that it avoids all server-side blob reads, lifts the configured full
visible-graph envelope, or improves measured latency/throughput.

The native tests cover exact emitted bodies, both hash domains, v0/v1/v2,
minimum shared-tree depth, exclusive blob thresholds, compound grammar,
explicit lazy retrieval, common haves, unsupported controls, current visibility,
read-only retention, inclusive resource limits and cancellation before output.
The optional pinned-Git campaign additionally checks real `.promisor` files,
initial missing-object sets, exact lazy blob hydration and `fsck --strict`.
It requires the repository-verified Git 2.54.0 oracle and Bubblewrap; unavailable
source, binary, receipt or isolation refuses rather than falling back to ambient
Git. Run it with:

```sh
cargo test --locked -p fgit-node --lib \
  pinned_git_partial_clone_promisor_and_lazy_read_round_trip -- --ignored --nocapture
```

Execution results must be read at their named revisions; test presence alone
is not a successful campaign. Full workspace, release, lint, broad differential,
remote-authentication and large-repository claims remain separate gates.

## Revision-bound verification follow-through

Source: `0ead373d9ee980923c5c97aeaf4e31a6d6cf4b0a`. Runner: Ubuntu 22.04, repository-pinned nightly and locked dependencies.

The previous Ubuntu 24.04 attempt at `cb40dd242a53f80a07fa961a27656110568cfc78` completed 235 node library tests, 27 daemon integration tests and 230 wire tests with no failures, but the separate pinned-client campaign stopped with exit 69 because Bubblewrap could not establish its namespace. This run retains the same sandbox requirement; no guard, assertion or isolation check was bypassed.

The expanded optional oracle test checks ordinary checkout as well as known-object lazy reads. The fixture serves bounded successive real sessions so a treeless checkout can retrieve its trees and blobs independently. Exact inventories require unrelated historical contents and gitlink targets to stay absent.

| Command | Exit | Completed target summaries |
|---|---:|---|
| `sudo apt-get update -qq` | 0 |  |
| `sudo apt-get install -y bubblewrap` | 0 |  |
| `cargo check --locked -p fgit-cli --all-targets` | 0 |  |
| `cargo test --locked -p fgit-node --lib` | 0 | test result: ok. 235 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 270.29s |
| `cargo test --locked -p fgit-wire --all-targets` | 0 | test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s; test result: ok. 2 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 8 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; test result: ok. 27 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s |
| `scripts/e2e/oracle/oracle.sh build git-2.54.0` | 0 |  |
| `cargo test --locked -p fgit-node --lib pinned_git_partial_clone_promisor_and_lazy_read_round_trip -- --ignored --nocapture` | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 235 filtered out; finished in 53.63s |

An unavailable or timed-out oracle is not a passing campaign. The six existing ignored wire-oracle tests are not covered by a normal all-targets run. These are command observations, not a full workspace, lint, release, security or independent batch gate.

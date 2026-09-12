# Native shallow clone and fetch

The bounded native Git daemon implements depth-limited clone, absolute-depth
changes, relative deepening, ordinary fetch from an already shallow client, and
unshallow. It uses one authenticated visible graph for boundary negotiation and
pack selection and composes with [partial-clone serving](PARTIAL_CLONE_SERVING.md).
There is no production Git subprocess, additional database, dependency, or
storage schema.

## Client workflow

Against an initialized, imported node running the bounded `fg serve` profile,
an ordinary client can perform the following workflow. The URL and branch below
are examples; use the repository ID, address and visible branch of that node.
The service must admit enough sessions for clone, checkout and successive fetches.

```sh
git -c protocol.version=2 clone --branch main --depth=1 --no-checkout \
  --filter=blob:none \
  git://127.0.0.1:9418/22222222222222222222222222222222.git shallow

git -C shallow -c protocol.version=2 checkout --detach origin/main
git -C shallow -c protocol.version=2 fetch --deepen=1 origin
git -C shallow -c protocol.version=2 fetch --deepen=1 origin
git -C shallow -c protocol.version=2 fetch --depth=50 origin
git -C shallow -c protocol.version=2 fetch origin
git -C shallow -c protocol.version=2 fetch --unshallow origin
```

The implementation serves protocol v0/v1/v2 and SHA-1/SHA-256. Omit the filter
for an ordinary shallow clone or use `tree:0` for a treeless shallow clone.
Checkout hydrates missing trees and blobs through the existing authorized lazy
fetch path. `--depth=N` is an absolute generation bound from the requested tips,
not a promise to return exactly N commits in a branching graph. `--deepen=N`
adds generations relative to existing shallow history. Repeating `--deepen=1`
therefore progresses through a linear history rather than repeatedly asking
for the same absolute depth. Time-based boundaries and ref-exclusion boundaries
remain unsupported by this production profile; unsupported controls do not
become full-clone fallbacks. Shallow receive/push semantics are not added here.

## One selected graph, two ancestry boundaries

`ShallowProof` is derived only from the complete native-verified visible graph
at the connection's selected publication basis. Its immutable graph metadata
is shared with the pack selector. It carries the connection deadline and native
pack limits; it is neither a persisted promise nor a source of authority.
Replacing a public repository view's closure invalidates its shallow proof.
The legacy annotated-tag adapter forwards both shallow support and boundary
resolution instead of inheriting a default refusal.

Multi-source shortest commit-generation traversal handles merge ancestry and
annotated-tag roots. Each included commit keeps its complete local tree/file
closure before a requested partial-clone filter is applied. Gitlinks are foreign
repository identities and never introduce local traversal or fetches.

The desired history stops at the **new** shallow boundary. The history already
established by client haves stops at the **old** client boundary. Computing both
against the new boundary would incorrectly subtract ancestors the client is
requesting during deepening. Ordinary fetch preserves the client's existing
boundaries while transferring newly reachable changes. A root exactly at the
requested finite depth is marked shallow consistently with the pinned profile.

Infinite-depth unshallow crosses every supplied old boundary still present in
the authenticated visible graph, including a boundary outside the current wants.
It also includes that boundary's missing ancestry in pack selection. Thus a
client that previously fetched a second shallow branch can become complete
without silently leaving that branch truncated. A finite depth change does not
claim to unshallow unrelated old boundaries.

Client markers never grant access. Hidden, disconnected or foreign markers do
not trigger storage reads or get echoed as authorized boundaries. A visible
non-commit marker is invalid. Every wanted object must remain inside the verified
scope. Canonical repository history and retention are never shortened by a
shallow transfer. Successful fetch does not stage objects, move refs, seal a
mutation, append forge events, or update the outbox.

### Relative deepening

The native provider follows the pinned Git 2.54.0 server's generation rule:
find the nearest reachable supplied client boundary from all wanted tips, then
add the requested increment. Tags preserve their target's generation. Multiple
paths use shortest generations; unrelated or unknown markers cannot choose
the offset. With no reachable old boundary, the offset is zero. This is not an
independent N-step expansion from every supplied marker.

The offset search shares the existing graph, cancellation callback and finite
work ledger with the desired/known closure calculations. It does not reread
native bodies or create another authority basis. Depth arithmetic is checked;
an effective relative depth above the profile's signed 32-bit limit is refused
rather than wrapping or silently becoming unlimited. The established raw
infinite-depth control retains its unshallow semantics.

Legacy clients negotiate the advertised `deepen-relative` capability; protocol
v2 carries `deepen-relative` as a fetch argument under the existing `shallow`
feature. The original increment is retained in `PackRequest`; a transient option
bit carries its meaning without changing that request's field layout. Relative
controls require a positive bounded depth and cannot combine time/ref exclusion
controls. Clearing the relative bit preserves other negotiated pack options.

The separate storage-free `fgit_wire::closure::compute_pack_closure` API does not
yet implement this relative mode and explicitly returns
`UnsupportedRelativeDeepening` before object reads. It must not silently treat
an increment as an absolute depth. The production native daemon uses the
connection-owned shallow provider described above, not that legacy graph API.

## Wire ordering and client compatibility

Legacy negotiation emits bounded `shallow`/`unshallow` records and the required
flush **before waiting for client haves**. An empty boundary update still has its
required handshake framing. Protocol v2 emits the delimited `shallow-info`
section before `packfile`. Boundary providers are checked for native hash domain,
ordered unique identities, authorization, conflicting additions/removals,
client membership of removals, and response limits.

Git 2.54.0's v2 multi-branch unshallow request repeats a `ref-prefix` while
expanding its refspecs. These are OR-query arguments, not conflicting state
assignments. The wire machine accepts repetitions, retains argument order, and
counts **every occurrence** against the unchanged `max_ref_prefixes` ceiling.
Each advertised ref is still visited/output at most once. Fragmentation, packet
counts and response byte ceilings remain enforced.

On successful `ls-refs` completion, request capabilities are reset along with
prefixes and requested attributes. A later command may specify `object-format`
again without a false duplicate error; repeated capability declarations inside
one command remain refused. The production adapter now retains this wire
machine rather than replacing it after a network read that contained `ls-refs`:
that same read may already contain a partial or complete following command.

At EOF the adapter checks both decoder completion and command state. Clean EOF
between commands remains accepted. A truncated next frame returns a framing
refusal, and a complete frame inside an unfinished next command returns
`IncompleteNegotiation`. Neither is mislabeled as a successful advertisement-only
session. Deterministic transport tests split multiple `ls-refs` commands followed
by fetch at every byte boundary and also use one-byte reads in both hash domains.
Their refused-want cases assert that the pack builder is never called.

History selection precedes partial-clone filtering and requested `include-tag`
expansion. The native history layer clears handled relative controls only in
the private request copy passed to the filter layer. Explicit lazy blob/tree
requests retain their existing semantics: a partial client's have-commit does
not prove it possesses all descendant bytes. Filters and shallow markers are
not authorization tokens.

## Regression entrypoints

The ordinary native suites contain graph, transport and framing tests, including
clients that wait for the legacy shallow response before sending haves. They
cover both hash formats, nested tags, multiple tips, inclusive limits, interrupted
selection, current visibility, refusal twins and exact emitted objects.

The repository's source/binary-verified Git 2.54.0 oracle and Bubblewrap are
required for the explicit real-client campaigns. Missing oracle identity,
receipts or isolation refuses; there is no ambient Git fallback.

```sh
cargo test --locked -p fgit-wire --all-targets
cargo test --locked -p fgit-node --lib
cargo test --locked -p fgit-node --test git_daemon_v2_fragments
cargo test --locked -p fgit-node --lib pinned_git_relative_ \
  -- --ignored --nocapture --test-threads=1
cargo test --locked -p fgit-node --lib pinned_git_shallow_clone \
  -- --ignored --nocapture --test-threads=1
cargo test --locked -p fgit-node --lib pinned_git_unshallow \
  -- --ignored --nocapture --test-threads=1
cargo test --locked -p fgit-node --lib pinned_git_partial_clone \
  -- --ignored --nocapture --test-threads=1
```

The relative-client matrix contains 18 cells: both hash domains, all three
protocol versions, and ordinary/blobless/treeless clients. Each clones at depth
one, performs two identical `--deepen=1` requests, checks each persisted boundary
and reachable-history set, checks out the requested native file bytes, and uses
a larger relative request to complete history. It checks strict integrity,
initial inventories, deleted-only object exclusion and unchanged publication
basis. Test presence is not execution evidence.

The earlier absolute shallow lifecycle matrix also contains 18 cells and checks
clone, checkout, absolute deepening, source-branch advancement, ordinary fetch
and unshallow. Separate campaigns cover six multi-branch unshallow cells and
twelve partial-clone/lazy-read cells. At source
`d9eb9c72c42813d00a0888a786b504128a1ca681`, run `34695189187` completed all three
of those earlier campaigns, 249 node-library tests, 243 wire tests, 27 selected
daemon tests and CLI all-target checking successfully. That historical result
does not certify the later relative-depth implementation.

The complete visible graph is still verified before advertisement. This profile
does not claim lower server-side history-reading cost, larger repository limits,
measured performance gains, smart HTTP, SSH authentication, repository-wide
protected-branch policy, or full Git compatibility. Full-workspace, lint, release
and independent batch gates remain separate; no bead is closed here.

# Native shallow clone and fetch

The bounded native Git daemon supports depth-limited clone, absolute-depth
changes, ordinary fetch from an already shallow client, and unshallow. It uses
one authenticated visible graph for boundary negotiation and pack selection,
and composes with [partial-clone serving](PARTIAL_CLONE_SERVING.md). There is
no production Git subprocess, additional database, dependency, or storage schema.

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
git -C shallow -c protocol.version=2 fetch --depth=2 origin
git -C shallow -c protocol.version=2 fetch origin
git -C shallow -c protocol.version=2 fetch --unshallow origin
```

The implementation supports protocol v0/v1/v2 and SHA-1/SHA-256. Omit the filter
for an ordinary shallow clone or use `tree:0` for a treeless shallow clone.
Checkout hydrates missing trees and blobs through the existing authorized lazy
fetch path. `--depth=N` is an absolute generation bound from the requested tips,
not a promise to return exactly N commits in a branching graph. Relative
`--deepen=N`, time-based boundaries and ref-exclusion boundaries are not provided
by this production profile; unsupported controls do not become full-clone
fallbacks. Shallow receive/push semantics are not added by this fetch change.

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
requested depth is marked shallow consistently with the pinned client behavior.

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
one command remain refused. This fixes both repeated `ls-refs` commands and the
per-command state boundary used before fetch.

History selection precedes partial-clone filtering and requested `include-tag`
expansion. Explicit lazy blob/tree requests retain their existing semantics:
a partial client's have-commit does not prove it possesses all descendant bytes.
The filter and shallow marker are not authorization tokens.

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
cargo test --locked -p fgit-node --lib pinned_git_shallow_clone \
  -- --ignored --nocapture --test-threads=1
cargo test --locked -p fgit-node --lib pinned_git_unshallow \
  -- --ignored --nocapture --test-threads=1
cargo test --locked -p fgit-node --lib pinned_git_partial_clone \
  -- --ignored --nocapture --test-threads=1
```

The shallow lifecycle matrix has 18 cells: two hash domains, three protocol
versions, and ordinary/blobless/treeless clients. It checks clone, persisted
`.git/shallow` boundaries, exact object inventories, ordinary checkout, absolute
deepening, a real source-branch advancement followed by ordinary fetch,
unshallow, and strict integrity checks. A separate six-cell test covers
multi-branch unshallow. The earlier twelve-cell partial-clone campaign remains
a regression lane. Test presence is not execution evidence.

The complete visible graph is still verified before advertisement. This profile
does not claim lower server-side history-reading cost, larger repository limits,
measured performance gains, smart HTTP, SSH authentication, repository-wide
protected-branch policy, or full Git compatibility. Full-workspace, lint, release
and independent batch gates remain separate; no bead is closed here.

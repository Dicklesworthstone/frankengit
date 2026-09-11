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

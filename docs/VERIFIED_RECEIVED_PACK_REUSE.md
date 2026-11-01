# Reuse verified received packs for full and incremental histories

The network receive and upload paths share a bounded, immutable compressed
representation inside one serving process (`frankengit-1tl9`). After pushes have
validated and placed their objects, a matching clone's pack-materialization
step can reuse one original pack, join complete entry runs from several
packs, or select individual verified entries without re-reading expanded blob
bodies, choosing new deltas, or recompressing them. This includes an initial
full push followed by compatible
thin incremental pushes, and incremental fetches whose client already holds
the verified external bases. Normal authorization and graph
selection still run first; this is not a claim of an I/O-free whole fetch.
The HTTP, SSH, and raw Git request children share this cache through their
service configuration.

## Selection and integrity

The receive parser optionally transfers ownership of its original input
allocation after ordinary framing, inflation, and native trailer validation.
The retained bytes remain quarantine data. The production validator must still
resolve every delta, verify every native object identity and structure, and
validate the requested closure.

A reusable candidate records every raw entry's verified identity, type and
expanded length, plus its delta-parent identity when present. It also binds the
original byte span, entry header, delta prefix and compressed-data boundary to
those identities. Capture checks those fields against the original bytes before
retaining them. Every entry must
belong to the validated closure and traverse the object fabric's placement
checks. A thin pack may retain a REF-delta dependency on an object already
verified by the receive path. This does not make the thin pack independently
servable. Duplicate identities, local dependency cycles, or incompatible
metadata prevent retention; OFS parents must remain inside their original run.

The candidate holds a cache reservation while its objects are staged. It becomes
eligible only after all immutable placement batches have passed publication,
including the final check for a conflicting existing object. Refusal, failed
publication, or abandoned staging drops the pending candidate. Cache activation
does not publish a ref: repository state still changes only at the ordinary
authority-head CAS.

Every fetch independently authenticates its basis and computes the visible
selection. Reuse must emit each selected native identity and type exactly once.
The first path looks for an exact, disjoint cover using complete cached packs.
If that cannot serve the request, selective reuse considers individual entries
from the retained sources, including sources containing unrelated objects or
overlapping representations. Neither path can authorize an object, add a
delta-support object, or widen a filtered, shallow, or have-reduced selection.
A verbatim OFS-delta representation requires the client's negotiated
`ofs-delta` capability. Selective reuse converts its selected OFS entries to REF
entries, so a self-contained result can also serve a client without that
capability.

The composed delta graph is checked against the complete selected object set.
For a self-contained response, every REF base must resolve inside that set with
the same object type. A negotiated thin response may additionally resolve a REF
base against the current authorized client-held proof described below. Depth
and fanout limits apply across pack boundaries, including multiple entries that
reference one external base; cycles refuse reuse. An unresolved base cannot be
supplied merely because it exists in storage or in a pack containing other
unselected objects. A failed cover does not prevent trying another compatible
retained representation, or the ordinary native writer.

### Incremental fetches with client-held bases

The existing native thin-pack profile controls this path: the client must
negotiate `thin-pack` and `ofs-delta`, supply haves, and request a full-history,
unfiltered fetch. Shallow and filtered requests keep the existing self-contained
policy because a have does not establish that such a client holds every object
in its history.

Preparation binds the identities and verified kinds of permitted client-held
objects to the same authenticated basis as the outgoing selection. Hidden or
unreachable haves cannot add an external base. Cache lookup receives this proof
only under the thin profile, and each external REF parent must match both an
identity and its kind. The response still contains exactly the selected objects;
it does not emit the held base or any other support object. Complete-run reuse
keeps OFS parents in the same run. Selective reuse may omit an original internal
parent only when that parent has the same current typed held proof; the emitted
delta then names it by native identity.

This lets an incremental fetch reuse the original thin push even after the
older base pack has been evicted from the server's representation cache. A
receiver must already have the declared external bases to reconstruct it.
Without the thin negotiation or a matching held proof, the same candidate is a
cache miss and the ordinary writer remains available. No object-body read is
needed to construct the held proof or verify a retained representation's graph.

Composition emits one new pack header, the unchanged complete entry run from
each selected source, and one newly computed native trailer. Keeping every run
contiguous preserves its relative OFS-delta distances; REF deltas resolve by
native object identity across runs. The source order is deterministic: an exact
single source is preferred, then fewer sources, then FIFO source order. The
payload streams these segments without allocating a combined compressed buffer.

### Selective entries and overlapping representations

Selective reuse starts only after the complete-run paths miss. It considers
verified representations of the requested identities, never emits a duplicate,
and does not copy an unwanted entry just to retain its delta support. A whole
object is an immediately available root; a delta becomes available when its
selected parent has a usable representation or its external parent has the
current typed held proof. Selected parents take precedence over held proofs.
Choosing a representation only after its parent is available prevents cycles,
while allowing a later rooted representation to satisfy an identity whose
earlier alternative participates in a cycle.

Choices use increasing delta depth, selected identity order, and FIFO source
order with a fixed local tie-break. Each candidate enters the bounded work
queue at most once. Source integrity is checked lazily before a representation
is chosen, including bytes omitted from the response. Depth and parent fanout
must fit the current envelope. An unavailable or over-budget complete choice
falls back to native construction; the selector does not claim an optimal
compressed size or search every possible combination.

Chosen entries are emitted in FIFO source order and original offset order
within a source. Whole-object and existing REF entries preserve their original
bytes. An OFS entry gets a REF kind and the verified parent's native identity in
its small prefix; its size declaration and zlib data stay unchanged. The pack
gets a new count, native trailer and full-byte SHA-256. Streaming reads borrow
source spans and emit bounded rewritten prefixes without joining compressed
data or reconstructing objects.

Current object-count, object-size, aggregate-expanded, output-byte, delta-depth,
and fanout limits apply to the complete output. Object-size checks include
inflated delta programs as well as native bodies; raw entry inflation and
reconstructed object totals are bounded separately. Omitted entries do not
consume the output's object or expansion allowance. The retained source still
occupies its full cache charge and must pass its full-byte SHA-256 and bound
metadata checks. These checks include cancellation checkpoints and run at most
once per source within each selection pass.
Incompatible or unavailable entries use the existing native writer. Cancelled
work remains cancelled.

## Operator control and custody

`fg serve`, `fg serve-http`, and `fg serve-ssh` accept:

```text
--received-pack-cache-mib <0..65536>
```

The default is **128 MiB**, including conservative metadata charges. Zero
disables received-pack capture and reuse. At most 64 representations are
retained, and each original input allocation must fit **64 MiB**. Both its
length and allocation capacity count; a pack outside the retention bound is
still received normally under the independent receive envelope.

This setting is separate from `--pack-cache-mib`, which controls deterministic
delta and compression memoization. Each active reuse reader pins its cache
entries and owns an independent cursor. FIFO eviction skips pinned readers, and
pending captures reserve their full charge before allocating metadata.
This is a retained-entry budget, not a total process RSS ceiling.

The source-count limit lets a full pack survive a longer sequence of small
incremental pushes while they still fit the same byte budget. Candidate
membership is indexed by selected object identity. An object owned by exactly
one eligible source forces that source into every possible exact cover;
overlapping sources are then removed and only their affected memberships are
revisited. Disjoint incremental histories therefore select their complete cover
without exponential enumeration.

Exact singleton representations retain priority. After forced selections, one
source that covers every remaining object is also sufficient; otherwise at
most eight unresolved candidates are exhaustively considered, with at most
255 residual combinations. Larger unresolved ambiguity moves on to selective
entry reuse, then the ordinary native writer if necessary. The complete-run
search preserves exact membership, minimum source count and FIFO tie-breaking
for its accepted covers. Graph and
ownership scratch remain bounded by selected membership and the existing
conservative per-object cache charge. Sources are pinned under the cache lock,
then comparisons, graph checks and hashing run outside that lock.

Selective search scratch is bounded by retained object membership, including
alternative representations, under the same conservative metadata charge.
Reader descriptors retain source allocations rather than duplicate zlib data.

The cache is process-local and disposable. A newly started service rebuilds
outgoing packs until it receives another eligible representation. Native
imports still use the native construction path. A self-contained clone also
needs a usable retained representation for every required base; a negotiated thin fetch can instead use its
authorized client-held bases. This change does not claim restart-persistent
reuse or completion of the large-history clone bead.

## Explicit representation receipt

`AuthoritySelectedPackPayload::receipt()` returns a
`PackMaterializationReceipt`:

- `Written(PackWriteReceipt)` records the native deterministic writer's frozen
  profile, checksum, ordering and compression receipts.
- `Received(ReceivedPackReceipt)` records the `received-pack-v1` representation,
  native checksum, full-byte SHA-256, entry count, separate OFS and REF delta
  counts, expanded bytes, output bytes, and maximum delta depth. A composition
  uses the distinct `received-pack-concat-v1` profile with newly computed
  checksums and aggregate counts. `source_pack_count()` identifies the number
  of complete verified sender runs in either profile.
- Responses that require client-held bases use `received-pack-thin-v1` or
  `received-pack-concat-thin-v1`. `external_base_count()` records the number of
  distinct external bases actually used. A thin-capable request that produces
  a self-contained result keeps the corresponding non-thin profile and a zero
  external-base count.
- Selective entries use `received-pack-select-v1` or
  `received-pack-select-thin-v1`. These profiles record the actual output's
  counts and graph limits; rewritten OFS entries count as REF entries.
  `source_pack_count()` counts the distinct retained source allocations used,
  even when only part of each source is emitted.

The singleton received profile preserves the sender's bytes and ordering; the
composed profile preserves the constituent entry runs and replaces their outer
framing. Selective profiles preserve compressed data while explicitly recording
their changed entry framing and selection. None claims equivalence to the native
writer's frozen encoding. All received profiles must represent the exact
authorized native object set. Local exports continue to use their explicit
deterministic writer profile.

## Regression coverage and execution status

Parser and wire regressions cover shared ownership without copying, original
metadata binding, retention limits, SHA-1/SHA-256, corrupted input, cancellation,
and complete HTTP body framing. At the source subtree published in
[`4399d1c5`](https://github.com/Dicklesworthstone/frankengit/commit/4399d1c5f828a9223a22a39bd47e21939e4ba7b7),
the focused pack/wire run completed with **659 passed, 0 failed, and 15 existing
ignored tests across 74 targets**. That historical result covers the parser/wire
foundation; it predates composition and does not verify its node integration.

The authored node cache tests cover exact membership, metadata integrity, internal and
external delta bases, resource ceilings, pending activation, eviction, active
readers, and cancellation. Integration tests exercise durable receive admission
and prepared upload selection. The first-clone case temporarily removes access
to object files after selection, then requires the original received pack bytes.
Other cases cover unreachable extras, changed refs, stale preparation,
filtered/shallow/incremental selections, client capabilities, independent readers,
fresh-process-style reopening, and collision failures before and during
immutable publication. Cache and transport cases also cover disabled retention.

The stock-client suite runs Git, HTTP, and SSH with received-pack reuse enabled
and disabled, while disabling the independent computation cache in both arms.
It pushes a delta-bearing history, immediately makes the first mirror clone in
the same serving process, then performs an incremental push/fetch and a fresh
full mirror clone. Exact refs, exact reachable object IDs, strict Git fsck, and
graceful server drain are its oracles. Native tests assert cache-hit behavior;
the transport suite by itself establishes neither a cache hit nor a speedup.
It records the actual Git/OpenSSH versions and does not claim pinned
differential evidence.

The authored composition regressions additionally resolve forward REF chains and shifted
OFS runs without an external-base oracle, exercise global depth/fanout and
aggregate limits, and reject corrupt parent associations. A native-node test
receives a full pack and a thin incremental push, removes access to all object
files after authorized selection, and materializes the composite. Receiving
that output into a second empty node independently checks its complete native
closure. Reduced, private, deleted and missing-base selections exercise the
ordinary writer fallback. These tests do not establish a whole-clone speedup
or persistence across service restarts.

The authored thin-reuse regressions pair an authorized held base with omitted,
wrong-kind and wrong-format proofs, enforce global fanout and depth through
external roots, and preserve cancellation. Native regressions prepare a fetch
against real client haves, remove fabric access after preparation, and require
the retained thin representation. A separately seeded receiver checks its
reconstruction. Non-thin, filtered, shallow and stale-basis requests retain their
existing boundaries. The scoped component result below covers cache logic;
the native regressions still require their own execution result.

The authored long-history regressions cover 64 disjoint sources, forward REF
chains at the internal and external depth limits, forced ownership propagation,
small residual choices against an independent exhaustive oracle, and bounded
fallback for large ambiguity. They also check exact membership, alternative
valid representations, aggregate limits, cancellation, pinned readers and byte
eviction. Native regressions receive a full pack followed by twelve thin pushes,
then require the entire thirteen-source clone without reading object files
after selection. Three large unrelated pushes independently exercise capture,
eviction under the unchanged byte budget, and ordinary-writer fallback for the
same authorized history. These native cases likewise need a separate node run.

The authored selective regressions remove unrelated entries between OFS bases
and children, use overlapping source representations, and compare the emitted
native identities and bodies independently of retained offset hints. They pair
omitted internal bases with permitted held proofs and missing or wrong proofs,
exercise client capability and selected-output envelopes, and retain integrity
checks over omitted source bytes. Native cases prepare actual filtered, shallow,
branch and have-reduced selections before making object files unavailable to
materialization. Their expected output remains exactly the authenticated
selection. These cases do not establish restart persistence or whole-repository
performance.

During the original single-pack implementation session, the node and CLI tests
and stock-client campaign **were not executed**. That session's repeated node
builds and metadata check stopped while compiling unchanged Asupersync under
the shared 8 GiB memory limit. Its filesystem subsequently filled and the
environment disconnected; remaining sources were recovered through GitHub and
reviewed, with some test/CLI source reconstructed. Those historical circumstances
do not describe a completed validation of the current composition changes.

For the composition source published in
[`ad72bae0`](https://github.com/Dicklesworthstone/frankengit/commit/ad72bae04a74f59f01d12ed4a3e8336158836697),
an isolated harness passed **29 received-pack component tests** using unchanged
production source and the real native pack dependencies. This result covers the
cache, composition graph, framing and reconstruction behavior. It does not
execute native OneNode integration, the CLI, SSH, the stock-client campaign, or
whole-clone performance measurements; those lanes require separate results at
the tested revision.

For the thin-reuse source published in
[`07031c86`](https://github.com/Dicklesworthstone/frankengit/commit/07031c862fba3fdb55e6a6a22a4f70e0b59827e3),
the production-source component harness passed **43 tests**. An independent
installed Git 2.51.1 oracle exercised **eight cases**: both native hash domains,
singleton and composed thin payloads, and base-present/base-missing twins.
`index-pack --stdin --fix-thin` accepted the production-generated payloads with
their bases; object bodies and inventory were checked through `cat-file`.
The same payloads were refused without their bases. This is scoped wire evidence
using the installed Git binary, not the project's pinned differential campaign
or execution of the native OneNode regressions.

For the longer-history source published in
[`445d3c53`](https://github.com/Dicklesworthstone/frankengit/commit/445d3c5379182dae340eb790d4d56c84d47e1d84),
the production-source component suite passed **57 tests**. A separate installed
Git 2.51.1 oracle accepted 64-source self-contained REF chains at depth 63 and
thin chains at depth 64 with their required root, and refused the same thin
bytes without that root, in both hash domains: **six cases**. Native IDs,
bodies and complete inventories were checked. These source-bound results
predate selective-entry reuse and do not execute native OneNode integration.

Run the focused lanes with the pinned toolchain and sufficient build capacity:

```bash
cargo test --locked -p fgit-pack -p fgit-wire --all-targets
cargo test --locked -p fgit-node --lib received_pack
cargo test --locked -p fgit-cli --all-targets
cargo build --locked -p fgit-cli --bin fg
FG_BIN="$PWD/target/debug/fg" bash scripts/e2e/suites/transport/received_pack_reuse.sh
```

Full-history cold-clone measurements, native-import capture, and persistence
across service restart remain separate work. Zero cache capacity is the runtime
rollback and requires no canonical-state or storage migration.

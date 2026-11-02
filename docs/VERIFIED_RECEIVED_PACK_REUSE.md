# Reuse verified received packs for full and incremental histories

The network receive, native directory import, file-backed bundle intake, and
upload paths share a bounded, immutable compressed representation and retain
disposable compressed custody for later service restarts (`frankengit-1tl9`).
After pushes or eligible packed imports have
validated and placed their objects, a matching clone's pack-materialization
step can reuse one original pack, join complete entry runs from several
packs, or select individual verified entries without re-reading expanded blob
bodies, choosing new deltas, or recompressing them. This includes an initial
full push followed by compatible
thin incremental pushes, and incremental fetches whose client already holds
the verified external bases. Normal authorization and graph
selection still run first; this is not a claim of an I/O-free whole fetch.
The HTTP, SSH, and raw Git request children share the live cache through their
service configuration. A newly created service configuration starts with an
empty live cache and must revalidate persisted custody before using it.

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

### Capture from a native directory import

Local idx-v2/pack-v2 imports can now retain the same compressed representation
through this cache contract. The existing streaming import still validates the
index, every encoded entry's CRC, the native trailer, every reconstructed native
identity and kind, and the complete required-kind graph. The optional cache
tees bytes from that original reader after reserving their entire raw allocation
and metadata charge. It does not reopen a mutable source path after validation.
The tee must match the original stream's EOF-authenticated full-byte SHA-256
receipt, including for SHA-1 repositories.

Only a source pack whose every entry belongs to the complete accepted import
closure can become a candidate. A valid pack containing an unreachable member
still imports its selected closure normally, but its representation is skipped.
Each captured member also records its strong payload commitment. As placement
processes the actual chosen import bodies, their canonical envelope commitments
must match every captured member. This additional join matters when loose files
or overlapping packs provide the same native identity: ID, kind and length alone
must not allow a different SHA-1 payload to borrow another body's successful
placement. Missing or contradictory strong evidence discards that candidate.

Raw custody shares the existing service-wide byte and entry allowance. Its
resident second parser pass has a separate cumulative inflation ceiling: the
minimum of that cache allowance, the default 128 MiB pack inflation bound, and
the selected import profile. This pass retains encoded entry programs, not
expanded delta results. Raising a streamed import's expanded-body limit does
not raise this resident ceiling. As soon as a source pack's entry inflation is
known to exceed it, the importer stops optional commitment hashing and drops
the raw tee; native verification and disk custody continue unchanged. The same
remaining parser allowance covers all candidates in an import, including failed
optional parses.

A durable import hands all eligible candidates to its existing `ReceiveStaging`
owner. They activate and optionally persist only after every staged object has
passed final immutable publication and collision checks. A normal admission
refusal abandons them with the staged objects. A standalone staging call uses
the same boundary after its own immutable placements finish. Several selected
source packs can be retained by one import and later composed by the unchanged
exact-selection rules above. Full and forward REF deltas and OFS deltas retain
their original compressed bytes; the native directory profile still requires
all source-pack delta bases to resolve within that source pack.

Allocation, capacity, optional framing, or cache filesystem failures do not
change the native import decision. Source corruption, placement failures and
the original request's cancellation still refuse through their existing typed
paths. A cache miss leaves ordinary pack writing available. Source removal
after import is harmless; cold use of retained files still performs the full
canonical revalidation described below. This adds native-import custody, not
a pack-proportional cold-clone or whole-repository throughput claim.

### Capture from file-backed full and incremental bundles

Full file-backed import, mapped full fetch, incremental synchronization, and
mapped incremental fetch now preserve eligible raw pack representations through
the same cache. No new intake flag is required. Later Git serving can reuse
them under its ordinary selected-object rules; streaming bundle export opts in
with [`--reuse-verified-packs`](NATIVE_GIT_BUNDLE_REUSE.md). The default export
encoder and canonical import receipts remain unchanged.

The tee reads at the pack boundary during the original native verification
pass. It reserves the complete raw allocation and object metadata before
allocating that buffer. A bounded stack prefix supplies the actual header count;
the native reader consumes that same prefix and the remaining original bytes.
Capture must match the returned `StreamPackReceipt` in native format, header,
trailer, exact byte count, and full-byte SHA-256 after authenticated EOF. The
preflight source digest and verification-pass digest must still agree. Reopening
a mutable bundle after validation cannot supply replacement custody.

The existing graph verification pass also records each uploaded raw member's
registered strong Git payload commitment from its authenticated scratch span.
Metadata uses the same bytes checked by the typed graph; blobs hash bounded
chunks through the native and scratch verifiers. Placement must independently
match every commitment against the actual selected `VerifiedObject` or the
successful `SyncedBlob` stage. Native ID, kind and length alone cannot discharge
this witness, including in SHA-1 repositories. These commitments do not grant
publication: the original stage is reauthenticated and all final collision
checks still run before the pending pack becomes reusable.

Every raw member must be in the final **uploaded** set, including required
transport-only delta bases. A mapped fetch that leaves raw entries unselected
simply skips whole-pack custody and places its exact selected closure. For an
incremental bundle, borrowed prerequisite objects do not count as uploaded
placements. Their verified identities may support a retained external REF base,
but later full serving must include a usable representation of that base, or
the current incremental/thin request must independently prove it is held.

One bundle contains one raw pack. Its optional second parse retains entry
programs under the minimum of the cache allowance, the default 128 MiB aggregate
inflation bound, and the selected native input profile. Known excess entry
inflation or an object outside the resident object bound disables the tee and
extra commitment work early, while the original file-backed verification
continues. Reconstructed-result commitment hashing follows the native import's
expanded-work bounds; the entry-program cap is not a total expanded-work or
process-memory claim. Large streamed blobs remain importable under their own
limits even when their representation is ineligible for this cache.

After selected staging succeeds and verification scratch is removed, completed
candidates transfer to the existing `ReceiveStaging` publication owner.
Capacity/allocation misses, optional reparse failure, and disposable cache I/O
do not alter the ordinary intake decision. Original source errors, stopped work,
corruption, cleanup failure and immutable collision failure remain fatal through
their existing paths. A refusal before publication abandons raw reservations
with private object custody. As elsewhere, successful cache activation is not
an authority-head commit receipt, and cold reuse still revalidates canonical
objects before serving.

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

Native imports still use their original validation and placement path. A self-contained clone
needs a usable retained representation for every required base; a negotiated
thin fetch can instead use its authorized client-held bases. Persistence does
not remove that dependency or the current selection and output limits.

### Disposable custody across service restarts

On Unix, validated received representations can be retained below
`<storage-root>/received-pack-cache/v1`. The directory is separated by the
repository's tenant, repository identity, incarnation, and native object format.
Each scope uses 64 fixed slots and a single staging file; file contents carry
the original pack and bounded identity/type/length hints. These files are
derived cache data. They are not a canonical object source, authority root,
retention root, or backup of missing objects. Removing them loses a reuse
opportunity and leaves the native writer available.
Other platforms retain the existing live-cache behavior and treat durable
custody as unavailable.

The writer applies the configured received-pack byte ceiling to the aggregate
logical charge of the retained records and staging reservation. That charge
includes raw bytes and conservative per-record and per-object metadata
allowances; old slots are evicted before staging a replacement. The 64-slot
bound does not multiply the configured allowance by 64. This is not a quota
on filesystem allocation blocks or total repository storage.

A cold fetch authenticates its repository basis and computes its permitted
selection before considering these files. Stored hints first restrict which
candidates are worth reading; they do not establish membership or native
identity. Before promotion to the live cache, the node reparses the actual
pack, verifies its native trailer, resolves and hashes its objects, and checks
that the reconstructed identities, types and lengths exactly match the hints.
It also verifies the corresponding canonical objects through the fabric,
including their strong payload commitments. The selected objects and any
permitted held bases must belong to the authenticated cumulative closure.
Persisted bytes cannot supply a private or deleted-ref object merely because
they once accompanied a public push.

An external REF-delta base is read only when the same current selection or
client-held proof permits it and the authenticated closure admits it. Its
canonical bytes must pass full integrity verification before reconstruction.
A restored thin representation still requires the negotiated thin profile and
the current typed held-base proof before materialization; restoring its raw
bytes alone cannot make it a self-contained response.

An unavailable, truncated, corrupt, stale, out-of-scope, or over-budget cache
candidate is a miss. It cannot repair a missing or corrupt canonical object;
if that object is required by the fetch, ordinary materialization still refuses.
Cancellation remains cancellation rather than turning into an optional miss.
Zero received-pack budget disables both capture and cold reuse, including use
of files already present. Re-enabling the budget allows intact eligible custody
to be considered again.

Cold revalidation performs real inflation and canonical integrity reads. It
saves later representation planning, delta selection and recompression; it
does not make the first fetch after restart free of object reads or establish
a whole-clone speedup. The focused restart tests cover self-contained packs,
composition after a thin push, and negotiated thin fetches in both native hash
domains. This does not complete the large-history clone bead. The configured
cache budget remains separate from total process RSS and whole-repository disk
use.

During cold native reconstruction, the delta resolver retains recent results
instead of permanently filling its cache with the earliest file versions.
Each successful cached read refreshes recency; admitting another fitting
result releases the least recently used results first. The retained payload
ceiling is the smaller of the existing resolver-cache allowance and the
64 MiB resident resolver budget. This policy never spills resolver entries,
and a zero allowance disables retention. Oversized results remain subject to
ordinary bounded reconstruction. Entry metadata stays bounded by pack count;
there is no growing access-history queue or scan of every cached result.

For histories whose recent delta bases fit this allowance, replacement avoids
reconstructing the same old chains after the cache fills. Evicted results still
spend the shared expansion and work budget when reconstructed again, and cache
hits still spend their copy work. Native hashing, exact hints, current upload
scope, final dependency/depth checks and canonical EOF verification remain
unchanged. Ordinary receive and the default resolver constructors keep their
existing retention and spill policy. Focused regressions compare both policies
under identical limits, including a history that exceeds cache capacity, and
compare reconstructed bytes and both native hash identities with the scalar
resolver. These are bounded-work and integrity checks; they do not establish
whole-repository clone timings or close `frankengit-1tl9`.

One cold pass shares its disk-inspection, inflated-program and native-resolution
allowances across candidates, including unsuccessful candidates. The parser's
resident inflation ceiling is the minimum of the cache allowance, receive
expansion ceiling and selected upload ceiling. Raising only the upload limit
cannot turn a small compressed cache into an unbounded resident parser. A
parser failure spends the remaining optional allowance because the parser does
not return a partial-work receipt. Exhausted optional work uses the ordinary
writer; request cancellation still stops the request.

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

The cold-custody regressions in
`crates/fgit-node/src/upload_visibility/tests/received_pack_reuse/restart.rs`
close the receiving node and create a new `NodeConfig`, so the test cannot pass
by retaining an `Arc` to the original live cache. They require both a
`Received` receipt and byte-for-byte equality with the original delta-bearing
ingress, then independently decode the selected native objects. They pair
missing/corrupt custody with the permitted restored case, disable and re-enable
the budget, remove or corrupt a canonical blob between graph selection and
cold validation, and remove the only ref to private objects before reopening.
Another case uses a relative node root without changing the process working
directory. The external-base case independently cold-opens the complete and
incremental fetches: the former must reconstruct the complete two-pack history,
while the latter must reuse the original thin bytes against the client's
authenticated held base. Native decoding checks both output object sets.
These are authored behavioral regressions; the historical execution counts
below predate this restart slice.

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

During the durable-custody implementation, the actual received-pack component
suite passed **86 tests**, including **12 new persistent-storage tests**, and
the actual object-fabric stream/integrity suite passed **11 tests**. The latter
checks the EOF-authenticated strong commitment for every native object kind in
both hash domains. The complete current `fgit-node` production library and all
**34 first-party dependencies** also passed pinned-compiler metadata checking
against the real cached third-party closure and the published FrankenSQLite
facade. Metadata checking is not linking or execution: the new native-node
restart and cold-validator tests remain authored integration coverage, and no
new whole-repository clone measurement is claimed here.

Run the focused lanes with the pinned toolchain and sufficient build capacity:

```bash
cargo test --locked -p fgit-pack -p fgit-wire --all-targets
cargo test --locked -p fgit-node --lib received_pack
cargo test --locked -p fgit-node --test import_pack_reuse
cargo test --locked -p fgit-node --test file_bundle_pack_reuse
cargo test --locked -p fgit-cli --all-targets
cargo build --locked -p fgit-cli --bin fg
FG_BIN="$PWD/target/debug/fg" bash scripts/e2e/suites/transport/received_pack_reuse.sh
```

The native-import fixtures in `crates/fgit-node/tests/import_pack_reuse.rs`
exercise real public node import and raw Git serving, with newly constructed
configuration on reopen. They cover both hash domains, OFS and forward REF
representations, multiple packs, cache disable/over-budget fallback, unreachable
entries, cache I/O failure, corrupt input, terminal admission refusal, and
placement-time cancellation followed by retry. They decode every successful
response and compare exact native inventories and bodies; reuse cases also
compare original compressed bytes. Focused private cases cover reservation
ownership and the strong placement witness. These are authored regressions;
their presence is not a claim of execution or a new throughput measurement.

The public `file_bundle_pack_reuse` target covers full file-backed intake with
OFS and forward REF entries in both hash domains, warm and fresh-configuration
cold clone/export, thin incremental import and mapped fetch, composition with
previously imported originals, exact mapped subsets, capacity and streamed-body
fallback, unselected raw members, corrupt input, atomic ref refusal, private
blob cancellation with same-key retry, and mutable-source replacement after
verification. A separate fault changes a real private blob's stored payload and
requires both refs and reusable custody to remain unpublished. Private verifier
cases require every exact strong placement
witness and retain original source-change/cancellation failures with capture
enabled or disabled. These are authored regressions; execution status must be
reported separately.

Full-history cold-clone measurements and broader restart/transport qualification
remain separate work. Zero cache capacity is
the runtime rollback and requires no canonical-state migration.

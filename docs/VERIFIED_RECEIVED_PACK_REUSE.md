# Reuse verified received packs for full and incremental histories

The network receive and upload paths share a bounded, immutable compressed
representation inside one serving process (`frankengit-1tl9`). After pushes have
validated and placed their objects, a matching clone's pack-materialization
step can reuse one original pack or join complete entry runs from several
packs without re-reading expanded blob bodies, choosing new deltas, or
recompressing them. This includes an initial full push followed by compatible
thin incremental pushes. Normal authorization and graph
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
expanded length, plus its delta-parent identity when present. Every entry must
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
selection. Reuse requires an exact, disjoint cover of those sorted native
identities and types using complete cached packs. Each candidate must be a
subset of the selection; overlapping objects cannot be emitted twice. A cache
cannot authorize an object, add a delta-support object, or widen a filtered,
shallow, or have-reduced selection.
An OFS-delta representation also requires the client's negotiated `ofs-delta`
capability. Self-contained REF deltas do not require that capability.

The composed delta graph is checked against the complete selected object set.
Every external REF base must resolve inside that set with the same object type;
depth and fanout limits apply across pack boundaries, and cycles refuse reuse.
An unresolved base cannot be supplied merely because it exists in storage or
in a pack containing other unselected objects. A failed cover does not prevent
trying another compatible retained representation, or the ordinary native writer.

Composition emits one new pack header, the unchanged complete entry run from
each selected source, and one newly computed native trailer. Keeping every run
contiguous preserves its relative OFS-delta distances; REF deltas resolve by
native object identity across runs. The source order is deterministic: an exact
single source is preferred, then fewer sources, then FIFO source order. The
payload streams these segments without allocating a combined compressed buffer.

Current object-count, object-size, aggregate-expanded, output-byte, delta-depth,
and fanout limits apply to the complete output. Object-size checks include inflated delta programs
as well as native bodies; raw entry inflation and reconstructed object totals
are bounded separately. The node rechecks the retained bytes' SHA-256 and
their metadata and parent association with bounded cancellation checkpoints
before reuse. Bytes are hashed only for candidates participating in a complete
cover, at most once per retained source per request.
Incompatible or unavailable entries use the existing native writer. Cancelled
work remains cancelled.

## Operator control and custody

`fg serve`, `fg serve-http`, and `fg serve-ssh` accept:

```text
--received-pack-cache-mib <0..65536>
```

The default is **128 MiB**, including conservative metadata charges. Zero
disables received-pack capture and reuse. At most eight representations are
retained, and each original input allocation must fit **64 MiB**. Both its
length and allocation capacity count; a pack outside the retention bound is
still received normally under the independent receive envelope.

This setting is separate from `--pack-cache-mib`, which controls deterministic
delta and compression memoization. Each active reuse reader pins its cache
entries and owns an independent cursor. FIFO eviction skips pinned readers, and
pending captures reserve their full charge before allocating metadata.
This is a retained-entry budget, not a total process RSS ceiling.

At most eight sources allow at most 255 cover combinations. Membership and
pairwise overlaps are computed once; cover enumeration uses these bounded
summaries. Graph scratch is bounded by the selected object count and the
existing conservative per-object cache charge. Sources are pinned under the
cache lock, then comparisons, graph checks and hashing run outside that lock.

The cache is process-local and disposable. A newly started service rebuilds
outgoing packs until it receives another eligible representation. Native
imports, selections that require splitting a cached pack, and histories whose
needed base representations have been evicted still use the native construction
path. This change does not claim restart-persistent reuse or completion of the large-history clone bead.

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

The singleton received profile preserves the sender's bytes and ordering; the
composed profile preserves the constituent entry runs and replaces their outer
framing. Neither claims equivalence to the native writer's frozen encoding. Both profiles must
represent the exact authorized native object set. Local exports continue to
use their explicit deterministic writer profile.

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

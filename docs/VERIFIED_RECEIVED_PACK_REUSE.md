# Reuse a verified received pack for the first clone

The network receive and upload paths share a bounded, immutable compressed
representation inside one serving process (`frankengit-1tl9`). After a push has
validated and placed a self-contained pack, a matching clone's pack-materialization
step can serve those original bytes without re-reading expanded blob bodies,
choosing new deltas, or recompressing them. Normal authorization and graph
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
expanded length. Every entry must belong to the validated closure and traverse
the object fabric's placement checks. Every delta base must be another entry
inside the pack. External thin bases, duplicate identities, dependency cycles,
or incompatible metadata prevent retention.

The candidate holds a cache reservation while its objects are staged. It becomes
eligible only after all immutable placement batches have passed publication,
including the final check for a conflicting existing object. Refusal, failed
publication, or abandoned staging drops the pending candidate. Cache activation
does not publish a ref: repository state still changes only at the ordinary
authority-head CAS.

Every fetch independently authenticates its basis and computes the visible
selection. Reuse requires exact equality of the sorted native identities
and types, including the entry count. A cache cannot authorize an object, add a
delta-support object, or widen a filtered, shallow, or have-reduced selection.
An OFS-delta representation also requires the client's negotiated `ofs-delta`
capability. Self-contained REF deltas do not require that capability.

Current object-count, object-size, aggregate-expanded, output-byte, delta-depth,
and fanout limits still apply. Object-size checks include inflated delta programs
as well as native bodies; raw entry inflation and reconstructed object totals
are bounded separately. The node rechecks the retained bytes' SHA-256 and
their metadata association with bounded cancellation checkpoints before reuse.
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
entry and owns an independent cursor. FIFO eviction skips pinned readers, and
pending captures reserve their full charge before allocating metadata.
This is a retained-entry budget, not a total process RSS ceiling.

The cache is process-local and disposable. A newly started service rebuilds
outgoing packs until it receives another eligible representation. Native
imports, arbitrary subsets of existing packs, and combinations of several
received packs still use the native construction path. This change does not
claim restart-persistent reuse or completion of the large-history clone bead.

## Explicit representation receipt

`AuthoritySelectedPackPayload::receipt()` returns a
`PackMaterializationReceipt`:

- `Written(PackWriteReceipt)` records the native deterministic writer's frozen
  profile, checksum, ordering and compression receipts.
- `Received(ReceivedPackReceipt)` records the `received-pack-v1` representation,
  native checksum, full-byte SHA-256, entry count, separate OFS and REF delta
  counts, expanded bytes, output bytes, and maximum delta depth.

The received profile preserves the sender's bytes and ordering. It does not
claim equivalence to the native writer's frozen encoding. Both profiles must
represent the exact authorized native object set. Local exports continue to
use their explicit deterministic writer profile.

## Regression coverage and execution status

Parser and wire regressions cover shared ownership without copying, original
metadata binding, retention limits, SHA-1/SHA-256, corrupted input, cancellation,
and complete HTTP body framing. At the source subtree published in
[`4399d1c5`](https://github.com/Dicklesworthstone/frankengit/commit/4399d1c5f828a9223a22a39bd47e21939e4ba7b7),
the focused pack/wire run completed with **659 passed, 0 failed, and 15 existing
ignored tests across 74 targets**. That result covers the parser/wire foundation.

The node cache tests cover exact membership, metadata integrity, internal and
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
graceful server drain are its oracles. Native tests establish cache-hit behavior;
the transport suite by itself establishes neither a cache hit nor a speedup.
It records the actual Git/OpenSSH versions and does not claim pinned
differential evidence.

The node and CLI tests and stock-client campaign **were not executed** in the
development session. Repeated node builds and a metadata check stopped while
compiling unchanged Asupersync under the shared 8 GiB memory limit. The shared
filesystem then filled and the execution environment disconnected. Remaining
sources were recovered through GitHub and reviewed, with some test/CLI source
reconstructed from the prior implementation. No final-tree node/CLI compilation,
runtime, formatting, or performance gate is asserted.

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

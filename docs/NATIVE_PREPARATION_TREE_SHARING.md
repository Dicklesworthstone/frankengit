# Request-owned directory sharing in native preparation

The path planner used by merge, squash, cherry-pick/revert, explicit conflict
resolution and linear rebase shares immutable validated directory maps within
one preparation. It no longer copies generated tree vectors and rebuilds their
maps for each subsequent visit. Original source trees can also be retained
under the bounded policy below. Exact-identity rename preparation uses the
same maps; only its explicitly mutable flattened paths are copied.

A three-way merge-join advances through the already ordered base/ours/theirs
maps. It uses constant auxiliary iterator state, preserves raw-name order and
returns borrowed entries rather than allocating a union of copied names and
performing three map lookups per path. Native Git tree serialization retains
its separate directory-as-slash ordering. Equal-side and one-sided paths still
validate their complete path length, but do not allocate a temporary full path.
Nontrivial content merges, attributes and conflict-resolution bindings continue
through the existing planner unchanged.

## Ownership and bounds

The cache is private to one `Planner` and its already-selected source. It never
survives a preparation, becomes a disclosure proof, or supplies original object
bodies to publication. Source adapters still verify native identities, kinds
and source selection. Cache insertion also performs the planner's existing
name, mode, object-format and duplicate-name checks. Failed reads and invalid
metadata are not cached. Every cache hit checks cancellation and charges the
same full tree-entry count as a fresh visit; no work budget is refunded.

Original trees are retained only while the combined tree map has fewer than
128 slots, and only when a tree has at most 4096 entries and 32768 name bytes.
Thus original retained name data is at most 4 MiB before map-key duplication,
and original cached entry count is also bounded by the cumulative planner
entry limit. These are cache-admission thresholds, not input limits: larger
trees remain readable under the existing source and preparation allowances.
Generated trees remain available even after that cache-admission threshold;
they retain the existing output/object bounds and cannot be evicted into an
object source that intentionally contains no preparation output.

This reduces repeated reads, parsing and copying; it does not remove the
100000 cumulative tree-entry limit, widen the public preparation profile,
introduce persistent caching or change native object encodings. Very wide
changed trees and long replay series can still exhaust their declared budgets.

## Verification boundary

`preparation::tests::shared_trees` adds ten Rust regressions covering a complete
small membership-pattern oracle, exact cache-hit accounting, cache admission
ceilings, generated-tree retention, cancellation, per-planner isolation,
malformed input, conflict order, native output identity, full-path bounds and
an eight-step rebase in both native hash formats.

An independent Python model executed 4096 join membership patterns and 2000
randomized cases. Its eight-step, 4096-entry rebase fixture retained identical
native tree identities and generated-tree inventories while reducing modeled
original-tree reads from 17 to 10. Both versions consumed 98304 logical entry
visits and refused a limit of 98303. This is model evidence, not Rust execution,
a measured native speedup, a durable-node test or a release qualification.

The implementation environment had no cargo, rustc or rustfmt. These native
lanes were not executed here:

```sh
cargo test --locked -p fgit-forge --lib preparation
cargo check --locked -p fgit-node --all-targets
```

No verification status or bead closure is implied by source/test presence.

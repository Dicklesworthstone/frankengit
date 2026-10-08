# Native incremental refresh of explicitly scoped lexical indexes

Related: `frankengit-root-doctrine-x2mv.4.19`, FG-032/FG-032a and plan sections
17 and 27. This is one search-maintenance capability, not closure of the broader
search usability, capacity, server scheduling or index-retention work.

`OneNode::refresh_scoped_source_index_local_in` and its guarded counterpart
refresh the complete regular-file inventory within one `LexicalScope`. They
require the exact existing scoped generation ID. They never select genesis,
change coverage, fall back to a rebuild, or initialize an unscoped index.

Current reference visibility is checked before any old index metadata is read.
The source head and native commit selected there are passed as mandatory pins
into TreeFS enumeration. A concurrent source change refuses rather than silently
becoming a new target of the same invocation. The indexed source may become
stale after preparation; successful publication is not a delivery-time freshness
claim. Queries remain read-only with their existing exact-source checks.

The existing scoped store verifies every prior segment before supplying opaque
reuse. The shared native refresh intake then enumerates the new tree with the
same prefix-pruning walker used by scoped builds. Only an exact previous raw
path/native blob pair reuses postings. New or changed paths fetch verified source
bytes; deleted paths and renames outside coverage disappear. Renames into coverage
are newly read even when their object bytes occurred elsewhere. Symlinks and
submodules remain explicitly counted exclusions, never traversed content.

Source file, corpus, path, depth and entry limits still apply. Reused source bytes
count toward file/corpus limits even though only actual blob reads are charged
as fetches. Previous-generation reads have their own finite read/work budgets;
refresh is not a way to bypass either source limits or index verification.

The guarded API computes the original candidate after complete preparation and
calls the caller-owned barrier before any successor payload put or root write.
A barrier failure publishes nothing. After the barrier succeeds, an error carries
`SourceIndexPublication` with the original candidate for read-only recovery.
There is no await or cancellation probe after confirmed publication. Repository
refs, forge events, outbox state and canonical authority-head generation are
unchanged by index refresh. The scoped generation uses its existing root-last
publication and exact-predecessor compare-and-swap, with no new codec or store.

## Native regression targets

```sh
cargo test --locked -p fgit-node --test source_index_scoped_refresh
cargo test --locked -p fgit-node --test source_index_scoped --test source_index_refresh
cargo check --locked -p fgit-node --all-targets
```

The new tests use the real node, TreeFS, index codecs and file-backed authority.
They cover both native hash formats, persisted reopen, cross-scope renames,
replacement/deletion, nested-sibling pruning, raw paths, empty/nonregular scopes,
source/index ceilings, foreign/stale predecessors, source pins, cancellation,
candidate barriers, original-candidate recovery and a real HTTP forge-only write.
Their presence is not execution evidence. The implementation environment has no
Rust toolchain; compilation and these native test targets remain to be run.

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

## Operator command

The existing `fg-index-scope` binary now accepts `refresh` alongside `build`,
`search` and `recover`. This is the native operation above, not a build alias or
an external scheduler. First create a scoped generation with `build`, then pass
its `index_token` as the required predecessor:

```sh
fg-index-scope refresh "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main --trusted-local --prefix src --prefix crates \
  --predecessor-token "$INDEX_TOKEN" \
  --candidate-file "$PRIVATE_DIR/refresh-1.json"
```

Repeat exactly the same canonical coverage as the original generation. Use
`--prefix-hex` for raw repository path bytes. Source movement may be independently
pinned with `--expected-head` and `--expected-commit`; these pins are enforced
rather than silently relaxed after loading the old index. Missing/stale/foreign
predecessors refuse. `build` remains the only command that can select genesis.

The candidate file must be new, in an existing private 0700 directory under the
existing Unix recording profile. The command synchronizes its candidate before
any successor index effect and retains it after publication, failure, or lost
stdout. An existing file is never replaced. A successful response must identify
that same recorded candidate. An uncertain result is inspected using the existing
read-only recovery command, not a new build or a changed predecessor:

```sh
fg-index-scope recover "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  refs/heads/main --trusted-local --prefix src --prefix crates \
  --candidate "$RECORDED_CANDIDATE"
```

`refresh` accepts the build-side `--max-file-bytes`, `--max-source-bytes`,
`--max-files`, `--max-entries` and `--max-depth` ceilings plus the independent
`--max-payload-bytes` prior-index read ceiling. Options only lower defaults.
Search terms, query filters, cursors and query-work flags do not select a partial
refresh and are rejected. The full option grammar is validated before node I/O;
candidate-path preflight also precedes node opening.

The `scoped_index_refresh` JSON report includes namespace, coverage, selected
source and generation identities. It separately reports `reused_documents`,
`rebuilt_documents`, `prior_documents_not_reused`, reused/rebuilt source bytes,
prior payload/generation bytes read, and preparation work bytes. Like the other
scope commands, all counters are decimal strings, not potentially rounded JSON
numbers. These are actual preparation counts, not measured speedups, guaranteed
freshness at delivery, or canonical repository mutations.

Additional regression targets:

```sh
cargo test --locked -p fgit-node --bin fg-index-scope
cargo test --locked -p fgit-node --test source_index_scoped_refresh_cli
```

Five new parser tests and one output test cover mandatory inputs, explicit raw
coverage, both native hash domains, independent limits, wrong pins, inapplicable
options and full-width counters. Two Unix integration tests invoke the real built
binary against real native fixtures, checking build/refresh/search/recovery,
record identity/permissions, persisted reopen, stale predecessors and refusal
without publication. These eight tests, like the preceding native tests, have
not been executed in the implementation environment. No Rust build, rustfmt,
Clippy, native test or workspace gate is claimed.

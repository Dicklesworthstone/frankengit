# Exact commit ancestry: implementation and measured scope

**Recorded:** 2026-10-12

**Obligation:** `frankengit-root-doctrine-x2mv.4.36` (partial implementation)

**Measured engine:** `0f3dea1ef5f8262b01d7f36480f19a973c512ffb`, `fgit-diff` subtree
`ddcd54e58c79f2d51816ffa06c6b6f57d3da9795`

`fgit-diff` now provides an immutable, reusable `CommitAncestryIndex` with exact
generation numbers, `is_ancestor`, and all best merge bases. In the recorded
100,000-commit synthetic workloads, building an index and answering one
merge-base query took less time than the retained scalar implementation.
Building an index for one ancestry query took **2.42–10.79 times** the baseline
time. This distinction determines where the current integration uses the index;
it does not establish an end-to-end `fg` speedup.

## Representation, algorithms, and contracts

The implementation is in
[`crates/fgit-diff/src/ancestry.rs`](../crates/fgit-diff/src/ancestry.rs).
It uses safe Rust and the standard library, with no new dependencies. Construction
loads the reachable commit-parent closure once, sorts commit identities by
their `Ord` order, and creates dense parent offsets and ordinals. An iterative
descendant-first Kahn traversal detects cycles. Reversing that order gives
`generation(root) = 1` and `generation(child) = 1 + max(generation(parent))`.
The generation vector is computed from the supplied parents, never accepted
from timestamps or a cached claim.

`is_ancestor` walks dense parent adjacency and prunes vertices below the target
generation. Equal identities are ancestors of themselves only if present in the
validated closure. All-best merge-base queries paint left/right reachability in
descending generation order. Every child is processed before its parents, so a
vertex's colors are final when it is processed. Parents of a common vertex are
dominated; common vertices without a common descendant are the best bases.
Each edge in the queried union closure is examined at most once. Equal-generation
frontier ties use ascending identity ordinals, and returned bases are sorted by
the original identity order. Parent input order cannot select a different base.
No floating-point arithmetic, random choice, or persistent codec is involved.

`AncestryQueryScratch` reuses dense marks and frontier storage. Epochs separate
queries, including failed queries and reuse with another index. Storage grows
with the largest index used by that scratch; a small query budget is not a
separate bound on the initial dense allocation. `work()` reports distinct
discovered commits and examined parent edges, including work before a refusal.
Per-query ceilings are inclusive, independent of construction ceilings, and do
not charge unrelated indexed components. A same-tip query needs one commit and
zero edges; a zero-commit limit refuses even that case.

Builds refuse missing source data, shallow boundaries, duplicate parent edges,
cycles, and exhausted commit/edge limits. Repeated starting tips are allowed.
Unknown query identities return `GraphClosureViolation`, including unknown
equal tips. `build_with_checkpoints` and query callbacks preserve caller errors
as `Source`, so cancellation or deadline expiry cannot become a negative
ancestry answer. Checkpoints cover start iteration, source discovery, adjacency,
topology, generations, and query work; no partial index or result is returned.
The original scalar
[`merge_bases_all`](../crates/fgit-diff/src/lib.rs) remains available as an oracle.

## Source binding and production consumers

An index proves graph properties of the supplied snapshot. The generic index
does **not** encode a repository identity, verify native object bytes, prove
current availability, or authorize publication. Callers must obtain parents
from the exact selected source and keep that source binding for the entire
query. Current integrations construct the index within each request; they do
not reuse an earlier request's object availability or source authorization.

| Consumer | Integration and retained obligations |
|---|---|
| Automatic merge preparation, explicit conflict resolution, and merge-base review | [`source_merge_bases`](../crates/fgit-forge/src/preparation.rs) constructs one index from the current `MergeObjectSource`. Its adapter checks object-format consistency and source checkpoints. [`resolution.rs`](../crates/fgit-forge/src/preparation/resolution.rs) and [`review.rs`](../crates/fgit-forge/src/review.rs) use that same boundary. Existing callers retain their treatment of no common ancestor and multiple best bases. |
| Native two-parent merge and squash admission | [`objects.rs`](../crates/fgit-admission/src/merge/native/objects.rs) first verifies the complete native object closure, identities, kinds, and budgets. It then builds one index from the parsed parent map and reuses it for the base-to-source and base-to-target checks. Squash includes the source history as an additional closure root. |
| Native fast-forward admission | Retains the existing exact, checkpointed parent walk after native closure verification. A new index for this single cold query is not justified by the recorded regression. |

The native admission adapter preserves its existing `GitCompatibleImport`
behavior: repeated historical parent headers are charged and verified in their
original bytes, then deduplicated only in the derived simple graph. Candidate
parent order is still compared exactly. This does not relax the generic index's
duplicate-edge refusal or forge preparation's input contract.

The forge/admission changes above are source-level integration descriptions.
Neither their compilation nor their integration test execution completed.
Both the union test build and the subsequent `cargo check` attempt ended with
the Asupersync compiler process receiving `SIGKILL` in the shared 8 GiB
environment. No passing forge/admission compile or test result is claimed here.

## Correctness evidence

The tested `fgit-diff` source is byte-identical to the subtree at commit
`0f3dea1ef5f8262b01d7f36480f19a973c512ffb`. The designated runner's
`cargo test -p fgit-diff --all-targets` completed with **123 passed, 0 failed,
1 ignored**. This attribution covers that crate's source, not the whole
workspace or later integration changes.

The 11 tests in
[`tests/ancestry_index.rs`](../crates/fgit-diff/tests/ancestry_index.rs) include
100,000 seeded query pairs over 1,000 DAGs of 8–64 vertices. Each pair checks
ancestry against an independent Boolean transitive closure and merge bases
against both a pairwise maximal-common-ancestor definition and the scalar
implementation. The seed is `0x78626d7634360001`; identity order is shuffled
independently of topology. Other cases cover crisscross/octopus graphs,
disconnected roots, every build/query checkpoint, inclusive limits, unknown
tips, bounded/cancellable start iteration, scratch reuse, and an iterative
100,000-commit chain. This is synthetic library evidence, not a discovered
native CLI suite or a proof over every possible graph.

## Recorded microbenchmark

The complete, unmodified
[`ancestry-index-2026-10-12.ndjson`](evidence/ancestry-index-2026-10-12.ndjson)
contains 196 records: provenance, two setup rows, **168 raw samples**, 24
summaries, and a successful terminal denominator check. Its SHA-256 is
`a83cac5cce9fea9f6d82c680f49a55527ce664b84ce10fe92eb4f577f0e7ef9e`.
Every sample matched its expected answer; every reused-index query read zero
source rows.

The run used `nightly-2026-08-31`, rustc `1.100.0-nightly` commit
`90850177249efe0321573c569aec5d12b257f8d6`, `x86_64-unknown-linux-gnu`, workspace
release defaults, and an Intel Xeon Platinum 8573C shared container with nine
visible logical CPUs. `Cargo.lock` SHA-256 is
`f44aac3a49874e796e8e2f41172a23ee8d99bd42ba4ee4c00ddcbfca612ab35b`.
The provenance also records the measured workspace-manifest hash and that
uncommitted integration changes were outside the measured crate.

Each graph has 100,000 synthetic, opaque 256-bit identities; these are not
hashes of native Git commit objects. The chain has 99,999 edges. The merge-heavy
graph has 107,769 edges: a chain with redundant parent shortcuts followed by
three sibling commits and two octopus tips sharing those three best bases.
Both inputs are constructed in memory before timing.

Seven samples per operation/variant were measured in the fixed order baseline,
fresh index, reused index, and identical baseline again (A-A). Fresh-index
timings include construction, query, and temporary teardown; reused-index
timings exclude prior construction and scratch priming. All values below are
observed **p50 milliseconds**; the last column is fresh-index time divided by
baseline time.

| Graph | Query | Baseline | Fresh index + query | Reused index | A-A baseline | Fresh/baseline |
|---|---|---:|---:|---:|---:|---:|
| Chain | Ancestry true | 46.199 | 147.591 | 1.406 | 46.195 | 3.195× |
| Chain | Ancestry false | 10.474 | 112.967 | 0.006849 | 10.418 | 10.786× |
| Chain | All best merge bases | 335.261 | 151.316 | 2.649 | 317.099 | 0.451× |
| Merge-heavy | Ancestry true | 12.461 | 122.505 | 0.965 | 12.662 | 9.831× |
| Merge-heavy | Ancestry false | 60.963 | 147.418 | 0.003864 | 65.176 | 2.418× |
| Merge-heavy | All best merge bases | 435.700 | 140.133 | 3.262 | 417.484 | 0.322× |

The cold merge-base measurements correspond to observed improvements of 2.22×
and 3.11×. The reused negative ancestry queries each visited one commit and
examined zero edges, showing generation pruning directly. These fast reused
queries do not demonstrate a production cache: no cross-request cache is
implemented.

The ancestry baseline is an independent exact parent walk that validates its
endpoints and walked parents. A fresh index validates the complete union
closure, so the ancestry comparison includes different preparation work. The
merge-base baseline and candidate both validate complete closure. Results are
checked outside the timed interval. No native object parsing, storage I/O,
transport, authority publication, or process startup is timed. CPU time, RSS,
allocation overhead, and end-to-end latency were not measured; setup payload
byte counts are not total memory measurements.

All raw p95/p99 values are retained. With seven samples, nearest-rank p95 and
p99 are both the sample maximum. The merge-base A-A p95 differences were
99.776 ms for the chain and 17.073 ms for the merge-heavy graph. These small,
shared-host samples support the stated observed microbenchmark result, not a
tail-latency guarantee or a stable capacity estimate. The cold ancestry loss
and its revisit condition are recorded as
[`NEG-035`](NEGATIVE_EVIDENCE_LEDGER.md#neg-035--a-fresh-index-is-not-a-faster-single-ancestry-query-x2mv436).

### Reproduce

The dependency-free example is
[`ancestry_index_benchmark.rs`](../crates/fgit-diff/examples/ancestry_index_benchmark.rs).
Use the designated verification runner and repository build/resource policies.
For a clean checkout, set the following labels to the source actually built;
for a dirty checkout, additionally record the exact patch and untracked inputs
instead of labeling it with `HEAD` alone. Replace the CPU placeholder with the
actual CPU, sharing, affinity, and load conditions.

```sh
export FGIT_ANCESTRY_SOURCE_REVISION="$(git rev-parse HEAD)"
export FGIT_ANCESTRY_SOURCE_TREE="$(git rev-parse 'HEAD^{tree}')"
export FGIT_ANCESTRY_LOCK_SHA256="$(sha256sum Cargo.lock | cut -d ' ' -f 1)"
export FGIT_ANCESTRY_TOOLCHAIN="$(rustc +nightly-2026-08-31 -Vv)"
export FGIT_ANCESTRY_TARGET="$(rustc +nightly-2026-08-31 -Vv | sed -n 's/^host: //p')"
export FGIT_ANCESTRY_PROFILE='release (workspace defaults)'
export FGIT_ANCESTRY_CPU='REPLACE_WITH_ACTUAL_CPU_AND_HOST_CONDITIONS'
export CARGO_TARGET_DIR="${TMPDIR:-/tmp}/fgit-ancestry-$$"
cargo +nightly-2026-08-31 build --locked --release \
  -p fgit-diff --example ancestry_index_benchmark
"$CARGO_TARGET_DIR/release/examples/ancestry_index_benchmark" \
  --commits 100000 --samples 7 --mode all > ancestry-index.ndjson
```

Missing/empty provenance is refused. Accept a campaign only when the process
exits successfully and its final record reports 168/168 samples with every
oracle matched. Keep the raw file, including slow samples and A-A controls.

## Remaining obligation

This slice does not complete `x2mv.4.36` or upgrade the `GRAPH-001` registry's
capability status. Still required:

- A persistent, source-bound ancestry index maintained on ref publication,
  with explicit generation selection and availability validation across requests.
- Admission fallback to the exact object walk when a persistent index is absent
  or stale, disagreement reporting, and a deletion test proving only timing changes.
- A discovered `scripts/e2e/suites/` suite driving a prebuilt `fg` through
  fast-forward merge and merge preparation on at least 100,000 native commits,
  with revision-bound baseline/candidate/A-A evidence.
- Completed forge/admission integration execution and explicit native
  graft/replace-ref refusal coverage for the eventual persistent-index path.

The present rollback boundary is the retained scalar ancestry/merge-base
implementation. Replacing or discarding the derived index cannot grant source
access or publication authority; a future persistent cache must prove that
property in its actual production fallback path.

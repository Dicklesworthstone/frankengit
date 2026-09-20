# Canonical-source index maintenance

`OneNode::reconcile_source_index_local_in` is the trusted-local maintenance
entrypoint for FG-032a. It automatically selects build, verified incremental
refresh, or no-op from one canonical source observation and one authenticated
index selection. Search requests remain read-only; maintenance is separate work.

The caller explicitly authorizes reconciliation of a complete reference. Unlike
`build` or `refresh`, this operation does not accept a caller-selected index
predecessor. It observes one and passes that exact identity to the native builder.
There is no retry or predecessor refresh inside the attempt. A source change
between planning and native TreeFS selection refuses through exact source pins.
The returned source describes the observation, not freshness at response time.

A current index returns its existing activation without reading source blobs,
scanning posting segments, staging bodies or advancing either authority. The
manifest and catalogs verify first. This no-op is a freshness observation, not
a full index-integrity audit; later segment reads still verify their own bodies.
A stale index uses the existing complete native refresh and exact posting reuse.
Only an uninitialized index without an unresolved checkpoint can build genesis.
Corrupt or missing required backing is never treated as an uninitialized index.

Callers may supply an exact canonical `expected_head` and a retained minimum
index activation. A higher/conflicting/unresolvable checkpoint blocks every
path, including genesis and no-op. Current canonical hidden-ref policy precedes
index disclosure. Source text and query fields cannot authorize this operation.

Each call uses the supplied finite request context throughout. Cancellation and
budgets refuse before a public result. A confirmed root publication remains a
success even if cancellation arrives afterward. Publication uncertainty retains
the candidate in `SourceIndexPublication`; a later maintenance invocation does
not prove that this original candidate failed. Reconcile never publishes a Git
ref, forge event, repository decision or outbox acknowledgement.

## Verification boundary

Seven integration tests use the existing native-import and file-backed OneNode
harness: initial build, idempotent no-op/reopen, actual Git edits, forge-only
staleness, unresolved checkpoints (including an uninitialized index), exact
source pins, failed builds/refreshes, cancellation, unpolled work and invalid
limits. Rust/Cargo are unavailable in the implementation environment: these
tests, compilation, formatting, Clippy and durable/full-workspace/release checks
have not been executed. Exact blob and whitespace checks are static checks.

```bash
cargo check --locked -p fgit-node --all-targets
cargo test --locked -p fgit-node --test source_index_reconcile
```

This entrypoint is not a scheduler, a retention pin, a full integrity scrub,
a historical-source query, or full FG-032 completion. Explicit build/refresh,
query freshness and the lexical codec are unchanged.

# Native history and line provenance

`fg log` and `fg blame` read native Git history directly from an authenticated
FrankenGit node. They reuse the same verified object owner as source review and
merge preparation. No checkout, external Git process, transaction seal, object
staging, ref update, forge event or outbox mutation is part of these operations.

## Commit history

```bash
fg log "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local --limit 50
```

The `topo-oid-v1` profile visits the complete reachable commit DAG. Every child
precedes all its parents. When multiple commits are ready, ascending native
object ID breaks the tie. This is deliberately not timestamp ordering: a
commit's author and committer timestamps cannot reorder causal ancestry.
Original parent order is retained inside each record.

The report includes the selected native tip, authenticated authority head,
exact commit bodies, trees and parents, total reachable commit count, and
`next_after`. Continue using the same ref, object format and limits, the
returned numeric offset, and the first page's `snapshot_token`:

```bash
fg log "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local --after 50 --limit 50 --expected-head "$SNAPSHOT_TOKEN"
```

Both the CLI and node API refuse an unpinned nonzero offset. An authority change
returns `SnapshotMoved` instead of splicing two histories. The token is an exact
precondition, not an authentication credential or a self-contained cursor.
Each invocation traverses the bounded DAG before slicing its page; pagination
does not pretend to make an otherwise over-budget history complete.

## Line attribution through merges

```bash
fg blame "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local --path crates/example/src/lib.rs \
  --line-start 20 --line-end 40
```

Line intervals are **zero-based and half-open**. Omitting the interval selects
all lines. An empty file has zero lines. A missing final LF, CRLF and invalid
UTF-8 remain exact bytes; no newline or encoding normalization is performed.
Only the selected line content is emitted, not an implicit full-file payload.

The `exact-lines-all-parents-v1` profile works as follows:

1. Load and validate the reachable commit graph, then process children before
   parents so convergent histories accumulate all pending line mappings once.
2. For each active commit, resolve the same raw path in its parents, preserving
   their original order. Compare regular-file lines with the existing bounded
   Myers engine. Identical blobs bypass content diff and reuse cached bytes.
3. Propagate a line to the first parent with an exact equal-line mapping. Lines
   unmatched in every parent originate at the current commit. A merge may thus
   attribute some lines to its first branch, others to its second branch, and
   manually resolved additions to the merge itself.
4. Before returning, check that every attributed origin slice exactly equals
   its selected output slice. Return the unique origin commits and their exact
   native bodies alongside the current and original blob/line/byte coordinates.

The parent-order rule also applies to octopus merges. Duplicate parent headers
remain in raw metadata but do not duplicate graph dependencies or line work.
Line attribution is deterministic for the stated diff profile and limits; the
actual `MyersTrace`/`MyersLinearRefinement` path and work bound are reported.

This profile does not guess renames or copies, ignore whitespace, execute
attributes or text conversion, or implement Git's presentation heuristics.
A file absent or non-regular in a parent is a same-path boundary; a missing
object is an error, never a boundary. NUL-containing content encountered in a
comparison refuses binary blame. Symlinks and gitlinks are not followed.

## Identity, disclosure and output

Both commands require `--trusted-local`: the caller must already be an
authorized local operator. The node also applies caller-supplied ref visibility
and canonical hidden-ref policy. Neither command is a remote authentication
service or path-capability broker. A path/range is a query filter, not a grant.
Only ancestors reached from the selected visible tip are traversed; unrelated
admitted objects are not added merely because they exist in the repository.

`--object-format sha256` selects SHA-256; SHA-1 is the default. `--ref-hex`
interprets the positional ref as lowercase hexadecimal. Blame accepts exactly
one of `--path` or `--path-hex`. Ref names must point directly to commits;
annotated-tag peeling and arbitrary caller-supplied starting OIDs are not part
of this interface. `--expected-head` may also pin an initial log or blame query.

JSON has explicit profile, scope, source-tip and authority-head fields. Commit
bodies and selected content are hex, plus escaped text when valid UTF-8. Each
blame row contains current byte/line coordinates and `origin_commit`,
`origin_blob`, `origin_line`, `origin_byte_start`, and `origin_byte_end`.
Byte and line ends are exclusive. The origin table is unique and ordered by
native ID; log records instead follow the declared topological order.

Author, committer, signature and message headers are original **claims**. A
native object hash verifies those bytes, not the named person's identity.
Reports explicitly say `author_headers_authenticated: false`. These are
unsigned derived reads, not approvals, provenance attestations or publication
capabilities. Control and bidirectional-formatting characters use the existing
safe JSON escaping rather than becoming terminal commands.

## Failure and resource boundaries

The fixed upper profile is 4,096 commits, 16,384 parent edges, 100,000 visited
tree entries, depth 64 and 4,096 path bytes. Blame admits at most 1 MiB and 20,000
lines per compared blob, 32 MiB of retained blob/span cache accounting, and 128
content comparisons. Each diff has at most 1,000,000 work units and 512,000 trace
cells. Metadata output is at most 64 KiB per commit and 4 MiB per report. Log
pages contain 1 through 100 records. The shared native object owner separately
limits individual reads to node policy/32 MiB and cumulative reads to 128 MiB.
JSON is capped at 64 MiB.

`--max-commits` and `--max-edges` narrow graph bounds. Blame additionally exposes
`--max-blob-bytes`, `--max-lines`, `--max-comparisons` and `--max-diff-work`.
These flags cannot raise the fixed ceilings. Parent-edge limits are independent
of native header-count limits, so a one-edge graph may still have ordinary tree,
author and committer headers.

Missing or corrupt history, cycles, invalid paths/ranges, unsupported tree modes,
resource exhaustion and cancellation return errors instead of successful partial
history or fabricated line origins. Checkpoints surround reads and bounded work;
an individual finite synchronous hash/diff is not claimed to be preemptible at
every instruction. No detached context or replacement budget finishes a query.

The node is explicitly closed before result output. Exit 0 means the complete
requested page or line range; exit 2 means no successful result. Output failure
may leave an incomplete JSON prefix. Consumers must require successful exit and
a complete JSON document, not merely a prefix containing `complete: true`.

## Implementation and verification

`fgit-forge::history` owns the pure graph/page/attribution algorithms.
`OneNode::read_commit_history_in` and `OneNode::blame_source_in` own authenticated
selection through the existing private `SelectedSource`. The CLI validates,
invokes those operations, closes, checks response bindings, and renders.
No new dependency or lockfile entry is required.

Fourteen Rust test functions are registered: eight core cases, two embedded-node
cases and four CLI cases. Coverage includes SHA-1/SHA-256 DAGs, both merge parents,
parent-order ties, shifted lines, raw bytes, empty files, missing final LF,
cycles, corrupt/missing/binary inputs, caching, bounds, cancellation, unchanged
canonical state, hidden refs, pinned pages, and write/flush failures.

```bash
python3 scripts/e2e/source_history_smoke.py --self-test
python3 scripts/e2e/source_history_smoke.py --fg /absolute/path/to/fg
```

The real-binary campaign builds its own native-object fixtures, checks exact
commit bodies and every originating line slice, exercises pagination and raw
paths, and compares canonical state before and after reads. It fingerprints the
provided executable. The self-test tests only fixture construction and the
checker; 36 intentionally corrupted reports were rejected in this editing
session. The two isolated fixture repositories also passed Git 2.47.3 strict
fsck and matched Git blame's expected five line origins in both hash formats.
Those are fixture checks, not executions of FrankenGit.

Cargo, rustc and a built `fg` were unavailable in this environment. Rust
compilation, native tests, the full binary campaign, rustfmt and Clippy were
not run. Source integration is not a passing native gate or a bead closure.
Broader Git log/blame compatibility, indexed unbounded histories, rename/copy
attribution and remote authorization remain outside these explicit profiles.

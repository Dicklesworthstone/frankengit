# Native source review: `fg diff` and `fg pr diff`

These read-only commands expose the existing native tree, Myers line-diff,
merge-base, and verified object machinery through one authenticated node
snapshot. They do not invoke Git, create a checkout, stage objects, seal an
operation, move a ref, append a forge event, or acknowledge a delivery.
No new dependency or lockfile entry is required.

## Compare two current refs

```bash
fg diff "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main refs/heads/topic --trusted-local
```

The default `direct` comparison compares the first commit's tree with the
second commit's tree. Both tips are selected from the same authenticated head.
This includes work present only on the first side as a deletion or reversal.

```bash
fg diff "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main refs/heads/topic --trusted-local \
  --comparison merge-base --path crates --context-lines 3
```

`merge-base` compares the unique best common ancestor with the second commit.
It excludes first-side-only changes. Unrelated histories and several best
bases return explicit errors, not a guessed base or an empty comparison.
A ref must point directly to a readable commit; this interface does not peel
annotated tags or accept arbitrary caller-supplied object IDs.

## Review a native pull request

```bash
fg pr diff "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local --expected-version 2 --context-lines 5
```

PR review defaults to `merge-base`. Its first commit is the PR's **recorded
target tip** and its second commit is the **recorded source tip**, not whatever
the branch names point to now. After a branch moves or disappears, retained
history still supplies those recorded objects. The command does not refresh
the PR, approve it, or change its expected merge preconditions.

After a native merge, the review uses `target_tip_before` and `source_tip`
from that event. It does not substitute the merged target commit or claim
that the diff is the merge result. Explicit merge-only receipts have the
same native coordinates without an invented PR opening or review history.
Legacy digest-valued events are not silently converted into native IDs.

`--expected-version` is an optional positive, exact aggregate version.
`--expected-head` accepts the algorithm-qualified `snapshot_token` returned by
a previous report, including the optional `head:` prefix used by saved CLI
inputs. A mismatch returns an error before disclosure. A token is a
precondition, not an authentication credential. Repeat it for separately
requested path scopes that must describe one common authority snapshot.

## Scope, format and output

Every invocation requires an authorized local operator's `--trusted-local`.
The node also accepts a ref visibility policy which can narrow, never widen,
canonical hidden-ref policy. Both PR branches must be visible. This is **not**
a remote credential verifier or a path-capability broker. Path filters narrow
query work/output; they do not grant or revoke authority.

`--object-format sha256` selects a SHA-256 repository; SHA-1 is the default.
`--path` and `--path-hex` accept repeated raw path-component prefixes, not
globs. `src` selects `src` and `src/...`, not `src2`. Absolute paths, NUL,
empty components, `.` and `..` refuse. Non-UTF-8 path prefixes use lowercase
hex. `fg diff --refs-hex` interprets both positional ref names as lowercase hex.

One JSON report carries:

* repository/head, requested commits, actually compared ancestor, both trees,
  ref-name bytes, optional PR number/version, comparison mode and path scopes;
* sorted raw-path entries with old/new native IDs, exact octal modes, and
  added/deleted/modified/mode/type classifications;
* text additions/deletions, the actual selected Myers implementation path,
  and old/new context hunks with exact bytes and source spans.

Byte intervals are half-open. `line_start` is **zero based**, as declared by
`line_origin: 0`; `line_count` counts newline-inclusive tokens. CRLF, invalid
UTF-8, and an absent final LF remain unchanged. Each hunk includes
`before_hex`/`after_hex`; valid UTF-8 also appears as escaped text, otherwise
that text field is null. No repository control byte is printed as terminal
control. Hunk data is review data, not an executable shell or a Git patch.

Directory changes are explicit object records alongside recursively changed
children, so `entry_count` is **not** a count of regular files. This also
preserves empty-directory and file/directory transitions. An added empty file
has an entry even though its text diff has no hunks. Mode-only changes retain
identical content identity without reading the blob. Symlink contents are
compared as data and never followed. Gitlinks are opaque identities; their
repositories are not traversed. NUL-containing blobs are explicitly binary
with lengths and native IDs, not fabricated text hunks.

The byte-oriented profile is `path-myers-v1`. It does not implement rename
similarity, whitespace normalization, `.gitattributes` drivers, textconv,
external diff commands, combined merge patches, or Git's exact presentation
heuristics. Rename-shaped changes appear as exact deletions and additions.
This is not a claim of complete `git diff` output equivalence.

## Bounds and failure behavior

The maximum profile is 100,000 visited tree entries, depth 64, 4,096-byte paths,
512 changed entries, 64 text comparisons, 1 MiB per compared blob, 4,096 hunks,
and 8 MiB of retained path/hunk bytes. Each text diff has at most 100,000 line
units, 1,000,000 work units and 512,000 trace cells. Merge-base discovery is
bounded to 4,096 commits and 16,384 edges. The shared object owner admits
at most 32 MiB per object read and 128 MiB cumulative source bytes; the 1 MiB
blob comparison ceiling is checked on the admitted blob before text diff.
JSON expansion is capped at 64 MiB.

The CLI can narrow `--max-changes`, `--max-blob-bytes`, `--max-output-bytes`,
and `--max-diff-work`. `--context-lines` accepts 0 through 20. These flags
cannot raise the ceilings. Missing/corrupt source, unsupported modes,
ambiguous bases, exhausted budgets and cancellation are errors, not successful
partial reports or evidence of no changes. Oversized binary files likewise
refuse; they are not silently skipped.

Cancellation checkpoints occur during source reads/tree traversal and before
and after each finite synchronous text diff. This does not claim interruption
inside every Myers frontier iteration. The request-owned database context is
never replaced or extended to finish the computation.

Exit 0 means a complete comparison for the declared scope, including zero
changes. Exit 2 means no successful review was returned. The node is explicitly
closed before report output. A write/flush error may leave partial output;
consumers must require a complete JSON document and successful exit rather than
trusting a prefix containing `complete: true`.

## Implementation and verification

`fgit-forge::review::compare_source` is the pure derived planner. The node's
`review_source_in` selects all authority/PR coordinates once, then reuses
merge preparation's private verified object source. The CLI only selects,
closes, validates response bindings and serializes the resulting review.
The existing merge, source-search and PR publication paths are retained.

Six pure-core tests, two embedded-node tests and four CLI tests are registered.
They cover exact hunk reconstruction in both object formats, direct versus
merge-base semantics, raw bytes, directory/type ordering, modes/links,
unchanged-subtree reuse, stale pins, post-merge PR coordinates, bounded failure
and output errors.

```bash
python3 scripts/e2e/source_review_smoke.py --self-test
python3 scripts/e2e/source_review_smoke.py --fg /absolute/path/to/fg
```

The real-binary campaign constructs native objects independently, checks exact
entry IDs and spans, reconstructs new blobs from reported hunks, exercises
both hash formats, checks deterministic repeated queries and PR pins, and
compares canonical state before/after reads. It fingerprints the supplied
binary. The self-test validates only fixtures and the checker, including 26
corrupted-report negatives; it explicitly reports `rust_executed: false`.

For this editing session, Python syntax/checker tests and Rust lexical/delimiter
checks were executed. Cargo, rustc and a built `fg` are absent, so Rust
compilation, native tests, the real-binary campaign, rustfmt and Clippy were
**not run**. Source integration does not close a bead or establish the full
forge/review compatibility gate.

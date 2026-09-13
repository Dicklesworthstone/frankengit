# Native linear rebase preparation

`fg rebase prepare` replays the explicit single-parent suffix `(upstream,
source-tip]`, oldest first, onto an independently selected branch tip. It uses
the native merge engine and returns an immutable, complete Git bundle. No Git
process, hook, user driver or alternate object database runs in production.

This is a linear rebase preparation profile, not an interactive sequencer.
Merge commits inside the selected suffix refuse instead of being flattened.
A merge commit may still be the onto target or the excluded upstream boundary.
Conflicts stop the whole preparation without returning a partial bundle.

## Exact-input command

```sh
fg rebase prepare "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/topic ./rebased.bundle \
  --trusted-local --profile path-v1 \
  --onto-ref refs/heads/main \
  --expected-source "$SOURCE_TIP" \
  --expected-onto "$ONTO_TIP" \
  --upstream "$OLD_BASE" \
  --committer 'Operator <operator@example.invalid>' \
  --timestamp 1789257600 \
  --empty stop
```

The source and onto must be distinct fully qualified visible branches. Their
exact native identities must share the repository's SHA-1 or SHA-256 format.
Both refs come from one authenticated current snapshot; an optional
`--expected-head alg:<algorithm>:<digest>` pins that complete snapshot as well.
The suffix traversal proves the named upstream is actually reached. It does
not substitute a guessed merge base or replay an unrelated range.

Raw branch names use `--source-ref-hex` for the positional source name and
`--onto-ref-hex <lowercase-hex>` instead of `--onto-ref`. Optional
`--max-commits`, `--max-edges` and `--max-output-bytes` can tighten the existing
bounded profile but cannot enlarge its hard limits.

Exit 0 means a complete artifact was prepared. Exit 3 means a conflict or a
newly-empty stop, with no artifact. Exit 2 means invalid input, a bound or
infrastructure failure, or incomplete output. The JSON receipt names the exact
input identities, snapshot, rewritten commit/tree, original-to-rewritten step
mapping and bundle digest. It explicitly distinguishes creation of the local
artifact from canonical publication. The create-only artifact writer refuses
to overwrite an existing path, and runs only after node shutdown.

## Native series semantics

The entire topology is selected before candidate construction. One shared
planner owns the tree-entry, content-merge, object and generated-byte counters
for every step; no new per-commit budget is granted. Parsed generated trees and
constructed blob bytes remain available to later steps. Without that state,
the second replay could attempt to load the first replay's new tree from an
object store that preparation intentionally never mutates.

For each original commit, the planner compares its original parent's tree with
its own tree and applies that change to the currently rewritten tree. Clean
onto work and clean earlier replay results are preserved. Each newly emitted
commit has exactly one parent: the previous rewritten commit, or the initial
onto target for the first step. A separate native-byte validator checks every
resulting parent and tree identity rather than trusting the step receipt.

The original author header, including its timestamp and timezone, exact message
bytes and optional encoding are preserved. The caller supplies the new committer
identity and UTC time. Original `gpgsig`/`gpgsig-sha256` headers are deliberately
not reused: they cannot authenticate rewritten bytes. Ambiguous metadata and
unsupported extension headers refuse instead of silently discarding unknown
information. Preserving an author string does not authenticate that identity.

Originally empty commits remain in the sequence. A change that becomes empty
on the new base uses the explicit `--empty` policy:

| Policy | Newly empty change |
|---|---|
| `stop` (default) | Stop with the original identity; no partial candidate. |
| `drop` | Record a dropped step pointing to the preceding rewritten tip. |
| `keep` | Preserve a new empty commit and its metadata. |

An empty suffix or an entirely dropped suffix points to onto and needs no new
commit. Its bundle can therefore carry a checksum-verified zero-object pack.
This is a ref-only outcome, not a manufactured empty commit.

## Complete, onto-only artifacts

The source commits are not parents of their replacements. Exporting only
newly generated objects would omit source-only blobs or subtrees reused by the
replay. The bundle instead contains the candidate's complete reachable native
closure minus onto's existing reachable closure. It includes borrowed original
objects that are absent from onto history. Onto is the sole external prerequisite,
and the advertised bundle ref is the original source branch.

Preparation validates the source graph, generated objects and final closure
without staging objects, creating a seal, moving refs, appending forge events,
granting approvals or changing the outbox. Cancellation refuses the preparation;
no partial set of generated objects is exposed as a publishable result.

## Review and publish separately

The existing `workspace apply` contract remains a single-commit operation and
is **not** widened to accept a rebase series. A prepared rebase may be reviewed
and published through the existing receive-pack path with an explicit old source
tip. A standard local Git repository that already has the onto prerequisite can
fetch the bundle into a separate review branch:

```sh
git fetch ./rebased.bundle refs/heads/topic:refs/heads/rebase-review
# Compare the actual candidate with the original source and onto histories.
git log --reverse --format=fuller "$ONTO_TIP"..refs/heads/rebase-review
git diff "$ONTO_TIP" refs/heads/rebase-review
# After reviewing the exact candidate, name the original source tip as the lease.
git push --force-with-lease="refs/heads/topic:$SOURCE_TIP" \
  origin refs/heads/rebase-review:refs/heads/topic
```

The local Git commands above are client operations, not production dependencies
of FrankenGit. `origin` must name the intended receiving repository; its normal
authorization and receive policy remain in force. Rebase can rewrite history,
so the old source identity is explicit rather than inferred from a potentially
stale tracking ref. A saved preparation neither requires the onto branch to
remain stationary afterward nor grants permanent approval to publish.

The native integration regressions use the actual production pack parser,
quarantine handoff, expected-old canonical admission, shutdown/reopen and
historical retry. They leave the single-parent workspace validator unchanged.
No repository-wide protected-branch policy or remote authentication is supplied
by this preparation feature.

## Verification boundaries

Ordinary tests cover native identities in both hash domains, successive content
merges, raw metadata, cumulative/inclusive budgets, source topology errors,
original and newly empty commits, cancellation checkpoints, stopped outputs,
borrowed dependencies, zero-entry packs and real receive publication/retry.

```sh
cargo test --locked -p fgit-forge --lib preparation
cargo check --locked -p fgit-cli --all-targets
cargo test --locked -p fgit-node --lib merge_prepare::rebase
cargo test --locked -p fgit-cli --bin fg rebase
```

Test entrypoints are not themselves passing evidence. Recorded results must name
the tested source revision and command status. Full workspace, lint, release and
pinned-Git differential campaigns remain separate gates.

Not implemented by this profile: interactive todo editing, reorder/squash/fixup,
conflict continuation, merge-topology recreation, rename/copy inference, custom
merge drivers, or automatic native rebase publication. These are explicit gaps,
not silent approximations.

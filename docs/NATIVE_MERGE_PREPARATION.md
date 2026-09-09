# Native merge preparation

`fg merge prepare` constructs a native two-parent merge candidate from two
branches selected at one authenticated repository head. `fg merge apply`
remains the separate operation that publishes an independently reviewed
candidate through the coupled Ref + Forge + Outbox transaction.

The production path uses FrankenGit's own object, merge, pack and authority
components. It does not invoke Git, run repository hooks or merge drivers, or
write a temporary mutable Git repository. This implementation adds no external
dependencies.

## Prepare an artifact

For an existing imported node with `main` and `topic` branches:

```bash
fg merge prepare ./fgit-data \
  11111111111111111111111111111111 \
  22222222222222222222222222222222 \
  refs/heads/main \
  ./candidate.bundle \
  --trusted-local \
  --profile path-v1 \
  --source-ref refs/heads/topic \
  --author 'Operator <operator@example.invalid>' \
  --timestamp 1788883200 \
  --message 'Merge topic into main' \
  > ./candidate-receipt.json
```

The author, timestamp and message are explicit reproducibility inputs. The
committer defaults to the supplied author; `--committer` selects a different
explicit identity. Both timestamps use UTC. Neither local Git configuration
nor the current wall clock supplies hidden metadata.

`--trusted-local` acknowledges the local operator's authority to read the
repository and create the artifact. It is not a remote authentication service
or a hostile-filesystem sandbox. `--profile path-v1` is mandatory: this command
does not imply another merge engine's rename, attribute or virtual-base rules.

The target and source must be distinct fully qualified branch names. Missing
and hidden refs share one refusal, and caller visibility can only narrow the
authenticated repository policy. Every original object read must belong to
the selected authority history and reproduce its native identity and kind.

## What path-v1 does

The planner computes all best common ancestors using the existing bounded
commit-graph implementation. Exactly one base is required. Unrelated histories,
shallow or unavailable dependencies, cycles, malformed graph references and
multiple best bases are errors rather than reasons to choose an arbitrary base.

It recursively merges exact paths. A path changed on only one side takes that
change, including deletion. Identical changes are reused. Regular-file content
that changed on both sides uses the existing deterministic line merge, with
executable-bit changes evaluated independently. Directories use native Git
entry ordering; unchanged subtrees and files are referenced by identity rather
than materialized as new payloads.

The resulting commit has target-before as its first parent and source as its
second parent. A fast-forward-capable input still creates an explicit two-parent
candidate. An already integrated source produces `already_up_to_date`, with no
candidate, bundle or repository mutation.

The profile is not Git `ort` equivalence. It does not infer renames, copy
relationships, directory renames, virtual merge bases, custom merge drivers,
filters or hooks. Rename operations are interpreted as their exact-path
add/delete changes. Divergent symlinks and gitlinks are not line-merged. NUL-
containing content requiring a two-sided merge is a binary conflict. When a
`.gitattributes` file in a participating directory or ancestor could affect a
required content merge, the planner reports `AttributesRequireDriver` rather
than executing a driver or pretending its semantics were applied. Unchanged
and one-sided content can still be reused without a content merge.

## Receipts and conflicts

A successful clean result writes one JSON object containing:

- the pinned source authority head and repository identity;
- source and target ref names as lossless hexadecimal bytes;
- `expected_source`, `expected_target`, `merge_base`, `candidate_commit` and
  `root_tree` as native Git identities;
- bundle path, byte count and constructed-object count;
- `profile: "path-v1"`, `outcome: "prepared"`, `node_closed: true`, and
  `published_to_repository: false`.

SHA-1 repositories produce a v2 Git bundle. SHA-256 repositories produce a v3
bundle with `object-format=sha256`. Both parent tips are prerequisites, so a
review repository must already have their reachable history. The artifact
contains the constructed objects, not a second copy of all unchanged history.

Conflicted results print `outcome: "conflicted"`, a merge base, and a bounded
array of raw path bytes, conflict kinds and base/ours/theirs native identities
and modes. They return a nonzero exit status. **No conflicted result carries a
candidate commit or a bundle, and conflict-marker bytes are never presented as
a clean merge.** Use the retained inputs for explicit resolution and review.

An already integrated source prints `outcome: "already_up_to_date"` and
`bundle_created: false`, returning success without creating the output path.

## Artifact and repository lifecycle

Preparation performs no seal, native-object staging, ref update, forge event
append or outbox transition. Generated objects remain in memory while the
candidate is independently checked by the production native merge validator.
That check re-hashes its objects, verifies ordered parents and common ancestry,
and walks its complete reachable closure before the bundle is built.

The node is explicitly closed before the CLI publishes the artifact. A node
shutdown failure leaves no output bundle. The output destination must be absent;
existing files, symlinks and directories are never overwritten. A complete
same-directory temporary file is synchronized and published with a create-only
hard link. Filesystems that do not support that operation refuse rather than
falling back to an overwriting rename. Unix file creation is restricted to the
owner and the parent directory is synchronized after publication.

An error after the link becomes visible says that the complete artifact exists
but finalization was not fully acknowledged. Receipt-output errors also retain
that distinction. Neither error means the repository was changed: preparation
never attempted repository publication. Temporary-file cleanup failures retain
the temporary path and original error rather than hiding them.

## Review, then apply

Review the candidate independently. The preparation receipt identifies what to
review; it is not approval, verification of project tests, or permission for an
agent to approve its own changes. A review repository must have both prerequisite
histories before it can inspect all unchanged objects referenced by the bundle.

After review, supply the exact receipt coordinates explicitly to the existing
mutation command:

```bash
fg merge apply "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main ./candidate.bundle \
  --trusted-local \
  --principal "$PRINCIPAL_ID" \
  --idempotency-key "$REVIEWED_ATTEMPT_KEY" \
  --source-ref refs/heads/topic \
  --expected-source "$EXPECTED_SOURCE" \
  --expected-target "$EXPECTED_TARGET" \
  --merge-base "$MERGE_BASE" \
  --expected-commit "$CANDIDATE_COMMIT" \
  --pull-request "$PULL_REQUEST_NUMBER" \
  --expected-version "$EXPECTED_AGGREGATE_VERSION"
```

The apply path reauthenticates current authority and independently validates
the reviewed bundle. If either branch moved, the earlier preparation does not
authorize overwriting it. Identical retries recover the original canonical
outcome. A version of zero explicitly creates a merge-receipt stream; it does
not invent earlier PR opening, review or approval events. See
[`MERGE_BUNDLE_COMMAND.md`](MERGE_BUNDLE_COMMAND.md) and the
[merge delivery contract](MERGE_FORGE_EVENT_DELIVERY_CONTRACT.md) for publication
and recovery semantics.

## Finite profile

The initial profile admits at most 4,096 ancestor commits, 16,384 graph edges,
100,000 cumulatively decoded tree entries, depth 64 and 4,096-byte paths.
It limits content merges to 64, each with a 1 MiB combined-input ceiling,
a separate 1 MiB output ceiling and explicit diff/merge work limits. There
are at most 128 reported conflicts, 10,000 constructed objects and 32 MiB
of constructed object bytes. The node's selected-source reads also have a
128 MiB cumulative byte ceiling and retain the node's per-object limit,
capped at 32 MiB. Runtime cancellation and finite request budgets remain
additional limits; none are silently extended.

These are acceptance ceilings, not a peak-memory or performance guarantee.
Programmatic callers may narrow `PreparationLimits`, not exceed its v1 maxima.

## Code and verification

`fgit-forge::preparation::prepare_merge` owns the pure construction rules.
`OneNode::prepare_merge_bundle_in` owns authenticated object selection, native
revalidation and artifact encoding. `fg merge prepare` owns the local file and
receipt lifecycle. The existing merge apply path remains the only mutation
step in this workflow.

The changes add thirteen Rust test functions: eight pure merge tests, two
embedded-node preparation/application tests, and three CLI parser/artifact
tests. The binary-level campaign independently derives exact expected blob,
tree, mode, parent and commit bytes for both hash formats, then exercises
prepare, deterministic repetition, explicit apply, idempotent retry, stale
competition, no-op and conflict cases in fresh processes:

```bash
python3 scripts/e2e/merge_preparation_smoke.py --fg /absolute/path/to/fg
```

The campaign refuses a missing executable. Its separate `--self-test` mode
checks only Python fixture construction and the full-object bundle inspector;
it explicitly does not report Rust execution.

In this editing session, Python syntax and helper checks were executed, including
corrupt/truncated/wrong-target bundle negatives. Independently constructed
SHA-1 and SHA-256 candidate bundles were also verified and fetched by installed
Git, with resulting content, executable mode and unchanged source refs checked.
Those are fixture/envelope compatibility checks, not execution of the Rust
implementation or pinned-oracle conformance.

Cargo, rustc, a built `fg`, Rust tests, rustfmt and Clippy were unavailable in
this editing environment. The native tests and full CLI campaign remain
unexecuted here. This source integration does not close a bead or establish the
full Git merge compatibility matrix.

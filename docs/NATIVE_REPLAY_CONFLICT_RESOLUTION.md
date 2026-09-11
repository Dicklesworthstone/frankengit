# Resolve one conflicted cherry-pick or revert

`fg cherry-pick resolve` and `fg revert resolve` finish the previously
conflict-only one-commit replay workflow. They reproduce the actual conflict
set from exact source/target/selected-commit inputs, apply explicit choices,
and build an ordinary single-parent candidate. They do not maintain a second
sequencer database, edit a checkout, invoke Git, or publish repository state.

## Example

First run the existing `prepare` command to inspect the conflicts. Then supply
one choice for every conflicted path using the same historical coordinates:

```bash
fg cherry-pick resolve "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main ./resolved.bundle \
  --trusted-local --profile path-v1 \
  --source-ref refs/heads/topic \
  --expected-target "$TARGET_BEFORE" --expected-source "$SOURCE_TIP" \
  --commit "$SELECTED_COMMIT" \
  --author 'Operator <operator@example.invalid>' --timestamp 1788883200 \
  --message 'Resolve the selected change' \
  --file src/example.rs 100755 ./resolved-example.rs
```

The existing `--mainline`, `--expected-head`, raw-reference, message-file and
lowered-budget options retain their meaning. SHA-1/SHA-256 are inferred from
the explicit native identities. Nothing reads a newer branch tip to repair a
stale request automatically.

Repeated `--ours PATH`, `--theirs PATH`, `--base PATH`, `--delete PATH`, and
`--file PATH MODE INPUT_FILE` options describe distinct conflicts. Each has a
`-hex` form for raw repository path bytes, such as `--ours-hex 7372632fff`.
Files require mode `100644` or `100755`. Empty files, binary bytes, CRLF and a
missing final newline are preserved. Empty content is not deletion. Local
inputs are bounded regular files; final symlinks and devices are rejected.
The filesystem profile is trusted-local, not hostile-host containment.

## Revert side semantics

For cherry-pick the three-tree comparison is `(selected parent, target,
selected commit)`. For revert it is `(selected commit, target, selected parent)`.
Consequently `--theirs` during revert selects the selected commit's mainline
parent version, while `--base` selects the version introduced by that commit.
`--ours` always selects the current target version.

Choosing an absent side is an error. Use `--delete` to remove the conflicted
path explicitly. Whole directory sides, executable modes, symlinks and opaque
submodule entries are preserved by identity; no symlink is followed. Supplied
file bytes always create a regular file with the explicit mode.

## One conflict detector, one reconstruction budget

Both two-parent merge resolution and single-parent replay resolution use
`preparation::resolution::resolve_discovered_conflicts`. The existing path
planner discovers conflicts and reconstructs the result. It checks that each
second-pass conflict reproduces the first pass's exact kind and three entries.

All conflicts require exactly one choice. Clean-path choices, duplicates,
component-overlapping paths, incomplete choices and absent sides refuse before
a candidate is returned. A `resolve` request with no actual conflicts refuses;
use `prepare` for that case. Changing an exact input starts a new preparation,
not a silent continuation of old conflict coordinates.

Discovery and reconstruction retain the same planner, object map, source and
resource counters. There is no second allocation of the tree/content/output
budget. The existing source-selection walk, cancellation checkpoints and
independent native-closure validator remain in force. Limits may be narrowed,
not disabled. When resolving all conflicts to the target leaves no net change,
the result is `no_change` with resolution receipts and no empty commit or bundle.

The node packs the candidate closure minus target history, including any
source-only blob or subtree selected by a resolution. The source commit is not
a parent or a hidden bundle prerequisite. Only the exact target-before commit
is the bundle prerequisite and sole parent.

## Separate review and publication

The resolution receipt has type `commit_replay_resolution` and includes the
existing exact-coordinate/metadata/artifact fields plus `resolutions`. Each
resolution reports its reproduced conflict, explicit choice and resulting
entry or deletion. The CLI checks the receipt against each requested side or
supplied file hash/mode before publishing an artifact. It uses the existing
create-only writer after node shutdown.

`prepare` keeps its original receipt shape. Successful `resolve` exits 0 for
`prepared` or `no_change`. Invalid/incomplete resolution exits 2 without a
candidate; the original `prepare` command retains conflict exit 3. Errors after
artifact visibility preserve that fact. Repository state is never changed by
either preparation command.

Inspect the saved candidate with `fg workspace inspect`, then publish explicitly
with `fg workspace apply`. These remain ordinary source-update operations,
not review approvals. The extension does not activate repository-wide branch
protection, implement rebase/ranges or durable continue/abort state, infer
renames, or execute custom merge drivers. It adds no dependencies or lockfile
changes and does not alter the canonical publication protocol.

## Verification boundary

Seventeen Rust test functions were added: eight core resolution tests, four
embedded-node tests and five CLI tests. They cover both object formats,
historical selection, clean-change preservation, target-only dependency packs,
exact commit bytes, root/mainline cases, inverse side semantics, explicit
missing-side deletion, no-change, raw bytes, shared budgets, cancellation,
visibility/staleness, publication/reopen/retry and receipt tampering. Existing
automatic replay and two-parent resolution tests remain registered.

`python3 scripts/e2e/replay_resolution_smoke.py --self-test` executed locally
and rejected 44 corrupted receipts/bundles. The isolated `--git-oracle` fixture
checks executed with Git 2.47.3 for SHA-1 and SHA-256, verifying complete
candidate bundles in target-only repositories. These execute no FrankenGit and
are not native conformance evidence.

`--fg /absolute/path/to/fg` is the actual fresh-process campaign. It exercises
prepare-conflict, explicit resolution, independent inspection, publication,
resolved no-change, inverse resolution, refusal and non-rollback retry, and
records the supplied binary's SHA-256. That campaign and all Rust compilation,
unit/integration tests, rustfmt and Clippy were not run in the editing
environment: no Rust toolchain or built `fg` is available. Source checks do not
replace the repository's independent revision-bound native gate. No bead was
closed or advanced on this basis.

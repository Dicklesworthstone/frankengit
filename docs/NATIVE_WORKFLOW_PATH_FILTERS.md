# Native PR workflow path filters

`fg workflow watch --pull-request NUMBER` accepts `paths` or `paths-ignore`
under `on.pull_request`, optionally combined with existing target-branch filters.
This is source-head execution, not a synthetic merge or hostile-fork sandbox.

```yaml
on:
  pull_request:
    branches:
      - main
    paths:
      - 'src/**'
      - '!src/private/**'
      - 'src/private/public.rs'
```

At least one changed path must remain selected after ordered patterns are applied
to that path. `paths-ignore` selects a run only when some changed path is outside
all exclusions. Both forms exclude a complete empty comparison. Branch and path
filters are conjunctive. The supported operators are literals, `*`, `**`, `**/`
and leading `!` exclusions/reinclusions in `paths`; other glob operators refuse.
Paths preserve exact bytes, case and spaces. Unicode normalization is not applied.
Directories alone are not changed files; file/directory transitions include the
file endpoint and affected descendants. Adds, deletes, mode changes, binary files,
symlink identities and opaque gitlink changes are covered without following links.
A rename is deletion plus addition, never a similarity inference.

## Canonical basis, not a caller's file list

The actual open native PR chooses its current source and target tips at one
authenticated head. The comparison finds their unique best merge base and walks
from that base to the current source tree. Target-only changes do not spuriously
select a source workflow. Old recorded PR tips are not substituted for current
tips. Both source discovery and path comparison use the same selected immutable
object owner. No Git process, alternate parser, new dependency or runtime is used.

Only graphs needing path selection cause this structural comparison. Existing
unfiltered workflows retain their behavior and graph identities. Filtered graphs
use `fgit-workflow/v6`, binding every ordered pattern and its inclusion mode.
The dispatch plan records comparison commits, tree roots, complete path count and
a domain-separated digest of the sorted length-framed raw paths. The digest is
not an authorization credential or independent proof of execution.

Ordinary explicit `workflow dispatch` lacks canonical comparison coordinates and
refuses a selected path-filtered graph before batch execution. The CLI accepts no
caller-supplied changed-file list. Explicit `workflow run` remains a named manual
execution, not an event-filter evaluator. Push path filters are not admitted by
this initial PR profile.

## Failure, recovery and bounds

All changes must be inspected before any workflow job is started. Missing objects,
ambiguous/disconnected history, invalid trees, cancellation, or a comparison beyond
its fixed limits refuse rather than return a truncated list or imply no changes.
The existing tree walker caps changed entries at 512 (including structural directory
entries), aggregate tree entries at 100,000, depth at 64 and paths at 4,096 bytes.
Merge-base discovery retains the 4,096-commit/16,384-edge bound. Source reads keep
the existing native 128 MiB allowance. No blob content is read for the comparison.
Matching accepts at most 512 unique sorted paths and 256 KiB of path bytes and
charges a 16 Mi-unit work ceiling including matcher setup. Each filter retains
32 patterns, 256 bytes per pattern and 4,096 total pattern bytes. These are explicit
native limits, not a claim to duplicate every hosted Actions fallback.

Excluded workflows create no jobs or checks. Artifact contracts naming an excluded
workflow refuse rather than silently dropping promised outputs. Existing attempt
records, replay suppression and original check keys still own execution/recovery.
The watcher may retain an unresolved event after a preflight failure; changing a
pattern or deleting output is not permission to replay that reserved invocation.
Retain its custody records and use the existing operator reconciliation boundary.

## Tests

`cargo test --locked -p fgit-schema --all-targets` exercises parsing, identities,
matching, bounds and legacy forms. `cargo test --locked -p fgit-forge --lib review::`
covers the reused walker and complete path inventories with a payload reader that
panics if invoked. `scripts/e2e/suites/smokes/workflow_path_filters.sh`, supplied an
actual prebuilt `FG_BIN`, runs real imports, PRs, native jobs, fresh-process retries
and canonical check publication in SHA-1 and SHA-256. Independently constructed
expected path digests distinguish merge-base from target-tip comparisons.
These are focused tests, not whole-workspace, release, physical power-loss or
hostile-code-isolation qualification.

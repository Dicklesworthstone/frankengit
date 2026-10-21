# Native workflow branch filters

Related: `frankengit-root-doctrine-x2mv.4.12`,
[NATIVE_REF_WORKFLOW_WATCH.md](NATIVE_REF_WORKFLOW_WATCH.md),
[NATIVE_PULL_REQUEST_WORKFLOW_WATCH.md](NATIVE_PULL_REQUEST_WORKFLOW_WATCH.md).

The native compiler and dispatcher accept a bounded `on` mapping. Branch filters
select execution; they do not grant capabilities, authorize a publisher, weaken
required checks, or turn an excluded workflow into a passing check.

```yaml
name: branch-selected-ci
on:
  push:
    branches:
      - 'topic/**'
      - '!topic/private/**'
      - 'topic/private/allowed'
  pull_request:
    branches:
      - main
  workflow_dispatch: ''
jobs:
  build:
    runs-on: fgit-trusted-local
    steps:
      - run: ./verify.sh
```

## Exact selection

`fg workflow watch` selects a push workflow against the actual canonical source
branch. With `--pull-request NUMBER`, it selects a PR workflow against the
canonical **target branch**, while executing the current **source commit**.
The PR metadata, target and source are selected at the same authenticated head;
the existing pinned source selection refuses intervening authority movement.
This remains source-head testing, not synthetic merged-tree execution.

`branches` is an ordered inclusion list. A positive match includes; a later
leading-`!` match excludes; a later positive match can reinclude. At least one
positive pattern is required. `branches-ignore` excludes any matching pattern
and permits nonmatching branches. It cannot contain leading `!` patterns or
coexist with `branches` on the same event. Patterns retain source order and are
not sorted or deduplicated.

Literal bytes match exactly, including case and UTF-8 spelling; there is no
Unicode normalization or lossy reference conversion. `*` consumes zero or more
bytes except `/`; `**` may cross `/`. At a component boundary, `**/` consumes zero
or more complete components, so `**/main` also matches `main`. Wildcards may match
raw non-UTF-8 reference bytes. Filters apply to `refs/heads/` references, never
tags or arbitrary bare names.

Other pattern operators (`?`, `+`, character classes, escapes), triple stars,
control/whitespace characters and expressions refuse with a source span. This
is a named subset, not a full Actions glob implementation. Unknown event mapping
keys/options, `paths`, `tags`, activity types and dispatch-input declarations
also refuse; they are not silently discarded.

Scalar and block-list event declarations retain their historical behavior.
Within a mixed mapping, an unfiltered event is explicitly written `push: ''` or
`workflow_dispatch: ''`. The existing scanner still refuses flow mappings and
bare keys without an indented value. This slice does not reinterpret YAML nulls.

## Ownership, bounds and evidence

Each event admits at most 32 patterns, 256 bytes per pattern and 4096 aggregate
pattern bytes. References are at most 1024 bytes. Matching uses fixed-memory
bounded dynamic programming rather than recursive/backtracking regular
expressions. Cancellation is checked per pattern token and at selection entry
and completion, with at most 1024 reference bytes between token checkpoints.

Graphs carrying filters use `fgit-workflow/v5`. The ordered pattern text and
include/ignore mode are part of canonical graph bytes, alongside existing
matrix, environment, working-directory and deadline records. Graphs without
filters preserve their existing v1-v4 identities. The generated construct
registry describes the admitted subset.

Dispatch plans for a filtered event retain `trigger_ref_hex`, including when
nothing matches. All definitions still undergo ordinary compiler and capability
preflight before batch reservation or process startup. Artifact selections
naming an excluded workflow continue to refuse rather than disappearing.
Excluded definitions create no job workspace, execution receipt or check.
An event with no matching definitions can settle as observed without claiming
that a build ran. Fresh-process replay suppression and original-result check
publication use the existing durable watcher records.

The explicit `fg workflow dispatch --event push` path uses its selected source
reference. Explicit `--event pull_request` has no canonical PR target and refuses
filtered PR definitions before creating a batch; use the native watcher with
`--pull-request` instead. Unfiltered explicit PR dispatch remains compatible.
Explicit single-workflow `run` commands remain manual execution requests and do
not consult event filters.

This is trusted-local host execution. Filters do not provide hostile-code
isolation, an all-events queue, automatic PR metadata updates, or merge approval.
Retain custody records across backup/restore. Old binaries refuse new filtered
workflow mappings instead of executing with ignored filters.

## Native verification

`cargo test --locked -p fgit-schema --test workflow_triggers` covers historical
bytes, ordered exclusion/reinclusion, malformed and bounded inputs, exact names,
missing targets, cancellation and a small exhaustive independent matcher oracle.
The broader schema suite checks existing graph identities and generated schemas.

`cargo test --locked -p fgit-node --test trusted_ref_workflow` exercises real
source selection, filtered execution and zero-run outcomes, node reopen, and
explicit PR missing-target refusals with an unfiltered permitted twin.

With `FG_BIN` naming the actual built Rust executable, run
`scripts/e2e/suites/workflow/branch_filters.sh`. The campaign drives push/PR
selection, exact plan coordinates, fresh-process deduplication, canonical success
publication, excluded targets, close/reopen and current-source advancement in
both SHA-1 and SHA-256 repositories. Existing watch and publication campaigns
remain applicable. These are functional tests, not full-workspace/release,
physical power-loss or hostile-isolation evidence.

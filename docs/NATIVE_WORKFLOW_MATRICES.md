# Bounded native workflow matrices

The static matrix profile lowers one declared job into ordinary native jobs.
The existing workflow scheduler, per-job workspace ownership, step-context
validation and journal/check identity machinery consume the resulting DAG.
There is no alternate executor, runtime, database or remote execution grant.
This remains the explicit trusted-local execution profile.

```yaml
name: build variants
on: workflow_dispatch
jobs:
  build:
    runs-on: fgit-trusted-local
    strategy:
      fail-fast: false
      matrix:
        mode:
          - debug
          - release
        platform:
          - linux
          - portable
        exclude:
          - mode: debug
            platform: portable
        include:
          - mode: release
            platform: custom
    steps:
      - run: printf '%s|%s' "$MODE" "$PLATFORM"
        env:
          MODE: '${{ matrix.mode }}'
          PLATFORM: '${{ matrix.platform }}'
  package:
    runs-on: fgit-trusted-local
    needs: build
    steps:
      - run: echo all-build-variants-passed
```

## Selected semantics

The native scheduler runs variants serially. Omitted `fail-fast` and explicit
`fail-fast: true` stop the remaining unstarted variants of that source job after
the first failed, timed-out, output-limited or refused variant. The failed job
finishes its eligible diagnostic/cleanup steps, artifact/log custody and workspace
closure first, and keeps its exact failure outcome. Later variants receive native
`skipped` observations with zero attempts, no workspace and no execution receipt;
they never become successful checks. This is the serial native normalization of
fail-fast, not a claim about cancelling concurrent matrix processes.

Explicit `fail-fast: false` continues the remaining variants. Independent jobs
and other matrices continue in either mode. Ordinary `needs` dependents remain
blocked by the real failed variant; `failure()` and `always()` diagnostics can
inspect a clean failure and the skipped siblings. Caller cancellation and lost
containment retain their global stop behavior and cannot be downgraded to a
matrix-local skip. A source-job `if: always()` does not override its fail-fast
policy. The legacy command-only coordinator refuses fail-fast matrices before
admission; the job-scoped trusted workflow path owns this behavior.

Only literal `true` and `false` policies are accepted. `max-parallel`, unknown
strategy fields, dynamic matrices and general expressions still refuse. All
variants are validated and charged against expansion bounds before execution;
fail-fast never licenses a partial preflight or a fresh run/output budget.

Axis names are sorted lexicographically. Values within each axis preserve their
source sequence order. The Cartesian product is formed in that deterministic
order, exclusions remove matching original rows, and includes are then processed
in source order. An inclusion merges into every surviving original row whose
axis values it does not replace. It may update previously added non-axis values.
An unmatched inclusion creates a separate row; appended rows never become new
include-merge targets. Include-only matrices are supported. Exclusions may name
only declared axes. Duplicate axis values, duplicate selected rows and an empty
selection refuse rather than introducing ambiguous or vacuous success.

Each variant is named `<source-job>__matrix_<zero-padded-index>`, starting at
`000`. Generated names must be disjoint from all declared job names. A
`needs: build` dependency addresses the whole declared group: it expands to all
selected build variants. A caller cannot name a hidden generated member to bypass
that join. Existing success, failure and always conditions consume the complete
set of terminal dependency outcomes. Ordinary matrix failure remains failure;
cancellation and unresolved containment retain their existing stop rules.

## Literal inputs, not executable interpolation

Only a complete scalar `${{ matrix.name }}` in job or step `env` values, step
`working-directory`, or job `defaults.run.working-directory` is substituted.
Every selected row must define the requested
name. The result is passed through the existing StepContext validator, retaining
all environment limits, reserved-name rules and workspace-relative path checks.
Job values are then inherited by their steps, with explicit step values taking
precedence. Workflow-level environment and run defaults remain literal and cannot
use a job's matrix. Invalid job values refuse even if a step would override them.
Shell selection is always a literal `sh` or `bash`; a matrix cannot supply an
interpreter name. See [run defaults](NATIVE_WORKFLOW_STEP_CONTEXT.md#workflow-and-job-run-defaults)
for per-field inheritance and explicit workspace-root resets.
There is no string interpolation in scripts, job conditions, runner labels, or
other fields. A value such as `$(touch unexpected)` remains environment data,
not inserted shell source. Scripts can deliberately evaluate their own inputs;
this is not a hostile-code isolation claim.

Each job retains its exact source-job name and all selected variable values,
including unused variables. These produce `matrix-origin` and `matrix-value`
records in the `fgit-workflow/v3` canonical graph. The graph commitment therefore
changes when a matrix input changes. A graph using fail-fast selects
`fgit-workflow/v9` and adds one `matrix-fail-fast` record per selected variant;
omitted and explicit `true` have identical graph bytes. Explicit `false` preserves
the previous canonical bytes and selected version, including later context,
deadline, trigger and shell extensions. Context-free v1 graph bytes and
pre-existing step-context v2 graph bytes are unchanged.

## Bounded expansion

The profile admits at most eight axes, 64 values per axis, and 256 raw Cartesian
combinations before exclusion. Includes and excludes each admit 64 records, and
each resulting row has at most 16 variables. Names are bounded ASCII identifiers;
values are literal strings of at most 1,024 bytes. Matrix job names are at most
128 ASCII alphanumeric/underscore/hyphen bytes.

The entire expanded workflow is limited to 128 jobs, 512 steps, 8,192 dependency
edges and an 8 MiB conservative allocation-accounting envelope. Job/step/byte
bounds are checked before source-node cloning. Dependency expansion is also
charged before appending IDs. Workflow/job environment inheritance charges new
copies before allocation against this same byte allowance, including ordinary
jobs in the graph; see [environment inheritance](NATIVE_WORKFLOW_STEP_CONTEXT.md).
These are workload limits, not measured peak-RSS
claims. Existing YAML byte/node/depth limits remain independent safeguards.

## Validation entry points

```sh
cargo test -p fgit-schema --test workflow_matrix --test workflow_matrix_fail_fast --test workflow --test workflow_context --test workflow_environment --test workflow_spans --locked
cargo test -p fgit-runner --test workflow_matrix --lib --locked
cargo check -p fgit-cli --all-targets --locked
```

Schema tests check independently enumerated Cartesian products, stable bytes,
include/exclude behavior, group dependencies, collision refusals, and exact
resource boundaries. Runner integration tests use real local shell processes
with independent workspaces and exercise failure joins, literal values,
cancellation, and shared output limits. The actual-binary suite lives at
`scripts/e2e/suites/workflow/matrix_execution.sh`; set `FG_BIN` to a prebuilt native
`fg`. It creates native SHA-1 and SHA-256 repositories, imports them, executes
matrix workflows, inspects durable results, publishes distinct per-variant
observations, retries exact publication identities, and recovers without the
original source directory. No external Git engine is used by these fixtures.

Fail-fast regressions cover live foreground shell execution, failure/always
diagnostics, independent matrix continuation, clean timeout/output/refusal twins,
caller cancellation and unresolved containment. Journal tests reopen the exact
failed and skipped observations, preserve zero attempts for unstarted variants,
and verify that receipt lookup does not execute them. The binary matrix campaign
also selects default and explicit fail-fast in both hash formats, publishes the
original failed and skipped results, retries the same publication, and recovers
after removing the source repository. These entry points establish no pass until
executed at the selected revision.

## Conditional completion and saved observations

A trusted run can complete successfully when its actual jobs succeed and an
optional `failure()` diagnostic is skipped. The whole-run `succeeded` field and
CLI exit status use this completion predicate after workspace closure and request
finalization. A failed matrix variant still blocks the ordinary dependent group;
a successful failure diagnostic cannot erase that failure. Cancellation, timeout,
output exhaustion, cleanup failure and retained workspaces remain non-success.
An empty/all-skipped run does not assert a successful execution.

The nested `execution.succeeded` field retains its historical, stricter meaning:
**every job individually succeeded**, including no skipped jobs. It remains false
for a successful run with skipped diagnostics. Keeping this legacy evidence
summary unchanged preserves existing frame bytes, journal commitments and
source/graph bindings. Whole-run completion does not rewrite saved per-job
outcomes, acknowledge delivery, retry execution or grant a required-check pass.
A skipped job still publishes `action_required`, never `success`.

The native receipt verifier and canonical publication path remain unchanged.
The matrix suite verifies exact graph/evidence identities, distinct check IDs,
unchanged refs and byte-identical publication retries through real `fg` processes.
This does not establish hostile-code isolation, physical power-loss behavior,
maximum-profile throughput or complete-workspace validation, and does not close
the larger CI product-loop bead or process-descendant containment gap.

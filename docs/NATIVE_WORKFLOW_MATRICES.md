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

An explicit `fail-fast: false` is required. The native scheduler runs variants
serially and continues independent work after ordinary failure; it does not
pretend to implement implicit fail-fast cancellation or `max-parallel`.
Unknown strategy fields, dynamic matrices, and general expressions refuse.

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

Only a complete scalar `${{ matrix.name }}` in step `env` values or
`working-directory` is substituted. Every selected row must define the requested
name. The result is passed through the existing StepContext validator, retaining
all environment limits, reserved-name rules and workspace-relative path checks.
There is no string interpolation in scripts, job conditions, runner labels, or
other fields. A value such as `$(touch unexpected)` remains environment data,
not inserted shell source. Scripts can deliberately evaluate their own inputs;
this is not a hostile-code isolation claim.

Each job retains its exact source-job name and all selected variable values,
including unused variables. These produce `matrix-origin` and `matrix-value`
records in the `fgit-workflow/v3` canonical graph. The graph commitment therefore
changes when a matrix input changes. Context-free v1 graph bytes and pre-existing
step-context v2 graph bytes are unchanged.

## Bounded expansion

The profile admits at most eight axes, 64 values per axis, and 256 raw Cartesian
combinations before exclusion. Includes and excludes each admit 64 records, and
each resulting row has at most 16 variables. Names are bounded ASCII identifiers;
values are literal strings of at most 1,024 bytes. Matrix job names are at most
128 ASCII alphanumeric/underscore/hyphen bytes.

The entire expanded workflow is limited to 128 jobs, 512 steps, 8,192 dependency
edges and an 8 MiB conservative allocation-accounting envelope. Job/step/byte
bounds are checked before source-node cloning. Dependency expansion is also
charged before appending IDs. These are workload limits, not measured peak-RSS
claims. Existing YAML byte/node/depth limits remain independent safeguards.

## Validation entry points

```sh
cargo test -p fgit-schema --test workflow_matrix --test workflow --test workflow_context --test workflow_spans --locked
cargo test -p fgit-runner --test workflow_matrix --lib --locked
cargo check -p fgit-cli --all-targets --locked
```

Schema tests check independently enumerated Cartesian products, stable bytes,
include/exclude behavior, group dependencies, collision refusals, and exact
resource boundaries. Runner integration tests use real local shell processes
with independent workspaces and exercise failure joins, literal values,
cancellation, and shared output limits. These tests are not a full persisted-node
or actual-fg-process end-to-end campaign. This patch does not complete the larger
CI product-loop bead or the unresolved process-descendant containment work.

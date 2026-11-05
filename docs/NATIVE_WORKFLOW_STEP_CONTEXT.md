# Native workflow environment and step working directory

The trusted-local workflow runner accepts literal `env` defaults at workflow and
job level, explicit `env` overrides on individual steps, and step-local
`working-directory`. The schema compiler lowers the three environment levels to
each step's complete effective map. The graph identity binds those inputs, and
the native process adapter applies them without rewriting the shell script. The
durable coordinator forwards the same validated context.

```yaml
name: explicit build context
on: workflow_dispatch
env:
  BUILD_MODE: debug
  LITERAL: '$(touch injected) is literal data'
jobs:
  build:
    runs-on: fgit-trusted-local
    env:
      BUILD_MODE: release
    steps:
      - run: mkdir -p build/nested
      - name: configured step
        env:
          BUILD_MODE: package
          STEP_ONLY: present
        working-directory: ./build/nested
        run: |
          printf '%s\n' "$BUILD_MODE"
          printf '%s\n' "$LITERAL"
          printf '%s' "$BUILD_MODE" > result
      - name: fresh step context
        run: |
          test "$BUILD_MODE" = release
          test -z "${STEP_ONLY+x}"
          test -f build/nested/result
          test ! -e build/nested/injected
  independent:
    runs-on: fgit-trusted-local
    steps:
      - run: test "$BUILD_MODE" = debug
```

Use the existing `fg workflow run` interface with `--trusted-local`, an explicit
workflow path, input prefixes including that workflow, and an existing private
run parent. No new command, permission, network service or secret provider is
introduced. Candidate and directory-dispatch execution share the same native
executor. This is still trusted host-user execution, not a hostile-code sandbox.

## Literal environment with explicit precedence

Every step starts with a cleared process environment and the base values
`PATH=/usr/bin:/bin` and `LANG=C`. Workflow defaults apply first, then job values,
then step values; a more specific declaration replaces the same name, including
with an empty string. The resulting map can explicitly replace the base `PATH`
or `LANG`. The parent shell's environment is not inherited.

In the example, the configured step sees `BUILD_MODE=package`, the next build
step sees `BUILD_MODE=release`, and the independent job sees `BUILD_MODE=debug`.
All steps inherit the workflow's literal `LITERAL` value. Step-only and job-only
declarations do not leak into siblings, and a shell's own exports do not change
another step's environment.

Values are literal strings supplied through the process environment API. A value
containing `$HOME`, `$(...)`, quotes, spaces or semicolons is not evaluated while
constructing the command. Scripts can deliberately interpret values themselves,
so this property is not a promise about arbitrary trusted script behavior.

Each declared environment map and each merged effective map is limited to
64 entries, 64 bytes per ASCII identifier, 8,192 bytes per value, and 65,536
aggregate identifier/value bytes. Identifiers match
`[A-Za-z_][A-Za-z0-9_]*`. Duplicate names, NUL, unresolved workflow expressions `${{ ... }}`,
and oversized values refuse. Empty literal values are supported.

Loader prefixes `LD_` and `DYLD_`, runner identity prefixes `FGIT_`, `GITHUB_` and
`RUNNER_`, and shell startup/control names `BASH_ENV`, `ENV`, `SHELLOPTS`,
`BASHOPTS`, `IFS` and `CDPATH` are reserved. Invalid-value diagnostics report a
source location and static reason without printing the value. Environment values
are ordinary repository source data, not secret storage or redacted credentials.
Every source layer is validated before overrides are applied: a forbidden
workflow value is still refused when every job replaces it, and a forbidden job
value is still refused when every step replaces it. Secret lookup and general
expression evaluation remain outside this subset.

For a static matrix job, job and step environment values can use the existing
whole-value `${{ matrix.name }}` form. Resolution happens before the normal
literal-value validation and inheritance. Workflow-level values cannot reference
a job's matrix, and partial interpolation such as `prefix-${{ matrix.name }}`
refuses. See [native matrices](NATIVE_WORKFLOW_MATRICES.md).

Inherited copies also consume the existing 8 MiB conservative expanded-workflow
allocation allowance, for both matrix and ordinary jobs. Source-node estimates,
newly copied inherited names/values and entry overhead, and expanded dependencies
share that budget. Effective-map limits and copy charges are checked before
inherited strings are copied. An explicitly overridden parent value is not
copied into the child. These are bounded-workload rules, not measured peak-memory
claims; YAML parser limits remain independent.

## Workspace-relative working directory

The default is the current job workspace root. `.` and `./` explicitly select
that same default. A leading `./` is normalized; `./src/tools` and `src/tools`
have the same graph representation. Other paths are nonempty, at most 1,024 bytes,
and contain only nonempty relative components. Parent traversal, absolute paths,
embedded `.` components, control characters, backslashes, colons and expressions
are refused during compilation.

The selected directory must exist at the moment its step starts. An earlier step
in the same job may create it. The process adapter checks each component and
refuses symlinks, files and missing directories before spawning that step. It
also checks that the canonical result remains inside the workspace. These checks
are not atomic containment against concurrent mutation by another host process;
this profile assumes operator-owned trusted workspace storage.

A directory selection applies only to its step. Subsequent steps without the
field start at the workspace root. Jobs continue to have independent working
copies. Existing cancellation, timeout, output limits and workspace cleanup
remain in force.

## Identity, older adapters and saved results

Context-free graphs retain their exact `fgit-workflow/v1` canonical bytes.
A nondefault effective step environment or directory selects `fgit-workflow/v2`.
Sorted, escaped `step-env` records and normalized `step-cwd` records bind the complete
execution inputs into the graph commitment. Source order of environment entries
does not change that commitment; changing a name, value or directory does.
Moving the same effective literal from a step to a job or workflow default keeps
that graph representation. The exact workflow source is separately bound by the
run and durable attempt, so a changed source cannot adopt an old attempt merely
because its effective execution graph matches.

Older `WorkflowExecutor` implementations default to refusing a context-bearing
graph before starting any job. The command-only capsule adapter also refuses
explicit context rather than losing it. The job-scoped durable adapter explicitly
forwards context to the native executor.

The existing execution report's `environment` field describes the **base**
environment, not each step's override map. The exact effective overrides are
recoverable from the workflow source and graph bound by the report. Saved job
observations, check-proposal journals and their later source-verified publication
therefore retain the graph identity, including context. This does not change
which check publishers or protection policies are trusted, or automatically turn
a local report into a required-check approval.

## Reproduction

Focused schema tests live in `crates/fgit-schema/tests/workflow_context.rs` and
`workflow_environment.rs`. Runner coverage includes
`crates/fgit-runner/src/workflow/context_tests.rs`, the command-only adapter's
`step_context_tests`, and the durable attempt test
`durable_execution_forwards_inherited_context_and_reopens_exactly_without_execution`.
The latter uses real private journal files and an explicitly recording executor;
it needs no process launch or procfs. The native process tests and binary-driven
suite require a Linux host with coherent process-group/procfs observations. The suite is
`scripts/e2e/suites/workflow/step_context.sh`; provide `FG_BIN` pointing to an
already built native `fg`. Its fixtures create native SHA-1/SHA-256 objects and
execute real imports, inheritance and matrix workflows, recovery, and saved-result
publication. Success and containment assertions are unchanged on hosts that
cannot provide those process observations.

The workflow construct artifact is emitted by
`fgit_schema::emit::workflow_registry`; an equality test checks it against the
checked-in JSON. No unrelated schema or workflow golden is regenerated for this
feature, and this document makes no full-workspace verification claim.

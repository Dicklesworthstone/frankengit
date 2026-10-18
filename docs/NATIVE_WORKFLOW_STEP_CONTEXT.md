# Native workflow step environment and working directory

The trusted-local workflow runner accepts explicit `env` and `working-directory`
fields on individual steps. The schema compiler validates them, the graph identity
binds them, and the native process adapter applies them without rewriting the
shell script. The durable coordinator forwards the same validated context.

```yaml
name: explicit build context
on: workflow_dispatch
jobs:
  build:
    runs-on: fgit-trusted-local
    steps:
      - run: mkdir -p build/nested
      - name: configured step
        env:
          BUILD_MODE: release
          LITERAL: '$(touch injected) is literal data'
        working-directory: ./build/nested
        run: |
          printf '%s\n' "$BUILD_MODE"
          printf '%s\n' "$LITERAL"
          printf '%s' "$BUILD_MODE" > result
      - name: fresh step context
        run: |
          test -z "${BUILD_MODE+x}"
          test -f build/nested/result
          test ! -e build/nested/injected
```

Use the existing `fg workflow run` interface with `--trusted-local`, an explicit
workflow path, input prefixes including that workflow, and an existing private
run parent. No new command, permission, network service or secret provider is
introduced. Candidate and directory-dispatch execution share the same native
executor. This is still trusted host-user execution, not a hostile-code sandbox.

## Literal, step-local environment

Every step starts with a cleared process environment and the base values
`PATH=/usr/bin:/bin` and `LANG=C`. Explicit step values are then applied, including
explicit replacements of those base values. The parent shell's environment is
not inherited. A value from one step does not appear in a later step or job.

Values are literal strings supplied through the process environment API. A value
containing `$HOME`, `$(...)`, quotes, spaces or semicolons is not evaluated while
constructing the command. Scripts can deliberately interpret values themselves,
so this property is not a promise about arbitrary trusted script behavior.

The accepted limits are 64 entries, 64 bytes per ASCII identifier, 8,192 bytes per
value, and 65,536 aggregate identifier/value bytes. Identifiers match
`[A-Za-z_][A-Za-z0-9_]*`. Duplicate names, NUL, workflow expressions `${{ ... }}`,
and oversized values refuse. Empty literal values are supported.

Loader prefixes `LD_` and `DYLD_`, runner identity prefixes `FGIT_`, `GITHUB_` and
`RUNNER_`, and shell startup/control names `BASH_ENV`, `ENV`, `SHELLOPTS`,
`BASHOPTS`, `IFS` and `CDPATH` are reserved. Invalid-value diagnostics report a
source location and static reason without printing the value. Environment values
are ordinary repository source data, not secret storage or redacted credentials.
Workflow/job-level inherited `env`, secret lookup and expression evaluation remain
outside this subset.

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
A nondefault step environment or directory selects `fgit-workflow/v2`. Sorted,
escaped `step-env` records and normalized `step-cwd` records bind the complete
execution inputs into the graph commitment. Source order of environment entries
does not change that commitment; changing a name, value or directory does.

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

Focused tests live in `crates/fgit-schema/tests/workflow_context.rs`,
`crates/fgit-runner/src/workflow/context_tests.rs`, and the command-only adapter's
`step_context_tests`. The binary-driven suite is
`scripts/e2e/suites/workflow/step_context.sh`; provide `FG_BIN` pointing to an
already built native `fg`. Its fixtures create native SHA-1/SHA-256 objects and
execute real imports, workflow runs, recovery, and saved-result publication.

The workflow construct artifact is emitted by
`fgit_schema::emit::workflow_registry`; an equality test checks it against the
checked-in JSON. No unrelated schema or workflow golden is regenerated for this
feature, and this document makes no full-workspace verification claim.

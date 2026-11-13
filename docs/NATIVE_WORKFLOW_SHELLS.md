# Native workflow shell selection

Trusted-local workflows can select `shell: bash` or `shell: sh` for a run step.
This lets scripts use Bash arrays and pipeline failure handling without embedding
another shell invocation inside the script. Canonical-source, candidate,
dispatch and watched workflows use the same compiler and process adapter.

```yaml
name: native shell build
on: workflow_dispatch
jobs:
  build:
    runs-on: fgit-trusted-local
    steps:
      - name: Bash build
        shell: bash
        run: |
          components=(core server)
          for component in "${components[@]}"; do
            printf 'Building %s\n' "$component"
          done
      - name: Portable diagnostic
        shell: sh
        run: printf '%s\n' 'Build steps finished'
```

Run this through the existing [trusted workflow command](TRUSTED_WORKFLOW_EXECUTION.md)
with its explicit trust, source input, private run-directory and run-ID options.
The native runner executes the workflow; this feature does not contact the
GitHub Actions service.

## Interpreter and failure semantics

| Step selection | Fixed interpreter and arguments before the script |
| --- | --- |
| Field omitted | `/bin/sh -eu -c` |
| `shell: sh` | `/bin/sh -e -c` |
| `shell: bash` | `/bin/bash --noprofile --norc -e -o pipefail -c` |

Omitting the field preserves the original native runner behavior, including
failure on an unset variable. Explicit `sh` and `bash` do not enable `nounset`;
scripts can request `set -u` themselves. Bash's `pipefail` makes a failed
pipeline component fail the step even when its final command succeeds.
An ordinary failed step still follows the existing `success()`, `failure()` and
`always()` rules; cancellation and containment failure never authorize a new
diagnostic process.

The shell is a closed literal choice, selected before execution. Custom paths,
templates, arguments, expressions and other shell names refuse during whole-graph
validation. The process adapter uses the absolute interpreter path and does not
search `PATH` or fall back to another shell if it is missing. The supported flags
follow the corresponding explicit-shell failure behavior described in
[GitHub's workflow syntax reference](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idstepsshell).
The native adapter supplies the script with `-c`; this is not a claim of complete
GitHub runner or temporary-script compatibility.

Each step retains its own [literal environment and working directory](NATIVE_WORKFLOW_STEP_CONTEXT.md).
The cleared environment, reserved startup variables, process-group ownership,
bounded output, deadlines and cancellation/drain rules remain in force. Bash is
an operator-installed trusted execution tool, not a newly linked production
dependency or a hostile-code sandbox.

## Identity, reports and recovery

Explicit shell selection becomes a `step-shell` record in the version-eight
canonical workflow graph. Changing the selected shell therefore changes the
graph commitment and cannot adopt an earlier durable attempt. Workflows without
explicit shells retain their previous canonical graph bytes.

Reports containing an executed explicit-shell step use report schema version 2.
The top-level `shell` and `shell_flags` fields are null, and every executed step
records its exact interpreter and fixed argument list. Mixed reports describe
legacy steps as `/bin/sh` with `[-eu, -c]`, explicit `sh` with `[-e, -c]`, and
explicit Bash with the full flags above. A report, or an individual job evidence
frame, containing only legacy steps retains byte-identical version-one encoding.

Native recovery, the operator watcher and browser check-evidence inspection
validate these versioned profiles. Unknown paths, missing flags, arbitrary
arguments, inconsistent versions and malformed fields refuse. Recorded evidence
keeps the original source, graph, run, attempt, resource limits and output bytes;
inspection does not execute the workflow again. A local successful observation
still needs the existing separately authorized check-publication path.

Existing execution adapters must explicitly opt into shell support in addition
to process-context support. Otherwise the entire graph refuses before the first
job starts, preventing an older adapter from silently running a Bash script as
`sh`.

## Focused verification

The schema tests are in `crates/fgit-schema/tests/workflow_shell.rs`. Real Linux
process tests in `crates/fgit-runner/src/workflow/shell_tests.rs` cover shell
syntax, pipeline and unset-variable behavior, clean environments, fixed paths,
output limits, cancellation, direct-child reaping and adapter preflight.
The observation tests retain version-one compatibility and check version-two
round trips and altered interpreter/argument refusals. Native integration tests
in `crates/fgit-node/tests/trusted_workflow/shell.rs` exercise both Git hash
domains, saved observations, restart and exact-key check publication. These are
test locations, not a claim that any broader release gate has passed.

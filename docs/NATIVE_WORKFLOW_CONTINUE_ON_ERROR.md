# Native workflow optional steps

Trusted-local workflows accept a literal `continue-on-error: true` on an
individual run step. An ordinary nonzero exit remains a failed execution in
the saved evidence, while the declared policy lets the job proceed to its next
normal step. This is useful for optional diagnostics or experimental checks
that should report their result without preventing required work from running.

```yaml
name: build with optional diagnostics
on: workflow_dispatch
jobs:
  build:
    runs-on: fgit-trusted-local
    steps:
      - name: Experimental analysis
        continue-on-error: true
        run: ./scripts/experimental-analysis.sh
      - name: Required build
        run: ./scripts/build.sh
  package:
    runs-on: fgit-trusted-local
    needs: build
    steps:
      - run: ./scripts/package.sh
```

Execute this through the existing [trusted workflow command](TRUSTED_WORKFLOW_EXECUTION.md)
with its explicit trust, source, input and private run-directory selections.
Canonical-source and candidate workflows, dispatch and watched workflows share
the same compiler and native execution semantics. This feature does not invoke
the GitHub Actions service.

## Exact failure semantics

The runner tolerates a failure only when all of these observations hold:

- The compiled step explicitly enables `continue-on-error`.
- Its raw outcome is `failed`, with a known nonzero process exit code.
- Captured output is complete.
- Process containment and workspace cleanup do not require retention.

The runner first applies its existing cancellation, deadline, output and
containment checks. A timeout, cancellation, output limit, incomplete observation,
worker refusal, missing exit status, or containment failure cannot become success
through this setting. Cleanup remains mandatory. An unjoined descendant still
prevents success even if the shell exits with an ordinary nonzero code.

An eligible tolerated failure leaves the job's current success/failure state
unchanged. Later `success()` steps can run and `failure()` steps remain skipped
unless another, untolerated step has failed. `always()` keeps its existing
meaning. A tolerated diagnostic cannot erase an earlier required failure.
Downstream jobs observe the final job outcome, and matrix fail-fast responds to
that same outcome. Tolerated ordinary failures alone do not fail the job or stop
its matrix siblings.

Omission and `continue-on-error: false` preserve the previous behavior: ordinary
failure makes the job fail, normal subsequent steps skip, and explicit failure
or always diagnostics may run in the same workspace. Job-level
`continue-on-error`, general expressions and matrix expressions in the policy
field remain unsupported. Only exact lowercase scalar `true` and `false` are
accepted; YAML truthiness such as `yes`, alternate case and collection values
refuse during whole-graph validation.

## Identity, evidence and recovery

An enabled policy contributes a `step-continue-on-error` record to canonical
workflow graph version 10. The graph identifies the exact job and step to which
the policy applies. Omitted and false fields keep prior version 1–9 graph bytes
unchanged. Matrix expansion copies the literal policy into each native variant.

Execution reports with an observed enabled step use report schema version 3.
Every executed step in that report retains its shell fields and records:

| Field | Meaning |
| --- | --- |
| `continue_on_error` | The source policy selected for this step. |
| `outcome_tolerated` | Whether this exact ordinary failure was tolerated. |
| `outcome` | The raw execution outcome, including `failed`. |
| `exit_code` | The original process exit code. |
| `output_complete` | Whether the captured streams are complete. |
| `workspace_retained` | Whether containment requires retaining the workspace. |

A tolerated exit 7 is still `outcome: "failed"` and `exit_code: 7`, with both
policy booleans true. A successful optional step has `outcome_tolerated: false`.
Reports without any executed enabled step retain their original version-one or
version-two encoding, including per-job evidence fragments from a larger run.

Native recovery and the operator/browser evidence readers verify this versioned
representation. Contradictory tolerance, unsafe outcomes marked tolerated,
malformed booleans and inconsistent versions refuse. The exact evidence binds
the source, graph, run and attempt; recovery reads it without rerunning commands.
An occupied run ID still refuses, and changing the workflow cannot adopt an
earlier attempt's identity.

An independently authorized check-publication command can publish a successful
job that contains an explicitly tolerated ordinary failure. The canonical check
still refers to its exact source, graph and retained evidence, so reviewers can
inspect the original failed step. This setting does not grant publication
authority, waive another required check, turn local observations into sandbox
proof, or weaken protection on the source that declares the policy.

## Focused verification

`crates/fgit-schema/tests/workflow_continue_on_error.rs` covers strict policy
lowering, exact identity, all prior graph versions, matrix propagation and
whole-graph refusal. Native runner and observation tests cover condition
selection, job dependencies, matrix behavior, unsafe observations, report
round trips and altered evidence.

`scripts/e2e/suites/workflow/continue_on_error.sh` uses a prebuilt `FG_BIN`
and real source-selected workflows in both SHA-1 and SHA-256 repositories. It
compares tolerated exit 7 with an otherwise identical required failure, checks
bounded output, a request-deadline stop and real orphan containment, exports
the original step evidence, publishes and retries exact canonical checks, and
recovers after both source and repository are offline. An external fixture
execution counter detects accidental reexecution. These are campaign locations
and scope, not a claim that the campaign or broader release gates have passed.

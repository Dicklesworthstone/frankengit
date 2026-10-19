# Native workflow job and step deadlines

Trusted workflows accept `timeout-minutes` on a job or a `run` step. Each value
is a literal decimal integer from **1 through 60**. It is an additional ceiling
on time already granted by the operator; it cannot grant more execution time.

```yaml
name: bounded build and test
on: push
jobs:
  build:
    runs-on: fgit-trusted-local
    timeout-minutes: 8
    steps:
      - run: cargo build --locked
        timeout-minutes: 6
      - run: cargo test --locked
        timeout-minutes: 2
  package:
    runs-on: fgit-trusted-local
    needs: build
    timeout-minutes: 2
    steps:
      - run: ./scripts/package.sh
        timeout-minutes: 1
```

The existing default operator profile allows **60 seconds per step** and
**600 seconds per workflow**. Under those defaults, the six-minute build step
above still gets at most 60 seconds. An operator-selected profile must already
permit longer execution for a larger YAML cap to have any effect. The trusted
coordinator also intersects its configured time and runner-resource ceilings
before calling the workflow interpreter.

## Budget meaning

A job's clock starts immediately before workspace startup. Startup, execution
of all its steps, and artifact capture consume one absolute job duration; the
clock is never reset between steps. A step receives the minimum of:

- the operator's per-step limit;
- its own optional `timeout-minutes` cap;
- the remaining job duration, if a job cap exists;
- the remaining whole-workflow duration.

A step's duration starts before its execution adapter performs process-context
and capture setup. Each step gets its own step cap, within the remaining job
and workflow time. Each expanded static-matrix job gets an independent job
clock, while all variants continue to share the original workflow ceiling.

Workspace cleanup always runs for a successfully started job, including when
its time has expired. Cleanup receives no cancellable predicate. A normal
startup refusal owns its own cleanup and is not closed a second time. The
interpreter checks the deadline again after cleanup before reporting success.
Durable terminal observation then follows the existing custody/drain protocol;
the job deadline does not cancel that protocol or erase a terminal record.

These are cooperative deadlines. A synchronous adapter must bound its own
operations and honor the supplied liveness predicate and step limit; the
interpreter cannot preempt an arbitrary blocked filesystem call. The trusted
process adapter applies the limit through its existing process-group cleanup.

## Outcomes and replay

Cap exhaustion reports `TimedOut`. A worker that observes a deadline through
its supplied liveness predicate may report cancellation internally; the
interpreter distinguishes that deadline from actual caller cancellation.
Observed caller cancellation stays latched even if a caller callback later
returns true again. An independent worker cancellation, corrupt success
observation, or containment failure is never reclassified as an ordinary
timeout.

A timed-out job does not make ordinary dependent jobs eligible. Independent
jobs may continue when the executor reports clean containment and the overall
request remains live. Existing containment rules still apply: the trusted host
process adapter retains a workspace after forced termination because it cannot
prove that an escaped descendant released access. Such a retained scope stops
later jobs and requires reconciliation.

Graph version `fgit-workflow/v4` commits every explicitly declared job and step
cap, together with existing context and matrix bindings. Graphs without either
field retain their exact v1, v2, or v3 canonical bytes. An explicit cap remains
part of the identity even when a tighter operator limit makes it redundant.
Retries use the original graph and observation; they do not acquire a new job
deadline by silently rerunning completed work.

All fields in all jobs are validated before execution. Zero, negative,
fractional, padded, exponent, expression, duplicate, and over-60 values refuse
with a source span. Plain and quoted decimal values have the same meaning.
The command-only coordinator profile refuses capped graphs before allocating
a run, idempotency entry, slot, or check proposal. Native foreground, trusted
coordinator, and durable trusted-workflow paths share the enforcing interpreter.

## Coverage

`fgit-schema/tests/workflow_deadlines.rs` covers canonical identity, exact
legacy bytes, value and shape refusals, context composition, and matrix caps.
`fgit-runner/src/workflow/deadline_tests.rs` advances a private test clock through
the real interpreter to cover exact deadline boundaries, cumulative startup and
step time, capture and cleanup, independent continuation, and cancellation and
containment precedence. Coordinator tests cover whole-graph command-profile
refusal and unchanged observation on retry. The Linux
`fgit-runner/tests/workflow_deadlines.rs` test runs real trusted shells with a
shorter operator deadline and confirms that YAML cannot extend it.

This extends the trusted workflow execution slice in
`frankengit-root-doctrine-x2mv.4.12`. It does not add hostile-code isolation,
canonical event scheduling, or a new authorization or resource-grant mechanism.

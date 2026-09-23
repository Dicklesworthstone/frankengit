# Durable result custody for node-owned trusted workflows

The FG-095b node integration connects `run_trusted_workflow_in` and the
candidate/merge workflow paths to the existing `WorkflowCoordinator` durable
execution driver. All three paths share `trusted_workflow::run_inputs`.
The node still selects verified source and owns disposable job workspaces;
the runner still owns dependency/step scheduling and normalized observations.
There is no second workflow interpreter, database, or authority source.

## Actual execution boundary

Preflight compiles the complete workflow, verifies selected source and supported
host entries, and admits an exact coordinator profile before reserving the
run directory. All 128 bits of the node's invocation nonce enter the local
trigger identity. Coordinator limits preserve the caller's exact durations,
including submillisecond values; millisecond resource ceilings round upwards,
not downwards. These are admission bounds, not new OS resource enforcement.

The existing exclusive `workflow-<run_id>` directory and synced `attempt.json`
remain the node's no-automatic-replay boundary. Two private sidecars now compose
the already implemented runner formats:

* `check-proposals.journal` retains queued proposals, exact per-job evidence,
  terminal proposals, and subsequent downstream custody acknowledgements.
* `execution.owner` holds an OS lock and an exact Prepared/Started/Completed
  attempt. Queue custody and a synced Started record precede the first scope.

Each normalized job observation is persisted after that job's cleanup and
before any dependent starts. A journal failure stops further scopes and leaves
unresolved ownership for reconciliation. The complete runner observation is
persisted before the node publishes its final `report.json`. A failed final
report write does not erase the owner or per-job journal and does not permit
rerunning the workflow. Crash between cleanup and persistence is still an
uncertain Started attempt, not an invented complete observation.

The journal instance derives from the existing immutable node attempt marker,
which binds source/head/incarnation, workflow blob/path, candidate/merge
coordinates, input prefixes and the full invocation nonce. The runner's exact
attempt binding additionally retains full-precision durations, compiled source,
profile and actor. Existing marker/report JSON schemas and report rendering
are unchanged. Historical directories are not adopted or silently upgraded.

## Authority and limitations

A trusted shell success remains an **ActionRequired proposal**, not a Success
check. Canonical check admission, authorized producer verification, protection
policy, and RCR/head-CAS publication remain separate unfinished integration.
Neither sidecar changes Git refs, canonical forge state, or repository authority.
The local invocation uses logical time zero, not an invented wall-clock time.

This remains the explicitly trusted local-owner Linux execution profile.
Scripts run with host-user privileges. Input-prefix selection is not a sandbox;
OS locks are advisory and hostile same-UID interference is not contained.
Retained workspace/descendant obligations remain explicit. The implementation
makes no hostile-CI, distributed scheduling, power-loss, or durability-provider
claim beyond the existing runner/local-filesystem contracts.

## Regression coverage and validation boundary

`trusted_workflow/durable/tests.rs` adds seven tests for per-job custody ordering,
real-file reopen/forwarding, corrupted append refusal, preexisting ownership,
pre-start cancellation, retained containment, full nonce/source-scope binding,
exact-duration preservation, and stable marker bytes. Its real OneNode case
imports both SHA-1 and SHA-256 repositories, runs actual shell steps in fresh
job workspaces, reopens authority, refuses duplicate execution, and reads back
exact per-job evidence without any authority-head advancement.

The Rust tests are authored but were **not compiled or executed** in the editing
environment: Cargo/rustc are unavailable. Source/API review, lexical delimiter
checks, fixture checks and patch application checks are narrower evidence.
Execute on the repository's pinned toolchain:

```sh
cargo test --locked -p fgit-node --lib treefs_workspace::trusted_workflow::durable
cargo test --locked -p fgit-node --test trusted_workflow
cargo test --locked -p fgit-runner --all-targets
```

## Reopening after response or final-report loss

`TrustedWorkflowRun::check_journal_scope` exposes the exact scope to retain;
`open_check_journal` reopens that result's proposal stream after execution.
`OneNode::open_trusted_workflow_journal` is an associated function that requires
neither a live node nor the final report. Supply the selected directory, retained
scope, optional trusted minimum journal pin, and cancellation predicate. It
verifies the original bounded, private, regular `attempt.json` against its exact
commitment before delegating lock acquisition, chain verification and evidence
readback to `FileCheckJournal::open`.

No JSON parser, source refresh, workflow recompilation, or execution retry is
involved. Complete or partial custody may be read and forwarded through the
existing journal API. `next_batch` rechecks all referenced evidence; `forward_next`
retains custody unless its configured sink durably accepts the exact batch.
A partial journal, an absent final report, or an available OS lock says nothing
about whether the prior process executed or was reaped. This read boundary never
recreates `execution.owner` and cannot substitute for host reconciliation.

A retained pin detects rollback of known journal data. A digest recomputed from
the same untrusted storage is not an independent anti-rollback witness. The
original marker may remain available when final output is lost, but recovering
trust in that marker is the local operator's responsibility.

Five additional authored Rust tests cover complete recovery without source,
node or final report; producer lock exclusion; partial/empty custody; missing
and mismatched files/scopes; bounded marker corruption/permissions/symlinks;
minimum-pin rollback refusal; and cancellation before I/O. These tests, like the
seven execution tests, have not been compiled or run in the editing environment.

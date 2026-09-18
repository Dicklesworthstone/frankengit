# Trusted pre-publication merge workflows

Implementation candidate for `frankengit-fg095b-workflow-execution-mynp`.
This extends the local execution path in [TRUSTED_CANDIDATE_WORKFLOW.md](TRUSTED_CANDIDATE_WORKFLOW.md)
to actual two-parent merge results. It does not complete FG-095b's hostile
runner, canonical check publication, trigger service, or distributed execution.

## Why checking either branch is insufficient

The files executed must be the candidate's resulting tree. Neither checking
only the source branch nor reconstructing a new automatic merge establishes
what the submitted candidate does. Explicitly resolved content and modified
workflow scripts must be read from the actual uploaded commit and pack.

`OneNode::run_trusted_merge_workflow_in` accepts an independently specified
`NativeMerge`, its bundle bytes, a workflow path, explicit top-level input
prefixes, a fresh run ID, private run directory parent, optional exact authority
head, and the existing `WorkflowLimits`.

## Validation before execution

The native input builder, `sparse_merge_candidate_manifest_in`, shares the
single-parent builder's implementation. The merge profile requires two distinct
bounded branch refs in the repository's native SHA-1 or SHA-256 domain. It
selects target and incoming tips under one authenticated current authority head,
checks canonical hidden-ref policy and any caller-imposed additional hiding,
and refuses moved pins or a mismatched optional head.

The bundle must advertise the exact target branch and reviewed candidate and
have precisely the target-before and source tips as its two prerequisites.
Prerequisite ordering is not authority. The commit's native parent order is:
target-before first, incoming second. The existing native merge validator also
proves that the explicitly named common base is an ancestor of both parents.
It validates actual object identities, kinds and the complete candidate closure.

Original objects available to unpacking and validation are restricted to the
union of those two verified parent closures. Objects present in unrelated
repository history cannot satisfy missing dependencies or external delta bases.
Unrelated uploaded objects fail the existing pack coverage check. This uses the
existing inflater and delta resolver, not a checkout or external Git engine.

After verification, TreeFS rechecks exact ordered parents before discovering
capability-visible files. `SparseCandidateManifest` keeps the canonical target
RCR/commit/tree separate from candidate commit/tree and verified parents. The
existing host adapter copies these input-only files and refuses edit import.
No candidate object, temporary branch, transaction, approval, or forge event is
created by this execution path.

## Execution, budgets and persistence

The workflow and all declared inputs come from the verified candidate. All
workflow graph and host-entry checks finish before the attempt directory is
created. The operator must explicitly trust these scripts: Linux execution
uses host-user privileges, not hostile-code isolation. Input prefixes are
selection, not a host filesystem, network, or secret sandbox.

Jobs use fresh candidate copies; ordered steps within one job share that job's
workspace. Dependencies, failure propagation, timeouts, captured-output limits,
no-replay ownership and cleanup use the same compiler/scheduler/runner as
canonical and single-parent workflows. Source validation is charged against
the run deadline. No new execution engine or external dependency is introduced.

The existing limits remain: 10,000 sparse entries, 16 MiB per selected entry,
64 MiB selected payload, and 256 MiB/100,000 entries across replicated job
copies. Native pack, original-read and object-closure limits also apply. A
resource or validation failure never returns partial input success.

Before processes start, the synced `attempt.json` records canonical target
provenance, actual executed candidate identities, exact bundle SHA-256, and a
`merge` object containing both byte-exact ref names, both tips, common base,
candidate and ordered parents. `report.json` preserves the same binding after
cleanup or explicit containment failure. Canonical/single-parent reports have
`merge: null`; existing fields retain their meanings.

An occupied run ID refuses after restart. A missing result is not proof that no
script ran; reconcile effects and descendants rather than removing the slot
and rerunning. Timeout containment retains affected workspaces and prevents
later jobs from starting. An output or shutdown failure cannot undo execution.

## Evidence boundary and verification

These are local execution observations. They do not attest a PR version,
review approval, verifier independence, hostile isolation or replay-algorithm
equivalence, and cannot satisfy canonical protected-ref checks by themselves.
Any later merge publication must revalidate the exact current source/target,
PR/policy state and sealed transaction through its existing authority path.

Regression targets:

```sh
cargo test -p fgit-runner --test merge_candidate_workspace
cargo test -p fgit-node --test trusted_merge_workflow
```

The host tests exercise real descriptor-relative copies, import refusal,
cancellation/obligation settlement and pre-discovery ordered-parent validation.
The node tests import actual native histories, run actual trusted child
processes, and reopen the file-backed node. Both branches fail in the principal
fixture while the merged result passes. Additional cases cover custom workflow
bytes, malformed parents, absent/moved source selections, a non-common base,
stale head, missing prerequisites, corrupt pack, no staging/publication,
restart/replay refusal, fresh copies and timeout retention.

These tests were authored but not executed in the implementation environment;
Rust compilation, formatting, Clippy and repository gates remain unverified.

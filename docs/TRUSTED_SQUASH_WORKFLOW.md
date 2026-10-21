# Trusted CI on the exact squash candidate

`fg workflow run-merge-candidate --method squash` executes the actual unpublished
single-parent squash result. The workflow and input files come from that exact
candidate, not the source branch, target branch, or a newly recomputed merge.
Native preparation and conflict-resolution output may both enter this structural
validation boundary; acceptance here does not prove the candidate is an automatic
merge or that it is approved for publication.

## Explicit method, unchanged trust boundary

```bash
fg workflow run-merge-candidate NODE TENANT REPOSITORY refs/heads/main \
  --trusted-local --method squash --bundle /private/squash.bundle \
  --candidate-commit CANDIDATE --expected-commit TARGET \
  --source-ref refs/heads/topic --expected-source SOURCE --merge-base BASE \
  --workflow workflow.yml --input workflow.yml --input src \
  --run-id 41414141414141414141414141414141 --run-parent /private/runs
```

Replace the uppercase coordinates with independently selected native values;
create the run parent as an operator-owned, nonsymlink `0700` directory. The
bundle can be prepared by `fg merge prepare ... --method squash`. Add
`--object-format sha256` for that repository format. An optional `--expected-head`
pins the authority snapshot as well. Existing byte-name and explicit artifact
capture/delivery flags retain their meanings.

The default is `--method merge-commit`, which still requires the ordered target
and source parents. `squash` requires exactly one parent: the selected target.
There is no automatic fallback, parent-shape guessing, rebase or fast-forward
execution method. The old node APIs remain strict two-parent wrappers.

Both methods require exactly the target and source bundle prerequisites. A
squash's lack of a source **parent edge** does not remove the source **validation
input**. Both current branch tips and disclosure rules are selected at one
authenticated head; both original object closures and their common-base ancestry
are verified. Pack coverage, thin delta bases, resource limits, declared input
capabilities and sparse materialization retain the existing checks. Invalid
method, stale pins, wrong base/parents, missing prerequisites and corrupt packs
refuse before reserving an execution slot or starting a script. Candidate
objects remain unpublished and neither branch moves.

## Evidence, artifacts and restart

The new node entry points are `sparse_merge_candidate_manifest_with_style_in`
and `run_trusted_merge_workflow_with_options_in`. They take the existing typed
`MergeCommitStyle`; no dependency or parallel execution engine is added.
`TrustedWorkflowRun.merge_style` records the verified method. For squash runs,
`merge.method` is `squash` and `merge.parents` contains the single target tip.
The explicit source and common-base coordinates remain present. `executed_commit`
and `executed_tree` name the candidate, whereas `source_commit` and `source_tree`
retain the canonical target base. The original two-parent JSON identity is
unchanged, preserving existing journal and artifact commitments.

That identity binds the synced attempt marker, durable check-proposal journal,
final report and captured artifact provenance. Substituting a different method
cannot reopen the original journal as the same run. Producers and consumers
share the existing same-attempt artifact checks and byte allowances; each job
still gets a fresh workspace. Outputs can be independently exported after node
restart and after successful job workspace cleanup.

An occupied run ID refuses reexecution. Use the existing `fg workflow recover`
with the original attempt-marker SHA-256 to inspect retained proposals, rather
than selecting a new ID as an automatic retry. Recovery does not execute scripts
or require the final `report.json`. SIGTERM/SIGINT use the existing cooperative
request/drain/cleanup path, including repeated signals. Ordinary job failures
and skipped dependencies remain nonpassing. Unproved containment remains an
explicit retained-workspace failure, never a passing result.

These are trusted-host execution observations, not hostile-fork isolation,
exactly-once external effects, an approval, or permission to merge. The command
does not publish checks, create a temporary canonical ref, mutate PR metadata,
or bypass the current canonical publication policy. Retain invocation and
journal custody across backup/restore; source-history verification is not
physical power-loss evidence.

## Native verification

`cargo test --locked -p fgit-node --test trusted_squash_inputs --test
trusted_merge_workflow` covers real authenticated source selection, exact parent
shape, original negative twins, native preparation, candidate-specific scripts,
artifacts after restart, method-bound journals, pre-cancelled intake and timeout.
The original single-parent candidate, two-parent merge and artifact suites remain
applicable.

With `FG_BIN` set to the actual built Rust executable, run
`scripts/e2e/suites/workflow/squash_candidate.sh`. Its 20 cases cover SHA-1 and
SHA-256, native preparation, strict preflight, actual combined input bytes,
producer-consumer handoff, artifact export, source-independent journal recovery,
repeat-execution refusal, failed/skipped jobs and repeated SIGTERM/SIGINT against
verified-live processes. The descendant liveness assertion precedes fixture
cleanup. These are functional native tests, not a full release or universal
containment gate.

# One verified candidate, one workflow dispatch

`OneNode::dispatch_trusted_merge_workflows_in` connects native merge/squash
validation to the existing multi-workflow dispatch engine. It does not prepare
another candidate or execute definitions from the canonical parents. The supplied
bundle, exact candidate, target/source refs and tips, merge base and chosen parent
style are verified before any batch reservation or script.

All direct YAML children of the selected candidate directory are compiled before
execution. The explicit event is `pull_request` or `workflow_dispatch`; no push
is synthesized. PR branch filters inspect the verified target ref. PR path filters
inspect the complete incoming canonical change against its unique merge base,
not the union of target and source changes and not caller-provided filenames.
The authenticated head used for that comparison must match candidate validation.
Candidate-only workflow changes affect the compiled definitions, not those
canonical changed-path coordinates. This is local selection intent, not proof
that a PR event occurred or a PR-version attestation.

The existing dispatch owns exclusive batch IDs, stable child IDs, preflight,
fresh per-job workspaces, bounded process-group cleanup, captured output,
artifact custody, immutable attempt journals and final reports. Workflows share
one absolute run deadline and the existing aggregate jobs, steps, materialization,
output and artifact allowances. No bound is increased. Ordinary failed jobs do
not suppress independent workflows; refusal, timeout, cancellation, output
exhaustion or unproved containment stops subsequent work. Zero matches stay
explicit and do not manufacture a passing check.

Candidate dispatch plans additionally record actual executed commit/tree, exact
bundle hash and both canonical parent selections. Historical canonical dispatch
plan bytes are unchanged. The candidate remains unpublished: no temporary ref,
canonical check, approval, or candidate object retention is created. An occupied
batch always refuses, even if a process died before its first child. Recover
original child journals without rerunning scripts; retain custody across restore.
Existing check-publication policy is not relaxed by these observations.

Tests in `trusted_merge_dispatch` execute the real node and host processes across
SHA-1/SHA-256, merge/squash, correct and excluded filters, malformed late definitions,
corrupt and stale candidate pins, fresh-process replay refusal, failed independent
jobs, cumulative output and artifact limits. Existing `trusted_merge_workflow`
remains the single-run regression suite. These checks do not establish hostile
isolation, automatic synthetic-merge watching, or completion of the entire CI
product-loop bead. No new dependency, runtime, Git fallback or unsafe code is added.

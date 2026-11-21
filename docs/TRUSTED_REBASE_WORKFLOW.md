# Required CI for an unpublished rebase candidate

`fg workflow run-rebase-candidate` executes a workflow from the final tree of an
already prepared native rebase series. `fg workflow publish-candidate --method
rebase` verifies a retained completed job and publishes its exact PR candidate
observation. A protected rebase merge can then satisfy its configured
`required_candidate_checks` without staging the candidate or creating a CI ref.

This closes the execution and publication gap between
[native PR rebase preparation](NATIVE_PULL_REQUEST_REBASE.md) and
[unpublished candidate protection](UNPUBLISHED_CANDIDATE_CHECKS.md), under the
existing PR and CI owners `frankengit-root-doctrine-x2mv.4.20` and
`frankengit-root-doctrine-x2mv.4.12`. Both SHA-1 and SHA-256 repositories use the
same path. The execution remains Linux trusted-local: the operator must review
and trust the actual candidate's scripts and workflow, which run with host-user
privileges.

## Execute the prepared series

Prepare and inspect the exact PR rebase bundle, retain its original subject and
independent SHA-256, and then run:

```sh
fg workflow run-rebase-candidate "$STORAGE" "$TENANT" "$REPOSITORY" \
  refs/heads/main \
  --trusted-local --object-format "$OBJECT_FORMAT" \
  --expected-incarnation "$INCARNATION" \
  --bundle "$REBASE_BUNDLE" --candidate-commit "$CANDIDATE" \
  --expected-commit "$TARGET" --source-ref refs/heads/topic \
  --expected-source "$SOURCE" --merge-base "$ORIGINAL_BASE" \
  --workflow workflow.yml --input workflow.yml --input src \
  --run-id "$FRESH_RUN_ID" --run-parent "$PRIVATE_RUN_PARENT"
```

Replace every variable with the retained native coordinates. The existing run
parent must be an absolute operator-owned nonsymlink directory with mode 0700.
The workflow must be included in the explicit input prefixes. Optional
`--expected-head` pins the authority snapshot; byte-encoded ref/workflow/input
names and the existing artifact capture and delivery options remain available.
The command's `--help` identifies those options and limits.

Validation completes before any execution slot or script starts:

- Both current branch pins and their disclosure rules are selected at one
  authenticated repository head.
- The bundle advertises the exact target and final candidate, with the target
  tip as its sole prerequisite. Original source-only objects cannot satisfy
  an uploaded edge or thin delta base.
- The original source suffix and rewritten target-based series each contain
  1–256 single-parent commits. The original common base must also be an ancestor
  of the target. Every rewritten commit is supplied in the bundle.
- Complete intermediate closures, actual native object identities, pack
  coverage and the cumulative 16 MiB commit-body allowance verify before sparse
  discovery. A missing intermediate blob refuses even if a later commit removes
  it from the final tree or the blob is available through the original source.
- Sparse TreeFS separately verifies the full ordered rewritten chain and
  materializes only authorized candidate input paths.

Native input, object, expansion and sparse budgets remain the existing bounded
candidate profile. Validation consumes the run deadline. An invalid bundle,
hidden or moved pin, nonlinear series, wrong base or cancelled request cannot
reserve a run slot. The old `run-candidate` and `run-merge-candidate` commands
retain their original strict parent contracts.

## Retain the actual execution identity

All jobs use the existing compiler, scheduler, process runner, fresh workspace
copies, output limits, durable check journal and cleanup path. The scripts and
inputs come from the submitted candidate tree. Nothing is silently recomputed
from the source or target branches.

The report's `source_commit`, `source_tree` and `source_rcr` retain the canonical
target base; `executed_commit` and `executed_tree` name the final candidate. The
existing candidate block retains its bundle digest. A separate `rebase` block
contains the original source/target/base coordinates, `method: "rebase"`, and
the final commit's actual immediate parent. For a multi-commit series that
parent is an unpublished intermediate commit, not the original target.
`merge` remains null for this distinct input profile. Canonical, single-parent,
merge and squash attempt bytes are unchanged.

The same identity binds `attempt.json`, the journal scope, the final report and
captured artifact provenance. Changing a reported parent or profile cannot
reopen the original journal as the same attempt. An occupied run ID refuses
reexecution, including after restart. A missing final report is not evidence
that no script ran; retained completed jobs can be recovered without it.

Retain the original journal ID from the trusted run and inspect its batches:

```sh
fg workflow recover "$RUN_DIRECTORY" "$TENANT" "$REPOSITORY" \
  --journal-id "$JOURNAL_ID"
```

Select a completed job's `batch_sha256` and its zero-based position in that
batch's `facts` array. Retain the optional snapshot pin as well. The existing
[recovery guide](WORKFLOW_RECOVERY_COMMAND.md) describes pagination and original
evidence export. Artifact custody proves retained bytes and provenance; it does
not grant cache reuse, publication or an independent runner attestation.

## Publish the retained check and merge

Publish the selected job using the original exact PR subject and artifact pin:

```sh
fg workflow publish-candidate "$STORAGE" "$TENANT" "$REPOSITORY" \
  refs/heads/main \
  --trusted-local --method rebase --object-format "$OBJECT_FORMAT" \
  --expected-incarnation "$INCARNATION" \
  --run-directory "$RUN_DIRECTORY" --journal-id "$JOURNAL_ID" \
  --batch "$BATCH_ID" --fact-index "$FACT_INDEX" \
  --principal-id "$PUBLISHER" --idempotency-key "$ORIGINAL_CHECK_KEY" \
  --pull-request "$PR_NUMBER" --expected-pull-request-version "$PR_VERSION" \
  --expected-policy-epoch "$POLICY_EPOCH" --source-ref refs/heads/topic \
  --expected-source-tip "$SOURCE" --expected-target-tip "$TARGET" \
  --merge-base "$ORIGINAL_BASE" --candidate-commit "$CANDIDATE" \
  --bundle "$REBASE_BUNDLE" --bundle-sha256 "$BUNDLE_SHA256"
```

The independent publisher must be the principal selected by the configured
candidate-check policy. Admission verifies the saved job evidence, bundle
digest, complete rebase series and exact current PR/ref/policy coordinates.
This validation does not render a human diff, so review-display limits do not
exclude an otherwise valid check. A successful observed job becomes a canonical
Success only through the existing verifier; failed, skipped and incomplete jobs
remain nonpassing.

Check events and retry identities retain their existing bytes. The observation
binds subject, candidate, original base, exact bundle and execution evidence.
`--method rebase` selects the required whole-series validator, not a distinct
canonical check method or an extra authority grant. A compatible candidate tree
does not gain a new execution merely by changing that selector. Recorded
terminal decisions are recovered before any new bundle access or eligibility
check; replay cannot convert an old refusal into success. The CLI receipt names
`requested_validation_profile: "rebase-series-v1"` for this selection. On
recovery this labels the current request, not a claim that the original
transaction used that validator.

Use the separate exact-candidate review and `fg merge apply-reviewed --method
rebase` workflow after all required checks and reviews pass. The latest matching
result from each configured publisher/graph/job must be Success. A newer failure
blocks merging; replaying an older green publication does not make it new.
Target, PR merge event and delivery obligation publish atomically, while the
source branch remains unchanged. Current path-owner, reviewer, queue and other
policy gates remain mandatory.

## Native API and remaining boundary

The new node methods are `sparse_rebase_candidate_manifest_in`,
`run_trusted_rebase_workflow_in`, and
`admit_trusted_rebase_candidate_workflow_check_in`. Existing journal record
selection and `recover_trusted_candidate_workflow_check_in` are shared. The
separate TreeFS `SparseCandidateManifest::build_rebase` constructor checks the
complete ordered rewritten chain while preserving canonical-base provenance.
`MergeCommitStyle` continues to represent only merge-commit and squash.

This increment executes an already prepared series. Automatic PR watchers,
collection preparation, queue preparation and directory dispatch retain their
existing merge/squash profiles. It does not add remote script execution,
hostile-code isolation, automatic reruns, rebase queue landing or durable build
output reuse.

Regressions are in `fgit-node/tests/trusted_rebase_workflow.rs` and the CLI's
`workflow_command::rebase::tests` and candidate-publication parser tests. They
exercise both hash domains with real native preparation, scripts, filesystem
artifacts, retained journals, check publication, protected merge and restart
recovery, plus adjacent stale, hidden, corrupt, missing-intermediate, nonlinear,
cancelled, wrong-profile and latest-failure cases. These test locations are not
a claim of a completed release, hostile-isolation or power-loss qualification.

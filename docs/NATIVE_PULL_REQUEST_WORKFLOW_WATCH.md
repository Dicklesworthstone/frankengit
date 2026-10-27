# Native pull-request source-head CI

Branch-selected execution is documented in [native branch filters](NATIVE_WORKFLOW_BRANCH_FILTERS.md).


The default native watcher can select `on: pull_request` workflows from an actual open,
same-repository pull request. It reuses the existing trusted-host executor,
artifact capture/delivery, cancellation owner and durable check publisher. It
neither opens a GitHub PR nor invokes Git or another `fg` subprocess in production.

For the actual combined merge or squash tree, opt into
[exact PR merge-candidate CI](NATIVE_PULL_REQUEST_MERGE_WORKFLOW_WATCH.md). That
mode requires an explicit CI branch, publication principal, incarnation and
deterministic commit metadata, and can publish candidate-bound canonical checks.
The source-head behavior described here remains the default.

```bash
fg --timeout-secs 300 workflow watch NODE TENANT REPOSITORY refs/heads/topic \
  --trusted-local --pull-request 7 --workflow ci --input ci --input src \
  --run-parent /private/runs --polls 100 --interval-ms 1000
```

The source branch is explicit and must match the selected PR's canonical source
reference. PR numbers are canonical positive decimal u64 values. Raw reference,
workflow-directory and input-name flags have the same meaning as ordinary watch.
Use `--object-format sha256` for SHA-256 repositories. Without `--pull-request`,
the existing push watch and its original identity bytes remain unchanged.

## Selection is a coherent canonical observation

The node reads the exact numbered native PR, then checks its version, visibility
and current source/target branches at the same authenticated authority head.
It does not mistake the next PR in a bounded page for the requested number.
Closed, merged, missing, hidden or source-mismatched PRs yield
`pull_request_unavailable` and execute nothing. Missing current source or target
refs also prevent execution. A head movement before reservation yields
`source_moved`; a later bounded poll may select again. The existing dispatch
requires that same selected head and source commit before scripts start.

The PR watch scope binds the existing tenant/repository/incarnation/branch/path
scope and the full PR number in a separate versioned hash domain. Event identity
binds that scope, PR number and version, the latest canonical source-ref decision,
and the observed target ref/tip. Opening, updating metadata, reopening, a new source
decision and an observed different target tip can each select a new event.
Comments, reviews, check publication and unrelated refs do not alter those inputs.
Different PRs using the same source have separate custody, and push events cannot
borrow a PR event's execution identity. Intermediate changes missed between polls
are coalesced; this is not an all-events webhook queue.

## Source-head only, not a synthetic merge

Every script and copied source input comes from the CURRENT source branch commit,
not from the old tip recorded when the PR was opened. Selected definitions must
declare `pull_request` in the supported native workflow syntax. The watcher does
not execute `push`-only definitions for a PR, and zero matches create no check.
Explicit artifact selectors still validate before execution; producer captures
and consumer deliveries retain the original current-attempt provenance checks.

The event receipt identifies the current executed source separately from
`recorded_source_commit`, `recorded_target_commit`, `observed_target_commit` and
the exact PR version. It explicitly says `execution_profile: source-head-only`
and `synthetic_merge: false`. A target change may cause a fresh source-head run,
but its success does not establish that a combined source/target tree builds.
This is not GitHub's synthetic-merge profile, `pull_request_target`, branch/path
filter compatibility, cross-repository fork execution or hostile-code isolation.
The local operator must trust all selected future scripts with host-user privileges.

## Optional canonical check publication

Add `--publish-checks --principal-id PUBLISHER --expected-incarnation INCARNATION`
to enable the same explicit reporting contract as a push watch. The publisher is
supplied by the operator, never by PR or workflow text. Pending original reporting
is reconciled before later polling; freshly settled results are published after
execution. Per-check original keys, complete evidence preflight, finite bounds,
permanent publisher binding and creation-only acknowledgement remain unchanged.

Closure or merge stops new execution, not recovery of an original settled result.
Publication recovery needs the retained PR-specific custody, not a new current PR
version to invent replacement keys. Ordinary admission still verifies publisher,
current source branch and evidence; stale undecided checks may be refused while
already-decided checks recover their original canonical result. Partial reporting
is not atomic across jobs and never authorizes repeating scripts. A missing or
corrupt handoff stops the watch instead of reconstructing it from report snippets.

The existing `fg pr checks` view deliberately selects the PR's EXACT RECORDED
source coordinates. After an independent branch move, `source_current=false`
returns no checks until the operator explicitly updates the PR metadata. The
watcher can execute and publish checks for the live source without mutating that
metadata, and its streamed check decisions identify that actual source. Updating
PR metadata reveals matching canonical checks but is a separate authorized
operation and a new PR version. This command does not silently rewrite review
coordinates, grant approval or weaken protected-merge requirements.

## Recovery and evidence

SIGTERM/SIGINT reach the same request-owned observer and active process group.
Unresolved execution blocks later events in that PR scope even after close/reopen,
new source commits or a fresh process. Retain the complete run parent across
restart and backup/restore. There is no force-reset, automatic script replay,
record pruning or exactly-once guarantee for external effects. SIGKILL cannot
perform cooperative descendant cleanup.

The focused native node tests cover PR lifecycle, both hash formats, current tips
versus stale recorded coordinates, source/target changes, canonical fast-forward
merge suppression, namespace separation, cancellation and original-decision
recovery after PR closure. The discovered `workflow/pull_request_watch.sh` suite
uses the actual compiled `FG_BIN`, not a mock backend: real producer/consumer
artifacts, canonical check views, repeated processes, a killed publisher, corrupt
saved evidence and signal drain. It creates only local native fixture PRs. These
are focused functional tests, not a full-workspace, release, physical power-loss
or untrusted-runner isolation gate.

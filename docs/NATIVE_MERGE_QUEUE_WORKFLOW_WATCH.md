# CI and optional landing for the native merge-queue head

The native workflow watcher can follow a merge queue, prepare the current head's
actual two-parent merge candidate, admit it on a fixed CI branch and execute that
exact combined tree. Optional canonical check publication makes the results
usable by existing exact-candidate branch protection. When the head changes, the
same controller selects its next eligible PR and source branch.

Queue selection, preparation, CI publication, execution custody and check
admission use the existing native implementations. An explicit automatic-landing
option joins those steps to the ordinary guarded landing admission. It requires
its own operator-selected principal and is disabled by default. The guarded
[queue landing commands](NATIVE_MERGE_QUEUE.md) remain available for manual use.

## Start a foreground or continuous watcher

Create an absolute private run parent with mode 0700, then select the queue's
fixed target and a separate CI branch:

```sh
fg --timeout-secs 300 workflow watch NODE TENANT REPOSITORY refs/heads/main \
  --trusted-local --merge-queue 1 --expected-incarnation INCARNATION \
  --workflow ci --input ci --input src --run-parent /private/queue-runs \
  --merge-candidate-ref refs/heads/ci-main --merge-principal CI_WRITER \
  --merge-author 'CI <ci@example.test>' \
  --merge-committer 'CI <ci@example.test>' \
  --merge-timestamp 1700000000 --merge-message 'Test the queue head' \
  --merge-method merge-commit --merge-profile path \
  --publish-checks --principal-id CHECK_PUBLISHER \
  --polls 100 --interval-ms 1000
```

The positional branch is the queue **target**, not a manually selected PR
source. `--merge-queue` and `--pull-request` are mutually exclusive. Queue mode
requires the complete merge-candidate option group and the repository's exact
incarnation. It permits only `merge-commit` two-parent construction; `squash`
does not select a queue landing profile. `path` and `exact-renames` select the
existing native preparation algorithms. All author, committer, timestamp and
message inputs are explicit; ambient identity and current time are not inputs.

Use `--object-format sha256` for a SHA-256 repository. Use the ordinary `--ref-hex`
positional-ref form for a target with raw branch bytes, and
`--merge-candidate-ref-hex` instead of the text CI reference option. The CI branch
must differ from both the target and the selected head's source branch.

For sustained operation, replace `--polls` with:

```sh
--continuous --stop-file /private/control/queue.stop --attempt-timeout-secs 300
```

The stop file must initially be absent. Creating it, SIGTERM or SIGINT requests
drain; it is never removed by the watcher. Each continuous attempt includes
pending check and landing recovery, one selection/dispatch, resulting check
publication and optional landing under a finite deadline. A global
`--timeout-secs`, when supplied, still bounds
the entire service. See [native watch lifetime](NATIVE_REF_WORKFLOW_WATCH.md).

This is Linux trusted-host execution. The operator must trust every future
selected workflow and input with the host account's privileges. The configured
input list controls copied source files and does not isolate scripts from the
host. A queue entry, remote token or repository file cannot configure this
controller or supply its publication principals.

## Exact queue selection and candidate execution

The watcher reads a visible canonical queue and its first ordered entry. The
queue must target the configured branch and have no active batch. It then
selects the actual open same-repository PR, its current version and live refs.
The queued source reference/tip, PR metadata and current source/target tips must
agree at the selected authority head. Hidden or absent state is not disclosed
as a candidate.

The execution event binds the queue number and version, exact head PR and its
version, source/target coordinates and policy epoch. Queue reordering or
replacement cannot inherit another observation's event. A policy change also
selects a distinct observation, even when the commit inputs are unchanged.
Comments and check publication alone do not create a new queue event.

Preparation uses `prepare_queue_head_bundle_with_profile_in`, which validates
the exact queue head and then delegates object construction to the existing
native PR preparation. Conflicts and stale observations execute no script.
The actual candidate bundles for CI and target landing, deterministic metadata,
original CI tip and publication key are durably retained before CI ref admission.
That admission uses an exact-old lease and ordinary repository policy. Queue membership never
grants permission to rewrite the CI branch.

After CI publication, the original queue and PR selection is revalidated. A
queue, source, target, visibility or policy race cannot substitute a different
candidate for execution. Definitions and copied files come from the admitted
combined tree. Only `pull_request` definitions are selected; branch filters
match the original PR target, and path filters inspect the incoming source
changes against their merge base. They do not match the CI branch or unrelated
target-only changes.

An empty, unavailable or active queue does not execute a candidate. A clean
idle result is not proof of successful CI. Ordinary failed builds can settle,
but their check conclusions remain failures. Existing poll and final summary
receipts distinguish non-green, stopped and unresolved work.

## Publish exact checks and optionally land automatically

`--publish-checks` requires `--principal-id` and explicit incarnation. The
CI writer and check publisher are independently chosen identities. Without
that opt-in, execution retains its evidence but publishes no check. Existing
policy must already trust the selected publisher and require the fixed CI ref,
workflow graph commitment and job. Running a workflow does not install policy.

Checks name the actual candidate commit and CI branch. The CI branch must still
point to that candidate when a protected merge is admitted. Source-head success
cannot satisfy protection for a different merge commit, and exact candidate
reviews remain independent requirements. A branch can also require canonical
queue landing through `--require-merge-queue`; ordinary PR publication remains
ineligible for that requirement.

To enable automatic landing, add both options to the queue watcher above:

```sh
--land-queue-head --landing-principal LANDING_PRINCIPAL
```

This requires the queue selector, complete two-parent merge configuration,
`--publish-checks`, check publisher and exact repository incarnation. The CI
writer, check publisher and landing principal are configured independently.
They may be the same operator identity where policy permits, but none is
inferred from another or from repository text. A local operator principal
retains its actual authentication classification; enabling this option does
not manufacture HTTP-token authentication or exempt it from branch policy.

After publishing checks, the controller verifies every selected workflow's
original completed execution, exact journal pin and successful job conclusions.
It also resolves the original check transactions and requires all to have
committed. Empty selections, failed or stopped runs, incomplete dispatches and
local `reported` or `settled` markers alone cannot authorize landing. These
requirements apply even when the branch has no required-check rule.

The controller then observes readiness through the same native preparation
used by actual admission. Missing reviews or required checks wait without
reserving a landing key or publishing a permanent refusal. Readiness grants
no authority: submission independently revalidates the current queue, PR,
policy, authentication, source/target refs, candidate objects and evidence.
One canonical decision moves the target, merges the PR and completes the queue
entry. Races can still produce an ordinary immutable terminal refusal.

Each pass lands at most one newly eligible head. Waiting and stale observations
appear separately from unresolved custody in JSON. The foreground and service
summaries include `landings_committed`, `landings_refused`,
`landings_previously_decided`, `landings_waiting` and `landings_stale`.
Previously decided counts report local retry suppression, not new commits.

### Manual landing of the same tested candidate

The retained event directory contains a ready `landing.bundle` addressed to the
actual target branch. Use this artifact with `fg queue land-candidate` or the
authenticated HTTP candidate endpoint to submit the exact tested commit. The
event records `merge_candidate.landing_bundle` and
`merge_candidate.landing_bundle_sha256`; `custody_directory_hex` names its
private directory as exact path bytes. The
`candidate.bundle` file advertises the CI branch; the target-addressed
`landing.bundle` preserves the same pack and candidate commit. No new merge
preparation is needed between testing and the landing upload.

Submit the event's exact queue/PR versions, policy epoch, tips, merge base and
expected commit under a deliberate original landing key. Native landing revalidates
everything and atomically moves the target, records the PR merge and completes
the queue entry. A changed observation needs new preparation and fresh evidence
where policy requires it. A previously refused landing retains its original
terminal refusal; later passing checks do not turn that key into success.

For an [HTTP candidate landing](NATIVE_HTTP_QUEUES.md), the original event maps
directly to the existing guarded multipart command. Use the retained
`landing.bundle` as its bundle part, an independently authorized landing token
and the deliberate original `Idempotency-Key`:

| Landing coordinate | Retained event field |
|---|---|
| Queue number in the route | `merge_queue.number` |
| `expected_incarnation` | `repository_incarnation` |
| `object_format` | The configured repository object format |
| `expected_version` | `merge_queue.version` |
| `expected_policy_epoch` | `merge_queue.policy_epoch` |
| `pull_request` | `merge_queue.pull_request` |
| `expected_pull_request_version` | `merge_queue.pull_request_version` |
| `source_ref_hex` | `ref_hex` |
| `target_ref_hex` | `merge_queue.target_ref_hex` |
| `expected_source_tip` | `commit` |
| `expected_target_tip` | `pull_request.observed_target_commit` |
| `merge_base` | `merge_candidate.base` |
| `expected_commit` | `merge_candidate.commit` |

These coordinates are sealed intent, not fields to refresh during a retry.
Use the hexadecimal HTTP ref fields for refs that cannot be represented as UTF-8
CLI arguments. The ordinary HTTP landing scope, deployment enable flag and
target-ref ceiling remain mandatory.

## Queue-wide custody and restart

One permanent watch scope binds repository incarnation, queue number, configured
target and workflow directory. It does not change when the head PR or its
source branch changes. Merge configuration, the first check publisher and,
when enabled, the landing principal are bound inside that scope; changing them
refuses instead of escaping an old responsibility under a replacement identity.

An unresolved event blocks later execution across the entire queue, including
after reordering, dequeue, head landing or queue removal. Keep the private run
parent, candidate bundle, publication receipt, event record, execution journal
and check handoff together across restart and restore. The existing bound of
1,024 retained events applies per scope. There is no automatic deletion or
force-reset path.

Previously settled events do not rerun scripts. Original check publication can
recover after the selected PR disappears or the queue becomes empty; recovery
uses retained candidate identities, not the current head. Failure after candidate
reservation retains the original key and lease and requires reconciliation.
Neither a disconnected client nor a missing final response proves rollback.

Automatic landing retains a bounded, creation-only attempt record before its
first submission. The retry key binds the original scope, operator, event and
observed authority basis. Reconstruction uses the original candidate's exact
command; it never refreshes source/target tips or queue versions under that key.
All outstanding landing attempts reconcile before current queue selection or
new work. A decided transaction recovers without the original `landing.bundle`,
including after queue removal, head movement or a lost terminal-output response.
An undecided transaction still requires its original verified bundle. Durable
acknowledgements suppress repeats and do not act as canonical evidence.

There are at most 32 retained landing attempts per event and 1,024 per scope,
in addition to the event bound. An acknowledged raced refusal can be followed
by a new attempt only after readiness succeeds at a later authority basis;
the original refusal remains unchanged. Unknown, malformed, orphaned or
excessive custody blocks progress. No automatic record deletion or identity
rotation evades these limits. Preserve the whole scope across restart.

New candidate events carry a versioned intent that permits ordinary restart to
resume an uncertain CI publication and begin the original candidate's first
dispatch, but only after proving no execution-start fence or dispatch directory
exists. The same input prefixes, limits and artifact configuration must match.
Original CI keys, old-tip leases, candidate bytes and source-head guards survive;
no newer queue head substitutes for that intent. Stale or refused candidates,
legacy events without this proof, and started or corrupt custody still block the
entire scope. Deferred intents appear as `pending_execution` in publication and
service receipts and provide no check evidence.

A completed execution whose final `settled` marker was lost can now reconcile
automatically from its durable `check-sources` handoff, original completed owner
receipts and exact journal pins. This runs before later polling, retained check
publication and owned service readiness, with the original check identities and
without another script run or CI-ref publication. Closed failed runs remain
failed checks. Missing or incomplete completion evidence still blocks the
queue. See [bounded native-watch recovery](NATIVE_WORKFLOW_WATCH_RECOVERY.md).

This slice executes one current queue head at a time. Speculative multi-PR
trains, a synthetic queue-ref namespace and the plan's named hosted policy
classes remain separate functionality. It adds no hostile-code isolation.

## Own the controller with the HTTP service

The same selection is available as an explicitly configured HTTP service sibling:

```sh
fg serve-http NODE TENANT REPOSITORY 127.0.0.1:8080 \
  --trusted-local --credentials-file /private/http-credentials \
  --continuous --stop-file /private/control/http.stop \
  --expected-incarnation INCARNATION \
  --workflow-trusted-local --workflow-format sha256 \
  --workflow-ref refs/heads/main --workflow-merge-queue 1 \
  --workflow-dir ci --workflow-input ci --workflow-input src \
  --workflow-run-parent /private/queue-runs \
  --workflow-merge-candidate-ref refs/heads/ci-main \
  --workflow-merge-principal CI_WRITER \
  --workflow-merge-author 'CI <ci@example.test>' \
  --workflow-merge-committer 'CI <ci@example.test>' \
  --workflow-merge-timestamp 1700000000 \
  --workflow-merge-message 'Test the queue head' \
  --workflow-publish-checks --workflow-principal CHECK_PUBLISHER
```

To enable the same optional landing path in that service, add:

```sh
--workflow-land-queue-head --workflow-landing-principal LANDING_PRINCIPAL
```

The controller waits for successful HTTP readiness before new candidate
publication, execution or target landing, and drains with the listener. Startup
check reconciliation does not submit a fresh landing before readiness. No workflow flag grants
network queue management, landing, receive or read permissions. Those endpoints
retain their independent deployment switches and token scopes. See
[HTTP-owned native CI](NATIVE_HTTP_WORKFLOW_SERVICE.md) for lifecycle and
credential details.

## Focused verification entrypoints

```sh
cargo test --locked -p fgit-node --test trusted_queue_merge_watch -- --test-threads=1
cargo test --locked -p fgit-node --lib queue::landing_tests::candidate::readiness -- --test-threads=1
cargo test --locked -p fgit-node --lib queue_landing::custody -- --test-threads=1
cargo test --locked -p fgit-cli --bin fg workflow_command::watch
cargo test --locked -p fgit-cli --bin fg smart_http_server::workflow
cargo test --locked -p fgit-cli --test workflow_queue_merge -- --test-threads=1
FG_BIN=/absolute/path/to/fg scripts/e2e/suites/workflow/queue_merge_watch.sh
FG_BIN=/absolute/path/to/fg scripts/e2e/suites/workflow/queue_merge_service.sh
```

These commands identify the focused tests and real-binary campaign; they do not
claim that an untested revision passed them or that the full FG-083 subsystem is
complete.

# Automatic native workflow checks for pull requests

On Linux, `fg serve-http` can discover and service open same-repository pull
requests targeting one fixed branch. `--workflow-pull-requests` selects this
mode. Each selected PR uses the existing native source-head workflow dispatcher,
durable execution records and optional canonical check publisher. The controller
keeps a durable inventory of every admitted member, so a restart cannot forget
unfinished execution or publication merely because a PR closed or disappeared
from current discovery.

This is a trusted local execution profile. Scripts from every current and future
eligible PR run with the service account's host privileges. The operator must
trust all principals and write paths that can change those scripts or their
inputs. Selected input paths govern copied source; they do not isolate scripts
from the host. This mode does not provide an untrusted-fork runner or
hostile-code isolation.

## Start the service

Provision the incarnation-bound scoped credential file described in
[the HTTP service guide](NATIVE_HTTP_WORKFLOW_SERVICE.md). Create the existing
absolute run parent with mode `0700`; the stop file must be absent in an
operator-owned directory.

```sh
fg serve-http NODE TENANT REPOSITORY 127.0.0.1:8080 \
  --trusted-local --credentials-file /private/http-credentials \
  --continuous --stop-file /private/control/http.stop \
  --expected-incarnation INCARNATION \
  --workflow-trusted-local --workflow-format sha256 \
  --workflow-pull-requests --workflow-max-pull-requests 32 \
  --workflow-ref refs/heads/main --workflow-dir ci \
  --workflow-input ci --workflow-input src \
  --workflow-run-parent /private/pr-workflow-runs \
  --workflow-interval-ms 1000 --workflow-attempt-timeout-secs 300 \
  --workflow-publish-checks --workflow-principal CHECK_PUBLISHER \
  --allow-pulls --allow-outcomes --allow-receive
```

`--workflow-ref` is the **target branch** in collection mode. Each PR's immutable
canonical source branch is discovered from that PR. `--workflow-format` must
match the repository's `sha1` or `sha256` format. Inputs remain explicit,
non-overlapping repository paths and must cover the workflow directory. A
committed workflow selects the native `pull_request` event, for example:

```yaml
name: pull request checks
on: pull_request
jobs:
  test:
    runs-on: fgit-trusted-local
    steps:
      - run: ./ci/test.sh
```

The CLI requires an explicit `--expected-incarnation` in collection mode even
when no check publisher is configured. The separate
`--workflow-trusted-local` acknowledgement and existing
`--credentials-file --continuous --stop-file` requirements also remain enforced.

The example enables PR, outcome and Git receive endpoints separately. Omit their
enable flags to keep those network capabilities disabled. Tokens still require
their own endpoint scopes. Automatic local discovery does not grant remote
execution, mutation, source-read or artifact-read authority. Credential rotation
controls HTTP grants; it does not change the local operator's explicit trust in
selected scripts.

## Selection and service

Discovery reads the native canonical PR inventory at one authenticated authority
snapshot, applies current visibility rules, and selects open PRs with the fixed
target. Its complete scan is bounded to ten pages of at most 100 visible PR rows
each, including rows that do not match the target. It checks that authority is
still current before admitting additions. Ordinary head movement defers the
poll without adding members or dispatching work. Startup must complete a stable
scan before readiness; retries share the same ten-page budget and finite
deadline. An incomplete scan or retained-member overflow cannot silently admit
a prefix of the discovered set.

Each admitted member uses its immutable PR number and source ref. The native PR
poller revalidates current PR state and branch coordinates before dispatch. A
closed PR or a PR whose current selection is unavailable does not authorize a
fresh execution. Existing branch/path filters, exact input selection, workflow
lowering and execution budgets apply to the chosen source tree.

The controller services one retained member per poll in rotating order. Discovery
and member work remain bounded by finite attempts; a selected member cannot renew
an active execution deadline. The polling interval defaults to 1000 milliseconds
and accepts 10–60000. The attempt ceiling defaults to 300 seconds and accepts
1–3600. The controller serializes member work and uses the listener's shared
stop/drain ownership. Intermediate source tips may coalesce between polls; this
is not an all-events delivery queue.

Collection mode executes **source heads**. It is mutually exclusive with
`--workflow-pull-request`, `--workflow-merge-queue` and every workflow
merge-candidate option. For checks on an actual combined tree, use the existing
[fixed-PR merge-candidate service](NATIVE_PULL_REQUEST_MERGE_WORKFLOW_WATCH.md)
or [queue-head service](NATIVE_MERGE_QUEUE_WORKFLOW_WATCH.md). A source-head
check cannot substitute for an exact-candidate check required by protection.

## Durable membership and restart

The private collection scope binds the exact tenant, repository incarnation,
object format, target branch and workflow directory. The scope also retains the
execution configuration and original reporting identity. Changing selected
inputs, publisher or execution/artifact contract cannot create a fresh view of
the same collection and silently discard previous responsibility.

Membership is grow-only in this profile. The controller persists and syncs each
new `(PR number, source ref)` member before opening its native custody, then
records initialization before any script can start. Initialized members must
retain their original controller/watch custody. Missing, corrupt or incompatible
custody refuses instead of creating a replacement owner. Pending initialization
can resume only through full native validation.

Startup loads **all** retained members, including PRs now closed or hidden. It
validates their original execution records and performs the existing bounded
check-publication recovery before readiness. Current discovery cannot replace
that inventory or erase an unresolved member. Readiness completes before any
fresh script starts. Unknown execution in any member stops the entire workflow
controller and drains the HTTP service.

The inventory is derived execution custody, not canonical repository authority.
Only ordinary authenticated canonical publication can record checks. Retained
membership never grants a hidden ref new visibility or authorizes a PR that the
current native selector refuses. Keep the run parent with repository restores
and follow [native watch recovery](NATIVE_WORKFLOW_WATCH_RECOVERY.md) for execution
and publication failures. Deleting or replacing that custody is not a supported
retry or capacity-management operation.

## Capacity, checks and artifacts

`--workflow-max-pull-requests` accepts **1–64**, default **64**. This is a limit on
all retained members, including closed or hidden PRs, rather than just today's
open PRs. The controller does not automatically retire members. Raising the
capacity up to 64 preserves the same custody scope; reducing it below the
retained count refuses. If the complete new selection would exceed capacity,
the controller refuses before admitting any of those additions. This bounded
profile is intended for repositories that fit the retained-member allowance.

Each member also retains the existing native watch limit of 1024 events per
scope. No automatic event deletion, interrupted-script retry or identity reset
is introduced. A normal failed build can settle and permit a later source event;
unresolved execution must be reconciled through original custody.

Checks require both `--workflow-publish-checks` and `--workflow-principal`.
Results retain the exact member PR/source coordinates and original idempotency
identity. The existing PR check view uses the PR's exact recorded source tip.
After an independent branch advance it reports `source_current: false` and
withholds checks until an explicit PR metadata update. The watcher can execute
and publish for the live source without rewriting that metadata or changing
review coordinates. See [native PR check selection](NATIVE_PULL_REQUEST_WORKFLOW_WATCH.md)
for this existing boundary.

A completed publication scan for one member cannot erase another
member's pending check responsibility. The final `workflow_service_drained`
receipt aggregates member observations and reports pending publication,
interruption, non-green results and service failure separately. A transport
shutdown alone is not a successful CI result.

The existing workflow artifact flags can capture logs/output files and deliver
verified outputs to dependent jobs for every selected PR. The same immutable
artifact provenance, capture limits and input-delivery bounds apply. Download
authorization remains the separate `artifact-read` grant, which covers the
configured repository-incarnation artifact namespace. See
[HTTP workflow artifacts](HTTP_WORKFLOW_ARTIFACTS.md) and the
[service output/input example](NATIVE_HTTP_WORKFLOW_SERVICE.md#file-outputs-and-dependent-jobs).

## Focused verification entrypoints

```sh
cargo test --locked -p fgit-cli --bin fg smart_http_server::workflow::tests::collection
cargo test --locked -p fgit-node --test trusted_ref_workflow service_pull_requests -- --test-threads=1
cargo test --locked -p fgit-cli --test workflow_pull_request_collection -- --test-threads=1
FG_BIN=/absolute/path/to/fg scripts/e2e/suites/workflow/pull_request_collection.sh
```

These entrypoints cover parser authority/bounds, native durable discovery and
recovery, and the actual HTTP service path. Their presence or successful type
checking does not establish that the native execution campaign ran at a given
revision.

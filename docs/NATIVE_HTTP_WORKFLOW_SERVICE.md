# Native CI owned by the HTTP service

On Linux, `fg serve-http` can own one native workflow controller alongside its
accepted HTTP sessions. The operator selects its branch or PR collection, workflow directory,
source inputs, private run parent and optional check publisher at startup. The
controller uses the same canonical source selection, execution custody and check
admission as [`fg workflow watch`](NATIVE_REF_WORKFLOW_WATCH.md).

## Explicit host execution authority

This is trusted local execution. Every future selected script runs with the
service account's host privileges. Trust every principal and every write path
that can change those scripts or their inputs. The input list selects copied
source files; it does not constrain scripts' access to the host.

`--workflow-trusted-local` is a separate required acknowledgement. The existing
HTTP `--trusted-local` transport acknowledgement alone cannot enable execution.
No HTTP request, bearer token, workflow text or repository file can select the
controller's run parent, publisher, watched branch or execution configuration.
There is no workflow-execution HTTP endpoint, and this profile does not provide
hostile-code isolation or an untrusted pull-request runner.

## Starting a service

Provision the ordinary incarnation-bound scoped credentials described by
`fg serve-http --help`, and create the private run directory with mode 0700.
The stop file must be absent in an existing operator-owned directory.

```sh
fg serve-http NODE TENANT REPOSITORY 127.0.0.1:8080 \
  --trusted-local --credentials-file /private/http-credentials \
  --continuous --stop-file /private/control/http.stop \
  --expected-incarnation INCARNATION \
  --workflow-trusted-local --workflow-format sha256 \
  --workflow-ref refs/heads/main --workflow-dir ci \
  --workflow-input ci --workflow-input src \
  --workflow-run-parent /private/workflow-runs \
  --workflow-interval-ms 1000 --workflow-attempt-timeout-secs 300 \
  --workflow-publish-checks --workflow-principal PUBLISHER \
  --allow-pulls --allow-receive
```

All workflow selection flags are explicit. `--workflow-input` repeats for distinct,
non-overlapping repository paths, including [nested prefixes](TRUSTED_WORKFLOW_INPUTS.md);
the workflow directory must be included in those inputs.
`--workflow-format` must match the repository's SHA-1 or SHA-256 object format.
The polling interval accepts 10–60000 milliseconds and defaults to 1000. Each
attempt accepts a 1–3600 second deadline and defaults to 300. Pending publication,
one source poll and its resulting publication share that finite request; an
active attempt never renews its budget. Existing per-step, per-run and output
limits continue to apply.

The CLI requires `--continuous --stop-file` so its signal and file controls own
execution drain. Create the regular stop file or send SIGTERM/SIGINT to stop the
listener and its controller. The file is retained. The native library also
offers a bounded listener wrapper for embedding owners that manage their own
process controls.

The workflow service requires `--credentials-file`. Each network endpoint remains
independently disabled until its ordinary enable flag is present, and each token
still needs that endpoint's scope. A workflow controller does not enable source
queries, Git receive, PR writes or artifact downloads. The example enables PR
APIs and Git receive explicitly; omit those flags to keep them disabled. Credential
rotation/revocation governs network grants; it does not replace the local
operator's explicit workflow service configuration.

## Checks, PRs and retained logs

Execution alone does not publish checks. Supply **both**
`--workflow-publish-checks --workflow-principal PUBLISHER`, together with
`--expected-incarnation`, to use the existing canonical check publication path.
The original reporting identity remains permanently bound to its custody scope.
Pending publication recovers under original identities before new execution;
failed or skipped job observations are never promoted to success.

Optional `--workflow-pull-request NUMBER` selects the native same-repository PR
profile. The PR must be open and its source branch must match `--workflow-ref`.
By default it executes the current source head and retains separate PR custody.
See [native PR workflow selection](NATIVE_PULL_REQUEST_WORKFLOW_WATCH.md).

### Discover open pull requests automatically

Use `--workflow-pull-requests` to discover visible open same-repository PRs
targeting `--workflow-ref`. This mode requires `--expected-incarnation` even
without a check publisher. By default it executes current source heads, rotates through
retained PRs one member per poll, and reuses the ordinary PR execution and
canonical check-publication paths. It cannot be combined with a fixed PR or
merge queue.

To test each discovered PR's actual combined tree, supply the complete merge
writer/metadata option group below with
`--workflow-merge-candidate-ref-prefix refs/heads/ci/collection` instead of an
exact candidate ref. Each PR owns `<prefix>/pr-<number>`; the prefix is a stem
without a trailing slash, and `--workflow-merge-candidate-ref-prefix-hex` supports
raw bytes. Both merge and squash styles work. Reserve that entire namespace for
the controller and keep PR source/target branches outside it. Candidate mode
and template identity are durably bound to the original collection scope, so
changing the mode or namespace cannot abandon earlier executions. See the
[collection candidate guide](NATIVE_PULL_REQUEST_WORKFLOW_COLLECTION.md#execute-every-discovered-prs-combined-tree)
for exact checks, namespace restrictions and recovery.

`--workflow-max-pull-requests` accepts 1–64 and defaults to 64. The limit applies
to the durable retained inventory, including closed or hidden PRs. New members
are persisted before their custody can acquire execution responsibility; every
retained member's original custody is checked before restart readiness.
Incomplete discovery or insufficient capacity refuses new admission, and
unknown execution stops the controller. The execution acknowledgement covers
scripts from every current and future eligible PR. See the
[collection guide](NATIVE_PULL_REQUEST_WORKFLOW_COLLECTION.md) for complete
commands, current visibility, recovery and the bounded retention profile.

### Execute the actual merge or squash candidate

Add the explicit merge-candidate option group to test the combined PR tree:

```sh
fg serve-http NODE TENANT REPOSITORY 127.0.0.1:8080 \
  --trusted-local --credentials-file /private/http-credentials \
  --continuous --stop-file /private/control/http.stop \
  --expected-incarnation INCARNATION \
  --workflow-trusted-local --workflow-format sha256 \
  --workflow-ref refs/heads/topic --workflow-pull-request 7 \
  --workflow-dir ci --workflow-input ci --workflow-input src \
  --workflow-run-parent /private/merge-runs \
  --workflow-merge-candidate-ref refs/heads/ci-main \
  --workflow-merge-principal CI_WRITER \
  --workflow-merge-author 'CI <ci@example.test>' \
  --workflow-merge-committer 'CI <ci@example.test>' \
  --workflow-merge-timestamp 1700000000 \
  --workflow-merge-message 'Test the exact candidate' \
  --workflow-merge-method merge-commit --workflow-merge-profile path \
  --workflow-publish-checks --workflow-principal CHECK_PUBLISHER
```

The CI branch, writer, author, committer, timestamp and message are mandatory
when any merge option is supplied. This exact-ref group also requires an explicit native
PR and repository incarnation. Collection mode uses its explicit prefix option
as described above. `--workflow-merge-method` accepts `merge-commit`
(default) or `squash`; `--workflow-merge-profile` accepts `path` (default) or
`exact-renames`. Use `--workflow-merge-candidate-ref-hex` instead of the text
reference flag for exact raw branch bytes. Literal merge messages beginning
with `--` remain data and are preserved exactly.

This configuration authorizes ordinary exact-old creation/replacement of a
CI branch distinct from both PR branches. Candidate publication and script
execution both wait for successful listener readiness. Failed readiness cannot
publish a CI ref. The check publisher remains independently configured, and
no HTTP endpoint is enabled by the merge group. The example enables no
optional network endpoints.

Definitions and source files come from the actual combined tree. PR branch/path
filters retain the original target and incoming change. Optional results name
the admitted CI commit and fixed CI branch, so existing exact-candidate protection
can gate a later separately submitted merge. Ordinary PR check views retain
their source-head coordinates.

Retain identical deterministic metadata and merge configuration across restart.
Conflicts and stale recorded PR tips produce non-green observations without
candidate publication or scripts. A failure after reservation retains the
original bundle/key/lease. New versioned intents can resume only their first
dispatch when exact custody proves execution never started; all other unresolved
events still stop later work. See
[exact PR candidate CI](NATIVE_PULL_REQUEST_MERGE_WORKFLOW_WATCH.md) for
protected-merge setup, immutable configuration and recovery.

### Execute the current merge-queue head

Use `--workflow-merge-queue NUMBER` instead of `--workflow-pull-request`, and
set `--workflow-ref` to the queue's fixed target branch. Queue mode requires
the complete merge-candidate group, explicit incarnation and `merge-commit`
style. The controller selects the current head PR/source, prepares and executes
the exact two-parent candidate, and optionally publishes its canonical checks.
The CI ref must differ from the target and selected source.

One queue-wide custody scope fences unresolved work even after the head changes;
settled check publication can recover after dequeue or an empty queue. Candidate
publication and execution still wait for listener readiness and drain with the
service. No target landing, queue-management grant or remote execution endpoint
is implied. See the [queue candidate CI guide](NATIVE_MERGE_QUEUE_WORKFLOW_WATCH.md)
for complete commands, exact check/landing coordinates and recovery behavior.

Automatic landing requires the explicit
`--workflow-land-queue-head --workflow-landing-principal LANDING_PRINCIPAL`
pair, together with the queue/candidate selection, check publisher and exact
incarnation. To refresh the next head's recorded target and continue that
pipeline, also supply
`--workflow-refresh-queue-head --workflow-refresh-principal REFRESH_PRINCIPAL`.
These are separate operator authorities; neither grants any HTTP endpoint
permission.

The refresh controller durably retains the complete original PR metadata and
queue/PR/policy/target observations before submission. It preserves queue order,
priority, source content and refs, and advances only the PR version. Candidate
preparation, execution, current reviews and exact checks still govern the next
landing. Pending original refreshes recover before later candidate work, and
missing or changed refresh authority on restart cannot abandon their custody.
Startup validates this custody without admitting a fresh or undecided PR update
before listener readiness. See the queue guide for retention bounds and outcome
recovery.

### File outputs and dependent jobs

The owned HTTP controller can capture exact output files and deliver them to
direct dependent jobs using the same contract as foreground `fg workflow`
commands. For example, commit this workflow as `ci/build.yml`:

```yaml
name: build and test
on: push
jobs:
  build:
    runs-on: fgit-trusted-local
    steps:
      - run: printf 'build-output\n' > package.bin
  test:
    needs: build
    runs-on: fgit-trusted-local
    steps:
      - run: test -s .fgit-artifacts/package.bin; cp .fgit-artifacts/package.bin tested.bin
```

Configure the producer output, consumer input and optional tested output when
starting the service:

```sh
fg serve-http NODE TENANT REPOSITORY 127.0.0.1:8080 \
  --trusted-local --credentials-file /private/http-credentials \
  --continuous --stop-file /private/control/http.stop \
  --expected-incarnation INCARNATION \
  --workflow-trusted-local --workflow-format sha256 \
  --workflow-ref refs/heads/main --workflow-dir ci --workflow-input ci \
  --workflow-run-parent /private/runs \
  --workflow-publish-checks --workflow-principal CHECK_PUBLISHER \
  --artifact-root /private/artifacts \
  --workflow-artifact ci/build.yml:build:package.bin \
  --workflow-artifact ci/build.yml:test:tested.bin \
  --workflow-artifact-input ci/build.yml:test:build:package.bin:package.bin \
  --workflow-artifact-logs
```

Create the run and artifact roots as private `0700` directories before starting.
Output selectors are `workflow:job:output`; input selectors are
`workflow:consumer:producer:output:destination`. They are repeatable, with at
most 64 output selections and 64 input selections. Matrix jobs use their exact
expanded IDs. For raw path bytes, use `--workflow-artifact-hex` and
`--workflow-artifact-input-hex`: encode each path field as hexadecimal and keep
the job fields as their ASCII IDs. Duplicate output selections, overlapping
consumer destinations and invalid paths refuse before the listener starts.

Every input must name an explicitly captured output from the consumer's direct
`needs` dependency. The native dispatcher validates that relationship against
the selected workflow before starting jobs. After a successful producer closes,
the consumer receives verified copies in its fresh `.fgit-artifacts/` namespace.
The original producer workspace is already gone. Source paths cannot be
overwritten, and inputs from a failed producer or another attempt cannot supply
successful dependency evidence. Missing, unsafe or oversized selected outputs
prevent producer success; input verification or delivery exhaustion prevents
the consumer from starting. Original failure/refusal conclusions remain in the
normal canonical check publication path.

| Server flag | Default | Accepted MiB |
|---|---:|---:|
| `--workflow-max-artifact-mib` | 16 | 1–64 |
| `--workflow-max-artifact-total-mib` | 64 | 1–512 |
| `--workflow-max-artifact-input-total-mib` | 64 | 1–512 |

Files and logs share the capture allowance across all selected workflows in
one dispatch. Every delivered copy charges the separate cumulative input
allowance, including fan-out. An input limit requires explicit input selections;
capture limits require file selectors or log capture. The combined input/output
path limit is 64 KiB. Supplying only `--artifact-root` keeps the existing
download-only behavior and does not enable workflow capture.

Saved `report.json`, per-job artifact receipts and input receipts identify the
original output, producing manifest, source, run and exact delivered
destination. Their artifact IDs can be read through
`GET /api/v1/artifacts/ID` and `GET /api/v1/artifacts/ID/content`. Each HTTP read
verifies immutable custody and bytes and requires the independent
`artifact-read` grant. A Git/source read grant cannot disclose artifacts, and
configuring local capture does not add a token grant. The artifact permission
covers the entire configured repository-incarnation namespace, including
hidden-ref outputs. Retaining the node, run parent and artifact root permits
restart to serve those same bytes and recover original checks without rerunning
scripts. Artifact custody does not authorize deterministic cache reuse.

### Retained logs

Optional `--workflow-artifact-logs --artifact-root /private/artifacts` captures
bounded raw stdout/stderr using existing immutable artifact custody. Defaults
are 16 MiB per payload and 64 MiB cumulative payloads per dispatch. Logs may
contain secrets printed by trusted scripts; they are not redacted. The HTTP
artifact surface still requires the independent `artifact-read` scope. See
[HTTP workflow artifacts](HTTP_WORKFLOW_ARTIFACTS.md) for its entire-incarnation
disclosure boundary. The server file-capture and artifact-input options above
use the same native contracts as the dedicated foreground workflow commands.

## Readiness, stop and recovery

The worker authenticates the exact repository incarnation, obtains exclusive
controller ownership, validates existing execution custody and reconciles
pending checks before HTTP readiness. It then waits for the listener's readiness
callback to succeed before starting scripts. A broken readiness output cannot
start a workflow. This lifetime lock supplements the existing per-event custody
locks; permanent event identities remain the protection against duplicate work.

`smart_http_listening` includes `workflow_enabled`. On stop, HTTP acceptance
retires and the controller receives a cooperative stop before accepted sessions
are joined. Active workflow processes drain under their existing native owners.
The worker's node closes before the listener emits `workflow_service_drained`;
the usual `smart_http_drained` follows the outer node's close. The workflow receipt
reports observed execution/check counts, non-green results, interruption,
reconciliation, publication pending, and node/service failure separately.

An ordinary failed build can settle and the service can execute a later source
event. A cooperatively cancelled build also settles when native owners prove
process, workspace and shared-input closure: one bounded terminal handoff keeps
its original cancelled checks for the next live publisher. Restart uses those
same receipts and never reruns the original scripts. Unknown or unclosed
execution, corrupt custody, incomplete publication or a worker failure stops
the service. An idle clean stop exits 0. A requested
shutdown that drains normally but reports non-green execution, interruption,
unresolved custody or known pending publication exits 1. Startup, controller
operation (including an exhausted attempt), output or cleanup failure exits 2.
A successful transport close is not proof of green CI. A cancelled read-only
publication scan alone does not invent pending work; that field retains observed
publication responsibility until a complete recovery pass clears it.

Retain the run parent across restarts and restores. The existing 1024 retained
event limit per scope remains enforced; no automatic deletion, identity reset,
retry of interrupted scripts or all-events delivery queue is introduced.
Intermediate branch tips may coalesce between polls. Startup can recover a
missing final settlement from the original durable completed-dispatch handoff
and verified closed execution/journal records before readiness. This performs
no script execution or CI-ref publication. See
[native-watch recovery](NATIVE_WORKFLOW_WATCH_RECOVERY.md) for its finite
verification profile.

Stopped dispatch handoffs bind the original selected count, terminal reason and
exact dispatch-plan digest. This also supports a stopped dispatch that selected
work but terminated before its first child, when that explicit terminal record
exists. Missing children alone do not prove a stop. An interruption during
earlier source discovery or an unfinished execution owner remains fenced.

For new merge-candidate events, startup may also defer a versioned intent whose
original scope, candidate artifacts and complete execution configuration verify
and whose execution-start fence and dispatch directories are absent. Such an
event remains `pending_execution`; it is never treated as settled or reported.
The startup check publisher only skips and counts it. Its original CI publication
retry and first script dispatch occur after the HTTP readiness callback succeeds,
using the original key, old-tip lease, candidate and head guard. Failed readiness
or a startup stop performs neither effect. Legacy events without that intent,
begun executions and corrupt or mismatched custody still refuse readiness.

Source index maintenance can run alongside CI with its existing explicit flags.
Both workers belong to the same listener's stop/drain path; enabling CI grants
no source access and does not replace index progress ownership.

## Focused service test entrypoints

```sh
cargo test --locked -p fgit-cli --bin fg smart_http_server::workflow
cargo test --locked -p fgit-cli --test workflow_pull_request_merge -- --test-threads=1
cargo test --locked -p fgit-cli --test workflow_http_artifacts -- --test-threads=1
FG_BIN=/absolute/path/to/fg scripts/e2e/suites/workflow/pull_request_merge_service.sh
FG_BIN=/absolute/path/to/fg scripts/e2e/suites/workflow/http_artifacts.sh
```

The actual-process campaign covers both Git object formats and both candidate
styles, readiness-output failure before ref publication, independent HTTP grants,
canonical candidate checks through HTTP, ordered shutdown and restart without
reexecution. These are test definitions and entrypoints; they do not claim a
native pass for a revision that has not executed them.

The artifact campaign uses actual `fg` processes in both Git hash formats. It
covers binary producer/consumer delivery after workspace cleanup, exact original
checks, independently authorized HTTP metadata/downloads and live credential
revocation, fresh-server restart without execution replay, and failed, missing,
oversized or delivery-budget-exhausted outputs. The campaign's presence and type
checking alone do not establish a native execution result.

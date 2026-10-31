# Native CI owned by the HTTP service

On Linux, `fg serve-http` can own one native workflow controller alongside its
accepted HTTP sessions. The operator selects its branch, workflow directory,
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

All workflow selection flags are explicit. `--workflow-input` repeats for distinct
top-level paths; the workflow directory must be included in those inputs.
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
when any merge option is supplied. The group also requires an explicit native
PR and repository incarnation. `--workflow-merge-method` accepts `merge-commit`
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
original bundle/key/lease and stops later work. See
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

### Retained logs

Optional `--workflow-artifact-logs --artifact-root /private/artifacts` captures
bounded raw stdout/stderr using existing immutable artifact custody. Defaults
are 16 MiB per payload and 64 MiB cumulative payloads per dispatch. Logs may
contain secrets printed by trusted scripts; they are not redacted. The HTTP
artifact surface still requires the independent `artifact-read` scope. See
[HTTP workflow artifacts](HTTP_WORKFLOW_ARTIFACTS.md) for its entire-incarnation
disclosure boundary. The dedicated foreground workflow commands retain their
additional explicit file-capture and artifact-input options.

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
event. Unknown or interrupted execution, corrupt custody, incomplete publication
or a worker failure stops the service. An idle clean stop exits 0. A requested
shutdown that drains normally but reports non-green execution, interruption,
unresolved custody or known pending publication exits 1. Startup, controller
operation (including an exhausted attempt), output or cleanup failure exits 2.
A successful transport close is not proof of green CI. A cancelled read-only
publication scan alone does not invent pending work; that field retains observed
publication responsibility until a complete recovery pass clears it.

Retain the run parent across restarts and restores. The existing 1024 retained
event limit per scope remains enforced; no automatic deletion, identity reset,
retry of interrupted scripts or all-events delivery queue is introduced.
Intermediate branch tips may coalesce between polls. An unresolved event blocks
later events and refuses service readiness on restart until reconciled.

Source index maintenance can run alongside CI with its existing explicit flags.
Both workers belong to the same listener's stop/drain path; enabling CI grants
no source access and does not replace index progress ownership.

## Focused candidate-service test entrypoints

```sh
cargo test --locked -p fgit-cli --bin fg smart_http_server::workflow
cargo test --locked -p fgit-cli --test workflow_pull_request_merge -- --test-threads=1
FG_BIN=/absolute/path/to/fg scripts/e2e/suites/workflow/pull_request_merge_service.sh
```

The actual-process campaign covers both Git object formats and both candidate
styles, readiness-output failure before ref publication, independent HTTP grants,
canonical candidate checks through HTTP, ordered shutdown and restart without
reexecution. These are test definitions and entrypoints; they do not claim a
native pass for a revision that has not executed them.

# Trusted branch-tip workflow watcher

`scripts/fg_workflow_watch.mjs` is an **external Linux operator tool** that connects
canonical ref observation to the existing Rust `fg workflow dispatch` command.
It does not implement Git, parse workflow YAML, replace the native scheduler,
change repository state, or publish checks. The Rust binary still selects and
validates source, compiles definitions, owns jobs/workspaces, and writes native
execution journals.

The operator must trust **every future selected branch revision** with the host
user's privileges. Input selection is not a process sandbox. Use a dedicated
trusted account and do not use this watcher for untrusted contributions. The
watcher passes a minimal environment (PATH `/usr/bin:/bin`, UTF-8 locale and UTC),
not the invoking process's credentials or arbitrary environment variables.

## Configure and run

Provide an existing native store, an existing private run-parent directory, and
an existing **empty** private state directory. All three must be disjoint,
normalized absolute paths without symlink aliases. Run/state directories must
belong to the current user and have mode 0700. Configuration must be a private
regular file. `fg` must be an explicit owner-controlled executable, not a shell
command or a symlink. Node.js 22 or later is required.

Example configuration (replace every repository/path identity with the actual
selected deployment):

```json
{
  "schema": "frankengit-workflow-watch-v1",
  "fg": "/srv/bin/fg",
  "storage_root": "/srv/native-store",
  "tenant_id": "11111111111111111111111111111111",
  "repository_id": "22222222222222222222222222222222",
  "repository_incarnation": "33333333333333333333333333333333",
  "object_format": "sha1",
  "ref_hex": "726566732f68656164732f6d61696e",
  "workflow_directory_hex": "2e6769746875622f776f726b666c6f7773",
  "input_prefixes_hex": ["2e676974687562", "737263", "436172676f2e746f6d6c", "436172676f2e6c6f636b"],
  "event": "push",
  "state_directory": "/srv/workflow-watch",
  "run_parent": "/srv/workflow-runs",
  "max_runs": 128,
  "trust": "selected-branch-host-execution"
}
```

`ref_hex` above is `refs/heads/main`; the directory is `.github/workflows`.
Inputs above select `.github`, `src`, `Cargo.toml`, and `Cargo.lock`. Choose every
needed top-level path explicitly. Hex preserves native byte names without
turning them into shell syntax. SHA-256 native repositories are also supported.
Only `push` and `workflow_dispatch` are native event-selection keys here.

### Capture outputs and feed dependent jobs automatically

Add an optional `artifacts` field to run the same explicit artifact pipeline on
each newly observed commit. For `.github/workflows/ci.yml`, where `build` writes
`dist/result` and `test` declares `needs: build`, this configuration passes the
verified output to `.fgit-artifacts/build/result` before `test` starts:

```json
{
  "artifacts": {
    "root": "/srv/workflow-artifacts",
    "maximum_file_mib": 16,
    "total_payload_mib": 64,
    "total_delivery_mib": 64,
    "selections": [
      {
        "workflow_path_hex": "2e6769746875622f776f726b666c6f77732f63692e796d6c",
        "job_id": "build",
        "output_path_hex": "646973742f726573756c74"
      }
    ],
    "inputs": [
      {
        "workflow_path_hex": "2e6769746875622f776f726b666c6f77732f63692e796d6c",
        "consumer_job_id": "test",
        "producer_job_id": "build",
        "output_path_hex": "646973742f726573756c74",
        "destination_hex": "6275696c642f726573756c74"
      }
    ]
  }
}
```

This is a field to add to the full watcher configuration above. The artifact
root must already exist as a normalized, nonsymlink, owner-private `0700`
directory. It must be disjoint from native storage, watcher state, run custody,
and the executable. The watcher validates it before acquiring an execution
lock or invoking the native binary. It never creates an artifact root implicitly.

Select 1–64 captured files and optionally up to 64 input deliveries. Paths are
hexadecimal native bytes; expanded job IDs remain literal bounded ASCII. Each
workflow must be a direct `.yml` or `.yaml` child of the configured workflow
directory. Inputs require an explicitly captured producer output and distinct
producer/consumer IDs. Destination collisions and ancestor overlaps within a
consumer refuse. The selected future workflow must still have the jobs and
direct `needs` edge: the native scheduler validates these against the actual
observed commit before reserving its batch.

The three allowances default to 16, 64, and 64 MiB respectively. File capture
accepts 1–64 MiB; cumulative capture and cumulative delivery each accept
1–512 MiB. Omit `inputs` and `total_delivery_mib` for capture only. Each delivered
file must also fit the native 16 MiB workspace limit; source plus inputs in one
job must fit 64 MiB, and the existing whole-dispatch materialization limits
remain in force. Combined selector paths are bounded to 64 KiB. Native path
rules apply before binding configuration: 4096 bytes per path, 255 bytes per
component, 64 components, no control bytes or Git metadata aliases. Destinations
are at most 4000 bytes and 63 components, leaving room for `.fgit-artifacts`.
Arbitrary non-UTF-8 bytes remain exact; no selector is interpreted by a shell.

The watcher sorts and binds the complete artifact contract into its immutable
configuration and commit intent. It passes `--artifact-hex` and
`--artifact-input-hex` to native dispatch, including separate capture and delivery
allowances. A native completion is accepted only if its dispatch plan and every
child report carry exactly that same contract. Missing, substituted or additional
contract fields leave execution unresolved; they never authorize a retry.
Changing the artifact root, selectors or allowances in a bound state directory
is refused, just like changing the source or executable. Configurations without
`artifacts` retain their existing serialized bytes and execution identities.

The check publisher and supervisor accept this same nested watcher configuration.
Output and input receipt arrays are execution observations; the publisher checks
the immutable `artifact_contract` against the original attempt marker without
requiring those later observations to appear in that marker. Publisher and
supervisor custody must be disjoint from all artifact roots. Multiple lanes may
use the exact same artifact root, relying on the native tenant/repository/trust
namespaces; partly overlapping roots are refused.

Native execution still verifies producer success, provenance, payload digests,
copy budgets, cancellation and workspace cleanup as described in
[`TRUSTED_WORKFLOW_ARTIFACTS.md`](TRUSTED_WORKFLOW_ARTIFACTS.md). Watcher status and
reconciliation remain available when the executable, source store or artifact
root is offline. They validate preserved reports and do not read, recreate or
recopy artifact payloads. This configuration grants no cache reuse, remote
artifact access, hostile-code isolation or additional publication authority.

```sh
node scripts/fg_workflow_watch.mjs once --config /srv/watch.json --trusted-local
node scripts/fg_workflow_watch.mjs serve --config /srv/watch.json --trusted-local --poll-millis 1000 --max-polls 86400
node scripts/fg_workflow_watch.mjs status --config /srv/watch.json --trusted-local
node scripts/fg_workflow_watch.mjs reconcile --config /srv/watch.json --trusted-local
```

One sweep reads bounded, snapshot-pinned `fg refs` pages, finds the selected
branch, and dispatches an unseen commit. It passes the exact observed head,
commit, ref bytes, configured incarnation, workflow directory, inputs and run ID
to the native command. Native incarnation checking occurs before execution;
the ref-inventory response itself does not carry an incarnation.

`serve` holds one exclusive owner across observation, dispatch, output and polling.
It defaults to one-second polls and a finite one-million-poll ceiling; both bounds
are explicit controls, not permission to reset execution identity. Ordinary failed
jobs do not prevent later commits from running. Only read-only observation failures
receive automatic retries: exponential polling delay, capped at 60 seconds, and
termination after three consecutive failures. A successful observation resets that
read-failure count. Execution, custody and output errors are never retried as reads.

The configuration is permanently bound to its state directory. Editing its
scope, inputs, binary path or other fields cannot quietly reset retry identity.
The complete selected intent is saved and synced; a separate synced start
marker precedes the native process. No shell is used to invoke `fg`.

## What is and is not triggered

The trigger is **an observed branch tip, not proof of an accepted push event**.
The native `event` selects matching declarations; it does not prove the event
happened. The first observation runs the current tip. Each commit is dispatched
at most once per intact retained configuration, including across restarts and
A → B → A branch movement. Metadata-only changes of the authority head do not
rerun the same commit. This is not a complete per-push event subscription:
intermediate commits between observations may be missed. It is not PR triggering.

A moved head between observation and native preflight refuses; the watcher does
not silently refresh the original intent. Inspect that unresolved attempt before
continuing. A missing branch is an idle observation, never a passing check.

## Completion, recovery and interruption

Normal success, normal job failure, a safely settled native stop, and no matching
definitions are distinct results. Native success remains a trusted-local execution observation,
**not a green protected check**, independent execution attestation, or merge
permission. Completed children must be identity-matched and report closed workspaces. The
watcher also checks the nested native execution profile, job/step outcomes,
retention flags, exit/success consistency and aggregate jobs/steps/output bounds.
A top-level success bit cannot override a retained workspace or containment failure.

Known native stops (`request_stopped`, `output_budget_exhausted`,
`workflow_refused`, `workflow_timed_out`, `workflow_output_limit`) with fully
settled reported children are recorded as **observed_stopped**, not success. The
number of selected but unstarted workflows remains visible; none is implicitly
resumed. A later commit may then run. Unknown stop reasons, missing reports,
contradictory success and any containment warning remain pending and block work.

An unknown execution prevents any later dispatch. `reconcile` reads the original
native batch's `report.json`, validates its retained scope, source, child IDs and
completion, and records that observation locally. It never invokes another
workflow, resumes a child, publishes an observation to the forge, or changes an
ID. Status and reconciliation do not need the native executable or source store;
they can still inspect preserved custody and reports while the native installation
is unavailable. Loss of stdout can therefore be reconciled without replay. Missing or
contradictory evidence stays pending.

SIGTERM/SIGINT stop new work and **drain** an active native dispatch. Killing the
native owner immediately would undermine its own step cleanup. The native
600-second deadline remains in force; the external last-resort watchdog is 660
seconds. Polling stops promptly on a stop request; a CLI output write is bounded
to ten seconds. Forced termination makes no claim that escaped descendants were
contained and retains `owner.lock`. SIGKILL of the watcher can leave its native
child running and its lock retained. No automatic PID-based lock stealing is
implemented. Independently stop/reap the original owner and children before any
operator repair; do not erase batch IDs or custody to rerun uncertain effects.

A queued intent with no start marker can be executed at its **original** pins.
A started intent is never automatically retried. State corruption, temporary
files from interrupted publication, or lost history refuse rather than resetting.
Status is a read-only local observation, not an atomic repository snapshot.

## Bounds and exit codes

At most 256 ref pages, 100 rows/page, 1 MiB/page and 16 MiB aggregate ref output
are read, sharing one 30-second observation deadline rather than resetting the
deadline on every page. Native stdout is bounded to 40 MiB; diagnostics to 256 KiB. There are
1–4096 retained commits, selected by `max_runs`, with no automatic eviction.
Native limits still apply: 32 definitions, 128 selected jobs, 512 selected steps,
600-second execution and 16 MiB captured output. Native run directories can be
large; the operator remains responsible for provisioned disk space and retention.

The service emits one JSON observation per completed poll and a final summary
when stopped or at its poll limit. A poll-count ceiling is not a wall-clock
schedule. Idle results never fabricate new workflow executions.

Exit 0 means idle, no match, or observed native success; 1 means an observed job
failure or safely settled native stop; 2 means input/observation/output failure;
3 means unresolved execution
or containment. No exit code independently authorizes a merge. Saved native and
watcher observations survive a failed CLI stdout write.

## Validation boundary

`node --test tests/operator/workflow_watch.test.mjs` runs actual private-file,
process, CLI, timeout, pagination, source-binding, deduplication and recovery
checks, including continuous polling, bounded read retries, offline reconciliation,
SIGTERM draining, SIGKILL between polls and output failure after completion. Its executable peer is explicitly a **native-schema fixture, not fg**.
These tests do not establish native Git selection, authorization, workflow
compilation, process-tree sandboxing, power-loss behavior or a whole-product
end-to-end pass. Related work: `frankengit-root-doctrine-x2mv.4.12`; the full CI
product-loop bead remains incomplete.

`node --test tests/operator/workflow_watch_artifacts.test.mjs
tests/operator/workflow_check_publish.test.mjs` additionally exercises bounded
artifact configuration, exact native arguments and report-contract matching,
scope/custody refusals, immutable retries, offline reconciliation, and automatic
publication with artifact-bearing reports. These use the same explicitly labeled
schema peers. The native `fg` build-to-test, retained-export and offline-recovery
tests remain `cargo test --locked -p fgit-cli --test workflow_run`.

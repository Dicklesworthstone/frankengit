# Trusted repository workflow execution

`fg workflow run` composes the existing native YAML compiler and foreground
workflow runner with an authority-selected repository snapshot and the Linux
TreeFS host-directory adapter. It is an explicit **local-owner command**, not a
remote CI service. The workflow file and every copied input come from the same
verified commit; a host checkout is not used as source authority.

This is the `trusted-local-foreground-v1` subset of
`frankengit-fg095b-workflow-execution-mynp`. It does not close that bead's broader
requirements for hostile execution, runner attestation, canonical check
publication, distributed coordination, or complete crash reconciliation.

## Trust boundary

Review and trust **all scripts and executables they can invoke** before running
this command. They execute with the host user's privileges. `--input` selects
which repository paths are copied; it does not isolate processes from other host
files, the network, the authority store, or the report directory. Scripts must
join their descendants before normal exit. Cleared environment variables and
private job copies do not create a hostile-code sandbox.

Do not expose this entry point as an HTTP, MCP, agent-capability, or untrusted
pull-request runner. Run parents must be operator-owned, pre-existing, absolute,
nonsymlink directories with mode `0700`. The operator must protect the parent and
its ancestor path from concurrent replacement. Host permissions are a caller
precondition, not an account-authentication mechanism.

There is no source publication, output import, credential injection, canonical
check event, review approval, or automatic retry. A successful local report is
not accepted evidence for moving a protected ref. Reports deliberately retain
`authoritative_check: false`, `hostile_code_isolated: false`, and
`published: false`.

## Example

An already imported repository can contain this file at `ci/local.yml`:

```yaml
name: local-source-check
on: push
jobs:
  inspect:
    runs-on: fgit-trusted-local
    steps:
      - run: test -s src/lib.rs
      - run: printf checked
  independent-copy:
    runs-on: fgit-trusted-local
    needs: inspect
    steps:
      - run: test -s src/lib.rs; printf verified
```

`name`, `on`, and `jobs` are required by the existing compiler. The `on` field is
part of the compiled graph; this command is a manual invocation, not a push-event
subscription. Every job must use the explicit `fgit-trusted-local` runner label.
Unsupported YAML fields, actions, expressions, runner labels, or cyclic/missing
dependencies refuse rather than being silently ignored. The compiler remains the
single owner of syntax and lowering; see `fgit-schema/src/workflow/registry.rs`.

Set these shell variables to an existing node's storage path, tenant/repository
identities, and a new absolute run-parent directory. The workflow and source
files above must already be present in `refs/heads/main`:

```sh
# NODE, TENANT_ID, REPOSITORY_ID, and RUN_PARENT are operator-supplied values.
mkdir -m 700 -- "$RUN_PARENT"
fg workflow run "$NODE" "$TENANT_ID" "$REPOSITORY_ID" refs/heads/main \
  --trusted-local \
  --workflow ci/local.yml \
  --input ci --input src \
  --run-parent "$RUN_PARENT" \
  --run-id 8b8e4a9328dc468489b0ea348cf3c561
```

Use a new nonzero 16-byte run ID for a deliberately new execution, **not** as an
automatic workaround for a failed/lost response. A run ID is encoded as exactly
32 lowercase hexadecimal digits. A later deliberately requested run needs its
own ID. Do not remove an occupied run directory to defeat the replay guard.

Both SHA-1 and SHA-256 repositories use their native object identities; supply
`--object-format sha256` for the latter. Optional `--expected-head` and
`--expected-commit` reject a changed source selection before host creation.
`--expected-incarnation` rejects a replaced repository instance before execution.
The head token uses the existing `alg:<algorithm-code>:<digest-hex>` syntax,
optionally prefixed with `head:`.

`--input` accepts distinct top-level file/directory names, not globs. It must
include the workflow's top-level component. Unselected sibling trees are not
copied. Raw-byte names can use `--workflow-hex`, `--input-hex`, and `--ref-hex`.
Path traversal, duplicate flags/inputs, mixed workflow spellings, unknown options,
zero run IDs, and missing trust confirmation refuse before opening the node.

## Execution and resource profile

The entire workflow graph and its source manifest are validated before any job
starts. Jobs run serially in the native deterministic topological order. Steps
within a job share that job's working directory. Every other job receives a new
copy of the original pinned source, even when it depends on an earlier job.
There is no implicit artifact/output transfer between jobs.

A failed job stops its remaining steps and skips dependent jobs. Independent jobs
can still run. A containment failure stops further job starts. Every begun job
passes through explicit, non-cancellable workspace close or a reported retained
workspace; cancellation is not implemented as simply dropping the work.

The CLI uses the native default execution limits: 60 seconds per step, 600
seconds per run, 256 KiB of retained output per stream, and 16 MiB of retained
output across the run. The node embedding API accepts validated `WorkflowLimits`
for more restrictive or supported wider envelopes. Source discovery shares the
outer run deadline. Individual synchronous operations are cooperative, not
preemptive wall-clock deadlines.

Source manifests are limited to 10,000 entries, 16 MiB per source object/file and
64 MiB of retained file payloads. Aggregate job materialization is limited to
256 MiB of replicated payloads and 100,000 replicated manifest entries. Native
fetch accounting additionally limits source reads. Symlink materialization,
gitlink materialization, and unsupported host paths refuse before execution.

The process adapter runs `/bin/sh -eu -c` with `PATH=/usr/bin:/bin`, `LANG=C`, and
no inherited environment variables. Tools must be installed in that profile or
named explicitly in trusted scripts. Captures are private, file-backed streams;
the retained-output bounds are **not** enforced OS disk/CPU/memory/network quotas.
A killed/reaped direct child is not proof that all descendants are gone.

## Results and interrupted attempts

The create-only `workflow-<run-id>` directory contains a synced `attempt.json`
before the first process starts. It binds the source head/RCR, native commit and
tree, workflow blob, exact declared inputs, run identity, compiled-graph/source
commitments, runner profile, and execution limits.

After execution and close/explicit containment, `report.json` is written and
synced, installed without replacement using a hard link, then the directory is
synced. Successful cleanup normally leaves only `attempt.json` and `report.json`.
A timeout/signal/cancellation that cannot establish descendant quiescence retains
job directories and captures with the result explicitly marked non-green.

An occupied run directory refuses on every invocation, including in a fresh
process. A missing or incomplete report means **unknown execution progress**,
not permission to rerun. Inspect the marker, retained workspaces/captures, and any
external effects before deciding on a new attempt. There is no automatic resume,
exactly-once external-effect guarantee, signed report, or distributed journal.
A trusted script runs as the same host user and can tamper with local records;
these files are operational observations, not independent attestation.

The CLI attempts explicit node shutdown before emitting a single JSON stdout
record with `type: workflow_result`. Its `run` field is the persisted node result;
`node_closed` and `node_cleanup_error` independently describe the later node
shutdown. Tool output is lossless hexadecimal, never raw terminal control bytes.
Exit codes are:

| Exit | Meaning |
|---|---|
| 0 | All jobs succeeded, their workspaces closed, and node shutdown completed. |
| 1 | A complete non-green execution report exists and node shutdown completed. |
| 2 | Input/infrastructure/output/node-cleanup failure; inspect any existing attempt before retrying. |

A completed result is not erased by a later shutdown or stdout failure. A caller
with a lost response should inspect `report.json`, not resubmit execution.

## Verification scope

`crates/fgit-node/tests/trusted_workflow.rs` exercises real native source import,
real child execution, per-job copies, ordered steps, failure/skip behavior,
preflight refusals, replay refusal after reopen, and retained timeout cleanup.
`crates/fgit-cli/tests/workflow_run.rs` invokes the actual `fg` binary against
SHA-1/SHA-256 nodes and checks receipt persistence, exit codes, required explicit
trust, replay refusal, and unchanged repository authority.

```sh
cargo test --locked -p fgit-runner --test workflow_execution
cargo test --locked -p fgit-node --test trusted_workflow
cargo test --locked -p fgit-cli --bin fg workflow_command::
cargo test --locked -p fgit-cli --test workflow_run
```

The implementation-session environment had no Rust compiler/Cargo/rustfmt.
These new tests and full repository gates were **not executed** there. The
commands above identify the required checks, not a passing result or release
certificate. No hosted or hostile-code readiness is claimed.

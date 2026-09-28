# Explicit event-matched workflow dispatch

`fg workflow dispatch` discovers and executes matching workflow definitions from
one canonical source snapshot. It is an explicitly trusted local-owner command,
not an unattended push listener, remote CI endpoint, or hostile-code sandbox.
The operator must review and trust every selected script with host-user powers.

## Invoke one pinned batch

```sh
fg workflow dispatch "$STORAGE" "$TENANT" "$REPOSITORY" refs/heads/topic \
  --trusted-local --event push \
  --workflow .github/workflows --input .github --input src \
  --run-parent /absolute/private/runs --run-id "$BATCH_ID" \
  --expected-head "$SNAPSHOT_TOKEN" --expected-commit "$SOURCE_COMMIT" \
  --object-format sha1
```

The run parent must already exist as a nonsymlink directory with mode 0700.
`BATCH_ID` is a nonzero 128-bit identifier in 32 lowercase hex digits. The exact
head and commit pins are mandatory; the head token uses the existing
algorithm-qualified snapshot-token syntax. SHA-256 repositories use
`--object-format sha256` and their native commit widths. An optional
`--expected-incarnation` further constrains repository selection.

Unlike `workflow run`, the `--workflow` argument names a **directory**. Only its
direct `.yml` and `.yaml` children are definitions; nested files and other
extensions are not discovered. The existing byte-valued `--workflow-hex`,
`--input-hex`, and `--ref-hex` forms remain available. Inputs must be distinct
top-level names and include the workflow directory's top-level prefix. They
select copied files, not the process's host-access permissions.

`--event` accepts `push` or `workflow_dispatch`. It is the local operator's
matching key, **not proof that a push was admitted**. Every discovered definition
is compiled through the native workflow compiler before any batch directory or
job is created. Unsupported YAML, runner labels, expressions, or trigger filters
refuse the complete preflight instead of silently selecting a weaker meaning.
Definitions whose compiled `on` list contains the selected event execute in raw
path-byte order. Their jobs retain the existing dependency and step semantics.

## One source and one finite execution envelope

The node opens one authenticated source snapshot and constructs one immutable
manifest. Every workflow reads that same manifest; a later workflow cannot pick
up a different branch tip or a predecessor's edited workspace. Each started job
still gets its own private copied workspace through the existing native runner.

A dispatch admits at most 32 definitions, 1 MiB of workflow text, 128 selected
jobs, and 512 selected steps. Aggregate job copies retain the existing 256 MiB
payload and 100,000-entry limits. The CLI uses one shared 600-second execution
budget and 16 MiB captured-output allowance, with the existing 60-second step
and 256 KiB per-stream limits. Definition discovery consumes the time budget;
completing a workflow does not replenish time or captured-output allowance.
These are bounded execution/capture policies, not OS-level hostile-code quotas.

Ordinary command failure does not suppress unrelated workflows. Cancellation,
timeout, output-limit failure, infrastructure refusal, or unproved containment
stops subsequent workflows. Already acquired execution and cleanup obligations
remain with the existing runner. Partial batch execution is not rolled back.

## Durable plan, child recovery, and publication

Before any process starts, the command exclusively creates
`dispatch-<batch-id>/dispatch.json` and synchronizes the manifest and parent
directories. The manifest binds the source coordinates, repository incarnation,
event-selection provenance, input prefixes, workflow blobs/graphs, and derived
child IDs. Each child ID is a domain-separated hash of the full batch identifier,
event, and raw workflow path; zero or colliding child IDs refuse preflight.

A selected child then uses the existing layout inside that batch:

```text
 dispatch-<batch-id>/
   dispatch.json
   report.json                         # after a completed/stopped batch
   workflow-<derived-child-id>/
     attempt.json
     execution.owner
     check-proposals.journal
     report.json                       # after this child's execution/close
```

An occupied batch ID **always refuses**, even when it has no final report or no
child has visibly started. A missing final report does not establish that no
script ran. Keep the original batch and reconcile its child journals; do not
delete it or change the batch ID just to evade the execution fence. This command
does not implement batch resume or implicit child replay.

Completed child directories are ordinary inputs to the existing
`fg workflow recover` and `fg workflow publish` commands. Use the original child's
marker/journal identity and exact completed fact. Dispatch does not acknowledge
or consume their custody, publish repository refs, or create a canonical check.
Publication remains a separate explicit action and retains its idempotent retry
semantics. Local successful observations remain `ActionRequired`, not an
independently authorized green check.

## Results and limits of the claim

Stdout is one `workflow_dispatch_result` JSON line after explicit node shutdown.
It contains the durable plan and child reports, exact matched/executed counts,
a stop reason when present, and node-cleanup status. Raw paths and tool output
use hexadecimal encoding. A zero-match batch explicitly reports zero runs and
never manufactures check authority; its successful local exit means only that
selection completed without work.

Exit 0 means the selected runs succeeded (possibly zero); exit 1 means a
non-green or stopped report; exit 2 means invalid input, infrastructure failure,
receipt-output failure, or node-close failure. After output loss, the saved batch
and child reports remain the recovery path; rerunning dispatch is not a way to
retrieve the report. An infrastructure error can follow real execution.

## Verification

```sh
cargo test --locked -p fgit-cli --bin fg workflow_command::dispatch::tests
cargo test --locked -p fgit-node --lib durable::dispatch::tests
cargo test --locked -p fgit-cli --test workflow_publication
python3 scripts/e2e/workflow_dispatch_smoke.py --fg /absolute/path/to/fg
```

The actual-binary campaign includes both native object formats, raw-byte workflow
names, trigger selection, immutable fresh inputs, independent failure, complete
preflight refusals, occupied batches, receipt-output loss, child recovery,
canonical observation publication, and exact publication retries. It is part of
the existing Cargo integration target, not a new automatic GitHub workflow.

`--self-test` checks independent fixture framing and damaged-report detection
only; it never executes Rust. The implementation environment lacked a Rust
compiler: native formatting, compilation, and execution require the commands
above. Fixture/checker passes are not a substitute for those results.

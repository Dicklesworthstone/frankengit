# Publish watched workflow observations

`scripts/fg_workflow_checks.mjs` connects the trusted branch watcher to the
existing Rust `fg workflow recover` and `fg workflow publish` commands. A
completed local job can now reach the repository's canonical workflow-check
stream without an operator manually copying its journal, batch and fact selectors.
The existing PR checks API/browser can display those observations for the matching
recorded source ref and commit. Its existing source-freshness rules still apply.

This is an external **trusted-local Linux operator**, not another Git engine,
workflow executor, check authority, or hostile-code sandbox. The Rust node still
verifies original custody and evidence, selects repository authority, decides
admission and publishes the observation and outbox obligation. This tool never
runs a workflow, changes a ref, acknowledges the proposal journal or grants merge
permission. It requires Node.js 22 or later and the native `fg` executable.

## Run the execution-to-publication loop

Configure the branch watcher as described in [TRUSTED_WORKFLOW_WATCH.md](TRUSTED_WORKFLOW_WATCH.md).
Keep that configuration unchanged: it selects the native binary, store,
repository incarnation, object format, ref bytes, inputs, execution directories
and trusted-host profile. Every selected revision must be trusted with the host
user's privileges. Use a dedicated operator account.

Create a separate, initially empty, owner-private 0700 publication directory.
It must not overlap the watcher state, native store, run parent or executable.
Choose the original local publisher's 32-character lowercase hexadecimal principal
ID explicitly. This is the native trusted-local actor selection, not a remote
bearer token or an account-enrolment mechanism.

Run the watcher and publisher as separate foreground services under the same
trusted operator, with separate owner locks:

```sh
node scripts/fg_workflow_watch.mjs serve \
  --config /srv/watch.json --trusted-local \
  --poll-millis 1000 --max-polls 86400
```

```sh
node scripts/fg_workflow_checks.mjs serve \
  --watch-config /srv/watch.json \
  --state /srv/workflow-publication \
  --principal-id 55555555555555555555555555555555 \
  --trusted-local --poll-millis 1000 --max-polls 86400 \
  --max-publications 128
```

Replace the example paths and principal with the actual deployment. Invoking
`serve` explicitly authorizes publication of matching completed observations as
that local principal. It does not authorize arbitrary new workflow execution.
The publisher can also be invoked once after execution:

```sh
node scripts/fg_workflow_checks.mjs once \
  --watch-config /srv/watch.json --state /srv/workflow-publication \
  --principal-id 55555555555555555555555555555555 --trusted-local
```

The publisher reads completed watcher records only. Queued or uncertain execution
is not treated as complete. A safely stopped dispatch can contribute observations
for its settled, executed children; selected but unstarted workflows produce no
synthetic checks. A dispatch with no matching definitions produces no check.

## Exact preparation and publication

Before its first publication for a watched run, the operator verifies the saved
watcher intent and completion against the original native dispatch report. It
matches each executed child's original `attempt.json` to the selected source,
workflow and empty execution plan. The exact raw marker SHA-256 becomes the
retained native journal ID.

The existing native recovery command enumerates the saved proposal history.
Pagination carries one exact journal snapshot, including already acknowledged
batches. Every completed job must have exactly one matching completed fact with
its evidence commitment. Source, authority basis, graph, execution limits,
trust domain, run and attempt identities remain fixed.

A complete private publication plan is synced before any job is submitted. It
retains every job's original directory, marker digest, minimum journal pin,
batch digest, fact index, evidence digest, source commit and stable publication
key. The publisher then syncs a per-job start record **before** launching native
publication. Finishing or restarting the operator never regenerates these keys.

The native publisher validates the selected saved evidence and performs its own
admission. A new observation must describe the branch's current source commit.
Source movement can therefore cause a canonical refusal. An identical retry can
recover its historical decision after source movement; the operator never edits
an old request to make it fit a new tip.

## Published conclusions and authority

| Actual native job outcome | Published conclusion |
| --- | --- |
| Succeeded, with original evidence verified by the native publisher | `success` |
| Skipped | `action_required` |
| Failed, refused or output limit | `failure` |
| Cancelled | `cancelled` |
| Timed out | `timed_out` |

The native custody journal still reports `action_required` for succeeded and
skipped jobs. The operator checks that original proposal separately from the
published conclusion: only the native verifier can establish that its retained
evidence describes a succeeded job and publish `success`. It preserves the
original journal bytes, exact job identity and publication key.

`success` describes the verified trusted-local job outcome. It is not independent
runner attestation or merge authority. A committed publication records the
observation; external delivery and protected-branch policy are separate
boundaries. Required-check enforcement and hostile runner attestation remain
incomplete. An old pending publication plan that called a succeeded job
`action_required` cannot be silently reinterpreted or assigned a new key after an
upgrade; use the original key's outcome recovery to resolve any prior publication.

## Restart and uncertain publication

A valid committed or refused terminal is saved before the next job starts.
Already retained terminals are not resubmitted during ordinary polling. If a
reply is lost or malformed after the start record, automatic publication stops.
Status remains available without the native executable or source store:

```sh
node scripts/fg_workflow_checks.mjs status \
  --watch-config /srv/watch.json --state /srv/workflow-publication \
  --principal-id 55555555555555555555555555555555 --trusted-local
```

`status` is a read-only historical view of local custody, not a fresh canonical
outcome lookup. An absent terminal does not prove non-commit. Resume explicitly:

```sh
node scripts/fg_workflow_checks.mjs resume \
  --watch-config /srv/watch.json --state /srv/workflow-publication \
  --principal-id 55555555555555555555555555555555 --trusted-local
```

`resume` processes only saved plans. It can send a previously unsent planned job
or retry an uncertain original publication through the native exact-key path.
It does not rediscover another run, refresh journal pins or rerun any workflow.
Original native markers, journals and referenced evidence must remain available.
The original principal and watcher/publication configuration must remain stable.
Changing them cannot silently create another retry namespace.

A multi-job publication is not atomic: earlier jobs may be committed while later
jobs remain unsent, unknown or refused. Status retains these distinctions. A
known canonical terminal wins over late cancellation or native cleanup failure.
Failure to save or print that terminal is reported separately; inspect retained
custody and use the original request rather than constructing a replacement.

## Ownership and limits

One exclusive owner covers discovery, publication, polling and progress output.
SIGTERM/SIGINT stop new work and drain the active native publisher. A final
watchdog enforces the selected whole-operation deadline; forced termination
retains the owner lock and makes no process-containment claim. SIGKILL can leave
the native process alive. No PID-based lock stealing or automatic lock removal
is provided. Independently reconcile the original process before operator repair.
Never delete old custody to cause a replay.

Each sweep has one 660-second cooperative deadline, at most 128 publication
calls and at most 128 jobs per plan. Each history-discovery pass is bounded to
128 pages, 1024 batches and 16 MiB of aggregate JSON. Native recovery calls are
limited to 30 seconds; native publication retains the shared remaining deadline.
The Rust publisher independently limits each selected evidence body to 1 MiB;
an oversized observation refuses rather than being reduced to a success flag.

A publication directory retains at most 128 watcher-run plans. Plans are bounded
to 1 MiB each and all custody reads to 32 MiB. Admission of a new plan reserves
room for its worst-case start and terminal records inside that same 32 MiB
ceiling. Large plans can therefore reach capacity before the run-count limit.
No history is evicted. These are allocation/metadata bounds, not an OS disk quota
or a guarantee against storage failure. Parent directories must remain stable
and operator-owned; hostile same-UID replacement is outside this local profile.

`serve` defaults to one-second polls and at most one million polls. Any recovery,
custody, publication or output error stops it; only another explicit command can
retry an uncertain submission. Output is NDJSON: a progress row for each observed
terminal followed by a final run/service summary. CLI writes have a ten-second
bound and a 4 MiB per-row ceiling.

Exit 0 means selected publications are committed, or there was no selected work;
1 means at least one retained canonical refusal; 2 means input or read failure;
3 means pending/unknown publication or a reached publication-work limit;
4 means a terminal or complete operation was observed but local cleanup/output
failed. No exit code independently authorizes a merge.

## Verification boundary

```sh
node --test tests/operator/workflow_watch.test.mjs \
  tests/operator/workflow_check_publish.test.mjs
```

The tests execute the real operator modules with private files, spawned CLI
processes, exact-key restart, multiple jobs, paginated history, both native hash
formats, full-width decision counters, cancellation, concurrency and output
failure. Their native executable peers are explicitly **contract fixtures**, not
Rust `fg`. They do not establish real-node Git selection, evidence decoding,
authorization/CAS, hardware power-loss, live deployment or a full-workspace pass.
The broader `frankengit-root-doctrine-x2mv.4.12` CI product loop remains partial.

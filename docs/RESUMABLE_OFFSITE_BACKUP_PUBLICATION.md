# Resumable offsite backup publication

Related bead: `frankengit-root-doctrine-x2mv.4.21` remains partial.
Comprehensive plan: §21.8, independently retained recovery copies.

The upload job preserves a private local copy of one authenticated archive and
its original approval before publishing an immutable intent. Each explicit run
publishes that exact checkpoint to the sealed set of HTTPS destinations. A run
can resume after losing the original source files, expiring URL capabilities,
an interrupted upload or a lost result stream.

This composes the existing [signed replica publisher](SIGNED_BACKUP_REPLICA_PUBLICATION.md)
and [conditional HTTPS uploader](SIGNED_BACKUP_HTTPS_PUBLICATION.md). The
[local replica job](RESUMABLE_BACKUP_JOBS.md) serves a separate filesystem
replenishment workflow.

## Private custody and independent inputs

Choose an existing directory owned by the current user with no group or other
permissions, for example mode `0700`. Keep it on storage whose retention policy
matches the required lifetime of the job. Retained files must be private regular
files with one link. The job holds open descriptors and checks named/opened
identity, ownership and metadata. Stable owner-controlled parents and POSIX
no-follow opens, hard links and file/directory synchronization are required;
these checks do not isolate malicious same-user writers.

Supply the public Ed25519 trust key and complete repository policy independently
on **both seal and every run**. The trust key and any TLS CA file must be outside
the job directory. Seal's input archive and approval must also be outside it.
A run may use a different path to the same trusted public key, but the trusted
key identity and original approval bytes must match the sealed checkpoint.
A later attempt may independently select fresh CA files and paths; they are not
sealed destination identities. During a run, the trust key and any selected CA
files remain held and checked. Substituting a CA between targets refuses before
further publication.

The policy contains `tenant_id`, `repository_id`, `incarnation_id`,
`object_format` (`sha1` or `sha256`) and `minimum_head_generation`. The namespace
and object format must match the sealed policy. A run may strengthen the
generation floor, never weaken it. The original signature, validity interval,
archive digest and length remain mandatory. A stronger floor that the retained
checkpoint does not satisfy refuses before remote work.

The explicit `--trusted-local` flag acknowledges selection of an owner-controlled
local job. The intent's content hash detects changes to its exact bytes; it does
not authorize an untrusted intent or grant authority to choose destinations.
Archive signatures do not supply endpoint authorization or global freshness.

## Select one to sixteen destinations

Create one private, singly linked JSON capability file per destination, at most
16 KiB each:

```json
{
  "archive": {
    "get": "https://storage.example/backups/checkpoint/archive?get-capability=...",
    "put": "https://storage.example/backups/checkpoint/archive?put-capability=..."
  },
  "approval": {
    "get": "https://storage.example/backups/checkpoint/approval?get-capability=...",
    "put": "https://storage.example/backups/checkpoint/approval?put-capability=..."
  }
}
```

GET and PUT for each object must have the same HTTPS origin and path. Their query
strings may differ. Every archive and approval object must be distinct across
the whole destination set. The job binds hashes of each normalized origin/path
pair, with targets sorted by their logical target IDs. Reordering the same set
is permitted; adding, removing or substituting an object is refused.

Capabilities are supplied afresh on every run. Query strings may be renewed
without resealing, provided the origin and path remain identical. This assumes
the service identifies its objects by origin and path: query parameters must
not select a different object. The intent and job receipts contain logical
target hashes, not the signed URLs or their query capabilities.

The service must support conditional `PUT` with `If-None-Match: *`,
`Expect: 100-continue` and exact `GET` readback. The existing uploader's TLS,
status, response-size and timeout rules apply. There is no redirect following,
insecure TLS mode, implicit overwrite, remote delete or automatic retry of an
uncertain PUT. An optional independent CA file supplies trust for private
services; hostname verification remains enabled.

## Seal the retained pair, then run the exact intent

For two destinations, seal with:

```sh
node scripts/repository_backup_upload_job.mjs seal --trusted-local \
  --job-directory /private/offsite-job \
  --input /source/repository.fgbackup \
  --approval /source/repository.approval.json \
  --trust-key /independent/operator-ed25519.pub \
  --target /private/store-a-capabilities.json \
  --target /private/store-b-capabilities.json \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --max-archive-bytes 1073741824 --max-total-bytes 3221225472 \
  --timeout-secs 300 --progress-json
```

Seal performs no network access. It authenticates the supplied approval and
retains the exact archive and original envelope through the existing verified
replica publisher. The files are named
`archive-sha256-<artifact-digest>.fgbackup` and
`checkpoint-sha256-<approval-digest>.approval.json`. Only after that pair is
retained does it publish `upload-job-sha256-<intent-digest>.json` using create-only
publication, exact readback and file/directory synchronization. An exact seal
retry verifies and synchronizes existing matching material without overwriting
it. Failures do not delete retained material.

Save the successful result's **`job.intent`** path. The intent binds the exact
checkpoint, signed statement, sealed policy, logical destination set and job
directory's canonical path/device/inode. Moving the job to another directory,
replacing its directory, editing its bytes or renaming its intent is not a
supported resume mechanism. To select a different checkpoint or destination
set, explicitly seal a new job from independently authenticated usable inputs.

Once seal has completed, the original source archive and approval paths are no
longer needed. Keep the retained pair and intent together. Run with the exact
returned intent and the same logical destinations:

```sh
node scripts/repository_backup_upload_job.mjs run --trusted-local \
  --intent "$EXACT_RETURNED_INTENT_PATH" \
  --trust-key /independent/operator-ed25519.pub \
  --target /private/store-a-capabilities.json \
  --target /private/store-b-capabilities.json \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --max-archive-bytes 1073741824 --max-total-bytes 6442450944 \
  --timeout-secs 300 --progress-json
```

Both commands optionally accept `--ca-file CERTIFICATE_PEM`, which applies to
all CLI destinations. `seal` requires `--job-directory`, `--input` and
`--approval`; `run` instead requires `--intent` and rejects those three options.
Neither command accepts a replacement checkpoint pin or a signing key.
`--help` performs no job, trust-file or network access.

Each run authenticates the retained approval against the freshly supplied key
and policy, checks the exact sealed statement/checkpoint and destination set,
and verifies the retained archive's bytes before remote access. Destinations
run sequentially. For each one, the uploader checks the existing approval and
archive with GET. A missing archive is conditionally published and read back
against the signed length/digest before the approval can be published.
Approval readback is repeated at the end, including exact reruns.

An existing approval with a missing archive refuses rather than repairing a
dependency under an already visible root. Conflicting remote bytes are never
overwritten. Exact existing objects can be reused after readback. A previous
successful job receipt is never used to skip these checks.

## Partial completion and explicit restart

Exit 0 returns a JSON seal or run result on stdout. `--progress-json` emits
redacted milestones on stderr. A sealed result has
`type: "repository_backup_upload_job_sealed"`, `state: "complete"`, the `job`
report, `snapshot`, `source_custody_retained: true` and `network_accessed: false`.
The job report contains its exact intent path/digest, checkpoint equality pins,
artifact length/digest and logical target IDs.

A successful run has `type: "repository_backup_upload_job_run"`,
`state: "complete"`, `completed_targets`, aggregate `streaming` accounting and
`remote_readback_verified: true`. Each target entry retains the sanitized child
receipt and its logical `target_id`. This records what was verified during
this attempt; it is not a mutable durable completion index.

Exit 1 means refusal, incomplete work or a reporting/cleanup failure after an
effect. It does **not** prove rollback. Structured error output includes `job`,
`upload_job` when available, `publication_state`, cleanup information and any
confirmed `completed_result`. The `upload_job` record retains completed target
receipts, the target active at failure and aggregate bytes charged so far.
`archive_put_unknown` and `approval_put_unknown` preserve uncertainty about
attempted writes. A target completed before a later target failed remains
represented as completed.

Keep the same intent and retained pair after interruption or lost stdout.
Refresh expired query capabilities if necessary, supply independent trust and
policy again, and explicitly run the same intent. Every target is checked again
through actual GETs, including targets reported complete by an earlier attempt.
Execution stops on the first failure. There is no automatic retry, remote cleanup
or rollback. A hard kill may leave
remote effects and private staging material; later runs do not infer failure
from missing receipts or claim/delete abandoned staging files.

SIGINT/SIGTERM request cancellation and drain the owned upload resources and
local descriptors. Closure on the client does not prove a remote handler has
finished its own work. A late cancellation, failed progress callback, broken
final output pipe or descriptor-close failure cannot erase already confirmed
completion. In that case inspect `completed_result` as well as the exit status.
Arbitrary progress/output consumers must make progress; the job does not
preempt a stalled caller callback.

## Limits and library API

Limits are fresh **per attempt**, not a durable cumulative allowance across
restarts. Archive payloads use bounded 64 KiB streaming buffers.

| Limit | Behavior |
|---|---|
| Destinations | 1–16 distinct archive/approval pairs |
| Archive ceiling | `--max-archive-bytes`: default 1 GiB; maximum 1 TiB |
| Aggregate payload allowance | `--max-total-bytes`: maximum 48 TiB; does not enlarge the archive ceiling |
| Default seal allowance | Three times the configured archive ceiling |
| Default run allowance | Three times the configured archive ceiling, multiplied by destination count |
| Deadline | `--timeout-secs`: default 300; 1–3600, shared across control intake and all targets |
| Intent and approval | Each at most 16 KiB |
| Target URL text | At most 256 KiB across all captured destinations, with the uploader's per-target bounds |

For an N-byte archive, seal reserves 3N archive-payload work for retaining its
local pair. A run reserves **3N for every destination before its first remote
request**: N initial local hashing bytes, N upload-source bytes and N remote
archive-readback bytes per fresh publication. An exact existing target consumes
2N but retains the same conservative 3N reservation. Thus two selected targets
need a 6N run allowance even if one target completed on a previous attempt.
Targets share one aggregate allowance and the remaining operation deadline.
Approval/key reads, bounded HTTP status bodies, framing and EOF probes are
accounted separately by the existing bounded primitives.

The ES module at `scripts/lib/repository-backup-upload-job.mjs` exports:

- `repositoryBackupUploadJobOptions(raw, mode)`, a parameter-only, closed-shape
  validator/capture function for mode `"seal"` or `"run"`;
- `sealRepositoryBackupUploadJob(options)`;
- `runRepositoryBackupUploadJob(options)`;
- `BACKUP_UPLOAD_JOB_TYPE`, `MAX_BACKUP_UPLOAD_TARGETS` and
  `MAX_BACKUP_UPLOAD_TOTAL_BYTES`.

Both operation functions accept `trustedLocal: true`, `trustKey`, `policy` and
`targets`. Each target row has `{ target }` or `{ target, caFile }`, where
`target` is the archive/approval GET/PUT object shown above. Unlike the CLI's
single CA option, library rows can select independent CA files per destination.

Seal additionally requires `jobDirectory`, `input` and `approval`; run requires
`intent`. Optional fields are `maximumBytes`, `maximumTotalBytes`, `timeoutMs`,
`signal` (`AbortSignal`), `onProgress` (an optionally asynchronous callback) and
`now` (a fixed epoch-millisecond validity clock for deterministic callers/tests;
omit it to use current wall time). The deadline uses a monotonic clock.
Unknown options and inapplicable operation fields refuse.

For example, with independently loaded `policy`, `targetA` and `targetB`:

```js
import {
  sealRepositoryBackupUploadJob,
  runRepositoryBackupUploadJob,
} from "./scripts/lib/repository-backup-upload-job.mjs";

const common = {
  trustedLocal: true,
  trustKey: "/independent/operator-ed25519.pub",
  policy,
  targets: [{ target: targetA }, { target: targetB }],
  maximumBytes: 1024 ** 3,
  timeoutMs: 300_000,
};
const sealed = await sealRepositoryBackupUploadJob({
  ...common,
  jobDirectory: "/private/offsite-job",
  input: "/source/repository.fgbackup",
  approval: "/source/repository.approval.json",
});
// A later process supplies trust, policy and fresh capabilities independently.
const result = await runRepositoryBackupUploadJob({
  ...common,
  intent: sealed.job.intent,
});
```

## Verification meaning

Success establishes signed-byte equality and exact HTTPS readback at each
destination during a sequential attempt. It does not establish simultaneous
availability, provider retention, durable physical storage or independent
failure domains. Local sync acknowledgments are not a hardware-power-loss
proof. This job neither parses native archive/forge semantics nor restores
canonical repository state. Native verification remains necessary before
restore.

The job does not maintain or consult a newest-checkpoint witness. The sealed
checkpoint and independently supplied floor prevent substitution or weakening
within this job; they do not prove that the checkpoint is globally newest.
There is no `--witness` option or witness-based rollback protection in this
publication command.

Focused library and CLI coverage is in:

```sh
node --test --test-concurrency=1 \
  scripts/tests/repository-backup-upload-job.test.mjs \
  scripts/tests/repository-backup-upload-job-cli.test.mjs
```

These suites use real local files, Ed25519 approvals and loopback HTTPS object
services to exercise retained-source restart, refreshed capabilities, partial
remote effects, resource limits, cancellation and truthful completion receipts.
Their payloads are opaque operator test bytes. Native archive verification,
public-provider interoperability, Rust/full-workspace acceptance and hardware
faults require separate evidence.

# Resumable signed-backup jobs

Related bead: `frankengit-root-doctrine-x2mv.4.21` (partial, not closed).
Comprehensive plan: §21.4 (unpublished-work recovery), §21.6 (verified recovery
materials) and §21.8 (independently retained recovery copies).

[Replenishment](SIGNED_BACKUP_REPLENISHMENT.md) can replace lost redundancy, but
an interrupted operator also needs its original intent and approval after the
source or result stream disappears. A job preserves those controls **before
copying**. Each run verifies actual surviving bytes instead of trusting a saved
success flag. It composes the existing selector, replica publisher, replenisher
and final scrub; it is not a native archive parser or repository authority.

## Seal once, run the same intent

Choose an existing owner-private job directory, separate from replica locations
and the independently managed trust key. All destination directories must also
already exist and be owner-private. For example:

```sh
node scripts/repository_backup_job.mjs seal --trusted-local \
  --job-directory /private/recovery-jobs \
  --candidate /source/repository.backup /source/repository.approval \
  --replica-directory /backup-a/repository \
  --replica-directory /backup-b/repository \
  --trust-key /trusted/operator-ed25519.pub \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION"
```

The JSON result's `intent` field is the exact content-addressed path to retain.
Sealing authenticates all supplied approvals and selects the highest uniquely
signed checkpoint. It preserves the **original signed envelope bytes** under
`checkpoint-sha256-<digest>.approval.json`, then publishes the canonical immutable
`job-sha256-<digest>.json` intent last. Both use create-only publication, readback
and file/directory synchronization. An exact seal retry verifies and synchronizes
matching controls without rewriting them. Seal creates no archive replicas.

```sh
node scripts/repository_backup_job.mjs run --trusted-local \
  --intent "$EXACT_RETURNED_INTENT_PATH" \
  --trust-key /trusted/operator-ed25519.pub \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --max-archive-bytes 1073741824 --max-total-read-bytes 9663676416 \
  --timeout-secs 300 --progress-json
```

Run does not accept destination, source, approval or checkpoint overrides. It
requires an independently supplied key and policy on every attempt. The namespace
must match and the policy floor may be strengthened, never weakened below the
sealed floor. Signature, validity interval, archive hash and length remain
mandatory checks. No signing key, re-signing or expiry bypass is provided.

The intent binds the original checkpoint, signed statement, selected source
payload paths, sorted destination paths and their device/inode identities, and
any witness selected at sealing. Its content hash detects alteration of that
exact file; **it does not authorize executing an untrusted job**. The explicit
`--trusted-local` selection and private, owner-controlled storage are required.
The archive signature alone does not authorize filesystem destinations.

## Recover after source loss or process death

Each run considers only the sealed highest-checkpoint source payload paths and
the exact content-addressed archive paths in its designated destinations. These
candidates all use the preserved original approval. Missing or damaged source
payloads can fail over to a surviving verified output of the same checkpoint.
Once a replica completes, the next publisher uses it as its source and still
reauthenticates the exact envelope/key pin and every archive byte. Ordinary
replenishment retains its old source behavior unless `sourceHandoff` is explicitly
enabled; the job runner enables it internally.

The original source approval can be lost even before any copy completes. Loss of
all source payloads requires at least one intact designated output; a saved job
cannot reconstruct bytes that no candidate retains. Missing or corrupt intent or
preserved approval refuses: run never reseals, regenerates trust, scans directories
for a latest job, or follows arbitrary source paths from an output receipt.

Matching outputs are read back and synchronized without rewriting their inode.
A corrupt existing output is not overwritten or deleted. Changed destination
identities refuse instead of silently redirecting a job into a replacement
folder. To change destinations, explicitly seal a new intent from usable inputs.
Final success still requires a complete output scrub, original approval pins and
a distinct verified file at every designated location. This is a sequential
check, not a simultaneous snapshot or independent-failure-domain proof.

There is no mutable job-completion index or job-owned lock. Two attempts may
encounter each other's create-only publications; a winner's actual bytes must be
verified before reuse. A hard process kill can leave private staging files, which
later runs neither claim nor delete. Re-run the same intent after ordinary errors
or an unwitnessed process kill; there is no automatic retry within the command.

## Required checkpoint witness

Append `--witness DIRECTORY` to both commands to use an already initialized
[checkpoint witness](RECOVERY_CHECKPOINT_WITNESS.md). The CLI holds its exclusive
lease through authentication, copying, final verification and descriptor cleanup.
A witness bound at seal time cannot be omitted or replaced by another empty
witness on run. Higher or conflicting signed evidence continues to block older
jobs even when the higher artifact has disappeared. Signed observations are
retained before current expiry, stricter-floor or narrower-size refusals.

An initially unwitnessed job may use an additional witness for an attempt; this
does not rewrite its immutable intent into a permanently witness-bound job.
Normal cancellation drains and releases ownership. A killed witnessed owner
leaves its lease blocking. There is no PID/age heuristic, automatic lock stealing,
state reset or unwitnessed bypass for a witness-bound job. An operator must follow
the witness's separate recovery procedures rather than weaken this boundary.

## Results, resources and applicability

Exit 0 returns a sealed-intent receipt or a fully checked run result. Exit 1 is
refusal or incomplete work, **not rollback**. Error JSON retains the job,
`replenishment.completed_replicas`, active publication state, cleanup information
and any confirmed `completed_result`. A broken final stdout pipe does not erase
the completed result. `--progress-json` emits one seal milestone or at most 17 run
milestones on stderr: the pinned checkpoint and each completed destination.
Progress/output consumers must make progress; arbitrary observers are not
preempted. SIGINT/SIGTERM request cancellation and owned-descriptor drain.

The combined sealed source/output set is limited to 64 candidate paths and 16
destinations. Canonical intent and approval files each have a 16 KiB limit.
The archive ceiling is at most 1 TiB; the aggregate per-attempt payload allowance
is at most 128 TiB. Existing archive scanning/copying uses 64 KiB buffers, with
small control reads and bounded EOF probes accounted separately. One monotonic
deadline spans witness ownership and the operation. Limits are freshly supplied
**per attempt**, not a durable cumulative budget across all restarts.

For two fresh destinations and a healthy N-byte source, run consumes 9N payload
bytes; 9N-1 refuses before publication. Reusing both outputs reads 7N but retains
the conservative 9N upfront reservation. Corrupt candidate reads consume the same
attempt budget, and a larger aggregate budget never raises the archive ceiling.
Seal's initial selection is a separate bounded operation.

This is trusted-local POSIX operator functionality requiring private, stable
owner-controlled parents, no-follow opens, hard links and file/directory sync.
Named/opened identity checks do not isolate malicious same-user writers. Sync
acknowledgments are not a hardware-power-loss proof. The job does not launch `fg`,
verify native archive semantics, reconstruct forge state, change canonical
repository authority/routing, or establish global newest-checkpoint knowledge.
Native verification remains mandatory before restore; the broader recovery bead
is not completed by this operator feature.

## Focused verification

```sh
node --test --test-concurrency=1 \
  scripts/tests/repository-backup-replication.test.mjs \
  scripts/tests/repository-backup-handoff.test.mjs \
  scripts/tests/repository-backup-job.test.mjs \
  scripts/tests/repository-backup-job-witness.test.mjs \
  scripts/tests/repository-backup-job-cli.test.mjs
```

Tests use real files and Ed25519, actual CLI subprocesses, SIGTERM drain, SIGKILL
with child reaping, exact restart after original source/control deletion, the
real persisted witness, and broken output pipes. Payloads are opaque operator
test bytes, not native `fg` archives. Rust compilation, full-workspace gates,
native restore and hardware faults require separate evidence.

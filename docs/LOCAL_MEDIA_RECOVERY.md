# Signed-native recovery from local backup media

Related bead: `frankengit-root-doctrine-x2mv.4.21` remains partial.
This is an acquisition mode of [the existing recovery command](OFFSITE_NATIVE_RECOVERY.md),
not a new archive parser, repository authority, or signing mechanism.

## Direct local acquisition

The integrated recovery operation previously required a populated cache, HTTPS
sources, or a chunk-reconstruction plan. An intact archive on independent local
media can now enter the same cache, signed-native preflight and explicit restore
path directly. No URL file, server, chunk catalog or manual content-addressed
cache naming is needed.

```sh
node scripts/recover_repository_backup.mjs restore \
  --input /media/backup-a/repository.fgbackup \
  --input /media/backup-b/repository.fgbackup \
  --approval /independent/repository.approval.json \
  --trust-key /independent/operator-ed25519.pub \
  --witness /independent/checkpoint-witness \
  --cache-directory /private/recovery-cache \
  --fg /absolute/path/to/fg --trusted-local --verification-instance 11 \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --destination /private/restored --destination-instance 12 \
  --approval-record /private/restore-approval.json \
  --max-archive-bytes 1073741824 --max-acquisition-bytes 4294967296
```

Use `verify` without destination/instance/approval-record options for native
preflight alone. `--input` is repeatable up to 64 times and each input claims the
same independently signed archive. The library field is `localInputs`, a
snapshotted array. The existing replica selector determines canonical pathname
ordering and permits missing/corrupt copies to yield only to another explicitly
supplied copy of that same signed artifact. Signature, policy, cancellation,
observer and unexpected I/O failures remain fatal.

In [grouped candidate mode](CHECKPOINT_SET_RECOVERY.md), `--input` belongs
to the preceding `--candidate APPROVAL_FILE`, like the existing acquisition
flags. Every candidate approval authenticates before the highest unique signed
generation is selected. Losing payloads and their parents are not read or
resolved. An unavailable newer checkpoint cannot fall back to older media, and
another candidate plan is never tried automatically. Local inputs cannot mix
with HTTPS or fragment-reconstruction inputs in the same plan.

## Ownership, readback and continuation

The existing replica publisher streams through a 64 KiB buffer, verifies the
source, copies without overwriting, rechecks the destination, synchronizes it,
and publishes original approval bytes last. Read-only source files are allowed.
Original media and conflicting cache files are never overwritten or deleted.

One independently retained witness spans acquisition, native preflight,
restore/resume, child drain and cleanup. Exact approval/key pins constrain every
handoff. All supplied approval paths remain separated from writable recovery
paths through native submission, even when their candidate lost selection.
Local source paths are also checked against witness, cache and native outputs
before acquisition and after exposed payload/handoff observers.

Missing local media directories are projected through their existing ancestors
for separation checks so an absent copy need not block an available one.
An existing dangling symlink is not guessed to be an absent mount and refuses.
Stable owner-controlled ancestors are required; these checks are not isolation
from arbitrary same-user filesystem mutation or malicious administrators.

A fresh N-byte local copy needs 3N payload work: source authentication, copying,
and destination readback. 3N-1 refuses before local payload callbacks or cache
staging. A full corrupt copy followed by a healthy copy needs 4N. Failed reads
consume the same budget; native-engine reads and bounded control-file reads
retain their separate limits. The existing publisher's aggregate ceiling is
4 TiB and the per-archive ceiling remains 1 TiB. These are ceilings, not guarantees
that a particular filesystem or callback completes before the deadline.

Repeated local approval-intake and unavailable-copy metadata do not invoke
external observers or rescan every local path. Payload and publication-handoff
observations still recheck the full declared path set. This avoids quadratic
metadata scans for many unavailable copies without changing signed selection.

Success reports `acquisition.mode: "local"` and the real publisher receipt.
Acquisition errors retain bounded `local_acquisition` replica attempts, selected
intent and payload counters when available. Copied bytes alone never mean native
completion. A confirmed cache receipt survives a later observer/native failure.
After media removal, omit the input flags and continue using the reauthenticated
cache. Interrupted restore still requires `--resume`, original checkpoint pins,
destination, policy and the exact original native approval record.

SIGTERM drains owned work. Killed owners leave blocking witness leases; there is
no automatic lock stealing or reset. Existing exit statuses are unchanged: 0 for
native completion and delivered output, 1 for refusal/uncertainty, 4 for observed
native completion followed by local cleanup/output failure.

## Verification scope

```sh
node --test --test-concurrency=1 --test-timeout=120000 \
  scripts/tests/repository-backup-recovery-control-paths.test.mjs \
  scripts/tests/repository-backup-recovery-local.test.mjs \
  scripts/tests/repository-backup-recovery-local-cli.test.mjs
```

The tests use actual local files, signatures and CLI/native-schema subprocesses.
Their native executable is explicitly not Rust `fg`; payloads are opaque test
bytes. They do not establish native archive/forge restoration, authority/CAS,
Rust compilation, whole-workspace acceptance, independent failure domains or
hardware power-loss survival.

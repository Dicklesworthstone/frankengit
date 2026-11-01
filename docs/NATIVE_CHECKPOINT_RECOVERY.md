# Native selection and recovery of signed source checkpoints

`fg backup verify-selected` and `fg backup recover` authenticate an explicit set
of source-backup approvals before opening any archive. They select the highest
unambiguous signed generation and run the existing native verification or restore
engine using that exact approval, archive descriptor and operation deadline.

This protects against selecting an older supplied checkpoint merely because the
newer archive is unavailable, damaged, expired or too large for the selected
budget. The independently supplied key, repository identity, generation floor
and expected archive checksum remain required. Selection proves which checkpoint
is highest **among the supplied approvals**. It cannot establish that an omitted
or unseen newer checkpoint does not exist.

An optional independently retained witness also remembers authenticated higher
checkpoints and conflicts across invocations. Initialize it explicitly with
`fg backup witness init`, then pass `--witness <directory>` to either native
selected operation. Ordinary unwitnessed commands retain their supplied-set scope.

## Verify the selected checkpoint

Supply each archive and its detached approval together. Candidate order does not
outrank signed generation:

```sh
fg backup verify-selected selected-check \
  --candidate older.fgit older.approval.json \
  --candidate newer.fgit newer.approval.json \
  --trusted-local --expected-sha256 "$NEWER_SHA256" \
  --trust-key /independent/backup-public.pem \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --incarnation-id "$INCARNATION" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --verification-instance 992 \
  --max-archive-bytes 2147483648 --max-blob-bytes 536870912 \
  --max-objects 250000 --timeout-secs 1800
```

The destination is a fresh verification scratch root. Successful preflight
checks the portable authority, exact selected Git inventory, native object
identities, original payload commitments, complete graph and selected retained
outcome evidence. The node closes and its scratch is removed before success.

## Recover the selected checkpoint

Use the same candidate and independent trust inputs with a new destination:

```sh
fg backup recover recovered-node \
  --candidate older.fgit older.approval.json \
  --candidate newer.fgit newer.approval.json \
  --trusted-local --expected-sha256 "$NEWER_SHA256" \
  --trust-key /independent/backup-public.pem \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --incarnation-id "$INCARNATION" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --destination-instance 993 \
  --max-archive-bytes 2147483648 --max-blob-bytes 536870912 \
  --max-objects 250000 --timeout-secs 1800
```

Restore uses the same quarantine, exact-intent resume, authority-last publication
and final destination readback as `fg backup restore`. The instance must differ
from the archived authority-store instance. Existing repositories are never
overwritten or rewound. An interrupted attempt can be explicitly retried with
`--resume` and the exact original selected approval, checksum, trust policy and
destination instance. The candidate list is selection input; it does not replace
the original sealed restore identity. A higher supplied approval on a later run
must still be selected, and cannot silently reinterpret an earlier restore intent.

A restore error after authority becomes visible says so. Keep the destination
and its owned recovery state for inspection or exact resume; an error does not
prove that publication was prevented.

## Selection and failure rules

1. Bound and snapshot one through 64 explicitly supplied candidate pairs. Paths
   are normalized lexically; selecting a name does not follow it as authority.
2. Read the independently trusted public key once and authenticate every supplied
   approval's signature, canonical statement, key identity and repository identity.
   Invalid lower candidates refuse the whole operation too.
3. Rank authenticated generations with exact `u64` ordering. Do not rank by
   pathname, archive availability, modification time or approval issuance time.
4. Require a unique canonical signed statement at the highest generation.
   Identical statements may describe multiple explicit copies. Distinct statements
   at that generation are ambiguous, even if their archive digests are equal.
5. Apply the winner's lifetime, independent generation floor, selected archive
   limit and independently supplied expected SHA-256. A failed eligibility check
   never falls back to a lower generation.
6. Retain the first normalized lexical `(archive, approval)` pair's original
   approval as the exact native/resume binding. By default, only that pair's
   archive is opened. With explicit `--replica-failover`, try payload copies of
   that identical highest statement in lexical order under one aggregate read
   allowance. Keep the acquired descriptor across all native checks; no other
   copy is attempted after native entry.

Authenticating a signed observation is deliberately separate from admitting it
for restore. Expired, future-dated, below-floor and currently over-budget statements
can participate in ranking; none gains publication permission by doing so. This
keeps an authentic but unusable higher statement from disappearing during intake.

All phases share one original deadline. Archive, blob, object-count and native
metadata bounds remain independent. Payload memory continues to use the existing
streaming verification and restore paths; candidate metadata is separately bounded.
The output receipt contains `selection` evidence and the directly embedded `native`
completion receipt. No child executable or receipt parser composes these commands.

## Recover from redundant copies of the same checkpoint

Add `--replica-failover` when the selected signed checkpoint has multiple explicit
copies and one may be missing, damaged or unreadable:

```sh
fg backup recover /fresh/restored-node \
  --candidate /media-a/repository.fgit /controls/original.approval.json \
  --candidate /media-b/repository.fgit /controls/replica.approval.json \
  --destination-instance 9002 --trusted-local \
  --expected-sha256 "$EXPECTED_SHA256" \
  --trust-key /independent/backup-public.pem \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --incarnation-id "$INCARNATION" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --replica-failover \
  --max-archive-bytes 2147483648 --max-read-bytes 15032385536
```

The same flags work with `verify-selected`, and can be combined with an existing
`--witness`. Every supplied approval still authenticates before payload access.
Only copies whose authenticated canonical statement is identical to the selected
highest statement may participate. An older checkpoint, a conflicting statement,
or a different archive digest cannot become a substitute.

The original selected approval remains fixed even if another payload supplies the
bytes. Independently valid envelopes with different whitespace or other permitted
outer serialization can name the same statement, but their bytes do not replace
the lexical-first approval's sealed resume binding. A later exact `--resume` may
read a different healthy copy while retaining that original approval and policy.

Missing, permission-denied, symlink, nonregular, short or wrong-checksum copies
can be recorded as unavailable or damaged. Repeated names for the same underlying
file are skipped without rereading its payload. Other I/O failures, an exhausted
read allowance, cancellation, expiry or deadline failure terminate the operation.
Once a copy matches the original whole-file checksum, malformed archive structure
or a native verification failure is terminal too: another copy of those exact
bytes cannot repair their meaning. Failover never retries a native operation or
reclassifies an uncertain restore as prevented publication.

`--max-read-bytes` is an independent aggregate allowance, available only with
`--replica-failover`. It defaults to seven times the selected archive-byte limit and
has a finite ceiling of 75,866,302,316,544 bytes (69 TiB). The ledger charges actual
bytes returned by every attempted payload and by every native archive pass.
Approval/control reads retain their separate bounds. A zero remaining allowance
does not manufacture EOF: a real zero-byte EOF probe is permitted, and any extra
byte is charged and causes a sticky refusal.

For an archive of length N, successful verification reads 3N bytes; a fresh
recovery reads 6N; readback of an already-published exact resume reads 3N. A failed
full checksum attempt adds N to those totals. Before each payload attempt, the
driver reserves enough remaining allowance for verification's 3N or recovery's
conservative 6N path; reservation does not charge bytes. Choose a larger explicit
allowance when more than one complete damaged copy may need to be read. Memory
use remains bounded by streaming buffers, metadata and at most 64 attempt rows.

Successful failover-mode receipts keep `selection.selected_index` and its original
`approval_sha256` unchanged. A separate `acquisition` object identifies
`acquired_candidate_index`, `candidates_attempted`, `duplicate_sources_skipped`,
`payload_bytes_read`, `payload_read_calls`, `max_read_bytes`, and the bounded
per-candidate outcomes. Its `read_budget_scope` is `all_archive_passes`.
`selection.replica_failover` records whether the explicit mode was enabled;
commands without it retain their original single-copy receipt shape.

## Retain recovery knowledge between invocations

Create the witness once under an existing owner-private directory, independently
of the repository and all recovery inputs:

```sh
fg backup witness init /private/recovery-witness --trusted-local \
  --trust-key /independent/backup-public.pem \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --incarnation-id "$INCARNATION" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION"
```

Append `--witness /private/recovery-witness` to `verify-selected` or `recover`,
including explicit resume. `fg backup witness inspect` accepts the same directory
and trust flags, reauthenticates retained signatures and reports the remembered
generation and conflict state without reading an archive.

Every authentic higher observation is persisted before checking its availability,
expiry or the selected payload budget. A later invalid candidate does not erase
observations already retained during the attempt. Two distinct statements at the
highest generation retain an ambiguity that cannot be hidden by omitting one on
the next invocation. A strictly higher authentic observation can supersede that
conflict. Raising the independent generation floor persists it; a later weaker
floor refuses. Missing or corrupt state never becomes an empty witness, and
initialization never replaces an existing directory.

Witness state uses the existing canonical `repository_backup_witness_v1` JSON,
with at most two original envelopes and a 64 KiB total bound. Private staged
writes are synchronized and read back before atomic state replacement and parent
directory synchronization. The exact independently supplied key and repository
identity remain mandatory; retained files cannot supply their own trust policy.

The exclusive durable lease spans observation, selection, native preflight or
restore, publication checks, node shutdown and cleanup. Witness custody and the
selected statement are checked again at native publication boundaries, alongside
the original approval's eligibility. Witness storage must be physically separate
from candidate/control paths and the native destination, including aliases through
parent directories. Lower archive payloads are not opened for these checks.

Ordinary failures before native work release the lease when no persistence debt
remains. A persistence failure, process crash, or error after entry into the native
engine conservatively retains `.witness-lock`: an untyped native error does not
prove that all owned work settled. No automatic lease stealing, age heuristic or
reset is provided. Independently establish that the owning work has stopped and
preserve and inspect its state before manually resolving such a lease. Successful
native completion remains completed if later receipt delivery or lease cleanup
fails; diagnostics preserve that distinction.

The witness constrains selection without changing the original approval's sealed
resume identity. It is optional local recovery memory, not repository authority
or an external freshness oracle. Its storage owner must preserve its latest state;
replacing the entire directory with an older copy is not detectable without an
external durable trust anchor. See [Recovery Checkpoint Witness](RECOVERY_CHECKPOINT_WITNESS.md)
for the shared format and existing operator interfaces.

## Scope

These are trusted-local repository-source operations. They do not authenticate
global newest-checkpoint completeness, publish routing, replay external effects,
restore excluded external artifacts, or replace canonical Repository Capsule key
policy and closure verification. `newest_checkpoint_verified` and
`candidate_set_completeness_verified` remain false.

For signed approval issuance, see [Signed Repository Backups](SIGNED_REPOSITORY_BACKUPS.md).
For recovery of bytes from damaged copies, see
[Native Backup Reconstruction](NATIVE_BACKUP_RECONSTRUCTION.md). Reconstruction
preserves the original approval; its recovered file can be supplied as the archive
for the same signed statement here. The existing JavaScript operator interfaces
remain described in [Checkpoint Set Recovery](CHECKPOINT_SET_RECOVERY.md).

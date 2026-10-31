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
6. Open the first normalized lexical `(archive, approval)` pair for that exact
   highest statement and retain its
   descriptor across native checks. This version performs no automatic replica
   failover. Missing, corrupt or natively invalid selected input terminates the
   attempt without choosing an older checkpoint or another copy.

Authenticating a signed observation is deliberately separate from admitting it
for restore. Expired, future-dated, below-floor and currently over-budget statements
can participate in ranking; none gains publication permission by doing so. This
keeps an authentic but unusable higher statement from disappearing during intake.

All phases share one original deadline. Archive, blob, object-count and native
metadata bounds remain independent. Payload memory continues to use the existing
streaming verification and restore paths; candidate metadata is separately bounded.
The output receipt contains `selection` evidence and the directly embedded `native`
completion receipt. No child executable or receipt parser composes these commands.

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

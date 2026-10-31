# Native reconstruction of damaged source backups

`fg backup catalog` and `fg backup reconstruct` preserve the bytes of an
original signed repository-source backup. They can recover an archive from
complementary intact ranges of several damaged copies, even when no single copy
still passes the whole-file checksum. Both operations use the native archive,
authority and graph verifier before publishing their output.

The inputs are explicit local files. These commands do not change live repository
placement, restore authority, publish routing, produce a new signature or select
the newest checkpoint. The existing source-backup scope and independent trust
requirements continue to apply. See [repository source recovery](REPOSITORY_SOURCE_BACKUP.md)
and [signed backup approval](SIGNED_REPOSITORY_BACKUPS.md).

## Prepare a catalog while a complete copy is available

First export the backup and obtain its detached approval, for example with
`fg backup export` and `fg backup attest`. Keep the approved archive checksum,
public key, namespace and minimum acceptable generation independently. Create
the catalog beneath a stable, owner-private directory:

```sh
fg backup catalog backup.fgit backup.chunks \
  --verification-root catalog-verify --verification-instance 990 \
  --trusted-local --expected-sha256 "$BACKUP_SHA256" \
  --approval backup.approval.json --trust-key /independent/backup-public.pem \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --incarnation-id "$INCARNATION" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --max-archive-bytes 2147483648 --max-blob-bytes 536870912 \
  --max-objects 250000 --timeout-secs 1800
```

The archive must pass its original approval, checksum, native object identities,
payload commitments, portable authority import, exact selected inventory,
complete graph and retained-checkpoint checks. The catalog is generated from
the same checked input and binds its complete original size and SHA-256. A
failed or incomplete preflight cannot publish a catalog.

Catalogs are derived recovery hints. Their chunk hashes help choose intact
ranges; they do not replace the independently trusted approval or whole-archive
commitment. Preserve a catalog when making the original backup. Reconstruction
requires one; it does not guess chunk commitments from damaged copies.

## Reconstruct into a new archive

Supply each candidate copy explicitly. The output and verification scratch must
be new, and the output parent must satisfy the same private filesystem profile:

```sh
fg backup reconstruct backup.chunks recovered.fgit \
  --replica /recovery/copy-a.fgit --replica /recovery/copy-b.fgit \
  --verification-root recovery-verify --verification-instance 991 \
  --trusted-local --expected-sha256 "$BACKUP_SHA256" \
  --approval backup.approval.json --trust-key /independent/backup-public.pem \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --incarnation-id "$INCARNATION" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --max-archive-bytes 2147483648 --max-blob-bytes 536870912 \
  --max-objects 250000 --max-read-bytes 12884901888 --timeout-secs 1800
```

The verifier instance must differ from the source authority-store instance.
One through 64 distinct, explicitly named replicas are supported. Candidate
paths are normalized and ordered deterministically. Symlinks and special files
cannot contribute bytes; an unavailable replica may be skipped when another
explicit copy supplies the required range. The command does not discover other
copies by directory scanning.

Each catalog range is tried against the available replicas using bounded reads.
An accepted range must match its chunk digest and stable source-file identity.
Failed candidate reads spend the same operation budget as successful ones.
Missing, short, changed or hash-mismatched material can be skipped within the
closed replica-failure rules. Unexpected I/O errors, expired approval, exhausted
budget and deadline expiry terminate the operation.

Reconstruction writes only to a private stage. After assembly, the same output
descriptor passes the original signed whole-file checksum and the complete
native authority, inventory, graph and retained-checkpoint preflight. A forged
catalog with a recomputed catalog checksum cannot authorize different archive
bytes. The original approval is preserved and is also the approval to use when
later verifying or restoring the reconstructed file.

Publication occurs only after native node shutdown, verification-scratch cleanup,
output verification and a final approval-lifetime/deadline check. The output is
linked without replacement and its parent directory is synchronized. Existing
outputs and replicas are never overwritten or removed. A late synchronization,
cleanup or receipt-output failure reports publication uncertainty; preserve any
visible output and independently verify it before deciding how to proceed.

## Resource and filesystem profile

Both commands share the existing `--max-archive-bytes`, `--max-blob-bytes`,
`--max-objects` and `--timeout-secs` controls. These limits remain independent.
They additionally accept `--max-read-bytes`, defaulting to four times the selected
archive-byte limit, with a finite ceiling of 67 TiB.

The read ledger counts actual artifact bytes across candidate reads, failed
attempts, whole-file readback, native record validation and graph verification.
It is never renewed for another replica or another pass. A healthy reconstruction
uses one archive-sized source pass and three archive-sized validation passes;
catalog creation uses three validation passes and one chunk-hash pass. Corruption
can require additional reads and therefore a larger explicit allowance. Actual
EOF probes remain required, including at an exact byte-budget boundary.

Payload transfers use buffers of at most 64 KiB. The 4 MiB chunk size is a digest
boundary, not a payload-buffer allocation. Inventory, graph and authority metadata
retain their separately documented bounds. These are resource mechanisms, not a
total RSS or throughput claim.

The binary catalog is separately bounded to 8,388,696 bytes. At most 64 replica
paths and 256 KiB of aggregate replica path text are accepted. The Unix filesystem
profile retains opened descriptors, checks named and opened file identities, and
requires a stable trusted parent; it is not a sandbox against a hostile process
with the same filesystem identity. Unsupported platforms refuse explicitly.

## Existing `FGCHNK01` wire format

The native commands use the same catalog format as
`scripts/lib/repository-backup-chunks.mjs`. Multi-byte integers are big-endian.

| Field | Encoding |
|---|---|
| Magic | Eight bytes, `FGCHNK01` |
| Original archive length | Unsigned 64-bit integer |
| Original archive SHA-256 | 32 bytes |
| Chunk size | Unsigned 32-bit integer, exactly 4,194,304 |
| Chunk count | Unsigned 32-bit integer, exactly the ceiling of length/chunk size |
| Chunk digests | Ordered SHA-256 values, 32 bytes each |
| Catalog checksum | SHA-256 of every preceding catalog byte |

The parser requires exact length, count, fixed chunk size, original signed
artifact identity and catalog checksum. Trailing bytes, unsupported formats and
inconsistent fields refuse. No canonical schema, authority identifier or Git
object identity changes.

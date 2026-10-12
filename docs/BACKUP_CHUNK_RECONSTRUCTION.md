# Reconstruct an approved source backup from damaged replicas

A complete-file failover cannot recover when every copy is damaged, even when
all original byte ranges survive somewhere. The trusted-local backup operator
now supplies `catalogRepositoryBackupChunks` and `reconstructRepositoryBackup`
in `scripts/lib/repository-backup-chunks.mjs` for that case.

Related bead: `frankengit-root-doctrine-x2mv.4.21` (partial). This is recovery of
an independent backup **artifact**, not publication of repository placement or
authority, a Git/archive decoder, Repository Capsule recovery or RaptorQ.
The normative original-commitment boundary remains unchanged.

## Before damage: save a chunk catalog

Call `catalogRepositoryBackupChunks` with `input`, create-only `output`, the
original `approval`, independently supplied `trustKey`, and exact `policy`.
The policy has the usual tenant, repository, incarnation, object format and
minimum head generation. It is not learned from the catalog.

The builder verifies the Ed25519 source-backup approval, scans the complete
artifact against its signed SHA-256 and size, and records each consecutive
4 MiB chunk's SHA-256. The final chunk may be shorter. It never produces a
catalog from an artifact that fails the original signed commitment.

Save this catalog while a complete approved archive is still available. It is
a deterministic derived hint, not a new signature or trust anchor. Copies can
be kept separately alongside the original approval and archive replicas.

## After damage: reconstruct, then use native verification/restore

Call `reconstructRepositoryBackup` with one to 64 explicit `replicas` (archive
paths), `catalog`, new `output`, original `approval`, independent `trustKey`,
and the same policy. Each chunk is tried against the sorted replica paths.
A complete healthy replica is not required; truncated replicas can contribute
complete surviving chunks. Missing, symlinked, changed or unusable files cannot
supply a chunk. Originals are never modified. A chunk missing from every copy
produces `backup_chunk_unrecoverable` with its zero-based chunk index.

Fragments are written only to an unpublished private file. Before linking the
result to its requested name, the operator synchronizes it and reads it back
in full, checking its size and SHA-256 against the **original signed archive**.
A forged but internally self-consistent chunk catalog can cause refusal, but
cannot authorize different output. No new signature is produced. Continue to
use the original approval with native `fg backup verify` and signed restore;
chunk reconstruction cannot replace native graph or authority verification.

This API repairs one explicitly selected checkpoint, not a latest-candidate
search. The independently supplied generation floor remains mandatory. It does
not by itself remember prior invocations or establish global currentness.

## Format and finite bounds

The catalog is a closed binary `FGCHNK01` profile. All integers are big-endian:
8-byte magic, u64 archive size, original 32-byte SHA-256, u32 chunk size (exactly
4 MiB), u32 chunk count, ordered raw 32-byte chunk hashes, then SHA-256 of all
preceding catalog bytes. The count must equal ceil(archive size / 4 MiB); total
length must be exact. The maximum 1 TiB artifact needs 262,144 hashes and an
8,388,696-byte catalog. The catalog has no paths, commands or native objects.

`maximumBytes` caps one archive (default 1 GiB, maximum 1 TiB).
`maximumReadBytes` separately caps actual source payload reads, including failed
fragment attempts, **plus** the full staged-artifact readback. Its default is
four times the archive ceiling, with an explicit maximum of 65 TiB. Before a
chunk attempt the remaining allowance must cover that attempt, the remaining
successful chunks and the mandatory readback. No retry renews a budget.
Catalog metadata reads and readback have their separate fixed format bound.
All payload read buffers are 64 KiB; no complete chunk or artifact is buffered.
Up to 64 source descriptors are held, with per-source aggregate diagnostics.

One monotonic deadline covers control reads, reconstruction, staging and the
pre-publication checks (default 300 seconds, maximum 3600 seconds). The original
approval's wall-clock expiry is checked throughout and immediately before the
create-only publication. Blocking filesystem calls cannot be interrupted.
Callback errors, unknown I/O errors, deadlines and cancellation are fatal, not
replica-unavailability hints. Cancellation drains owned descriptors before the
attempt returns. No background work or automatic mutation retry is started.

## Filesystem ownership and evidence limits

The destination parent must already be owner-private. Stable trusted local
parent paths and a filesystem supporting no-replace hard links are required.
Output never overwrites an existing file, directory or symlink. Competing
publishers cannot replace the winner. Temporary cleanup removes only the
invocation's own inode. After visibility, a synchronization, cleanup or close
failure reports the publication state; it does not delete the destination or
imply rollback. A crash may retain unpublished temporary files for inspection.

`node --test tests/operator/repository-backup-chunks.test.mjs` exercises actual
Ed25519 signatures, damaged and truncated files, full reconstruction with no
healthy complete copy, wrong catalogs, exact budgets, expiry, cancellation,
concurrent publication and output preservation. Those are byte-recovery tests,
not a substitute native engine. Opaque test artifacts are not native `fg`
archives. No Rust, full-capsule, forge/external-artifact, hardware power-loss,
independent-failure-domain or full-workspace verification is claimed.

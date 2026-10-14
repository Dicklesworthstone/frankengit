# Recover from damaged backup replicas

Related bead: `frankengit-root-doctrine-x2mv.4.21` remains partial.
This extends [offsite/native recovery](OFFSITE_NATIVE_RECOVERY.md) with explicit
local reconstruction under the same retained checkpoint witness and native trust
boundary. It does not implement another Git engine, archive parser or authority.

## Select reconstruction explicitly

Use the existing recovery command, replacing HTTPS sources with a chunk catalog
and 1..64 explicit damaged or truncated copies:

```sh
node scripts/recover_repository_backup.mjs verify \
  --cache-directory /private/recovery-cache \
  --repair-catalog /independent/repository.chunks \
  --repair-replica /damaged/copy-a.fgbackup \
  --repair-replica /damaged/copy-b.fgbackup \
  --approval /independent/repository.approval.json \
  --trust-key /independent/operator-ed25519.pub \
  --witness /independent/checkpoint-witness \
  --fg /absolute/path/to/fg --trusted-local --verification-instance 11 \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --max-archive-bytes 1073741824 --max-acquisition-bytes 6442450944
```

For `restore`, additionally supply the explicit destination, destination instance
and separate approval record described in the linked recovery guide. Native
preflight always precedes restore. Neither native failure nor missing repair
material triggers an automatic network fallback or another checkpoint selection.
`--sources` and `--ca-file` cannot be combined with the repair options.

## Original commitments and bounded work

Generate the catalog with `catalogRepositoryBackupChunks` in
`scripts/lib/repository-backup-chunks.mjs` while an intact approved archive exists.
It supplies fixed 4 MiB chunk hints, not authority or erasure-coding redundancy.
Every chunk must survive in a supplied copy. A missing, invalid or irrecoverable
catalog/range refuses rather than inventing data. The full reconstructed result
must match the original independently signed digest and length, even when a
forged catalog is internally self-consistent.

The reconstructor writes only owned quarantine and a create-only cache output.
The existing replica publisher reauthenticates and synchronizes the result before
publishing original approval bytes; native signed checks then remain mandatory.
Original copies and conflicting cache files are never overwritten or deleted.
The witness, cache, native outputs, controls and fragment inputs must satisfy the
existing lexical/physical separation and stable owner-controlled-parent rules.

One acquisition budget covers successful and failed fragment reads, complete
readback and cache publication. An N-byte archive needs at least 4N payload work;
failed probes need additional allowance. Publication work is reserved before
staging. Catalog/control reads are separately bounded; native-engine reads retain
their native limits. Replica paths are unique, canonical and bounded to 256 KiB.

## Interruption and exact continuation

A completed reconstruction is retained in `recovery.reconstruction` before later
observers or native work. Unrecoverable-range errors expose the chunk index and
bounded source diagnostics. Reconstruction alone is never native completion.
SIGTERM drains owned work; SIGKILL can leave quarantine and a blocking witness
lease. No lock stealing, reset or deletion of another process's scratch occurs.

An authenticated cache hit skips repair and network reads. The fragment/catalog
arguments can be omitted on explicit offline continuation. Native `--resume`
still requires the original checkpoint equality pins, destination, policy and
version-2 approval record. Exit 4 remains reserved for observed native completion
followed by local cleanup/output failure; other refusals/uncertainty use exit 1.

## Focused verification

```sh
node --test --test-concurrency=1 \
  scripts/tests/repository-backup-recovery-repair.test.mjs \
  scripts/tests/repository-backup-recovery-repair-cli.test.mjs \
  scripts/tests/repository-backup-recovery.test.mjs \
  scripts/tests/repository-backup-recovery-cli.test.mjs
```

Tests use real files, Ed25519 signatures, subprocesses and signals, but their
native executable is explicitly a schema fixture, not Rust `fg`. Opaque payloads
are not native archives. These tests do not establish native authority/forge
restoration, Rust compilation, full-workspace acceptance or power-loss survival.

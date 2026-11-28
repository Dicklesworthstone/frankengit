# Signed source recovery with an exact LFS companion

Owning recovery obligation: `frankengit-root-doctrine-x2mv.4.21`; comprehensive
plan sections 21.5–21.8. The operator commands below carry the existing native
source archive and optional FGLF companion through export, independent native
verification, source approval, and resumable restore.

The Ed25519 DSSE v1 approval still signs **only the source archive**. The native
verifier derives the complete LFS pointer inventory from that authenticated
archive, checks the companion's exact original repository/head identity, and
verifies every selected payload's SHA-256 and length. The companion also needs
an independently retained whole-file SHA-256 pin. An approval alone does not
assert that an LFS companion exists, and this does not introduce a signed-pair
format or change the existing source-only approval schema.

## Export and approve both verified inputs

Use existing owner-private output directories and new output filenames. The
source declarations must describe the exact checkpoint being exported. `FG` is
the absolute path to a trusted native executable implementing the optional LFS
backup profile.

```sh
node scripts/attest_repository_backup.mjs export-sign \
  /private/source /private/backup/source.fgit /private/backup/source.approval \
  --fg "$FG" --trusted-local --verification-instance 990 \
  --private-key /private/backup-signing.pem \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --incarnation-id "$INCARNATION" --object-format sha256 \
  --head-generation "$HEAD_GENERATION" \
  --lfs-root /private/source-lfs --lfs-output /private/backup/source.lfs
```

Both LFS options are required together. All three outputs must be distinct and
outside both input directories. Existing files are never overwritten. The
native export receipt must contain `lfs_payloads_included: true` and an exact
companion receipt. A separate native verification must agree on the source and
companion hashes, lengths, inventory counts and payload counts before the private
key is read. The operator rehashes actual companion bytes after verification
and again before approval publication.

The result carries `lfs_archive`, `lfs_companion` and
`lfs_companion_signed: false`. Retain `lfs_companion.sha256` independently along
with the source approval and public-key/floor information. The receipt's byte
and object counts are lossless decimal strings.

The three files are separate publications. Failure can leave only a companion,
both archives without an approval, or an already visible approval. Error output
retains the source and companion paths and publication state; it never deletes
retained archives or repeats export automatically. Inspect those files before
choosing a new operation. A retained pair can be verified and approved explicitly:

```sh
node scripts/attest_repository_backup.mjs verify-sign \
  /private/backup/source.fgit /private/backup/new.approval \
  --fg "$FG" --trusted-local --verification-instance 991 \
  --private-key /private/backup-signing.pem \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --incarnation-id "$INCARNATION" --object-format sha256 \
  --head-generation "$HEAD_GENERATION" \
  --lfs-archive /private/backup/source.lfs \
  --expected-lfs-sha256 "$INDEPENDENT_LFS_SHA256"
```

Offline `sign` and signature-only `check` do not accept LFS options: they do not
run the native pointer verifier. Native `fg backup attest` retains its existing
source-only interface; the examples above deliberately use the operator adapter.

## Verify and restore an approved pair

The public key, exact identity, minimum head generation and companion digest are
independent trust inputs. The adapter authenticates the source approval and
actual source bytes before invoking the native verifier. Both native phases
receive the same companion pathname and checksum, plus private copies of the
original source approval and public key.

```sh
node scripts/restore_repository_backup_native.mjs restore \
  /private/backup/source.fgit \
  --fg "$FG" --trusted-local \
  --approval /private/backup/source.approval \
  --trust-key /independent/backup-public.pem \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --incarnation-id "$INCARNATION" --object-format sha256 \
  --minimum-head-generation "$INDEPENDENT_FLOOR" \
  --verification-instance 992 --destination-instance 993 \
  --destination /private/recovered --approval-record /private/restore.intent \
  --lfs-archive /private/backup/source.lfs \
  --expected-lfs-sha256 "$INDEPENDENT_LFS_SHA256"
```

For a read-only preflight, use `verify` and omit the destination, destination
instance and approval-record options. A paired success requires the native
`lfs_payloads_verified` or `lfs_payloads_restored` flag and a companion receipt
matching the requested pin. Restore must agree with the preflight's inventory
counts. Native restore installs and verifies LFS custody before publishing
authority; the adapter does not decode archives or create repository state.

An interrupted restore is resumed with the same command plus `--resume`. Paired
operations retain a version-3 approval record binding the original source
approval, independent public-key policy, destination instance, and companion
digest and byte count. A retry cannot add, omit or exchange the companion.
Source-only version-2 record bytes and native intents remain unchanged. Neither
record is automatically upgraded. Unknown native scratch or incomplete
destination state is retained for inspection, and a lost response does not
establish non-publication.

## Bounds and coverage

`--max-archive-bytes` defaults to 1 GiB and permits at most 1 TiB. It bounds each
archive independently; it is not a combined two-file ceiling. One deadline
spans native export, local streaming hashes, native verification and publication.
The operator uses bounded streaming reads; it never loads the companion payload
into memory. Native inventory and per-object limits still apply, including
100,000 selected objects under this adapter and 512 MiB per LFS payload. The
optional native LFS store requires a supported Unix host.

This preserves exact selected LFS custody. General `external_artifacts_*` fields
remain false because packages, workflow outputs, other artifact classes,
deployment credentials and service configuration are outside this profile.
Restore does not activate HTTP serving or change routing. It is not complete
Repository Capsule recovery, highest-checkpoint discovery or a measured site
loss drill. The [local replica publisher](SIGNED_BACKUP_REPLICA_PUBLICATION.md#optional-verified-lfs-companion)
can natively verify and copy both archives to another private directory, retaining
the unchanged source approval and companion recovery pins. Source-only job and
HTTPS transfer commands retain their existing scope and do not automatically
carry the companion.

## Focused validation

```sh
TMPDIR=/tmp node --test --test-concurrency=2 \
  scripts/tests/repository-backup-export.test.mjs \
  scripts/tests/repository-backup-export-lfs.test.mjs \
  scripts/tests/repository-backup-verified-sign.test.mjs \
  scripts/tests/repository-backup-recovery.test.mjs \
  scripts/tests/repository-backup-native-lfs.test.mjs
```

The focused adapter tests use real Ed25519 keys, files, private publication and
owned child processes. Their explicitly simulated native peers exercise receipt,
pin, cancellation, path-separation and retry boundaries; they are not execution
evidence for the Rust archive engine. The existing native backup suites remain
the native implementation gate.

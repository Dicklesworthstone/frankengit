# Immutable local artifact custody

`fgit_object_fabric::artifact::storage` persists the existing `ArtifactIdentity`
and its exact raw payload. The payload lane belongs to the object-fabric owner;
it does not encode artifacts as Git objects or introduce a second database.

The selected namespace binds tenant, repository, repository incarnation and an
explicit trust-domain label. Lookup checks the complete stored scope, artifact
identity, payload length and SHA-256, not just a filename or metadata checksum.
Copying a valid object into another namespace cannot satisfy that lookup. All
stored digests must be SHA-256 with 32-byte bodies, including optional producer
and receipt references. A filename or caller-supplied provenance label is not an
authenticated producer identity, permission, or evidence that a build succeeded.

## Publication and recovery

Upload streams from an already opened regular file into a unique private stage,
verifies exact length and digest, syncs the stage, and independently rereads the
retained container. Only then can a hard link install the immutable artifact
name. An existing name is accepted only after complete identity and payload
verification; corrupt existing bytes are refused and never overwritten. Scope
and final namespace directories are synced before a completed result returns.

Export verifies the whole stored payload into a private temporary file, syncs
and rereads that output, then links it to an absent destination. Invalid data
cannot expose an unverified prefix under the destination name. Existing files,
directories and symlinks are not replaced. A failure after final linking is
reported as publication uncertainty, not proof of absence. Exact upload retries
reverify retained bytes and settle the same object without replacement.

Returned cancellation and unwinding remove only the operation's owned staging
name. Physical crashes can leave private staging files; those names are never
scanned or adopted as recovery roots. A committed object is recovered by its
exact scope and ID, including after the original input file is removed.

## Bounds and trust

The default per-payload ceiling is 64 MiB, configurable up to 512 MiB. Transfers
use 64 KiB chunks and metadata is bounded by 8 KiB. One absolute deadline and
liveness callback cover all read, validation, staging and retry phases. Cancellation
is checked between chunks and before the visibility boundary, never used to claim
that an already linked file is absent. Filesystem system calls are not preempted
by that cooperative deadline. Retained data still needs an operator filesystem
quota; these per-operation limits are not a store-wide disk quota.

This Linux profile requires existing absolute operator-private 0700 storage and
export-parent directories. Components must be directories rather than symlinks;
objects and stages are 0600 files. The operator must protect directories and their
ancestors from concurrent replacement. The checks are not a hostile-filesystem
race-proof sandbox and do not authenticate the caller. No external network or
credentials are required by the storage operations.

Artifact custody is NOT canonical repository or namespace publication. There is
no mutable artifact alias, automatic workflow capture, check grant, retention
registry mutation, deletion, or cache-hit decision here. Retention values are
identity-bound metadata, not enforcement of time-based deletion or a legal-hold
service. The existing OutputStore and deterministic-build reuse policy are not
made durable by this payload slice. Those consumers can use exact immutable
artifacts without treating payload existence as authorization.

## Validation

`cargo test -p fgit-object-fabric --test artifact_storage --locked` covers real
files, concurrent writers, source-free reopen/export, all retention encodings,
namespace isolation, poisoned metadata/payload, truncated files, invalid digest
domains, byte limits, cancellation boundaries, callback unwinding, private-path
checks and no-overwrite export. Existing artifact identity and planted-negative
suites remain applicable. These tests are not physical power-loss or hostile
filesystem isolation evidence, and do not close the entire CI product-loop bead.

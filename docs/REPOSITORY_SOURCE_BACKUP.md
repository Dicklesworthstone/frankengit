# Bounded repository source recovery

`fg-repository-backup` addresses the source-data gap in FG-033a. It transports
one portable embedded authority snapshot **and every Git object in the exact
same authority-selected closure**, including admitted history no longer
reachable from current refs. Physical orphan files are not recovery roots.

This is a trusted-local source-recovery transport, not a Repository Capsule,
signed backup profile, latest-checkpoint selection protocol, or complete service
backup. It does not create a canonical body schema, change canonical identities,
advance the checkpoint head, sign evidence, or publish routing. The format's
SHA-256 is an ordinary whole-file trust pin, not a new authority identifier.

## Commands

```sh
cargo run --locked -p fgit-node --bin fg-repository-backup -- \
  export ./fgit-data ./source-backup.fg \
  11111111111111111111111111111111 22222222222222222222222222222222 \
  --trusted-local --object-format sha1

cargo run --locked -p fgit-node --bin fg-repository-backup -- \
  restore ./source-backup.fg ./recovered-node --trusted-local \
  --expected-sha256 "$INDEPENDENTLY_TRUSTED_SHA256" \
  --destination-instance "$UNUSED_DESTINATION_INSTANCE"
```

Both commands accept `--max-archive-bytes` and `--timeout-secs`. For an explicitly
selected 2 GiB archive budget and a 30-minute cooperative operation deadline,
append `--max-archive-bytes 2147483648 --timeout-secs 1800` to each command. Limits
are operator input, never automatically enlarged to fit an archive. Integers
must be positive canonical decimal; duplicate or unsupported flags refuse.

Export's native format defaults to SHA-1; SHA-256 is explicit. A mismatch with
the authenticated repository configuration refuses. Restore takes repository,
tenant, incarnation and native format from the checksum-pinned archive, and
checks them against the restored node's canonical materialization. It preserves
canonical body bytes and generations while the existing portable-store importer
remints backend tokens under a distinct destination instance.

Keep the checksum through an independently trusted channel. Reading an attacker-
controlled checksum beside the archive does not establish provenance. Pinning an
exact archive does not prove it was the newest checkpoint. Restoring an older
source snapshot here is a new isolated copy, never an in-place rollback or an
activation of production routing.

## Scope and limits

Included: the single-head authority bundle's immutable rows and issuance ledger,
plus the complete cumulative admitted Git object set for that same head. Source
objects are read by canonical ID through the verified fabric, never by scanning
source directories. Native identities and original independent payload
commitments are preserved and checked. Commit/tree/tag edge types, reference
kinds, local connectivity and acyclicity use the existing graph checker.
Gitlinks are external commit data, not local traversal permission.

Not included: physical orphans, separate external artifacts/packages, signing
keys, credentials, host configuration outside authority, runner workspaces,
materialized search/graph indexes, external-effect delivery, or routing. Review
restored outbox state and external dependencies before serving or executing
workers. The command does not certify full service readiness, retention/GC
safety, all signed capsule requirements, or `git fsck --strict` parity.

The complete uncompressed transport budget defaults to **1 GiB**, with explicit
values from 1 byte through 1 TiB. This replaces the former 64 MiB whole-archive
buffer ceiling. Each object remains bounded at 32 MiB, the inventory at 100,000
objects, refs at 100,000, and inspected graph edges at 1,000,000. Authority
metadata keeps its separate 64 MiB encoded-field bound; portable-store row/body
and canonical-codec limits additionally apply and can refuse sooner. Selecting
a larger archive does not enlarge these independent limits. An export must fit
the same decoder envelope that restore uses.

The cooperative deadline defaults to 300 seconds, with explicit values from
1 through 86,400 seconds. All verification passes share one original deadline;
starting a later pass does not renew it. Blocking filesystem calls cannot be
forcibly interrupted, and inherited runtime budgets may refuse earlier. Cleanup
still runs when the operation refuses. Partial results are refused, never
silently truncated or downgraded to a byte-only audit.

Payload processing is streaming. The decoder retains one reusable object buffer
and bounded authority metadata, not an archive-sized payload buffer or inventory
of payload slices. Graph verification still needs its separately bounded object
and edge tables; node placement/readback and hashing may use additional bounded
per-object buffers. This is not a claim that total process memory is 32 MiB or
that metadata/allocator overhead is measured by the archive byte counter.

## Snapshot and publication rules

Export obtains metadata in the backend's SQL snapshot, closes that store, opens
the node, then matches head **key, token, generation and exact bytes**. It writes
objects one at a time through a private file handle, hashing the successfully
written bytes. It rewinds that same file and independently decodes, rehashes,
and graph-checks the actual staged bytes. Exact EOF and the writer's checksum
must agree before the source head is revalidated and the node closes. Only then
is the synced temporary file hard-linked into a previously absent destination.
A short write, failed flush, failed readback, cancellation, or changed source
head cannot produce a final backup path. A racing destination is never replaced.
The source may advance after the final observation; a backup is a checkpoint,
not a lock on future mutation.

Restore opens the input once and retains that handle throughout the operation.
It first streams the independently trusted SHA-256 check, then streams framing,
native identities and original payload commitments before creating a destination.
The validated metadata and checksum are retained, not the Git payloads. A later
pathname replacement does not switch the open input. Every later pass rewinds
that same handle, matches the original metadata, verifies each record, and
recomputes the complete original file checksum through exact EOF. An in-place
change cannot reuse a prior pass's validation, even if the modified records have
individually valid native identities and commitments. These protections do not
make an attacker-controlled checksum trustworthy.

Restore atomically reserves a new private root, imports authority into
`.restore-quarantine`, and materializes that imported head. Archive record IDs
must equal the canonical selected set exactly; missing **and extra** records
refuse. A complete graph-and-checksum pass precedes all object placement. A
separate, rehashed pass places objects only inside the selected set and reads
each back byte-for-byte. Visitor results remain tentative until the pass's
checksum and EOF validate; neither tentative metadata nor an object placement
publishes final authority. The quarantined node is closed, reopened, verified
again and closed again.

Only this verified closed image can enter publication. Object storage and any
closed-image WAL are installed first and synced; a remaining nonempty rollback
journal refuses. The process-local shared-memory cache is not copied. The final
`authority.fsqlite` is installed by a no-replace hard link **last**. A fresh node
open at the final path verifies the same head, selection and bytes before its
shutdown and success receipt. This avoids silently dropping a WAL merely because
close was successful.

Repeated reads are an explicit tradeoff for bounded memory and detecting changed
inputs without trusting an earlier pass. Export reads back its staged file;
restore uses a raw checksum pass, an initial decoder pass, graph validation,
installation, quarantine-reopen verification, and final-reopen verification.
No throughput, RPO/RTO, or peak-RSS benchmark claim is made from this design.

No archive-controlled host paths are interpreted. Parent directories must be
trusted and stable, and the reserved target/quarantine must not be concurrently
opened or modified. This is not hostile-same-UID filesystem containment. The
existing object-fabric writer owns per-object placement/durability semantics;
these commands do not establish a new cross-filesystem durability profile.

Failures leave the reserved restore directory for investigation. Before head
publication, the public root has no authority database. Failures after the head
link explicitly report that authority is visible, and never delete the target
or pretend the operation rolled back. A dropped preparation does not publish.
The public root is not routed automatically, even after successful verification.

## Transport layout: FGSRC001

All lengths/counts use unsigned big-endian 64-bit fields. The transport has no
archive paths, compression, relative offsets or alternate encodings:

```
8 bytes     literal FGSRC001
16 bytes    tenant ID
16 bytes    repository ID
16 bytes    repository incarnation ID
1 byte      native format: 1 = SHA-1, 2 = SHA-256
8 bytes     authority bundle byte length
N bytes     existing canonical ExportBundle encoding (unchanged)
8 bytes     object count
repeated in strictly increasing native-ID order:
  20/32 bytes native object ID, width fixed by format
  1 byte      kind: 1 commit, 2 tree, 3 blob, 4 tag
  8 bytes     payload byte length
  32 bytes    original independent payload commitment
  N bytes     exact payload
EOF           required; no suffix permitted
```

Streaming does not change this layout. The original buffered encoder and decoder
remain test-only compatibility oracles, and tests compare exact emitted bytes
in both hash domains. Existing small FGSRC001 archives are readable. Older
binaries still refuse archives exceeding their former 64 MiB envelope; the
unchanged format does not imply that every historical implementation supports
the newer resource profile.

The transport is intentionally not a `CanonicalBody`. Host file locations and
these transport bytes never replace the existing canonical authority, object,
closure, repository or transaction identities.

## Verification status and commands

The implementation and tests were authored with source/API review, but Rust
compilation and execution were unavailable in the editing environment. No Rust
pass, conformance, crash-matrix, or production-readiness claim is made here.

```sh
cargo test --locked -p fgit-node --bin fg-repository-backup
cargo test --locked -p fgit-node --test repository_backup_command
cargo test --locked -p fgit-node --test repository_backup_large
```

Unit regressions cover both native domains, every truncation, unsupported format,
length/count bounds, independent native/strong commitment damage, cancellation,
exact snapshot joins, checksum gating, no-replace publication, closed-image WAL
ordering, and the pre-head interruption boundary. Streaming regressions add
partial/interrupted reads and writes, failed flushes, poisoned codecs, exact
byte budgets, changed-but-individually-valid records, unchanged trust pins,
path replacement, and deadlines shared across passes.

The original process/node integration case removes its entire isolated source,
restores from the archive alone, checks deleted-branch history and omitted
physical residue, and publishes a new branch after restore. Its refusal twin
removes a record while keeping valid framing and a recomputed trusted test
checksum; the final destination head must remain absent. The added large-source
case writes three 24 MiB SHA-256 blobs, exports/restores from disk after removing
the isolated source, and requires explicit 64 MiB budgets to refuse without a
published backup or a created restore root. These Rust scenarios are authored,
not executed results. Tests using opaque filesystem fixtures demonstrate file
ordering only, not FrankenSQLite semantics; the process integration owns the
real-engine claim when executed.

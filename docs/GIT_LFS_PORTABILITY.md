# Portable Git LFS custody

`fg lfs inventory`, `fg lfs verify`, `fg lfs export`, and `fg lfs import` inspect,
verify, and move LFS bytes
with an explicit native source selection and an independently trusted archive
checksum. They let an operator restore the LFS payloads needed by a restored
repository or copy them into a fresh repository incarnation.

The commands use the existing immutable artifact store and the same exact
SHA-256/length identities served by [Git LFS basic transfer](GIT_LFS_BASIC_TRANSFER.md).
They do not move a branch, create a Git object, publish an artifact alias,
change repository authority, or install a retention root. Source archives and
authority recovery still use the existing `fg backup` and Git bundle commands.
This companion covers LFS payloads referenced by its named native inventory;
it is not a complete service backup.

## Inspect the destination and obtain its pins

All commands require Linux, explicit `--trusted-local`, and whole-repository
operator authorization. Repository, custody, and archive paths are absolute.
Every directory component must be a real directory, with no symlink or parent
traversal. Archive parent directories and LFS custody roots must already exist
with mode `0700`. An import archive must be a regular private file owned by its
parent directory's owner, with no group or other permissions. The final input
is opened with no-follow and nonblocking flags and its actual descriptor is
checked again before copying. Protect these paths and their parents against hostile
replacement throughout the operation, as for the existing local artifact store.

```sh
fg lfs inventory /srv/restored-node "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --object-format sha256
```

The JSON result contains `source.incarnation_id` and `source.head_sha256`. Keep
those exact values for an import into this repository. The latter is the raw
SHA-256 of the complete authenticated authority-head body; it is deliberately
labelled differently from other native source snapshot tokens. The result also
retains the opaque head token and generation. Within an operation, every head
revalidation compares the complete key, token, generation, and body bytes.

`pointers` lists sorted, unique `{ "oid": "…", "size": … }` identities.
`native_objects` and `native_bytes` describe the work needed to derive the list.
`custody_verified:false` means inventory has verified the native pointer source,
but has not checked whether the LFS payloads are present. It does not enumerate
files in the artifact directory or infer a pointer from a stored payload name.

Inventory includes every object in the current authority-selected native
closure, including admitted history no longer reachable from current refs.
Every selected object is verified against its native identity and original
payload commitment. Large native blobs are read in bounded chunks; only a
small prefix is retained for pointer recognition. An unverified header cannot
silently remove a pointer from the inventory. Physical orphan objects are not
selected.

This profile recognizes canonical, extension-free Git LFS v1 pointers. A blob
beginning with the LFS specification version prefix but carrying an unsupported
version, extension, malformed fields, or excess bytes refuses the operation.
Conflicting lengths for one OID also refuse. Such input is never silently
reported as a complete supported inventory.

## Verify referenced payloads without an archive

After restoring native repository state and its LFS companion, or when checking
an existing node's stored data, run:

```sh
fg lfs verify /srv/restored-node /srv/restored-lfs \
  "$TENANT_ID" "$REPOSITORY_ID" --trusted-local --object-format sha256 \
  --expected-incarnation "$INCARNATION_ID" \
  --expected-head-sha256 "$HEAD_BODY_SHA256"
```

The optional pins come from the inventory command above. If they are omitted,
verification selects the current authenticated repository snapshot. It derives
the complete supported pointer inventory and then checks each unique payload
in that repository's actual custody namespace. A file with the expected name is
insufficient: its full SHA-256, exact length, container framing, and tenant,
repository and incarnation binding must all verify. Identical bytes in another
incarnation's custody do not satisfy this check.

Verification reads payloads in bounded chunks into a sink. It creates neither
an archive nor a temporary payload copy, and never modifies or repairs payloads.
It checks retained admitted history as well as current refs; physical orphan
files remain outside its selection. Source and aggregate payload budgets apply
before custody verification, and all scans share one operation deadline. Use
the same `--max-source-objects`, `--max-source-bytes`, `--max-objects`,
`--max-payload-bytes` and `--timeout-secs` controls described below.
Archive checksum and archive-byte controls do not apply to `verify`.

On success, the `lfs_verify` JSON receipt includes the exact source identity,
native objects/bytes scanned, unique LFS objects/bytes checked,
`custody_verified:true`, `head_revalidated:true`, and `complete:true`.
The command revalidates the full authority-head receipt and shuts down the node
before emitting this result. A changed head, missing or corrupt selected
payload, unsupported pointer, unsafe custody path, or exhausted budget refuses
with a nonzero exit and no complete verification receipt. Missing and corrupt
payload diagnostics name the affected OID. After restoring valid custody, the
same pinned command can be retried.

This is a snapshot integrity observation, not a retention promise: subsequent
external corruption or repository changes require another check. It does not
scrub unreferenced physical files, repair corruption, validate backup coverage
outside the selected native pointers, or replace the native repository's own
integrity checks. A lost or partial output receipt should be resolved by rerunning
the read-only command.

## Export the source's referenced payloads

```sh
mkdir -m 700 /srv/lfs-exports
fg lfs export /srv/source-node /srv/source-lfs \
  /srv/lfs-exports/repository.lfs "$SOURCE_TENANT_ID" "$SOURCE_REPOSITORY_ID" \
  --trusted-local --object-format sha256
```

Export reads the source's actual authenticated incarnation and head, derives
its native pointer inventory, then reads and verifies each named LFS payload.
Missing or corrupt custody refuses the complete export. Duplicate pointers to
the same exact object produce one payload record.

The archive is built through a private `0600` staging file. The actual staged
bytes are independently decoded and verified, the source head is revalidated,
and the node runtime is shut down before no-replace publication of the final
file. Existing files and symlinks are refused. Failure after publication is
reported as a visible archive, not as proof that no output exists.

Save the export result's `sha256` independently of the archive. The result also
records the source tenant, repository, incarnation, Git object format, exact
head labels, object count, payload bytes, and archive bytes. This checksum is
the importer's trust input; an archive's own labels do not authenticate its
origin. Neither a filename nor a checksum read from the same untrusted source
establishes independent trust.

`--expected-incarnation` and `--expected-head-sha256` can optionally pin an
export or inventory to a previously observed source. A mismatched pin refuses
before scanning native payloads.

## Import into the explicitly selected target

First restore or import the Git source so the destination's canonical native
history already contains the intended pointers. Then inspect that destination
with `fg lfs inventory`, and use its exact incarnation and head body checksum:

```sh
mkdir -m 700 /srv/restored-lfs
fg lfs import /srv/restored-node /srv/restored-lfs \
  /srv/lfs-exports/repository.lfs "$TARGET_TENANT_ID" "$TARGET_REPOSITORY_ID" \
  --trusted-local --object-format sha256 \
  --expected-sha256 "$INDEPENDENT_ARCHIVE_SHA256" \
  --expected-incarnation "$TARGET_INCARNATION_ID" \
  --expected-head-sha256 "$TARGET_HEAD_SHA256"
```

All three pins are mandatory for import. The destination namespace may differ
from the source tenant, repository, incarnation, and Git object format. LFS OIDs
are raw SHA-256 payload identities, independent of either repository's Git
object-ID domain. Source labels are retained as provenance; the explicit local
authorization and the current target's authenticated pointer selection control
what is imported.

Import completes these checks before its first immutable payload write:

1. Copy the bounded input into an owned private file and unlink its temporary
   name. Later changes to the caller's input cannot change this operation's
   second pass.
2. Verify the entire archive, including every payload's SHA-256 and length,
   strict ordering, complete framing, exact EOF, resource bounds, and the
   independently supplied whole-archive checksum.
3. Authenticate the target namespace, exact incarnation, and head pin; derive
   and verify the complete bounded native pointer inventory.
4. Require the archive to cover every exact target `(OID, size)` pair.

Only target-referenced records are then copied into the target's own existing
LFS custody namespace. Valid archive records absent from the target inventory
are skipped. This allows a source archive retaining historical pointers to
populate a fresh clone with a smaller reachable history, while preventing an
archive from injecting arbitrary unreferenced objects into target custody.
Even skipped records must pass the full archive verification.

The result reports `objects_created`, `objects_already_present`,
`unreferenced_objects_skipped`, and `unreferenced_payload_bytes_skipped`.
It records both source and target labels and explicitly reports
`refs_published:false` and `retention_roots_published:false`. The imported bytes
are immediately readable through the existing LFS store and authenticated
basic-transfer service when that service opens the same target custody root.

## Interrupted operations and retry

Each payload retains the existing root-last immutable artifact publication
protocol: verify input, sync private staging, verify actual retained bytes,
install without overwriting, and sync the namespace. A repeated identical
payload is verified and returns `AlreadyPresent`.

Import is not a multi-object transaction. Its exact target head is revalidated
before and after every put, and again before a successful result. A concurrent
source change, cancellation, storage error, or failure to write the final JSON
can leave an already verified subset in permanent custody. An uncertain put
may also have installed its immutable name. These outcomes do not move refs or
permit unverified payload bytes to be served.

The error JSON retains `put_attempts`, `objects_created`, and
`objects_already_present`. `retained_custody_may_exist:true` is conservative: it
means a put was attempted, not that every attempted object was published. Keep
the original archive, independent checksum, and target coordinates. If the
target still has the same pin, retrying them verifies existing objects and
completes missing custody. If authority moved, inspect and deliberately choose
the new target before starting a new bounded import. Do not delete valid
custody to clear a refusal.

Invalid checksum, malformed archive, unsupported pointers, wrong target pins,
and incomplete target coverage are all checked before any payload put. A
private spool is temporary operation state; it is not a published artifact or
another authority source.

## Bounds

| Bound | Default | Explicit supported maximum |
| --- | --- | --- |
| LFS payload per object | 512 MiB | 512 MiB |
| LFS records | 100,000 | 1,000,000 |
| Aggregate LFS payload bytes | 1 GiB | 1 TiB |
| Entire archive bytes, including framing | 1 GiB | 1 TiB |
| Selected native objects inspected | 100,000 | 1,000,000 |
| Selected native payload bytes inspected | 1 GiB | 1 TiB |
| Operation deadline | 300 seconds | 3,600 seconds |
| Inventory JSON | 16 MiB | 16 MiB |

The corresponding options are `--max-objects`, `--max-payload-bytes`,
`--max-archive-bytes`, `--max-source-objects`, `--max-source-bytes`, and
`--timeout-secs`. These are independent limits: raising archive bytes does not
raise the payload or source scan budget. Existing native codec, metadata-object,
history, and runtime budgets can refuse earlier. A leading global
`fg --timeout-secs` only shortens the selected operation deadline. All passes
and puts share that deadline; it is never renewed per object.

Archive encoding/verification and native blob scanning use chunks no larger
than 64 KiB. Export obtains one fully verified LFS reader at a time: it copies
the stored payload into private unlinked temporary custody, verifies that copy,
then streams it into the archive. Payload-sized memory allocations are not
required. The temporary copy can occupy up to 512 MiB of disk space in the LFS
custody root, in addition to the archive stage. Import streams each verified
record into the existing custody writer. All verification passes, copying, and
delivery retain the original operation deadline. Filesystem calls themselves
can block; deadline and cancellation checks are cooperative between those calls.

This larger supported payload envelope does not change the v1 archive framing
or object identity. Existing smaller archives remain readable. Older readers
with the 64 MiB envelope refuse archives containing larger records; use a
reader supporting the required payload size at the destination.

The companion format is a versioned noncanonical transport. It contains no host
paths, compression, executable content, authority rows, or ref commands. It has
no self-authenticating manifest or automatic source-authority proof. It does
not add pointer-aware garbage collection, lock support, receive-time pointer
availability gates, remote replication, or full backup completeness. Those
remain outside this bounded portion of `frankengit-fg053-lfs-i3h`.

Focused tests cover the archive framing, streaming and corruption boundary;
private-input custody and destination coverage; exact source pins and pointer
recognition; and real persisted native repositories with independent source
and target incarnations. Generated payloads above the buffered 64 MiB ceiling
exercise streamed custody, HTTP delivery, and pinned companion round trips
without allocating complete payloads in the fixtures. Test execution results
must be bound to the tested revision; the existence of these fixtures is not a
release or conformance claim.

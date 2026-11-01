# Native verified backup replica publication

Related: `frankengit-root-doctrine-x2mv.4.21` (still incomplete); comprehensive
plan section 21. `fg backup replicate` makes another exact, independently
recoverable copy of an approved repository-source backup. Complete native
verification precedes destination publication. The command uses the Rust node
and filesystem implementations directly, with no helper executable or new
signature.

## Command

Choose an existing owner-private replica directory. Keep it physically separate
from the inputs, trust key, verification scratch, and optional witness. The
verification root must be new; its instance must differ from the archive's
original authority-store instance. Supply the checksum, public trust key,
repository identity, and minimum generation independently:

```sh
fg backup replicate /private/replicas \
  --candidate /source/repository.fgit /source/repository.approval.json \
  --candidate /other-copy/repository.fgit /other-copy/repository.approval.json \
  --verification-root /private/replica-verification \
  --verification-instance 992 \
  --trusted-local --expected-sha256 "$BACKUP_SHA256" \
  --trust-key /trusted/operator-ed25519.pub \
  --tenant-id "$TENANT" --repository-id "$REPOSITORY" \
  --incarnation-id "$INCARNATION" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --replica-failover --witness /independent/checkpoint-witness \
  --max-archive-bytes 2147483648 --max-blob-bytes 536870912 \
  --max-objects 250000 --max-read-bytes 12884901888 --timeout-secs 1800
```

`--replica-failover` and `--witness` are optional. The witness must be initialized
explicitly using the existing `fg backup witness init` surface. No private key
is accepted. Native `verify-selected` and `recover` consume the returned
`candidate.input` and `candidate.approval` paths directly.

The command authenticates every explicit approval before accessing archive
payloads. It selects the highest unambiguous canonical statement and preserves
the first lexical pair's original envelope. A higher expired, missing, corrupt,
or conflicting checkpoint never permits fallback to an older generation.
Explicit failover tries only aliases of the same selected statement, and only
before pinned archive admission. Native format, authority, inventory, payload,
and graph failures are terminal.

## Verification, publication and retry

The selected archive passes the ordinary native preflight: exact original
checksum and length, bounded decoding, portable authority import, authenticated
materialization, selected Git-object inventory, original payload commitments,
complete graph traversal, retained-checkpoint checks, node shutdown, and scratch
cleanup. The original source descriptor stays open throughout preflight and
publication. Returned JSON is a report of typed evidence, never publication
permission parsed from another command's output.

A fresh publication then streams the original source through one 64 KiB buffer
into an exclusive private stage. It verifies the signed whole-file hash and
length, synchronizes the file, publishes it create-only, and reads back the
published body under the same byte ledger. It synchronizes the body and parent
directory before publishing the exact originally authenticated approval LAST.
The approval is compared byte-for-byte and its file and directory synchronized.
No reformatting, re-signing, mutable `latest` pointer, or directory discovery is
involved. Output names bind the exact original bytes:

```text
archive-sha256-<archive-digest>.fgbackup
checkpoint-sha256-<original-envelope-digest>.approval.json
```

An exact retry verifies and synchronizes existing files while preserving their
inodes. An identical concurrent publisher may win, but its bytes must pass the
same checks before reuse. Conflicting content, wrong lengths, symlinks, extra
hard links, nonprivate files, or observed source/directory substitution refuse.
The command never overwrites an existing output or deletes an original source.
If the exact approval already exists while its body is missing, the body can be
recreated from the original verified bytes; the approval remains untouched.
Consequently `body_before_approval` describes this invocation's approval
publication rule, not the original creation chronology of reused files.
`archive_created` and `approval_created` explicitly distinguish creation/reuse.

## One finite read budget

One original approval lifetime, monotonic deadline, and actual-byte ledger span
selection, native preflight, copying, and destination readback. The archive-size,
blob, object, metadata, and elapsed-time bounds remain independent. Reservations
ensure sufficient remaining allowance before starting the next pass; only bytes
actually returned by reads are charged. Actual EOF probes are performed, and
any unexpected extra byte is charged before refusal.

For a healthy archive of exactly N bytes:

| Operation | Archive bytes read |
|---|---:|
| Intake checksum and bounded decoding | 2N |
| Native graph/payload preflight | N |
| Fresh source copy | N |
| Final destination readback | N |
| Complete fresh publication | **5N** |
| Exact existing-body retry, including native preflight | **4N** |
| One full corrupt alias followed by healthy fresh publication | **6N** |

Intake reserves 3N. After native verification, the publisher observes whether
the exact body already exists and reserves 1N for reuse or 2N for creation before
creating a private output. Thus a healthy fresh operation at 5N succeeds while
5N minus one refuses before staging; an exact retry needs 4N. Failed candidates
remain charged. Short or unavailable sources charge only bytes actually read.
Small approval and key reads keep their separate finite metadata bounds.

`--max-read-bytes` defaults to six times `--max-archive-bytes`, with a 68 TiB
ceiling. Raising this aggregate allowance never widens the per-archive or native
object limits. There is no implicit budget reset between retries or native work.

## Completion and failures

The JSON success receipt has type `repository_backup_replica_published` and
includes the candidate paths, original selection, native preflight receipt,
acquisition attempts, actual payload bytes/read calls, configured allowance,
creation/reuse decisions, and durable publication evidence.

Errors preserve the strongest observed boundary: not started, staging,
publication uncertain, body visible/durable, approval visible, or pair durable.
A cancellation after body publication can leave a valid unadvertised body for
an exact retry. Cleanup removes only an invocation's still-identifiable private
stage; uncertain or visible outputs remain. The command never treats a failed
receipt write as evidence that publication did not happen. A late observer,
witness-release, or stdout error includes the known completed receipt.

With an optional witness, each new authenticated higher or conflicting
observation is retained before eligibility or payload checks. The witness stays
leased through native work and publication. Unresolved native preflight errors
retain that lease; a returned synchronous filesystem operation has no background
transfer work and can finalize a healthy witness while preserving the reported
publication uncertainty. Neither path rolls back its authenticated high-water
observation.

## Scope and validation

This is a trusted-local Unix filesystem operator path. It requires no-follow
opens, create-only links, file and directory synchronization, owner-private
storage, and stable trusted parent paths. It does not isolate a hostile same-user
writer, prove separate failure domains, or establish remote/object-store durability.
It publishes recovery files without advancing repository authority or routing.
The underlying source-backup profile remains unchanged; this is not complete
Repository Capsule export/recovery or global newest-checkpoint discovery.

The existing JavaScript [replica publication adapter](SIGNED_BACKUP_REPLICA_PUBLICATION.md)
remains a distinct surface. The native command adds mandatory typed native
preflight and carries the original descriptor, approval and budget into the
publisher in the same process.

Regression sources cover both Git hash formats, genuine native archives,
recovery after loss of every original copy, original-envelope preservation,
precise budget boundaries, exact inode-preserving retry, invalid signatures,
validly signed incomplete native inventory, conflicting destination files,
cancellation/expiry, interleaved publishers, and late completed receipts. CLI
coverage invokes the actual `fg` executable with no helper programs on PATH.
These cases require the native test gate. Authored or formatter-checked test
source alone is not a passing integration result.

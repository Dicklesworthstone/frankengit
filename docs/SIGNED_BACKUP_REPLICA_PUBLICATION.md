# Signed backup replica publication

Related: `frankengit-root-doctrine-x2mv.4.21` (partial, not closed).

The native `fg backup replicate` command is documented in
[native verified replica publication](NATIVE_BACKUP_REPLICATION.md). It performs
mandatory complete native preflight before publication and retains one original
source descriptor, approval, deadline, and actual-byte ledger in the Rust process.
The JavaScript adapter described below remains a separate operator surface.

## Optional verified LFS companion

The local JavaScript publisher also accepts an explicit paired operation. Supply
the companion checksum independently and select the trusted native `fg` executable
and a fresh verification instance:

```sh
node scripts/replicate_repository_backup_native.mjs \
  --candidate /source/repository.fgbackup /source/repository.approval.json \
  --trust-key /independent/operator-ed25519.pub \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --replica-directory /private/replicas \
  --lfs-archive /source/repository.fglf --expected-lfs-sha256 "$LFS_SHA256" \
  --fg /absolute/path/to/fg --trusted-local --verification-instance 992
```

The library options are `lfsArchive`, `expectedLfsSha256`, `fg`,
`trustedLocal: true`, and `verificationInstance`. The companion path and digest
must be supplied together; verifier-only options without a companion refuse.
Source-only calls retain their previous options, result fields and approval bytes.

Selection still authenticates every explicit approval and chooses the highest
uniquely signed source checkpoint first. The signed native adapter then verifies
that exact source archive and independently pinned FGLF companion together. It
checks the original source pointer inventory, exact snapshot and payload
commitments. A missing, wrong, corrupt or substituted companion refuses; it
cannot trigger selection of an older source or source-only completion. No FGLF
decoder or second repository authority is introduced in JavaScript.

The original DSSE v1 approval continues to sign only the source archive. It is
neither extended nor re-signed. Native source-pointer verification authenticates
the companion's contents; its independently retained checksum also pins the
exact transport bytes. The publisher retains open source and companion handles
across preflight and checks their identity and metadata before publication. Pair
inputs must be physically separate from the destination and from one another;
observed parent aliases, hard-link aliases and output collisions refuse.

Both bodies use the existing bounded private-stage, create-only publication,
exact readback, file-sync and directory-sync protocol. The companion name is
`lfs-sha256-<companion-digest>.fglf`. A fresh approval is published only after
**both** bodies are durable. A reused approval must be revalidated and both
bodies verified before acknowledging the pair. As with source-only retry, an
identical existing approval does not prevent recreating a missing body from the
exact original verified input; no existing body or approval is overwritten.
The paired `lfs_before_approval` field is true only when this invocation created
the approval after verifying both durable bodies. It is false when the approval
was reused, including an exact retry or adding a companion to a preexisting
source-only replica; that invocation cannot attest to the approval's creation
chronology. `lfs_durable_before_acknowledgement` is true for every successful
paired result. The legacy source-only `body_before_approval` field is unchanged.

The unchanged `candidate: {input, approval}` remains usable by existing source
selectors. Paired results additionally contain `lfs_archive`, the normalized
`lfs_companion` receipt, the native verification receipt, and separate creation
or reuse disposition. `lfs_companion_signed` remains false. Supply
`candidate.input`, `candidate.approval`, `lfs_archive` and
`lfs_companion.sha256` to `restore_repository_backup_native.mjs` using its
`--lfs-archive` and `--expected-lfs-sha256` options. Restore must perform its own
signed native checks; a replication receipt is not permission to publish a
repository head.

### Paired budgets, interruption and scope

The per-archive `--max-archive-bytes` ceiling applies independently to each body.
The JavaScript `--max-total-read-bytes` ledger covers source selection plus source
and companion publication scans. For a healthy N-byte source and L-byte
companion, fresh publication charges **3N + 2L**; an exact existing-body retry
reads **2N + L**. The operation conservatively reserves the fresh copy/readback
allowance for both bodies before native preflight, including on retry. Failed
source aliases remain charged. Paired mode defaults to eight times the
per-archive ceiling, with an 8 TiB aggregate ceiling; source-only defaults and
ceilings remain unchanged.

**This JavaScript ledger does not meter the signed native preflight**, including
the adapter's authentication and post-verification hash scans. That work has its
own finite native archive, object, metadata and operation limits. The receipt
reports `byte_budget_scope: "selection_and_replica_publication"` and
`native_preflight_metered: false`; it makes no whole-process byte-count claim.
One original monotonic deadline and cancellation signal still span selection,
preflight, both publications and cleanup. There is no renewed operation lifetime
after native verification.

Cancellation or failure after publishing one body retains it for an exact retry,
with the approval absent until both bodies are durable. Errors retain the strongest
observed publication state, companion path/state and any unknown native scratch.
The publisher never recursively removes native verification state or another
invocation's temporary files. Existing conflicting or corrupted outputs require
explicit operator handling; retry does not overwrite them.

This operation publishes to a local directory. For an offsite pair, the separate
[direct HTTPS publisher](SIGNED_BACKUP_HTTPS_PUBLICATION.md) performs combined
native preflight and checks both remote bodies before a fresh approval. [Direct
HTTPS acquisition](SIGNED_BACKUP_HTTPS_ACQUISITION.md) downloads both pinned
bodies and uses this paired publisher to verify and publish them locally.
Replenishment, scrub and sealed jobs still use their source-only contracts;
passing them a source candidate does not carry or validate its LFS companion.
Complete capsule recovery, other external artifacts and global checkpoint
currentness remain outside this operation.

The dedicated `scripts/tests/repository-backup-replication-lfs.test.mjs` suite
uses real Ed25519 signatures, files and subprocesses, with an explicitly labelled
native protocol peer. It covers both Git hash labels, highest-checkpoint refusal,
exact copied bytes, source loss, unchanged-inode retries, byte limits, aliases,
substitution, cancellation, unknown native scratch and CLI handoff. The peer is
not a Rust archive decoder or a native restore drill; those claims require an
independently qualified real `fg` run.

`scripts/lib/repository-backup-replication.mjs` publishes another exact copy of
an independently approved native backup. It selects the highest uniquely signed
checkpoint from an explicit candidate set using the existing selector. A missing
or corrupt copy may use an identical signed replica; a lower checkpoint is never
a fallback. It reauthenticates the exact selected envelope and trusted key before
touching the destination. There is no signing-key input and no re-signing.

The caller provides an existing owner-private local directory. A 64 KiB buffer
streams the archive into an exclusive temporary file. Its hash and exact length
must match the signed statement. The body is synchronized and linked create-only
to its SHA-256 name; the published body is read back, then its file and directory
are synchronized. Only then is the original approval envelope published through
the existing synchronized, create-only control-file primitive. Its filename binds
the original envelope bytes, not a newly canonicalized interpretation.

The output `candidate: {input, approval}` is directly consumable by the existing
selector and approved native verify/restore path. The native verifier remains
mandatory; this command does not parse native archives, restore a node, advance
an authority head, or prove that the signed claims match native repository state.
It does not establish the newest global checkpoint or complete capsule recovery.

## Retry and failure boundary

Exact existing files are read back and synchronized rather than rewritten.
Conflicting files, symlinks, substituted source bytes, changed directory identity,
and changed approval bytes refuse. An identical concurrent publisher may win;
the losing operation must verify the winner's bytes. There is no overwrite,
automatic destination deletion, directory scan, or repair of a corrupt existing
file. A missing body below an identical approval can be recreated from the signed
original bytes without changing the approval.

A cancellation before approval publication may leave a valid, unadvertised body.
Retrying the same signed checkpoint reuses it. Failures include publication state
and known candidate paths; a visible body or approval is never treated as rollback.
Cleanup removes only this invocation's still-identifiable temporary file. Process
kill or physical crash can leave private temporary files; a later invocation does
not claim ownership of, or automatically remove, another invocation's leftovers.
Different checkpoints have different paths; no mutable `latest` pointer exists.

The archive-size ceiling and whole-operation payload-read budget are separate.
The latter includes selection, streaming copy, destination readback, and retry
reads. Small approval/key reads and one-byte EOF probes are separately bounded.
Replication passes the separate size and aggregate read limits to selection: an
archive of size N can reject one corrupt copy, authenticate its healthy alias,
copy it and read back the destination within exactly 4N payload bytes. The same
operation with a 4N-1 budget refuses before staging. Increasing the aggregate
budget never permits an archive above the per-archive size ceiling. Standalone
selector callers retain the previous shared-budget default unless they explicitly
supply the bounded `maximumReplicaBytes` option.
One monotonic deadline and cancellation signal span the operation. Progress
callbacks are trusted local observers and must return: arbitrary caller code is
not preempted or sandboxed. A late failure after confirmed publication includes
the completed result rather than implying no publication occurred.

## Applicability

This is a trusted-local POSIX filesystem operator surface, not a production Rust
storage backend or multi-region replication protocol. It requires no-follow
opens, create-only hard links, file and directory synchronization, and private
owner-controlled directories. Named/opened inode checks detect observed changes;
they do not isolate malicious same-user writers or guarantee remote filesystem
semantics. Successful synchronization means OS/filesystem acknowledgments, not a
hardware-power-loss proof. Tests use real files and Ed25519; neither mocked native
receipts nor filesystem tests constitute native restore acceptance.

## Command-line use

Create or choose a private destination directory on a filesystem supporting the
required POSIX operations. Keep the public trust key and minimum generation
independent of the candidate archive and approval.

```sh
node scripts/replicate_repository_backup_native.mjs \
  --candidate /source/repository.backup /source/repository.approval \
  --trust-key /trusted/operator-ed25519.pub \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --replica-directory /private/backup-copies \
  --max-archive-bytes 1073741824 \
  --max-total-read-bytes 4294967296 \
  --timeout-secs 300
```

The command returns JSON containing `candidate.input`, `candidate.approval`,
the pinned approval/key binding, read accounting, and whether each file was
created or reused. Repeat the same command for an exact retry. A returned
candidate can be used as the `--candidate ARCHIVE APPROVAL` pair in
`scripts/select_repository_backup_native.mjs select`, `verify`, or `restore`;
the latter two retain their independent native verification requirements.

Errors retain `publication_state`, known `replica` paths, and cleanup/retained
scratch information. A failed result-pipe write after completion also carries
`completed_result`. Neither loss of stdout nor a caller disconnect proves that
no replica was published. SIGINT/SIGTERM request cooperative cancellation and
owned-descriptor cleanup; a hard process kill can leave unadvertised scratch.

All reused output files must be owner-private and singly linked as well as
byte-identical. This does not change, weaken, or replace the native authority,
retention, archive-parser, or restore admission policies.

Focused verification:

```sh
node --test --test-concurrency=1 \
  scripts/tests/repository-backup-replicas.test.mjs \
  scripts/tests/repository-backup-replication.test.mjs \
  scripts/tests/repository-backup-replication-cli.test.mjs \
  scripts/tests/repository-backup-replication-budgets.test.mjs
```

The CLI tests execute actual Node commands, feed their published candidates into
the actual selector, and kill/reap separate Node processes during streaming and
after body durability. The resumed CLI must preserve already-published body
inodes and must not delete a killed process's private staging files. These are
operator/process-crash tests; Rust, actual `fg` restore, hardware faults, and the
whole-workspace gates remain separate evidence requirements.

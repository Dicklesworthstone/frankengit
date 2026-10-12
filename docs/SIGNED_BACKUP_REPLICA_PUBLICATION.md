# Signed backup replica publication

Related: `frankengit-root-doctrine-x2mv.4.21` (partial, not closed).

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

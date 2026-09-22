# Resuming an interrupted repository source restore

This extends the FG-033a source-recovery transport described in
[REPOSITORY_SOURCE_BACKUP.md](REPOSITORY_SOURCE_BACKUP.md). It does not change
FGSRC001, canonical bodies, repository generations, or the source backup scope.
The default `restore` still requires a new destination and refuses any existing
path. Only an explicit `--resume` can continue an owned restore directory:

```sh
cargo run --locked -p fgit-node --bin fg-repository-backup -- \
  restore ./source-backup.fg ./recovered-node --trusted-local \
  --expected-sha256 "$INDEPENDENTLY_TRUSTED_SHA256" \
  --destination-instance "$ORIGINAL_DESTINATION_INSTANCE" \
  --resume --timeout-secs 1800
```

Use the **same trusted checksum and destination instance as the first attempt**.
The archive may move to another input pathname, but its complete bytes must still
match the independently retained pin. A new explicit invocation has a new finite
resource/deadline envelope; there is no implicit or unlimited retry loop. Changing
a resource limit does not change the intended repository snapshot.

## What can resume

An immutable `.restore-intent` is synced before any authority import or Git
object placement. It contains exactly 48 bytes: `FGRES001` (8 bytes), the trusted
archive SHA-256 (32 bytes), and the destination store instance (big-endian u64).
It binds the request; it **does not attest to progress or success**. An empty,
truncated, unsupported, mismatched, or absent intent refuses. Interrupted roots
created by older binaries without an intent are deliberately not adopted.

A retained `.restore-lock` file is exclusively locked through `File::try_lock`
for restore execution. A competing cooperating restore refuses rather than
waiting indefinitely or disturbing the current owner. The operating-system lock
is released on handle/process exit; the file is never deleted to break a lock.
Unsupported locking/filesystems fail closed. This is an advisory coordination
boundary, not protection against hostile same-UID path replacement. Do not run
node services or externally mutate a root while it is being restored.

The retry derives the phase from data and re-verifies it:

| Observed state | Behavior |
|---|---|
| Intent only, or wholly rolled-back authority | Import into the reserved quarantine using the original destination instance. |
| Exact committed authority, partial Git object placement | Reuse the authority receipt, verify the full archive graph, and admit missing/identical objects through the existing fabric. |
| Objects or closed WAL moved, final authority absent | Return these fixed paths to quarantine **before opening the database**, then reverify and prepare again. |
| Final authority already installed | Verify the entire authority image and all selected objects read-only. Do not import, republish, or repair it. |
| Different or advanced authority, conflicting data locations, damaged objects | Refuse and preserve evidence. No rewind, merge, overwrite, or silent repair. |

Whole-image comparison is important: matching head bytes alone does not rule
out a missing immutable body, a different historical issuance row, or extra
staged authority state. `resume_portable_import` and `verify_portable_import`
compare the full bounded image in one SQL transaction under the existing
operation lease. Source tokens are compared through their original coordinates
and expected destination reminting. Exact retries return the same destination
receipt and issue no new token. The strict original `import_portable` API remains
non-idempotent on occupied destinations. Source provenance is still caller-owned.

## Publication and failure boundaries

A preparation now **moves** the closed WAL rather than retaining two hard links
to it. Each move therefore has one source/destination location for restart.
Resume checks all relevant path types/collisions first. Both locations occupied,
a WAL without its database, unexpected public sidecars, or moved data without
quarantine refuse instead of guessing which state is newer. The engine, not a
filesystem heuristic, handles any rollback journal inside the private image.
A still-unresolved rollback journal after node close blocks final publication.

Final authority remains the last installed data path. The private quarantine is
now retained until final-location reopen verification and node shutdown finish;
publication alone cannot delete recovery evidence. A crash after the authority
link or a lost success response can be resolved by the same explicit resume.
If the published repository has accepted new work in the meantime, resume
refuses even when its old source snapshot is otherwise valid.

All streaming passes retain the original input handle and checksum requirement.
No checkpoint skips graph, selection, commitment, EOF, or storage readback checks.
Already-published mode does not recreate a missing or corrupt object. A success
receipt adds `resume_requested` and `already_published` booleans; these describe
this invocation, not a new canonical state. The intent and lock files remain so
another lost-response retry can verify the result again.

Routing, external-effect workers, credentials, external artifacts, signatures,
and full service readiness remain outside this command. Operator review before
serving remains mandatory. The lock does not make unrelated node tools cooperate.

## Tests and validation scope

```sh
cargo test --locked -p fgit-authority-fsqlite --lib portable_store::resume
cargo test --locked -p fgit-node --bin fg-repository-backup
cargo test --locked -p fgit-node --test repository_backup_resume
cargo test --locked -p fgit-node --test repository_backup_command
cargo test --locked -p fgit-node --test repository_backup_large
```

The new tests cover complete-image retry, extra/newer state refusal, interrupted
SQL staging, cancellation/bounds, exact marker framing, ownership locks, every
object/WAL move prefix, conflicting paths, and delayed cleanup. Real node tests
stop the production restore at eight boundaries in both native hash domains,
resume from the backup alone, and compare the full destination image across
repeated retries. Additional cases cover partial object placement, corruption
without repair, and accepted post-restore work that must not be rewound. Actual
command tests exercise completed retries and cross-process lock exclusion.

These Rust tests were authored but not executed in the editing environment,
which lacks Rust/Cargo. This is not a Rust pass, exhaustive process-kill campaign,
power-loss filesystem proof, or a new durability/RPO/RTO claim. Opaque filesystem
fixtures prove ordering only when run; real engine tests own the database claim.

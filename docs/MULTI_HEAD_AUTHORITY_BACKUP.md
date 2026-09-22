# Multi-head embedded authority backup

`fg-authority-backup --all-heads` exports every occupied authority head slot,
all immutable authority bodies, and the entire interleaved version-token
issuance ledger in one SQL snapshot. It does not choose a preferred head or
silently omit a secondary slot.

This is embedded metadata recovery, not a complete service or multi-repository
Git-object backup. An authority slot may belong to a repository or another
subsystem; its key and body remain opaque here. Whole-store export is a
trusted-local operator operation on the embedded backend, not a remote
read/disclosure API. The ordinary authority contract still has no listing API.

## Commands and compatibility

```sh
cargo run --locked -p fgit-node --bin fg-authority-backup -- \
  export ./authority.fsqlite ./all-heads.backup \
  --trusted-local --all-heads

cargo run --locked -p fgit-node --bin fg-authority-backup -- \
  restore ./all-heads.backup ./restored-authority \
  --trusted-local --all-heads \
  --expected-sha256 "$INDEPENDENTLY_TRUSTED_SHA256" \
  --destination-instance "$UNUSED_DESTINATION_INSTANCE"

# Resume an interrupted attempt or resolve a lost success response.
# Reuse its ORIGINAL destination instance; do not choose another one.
cargo run --locked -p fgit-node --bin fg-authority-backup -- \
  restore ./all-heads.backup ./restored-authority \
  --trusted-local --all-heads --resume \
  --expected-sha256 "$INDEPENDENTLY_TRUSTED_SHA256" \
  --destination-instance "$ORIGINAL_DESTINATION_INSTANCE"
```

Use `--all-heads` on both export and restore. Without it, the existing single-head
`authority-export` major 1 behavior is unchanged and multi-head live stores refuse.
With it, major 2 is selected explicitly. Neither decoder falls back to the other.
`--resume` is accepted only for `restore --all-heads`; duplicate flags refuse.
The default restore still requires a new directory. Legacy directories without
the original all-heads intent cannot be adopted, even if their database looks valid.

The `authority-export` schema family and registered backup-export identity domain
are reused; major 2 replaces the optional single head with an ordered head sequence.
The SQL schema generation remains 1. Canonical keys, body bytes and head generations
are preserved. This does not change repository-head or transaction schemas.

`FGSRC001` and `fg-repository-backup` remain separate, single-head source transports.
This flag does not add their Git object inventory, choose retention roots, or
certify auxiliary index artifacts. Object fabric, external artifacts, signing
keys, credentials, workspaces, process state and routing are not included.

## Whole-image validation

Body and head keys must be strictly increasing. Duplicate and misordered keys
refuse rather than being sorted or deduplicated. Binary keys and bodies survive
byte-for-byte. The ledger has one contiguous global issuance sequence starting
at 1. Every token must equal its source-instance/sequence minting coordinate.
Missing rows, foreign tokens, duplicate sequences and truncated tokens refuse.

Each head has its own strictly increasing generation history. Generations
`5, 1, 9, 2` are valid for alternating slots progressing `5 -> 9` and `1 -> 2`.
Each row must belong to an included head, and each head must match the exact
bytes, generation and token of its own latest issuance row. A superseded secondary
head refuses even when the primary head and whole-file checksum are valid.
Validation uses O(issuance rows * log(heads)) binary-search lookups and O(heads)
additional tail storage. This is an algorithmic bound, not a benchmark result.

Backend export preflights row counts and byte lengths in the same SQL snapshot
as the ordered payload reads. An operation lease excludes command interleaving
on that connection. Import requires a wholly empty destination and a distinct
store identity. Bodies, the reminted ledger and all heads commit in one SQL
transaction. An uncertain COMMIT never proves no state was written.

Tokens are reminted using original global issuance sequences, not head ordinals
or generations. Source receipts do not authenticate at the destination. The next
ordinary write continues after the restored maximum sequence. Globally unused
instance selection remains the operator's responsibility; difference from this
one archive cannot establish uniqueness across installations.

`resume_multi_head_import` and `verify_multi_head_import` compare the complete
intended image in one SQL transaction. Exact retries return the same destination
receipts without adding rows or issuing tokens. Resume can import an entirely
empty image; verify never initializes one. Extra bodies, altered history, missing
heads and later secondary-head updates all refuse. These are not repair or merge
APIs, and a matching current head alone is insufficient.

## Private restoration and explicit resume

Checksum, format, lineage and capacity checks precede destination changes. The
command retains the decoded snapshot rather than reopening the input by pathname.
It reserves the following operational paths, none of which is canonical authority:

- `.restore-lock`: a retained file with an exclusive OS-owned lock. Another
  cooperating restore refuses immediately; process/handle exit releases the lock.
- `.authority-restore-intent`: an immutable, atomically published 48-byte binding:
  `FGARM002`, the trusted archive SHA-256, and destination instance as big-endian u64.
- `.authority-restore-quarantine`: created and synced before the intent. Only this
  private database may be initialized or continued by an unpublished retry.

The marker grants no proof of progress. Every attempt checks the original pin,
instance and complete data again. A missing, malformed, mismatched or foreign
intent refuses. The archive may move to a new pathname, but its bytes must match
the same independently retained checksum. There is no automatic retry loop.

A fresh restore imports into quarantine, verifies the whole image, closes the
store/runtime, reopens through a new connection/runtime, verifies it again and
closes again. Only then is a remaining closed-image WAL synced and moved to the
public root. A nonempty rollback journal refuses publication; the process-local
shared-memory cache is not copied. `authority.fsqlite` is hard-linked into its
previously absent final location last. A final-location reopen, whole-image
verification and shutdown precede cleanup and a success receipt.

When final authority is absent, resume first returns any moved WAL beside its
quarantined database, before the engine opens it. Conflicting WAL locations, a
sidecar without its database, or unexpected path kinds refuse. The engine owns
rollback-journal recovery; file heuristics never interpret transaction contents.
An exact committed quarantine reuses its receipts. An entirely rolled-back image
can be imported again. A partially occupied or different image is not filled in.

When final authority exists, resume only verifies it: no import, republish or
canonical repair. New accepted work, even on just one secondary head, refuses.
Quarantine remains until final verification and shutdown finish. Cleanup removes
only fixed owned staging names; unknown files remain and prevent directory removal.
Intent and lock files remain for another lost-response retry.

The quarantine predates the durable intent. Therefore, an intent with neither
quarantine nor final database is damage, not a new attempt: resume refuses to
recreate a lost completed database from an older snapshot. Older interrupted
images lacking this evidence are deliberately not guessed into a recoverable state.

Errors distinguish a final authority path that is absent from one already visible.
Neither an error nor directory existence proves whether a private SQL import
committed. A failure after final publication never claims rollback or deletes the
public target. Receipt-output failure does not undo a completed restore.

## Operational boundary and limits

Keep the destination offline and its parent paths trusted and stable. The restore
lock excludes cooperating restore commands, **not ordinary node services**.
Node-wide shared/exclusive storage-lifecycle coordination is not implemented by
this command. This is not hostile same-UID filesystem containment or a new
cross-filesystem/power-loss durability profile. Routing and workers are never
activated. Restored outbox state and external dependencies need operator review.

The existing limits are unchanged: 64 MiB serialized input/output, 64 MiB aggregate
variable fields, 100,000 issuance rows and 4,096 head slots. Default backend limits
add 65,536 immutable bodies and 1 MiB per body. Codec/runtime limits may refuse
sooner. Library head-count configuration has a hard ceiling of 65,536. A retry
gets its own finite runtime contexts, not permission to increase data limits or
skip checks. No whole-command wall-clock or measured-memory claim is made here.

Receipts retain `authority_multi_head_backup_export` / `authority_multi_head_backup_restore`,
`schema_version: 1`, and `format: "authority-export-v2"`. Counts do not collapse
several generations into one misleading `head_generation`. Restore additionally
reports `authority_installed_last`, `resume_requested` and `already_published`,
alongside `all_heads_verified` and `reopened_and_verified`. These describe this
scoped operation, not signatures, Git-fabric completeness or service readiness.

## Verification

```sh
cargo test --locked -p fgit-authority-fsqlite --lib portable_store::multihead
cargo test --locked -p fgit-node --bin fg-authority-backup
cargo test --locked -p fgit-node --test authority_backup_multihead
cargo test --locked -p fgit-node --test authority_backup_resume
cargo test --locked -p fgit-node --test authority_backup_command
```

The added recovery tests stop the production driver at seven boundaries and retry
from the archive alone, including after final publication and after cleanup. They
check unchanged receipts and ledger length, empty images, partial occupied images,
extra bodies, advanced secondary heads, lost completed databases, wrong intents,
WAL move interruption, path conflicts, unknown-file preservation and lost output.
Command processes exercise repeated retries, moved input paths and lock exclusion.
These returned-interruption tests are not an exhaustive process-kill campaign.

Rust tests are authored but not executed in the editing environment, which has no
Rust compiler or Cargo. Python checks exercised SQLite process exit before/after
commit, WAL relocation/publication, actual OS locks and no-replace links, plus Rust
lexical delimiters and receipt JSON. SQLite is a reference here, not FrankenSQLite;
none of these results establishes Rust compilation, crash conformance, power-loss
safety, benchmarked performance or full-service recovery readiness.

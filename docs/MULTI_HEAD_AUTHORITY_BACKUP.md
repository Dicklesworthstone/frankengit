# Multi-head embedded authority backup

`fg-authority-backup --all-heads` closes the single-head limitation of the
embedded metadata backup path. It exports every occupied authority head slot,
all immutable authority bodies, and the entire interleaved version-token
issuance ledger in one SQL snapshot. It does not choose a preferred head or
silently omit a secondary slot.

This is an extension of the embedded portable-store recovery implementation,
not a complete service or multi-repository Git-object backup. An authority slot
can belong to a repository or another subsystem; its key and body remain opaque
at this boundary. The normal authority contract still has no public listing or
scan capability. Whole-store export is a trusted-local operator operation on
the embedded backend, not a remote read/disclosure API.

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
```

Use `--all-heads` on **both** commands. Without the flag, the existing single-head
`authority-export` major 1 format and behavior remain unchanged. Major 1 still
refuses a live store with multiple heads. With the flag, the new major 2 decoder
is selected explicitly. Neither decoder falls back to the other after a failure.
There is no automatic upgrade or rewriting of old archives or stored bodies.

The `authority-export` schema family and registered backup-export identity domain
are reused; major 2 replaces the optional single head with a sequence of head
records. The SQL schema generation stays 1. Canonical database body bytes, keys,
and head generations are preserved. This format version does not change the
repository authority-head or transaction schemas.

The source backup transport `FGSRC001` and `fg-repository-backup` remain separate
and single-head. The flag does not add multiple-head support to their Git object
inventory, choose retention roots, or certify that auxiliary index artifacts
have been backed up. External artifacts, object fabric, signing keys, credentials,
workspaces, process state and routing are not included.

## Whole-image validation

Immutable body keys and head keys must be strictly increasing. Duplicate keys
and misordered keys are refused rather than sorted or deduplicated. Binary opaque
keys and bodies survive byte-for-byte.

The complete ledger has one contiguous global sequence, starting at 1. Every
token must equal the source-instance/sequence coordinate that the embedded token
mint would issue. A wrong instance, wrong sequence, truncated token, duplicate
sequence or missing issuance row is rejected.

Each head has its **own** strictly increasing generation history. For example,
issuance generations `5, 1, 9, 2` are valid when the writes alternate between two
slots: `5 -> 9` and `1 -> 2`. A global-generation check would wrongly refuse this
ordinary history. Every issuance row must belong to an included head, and every
head must match the exact token, generation and bytes of its own latest issuance
row. A previously valid but superseded secondary head therefore fails validation,
even when the other head and the whole-file checksum are valid.

Validation uses binary search over the sorted head keys and one tail ordinal per
head: O(issuance rows * log(heads)) lookups and O(heads) additional tail storage,
not a full ledger scan for every head. Actual performance has not been benchmarked.

## Export, atomic import and retries

The backend preflights row counts, aggregate field lengths and maximum body sizes
inside the same SQL transaction as the ordered payload reads. The operation lease
prevents other callers sharing the connection from interleaving commands into the
snapshot. Cancellation and failed rollback retain the existing connection recovery
rules; an unfinished transaction cannot be exposed as a completed backup.

Import requires an empty destination and a distinct destination store identity.
Emptiness includes the immutable-body, head and issuance tables. A damaged store
with only a ledger row is not considered empty. All bodies, the complete reminted
ledger and every head are staged in one transaction and become visible together.
A failure after attempting COMMIT remains an unknown publication, not evidence
that no head was written.

Tokens are reminted using each original **global issuance sequence**, not the
head's ordinal or its generation. Source receipts consequently do not authenticate
at the new destination. The next ordinary head write continues after the restored
maximum global sequence. Choosing a globally unused destination instance is an
operator obligation; merely differing from this archive's instance cannot prove
uniqueness across other installations.

The library offers `resume_multi_head_import` and `verify_multi_head_import`.
They compare the complete intended image in one SQL transaction. Exact committed
retries return the original destination receipts without appending rows or issuing
tokens. Resume may import an entirely empty image; verify never initializes one.
Any extra immutable body, changed historical ledger entry, missing head or advanced
head refuses. These APIs do not merge, repair or roll back existing stores.

The command currently performs **fresh-directory restore only**, not command-level
resume. It verifies the complete imported image, closes the store and runtime,
then opens a fresh connection/runtime and verifies that persisted image again.
Only after close, runtime drain and directory synchronization does it emit success.
Existing directories and backup files are never overwritten. A failed restore
retains its directory for investigation; its presence proves neither success nor
non-commit. A receipt-output failure likewise does not undo an import or export.

All filesystem operations require trusted, stable parent paths. Keep the restored
store offline and do not concurrently mutate it during import and verification.
This is not containment against hostile same-UID filesystem changes. The command
never activates routing or workers; restored outbox state and external dependencies
require operator review before any service is started.

## Independent bounds and receipt fields

The command uses a 64 MiB serialized input/output ceiling, a 64 MiB aggregate
variable-field budget, at most 100,000 issuance rows and at most 4,096 head slots.
Portable and backend limits both apply: with the current default authority profile,
immutable bodies are capped at 65,536 and each body at 1 MiB. Canonical-codec and
runtime limits can refuse earlier. These are separate dimensions; increasing one
through library configuration never automatically raises another. The library's
head-count configuration has a hard ceiling of 65,536. No unbounded profile or
partial/truncated backup is accepted.

Successful all-heads receipts use `authority_multi_head_backup_export` or
`authority_multi_head_backup_restore`, receipt `schema_version: 1`, and
`format: "authority-export-v2"`. The format major and receipt schema version are
different contracts. Receipts include `heads`, `bodies`, `issuance_rows`, source
instance and checksum; they do not collapse several generations into one misleading
`head_generation`. Restore also includes the destination instance and
`all_heads_verified` / `reopened_and_verified`. Signature, Git-fabric and routing
non-claims are explicit. Successful export is a snapshot observation, not a claim
that the source cannot advance afterward.

## Verification

```sh
cargo test --locked -p fgit-authority-fsqlite --lib portable_store::multihead
cargo test --locked -p fgit-node --bin fg-authority-backup
cargo test --locked -p fgit-node --test authority_backup_multihead
cargo test --locked -p fgit-authority-fsqlite --test export_import
cargo test --locked -p fgit-node --test authority_backup_command
```

The added Rust cases cover both schema versions, every truncation of a fixture,
strict ordering, per-slot generation histories, exact limits, cancellation,
transaction abandonment, queued writers, source-token rejection, whole-image
retry and secondary-head advancement. The command integration creates an actual
two-head disk store, exports it, removes the isolated source, restores using the
archive alone, and attempts new writes to both restored heads. Refusal twins use
recomputed checksums around malformed/missing/stale secondary-head histories and
require that no destination directory be created.

These Rust tests were authored but not executed in the editing environment,
which has no Rust compiler or Cargo. Python specification tests, seeded history
checks, SQLite reference transaction/isolation checks, and source checks were run;
they do not establish a Rust pass, FrankenSQLite crash conformance, power-loss
safety, measured memory/throughput, or full-service recovery readiness.

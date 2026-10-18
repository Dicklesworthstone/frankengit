# Approved native source recovery

The operator command `scripts/restore_repository_backup_native.mjs` and the
selected-checkpoint adapter call the existing native `fg backup verify` and
`fg backup restore` engines. They do not decode an archive or publish authority.
This is the source-recovery portion of `frankengit-root-doctrine-x2mv.4.21`, not
complete signed-capsule or external-artifact restoration.

## Signed execution, not just a signed preflight

The operator authenticates the original DSSE envelope, independent Ed25519 public
key, namespace, generation floor and archive bytes. It copies the authenticated
envelope and public key into exclusive mode-0600 files under one mode-0700
private directory. Both native phases receive those same copies and all seven
native approval flags: `--approval`, `--trust-key`, `--tenant-id`,
`--repository-id`, `--incarnation-id`, `--object-format` and
`--minimum-head-generation`. No signing/private key enters the native process.

The operator rechecks the owned files before submission. Native signed mode
independently verifies them, checks the archive and observes approval expiry
immediately before its authority publication boundary. The operator accepts
only a signed receipt with the exact statement, trusted key, generation floor
and native ownership binding. There is no unsigned fallback for an older binary
that rejects these flags or returns an unsigned receipt.

`approval_effect_time_enforced: true` describes this native expiry observation;
it does not promise an external key-revocation lease or retroactive rollback.
A successful publication cannot be reclassified as prevented because approval
expires while its receipt is being delivered. Interrupted or malformed native
replies remain unknown, not evidence of rollback.

## Exact restart identity

New operator restore records use `repository_backup_restore_approval_v2`. In
addition to the destination, instance, policy and signed statement, the record
contains `native_signed_mode: true` and `approval_binding_sha256`. The binding
matches the native implementation in
`crates/fgit-node/src/source_retrieval/backup/repository/approval.rs`; it commits
to the original envelope bytes, trusted SPKI key and independent policy.
Even changing insignificant envelope whitespace changes the native resume
identity. Keep the original approval file intact for an explicit `--resume`.

Resume compares the existing private record before starting native preflight.
Changed bindings and all version-1 records are refused without overwriting the
record, attempting unsigned mode or altering the destination. This includes
version-1 records from older operator versions: they are not automatically
upgraded or assumed to describe a native signed intent. The native restore
engine still independently checks its own immutable `.restore-intent`.

## Ownership and failure diagnostics

All operator phases share one bounded lifetime; native work is not granted a
fresh whole-operation budget after preflight. Once the child has closed, only
the two owned control files are removed. Unexpected files and native diagnostic
scratch are never recursively erased by the adapter.

If child containment fails, the control files remain available for diagnosis,
while the operator closes its own file descriptors. Errors expose
`approval_scratch` and `cleanup_error` where applicable. Cleanup failure after a
confirmed native result retains `state: complete` and `native_receipt` rather
than claiming either rollback or an entirely successful operator cleanup.
Never serve an incompletely verified root or replay restored outbox effects
automatically. Full capsule, routing and external-artifact claims remain false.

## Executable checks

```sh
node --test tests/operator/repository-backup-native-approval-bridge.test.mjs \
  tests/operator/repository-backup-native.test.mjs
```

These tests exercise actual filesystem ownership, cryptography, command processes,
input substitution, receipt checks and restart guards. Their native protocol
peer is explicitly fake; it does not prove Rust archive or authority behavior.
The same target includes an opt-in real-`fg` export, signed restore and exact
resume test, enabled by `FG_NATIVE_BIN=/absolute/path/to/fg`. Without that binary
it is explicitly skipped. Native integration and the broader recovery acceptance
must be evaluated separately; this operator increment does not close the bead.

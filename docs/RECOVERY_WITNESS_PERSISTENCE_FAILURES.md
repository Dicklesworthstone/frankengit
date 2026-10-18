# Failed checkpoint-witness persistence

Related bead: `frankengit-root-doctrine-x2mv.4.21` remains partial.
This extends the failure behavior of [the retained checkpoint witness](RECOVERY_CHECKPOINT_WITNESS.md)
and [offsite-to-native recovery](OFFSITE_NATIVE_RECOVERY.md). The version-1 witness
bytes, signature rules, independent key and minimum-generation policy are unchanged.

## A failed update cannot authorize an older restart

Once an authenticated newer checkpoint, same-generation conflict, or independently
increased floor requires persistence, failure anywhere in that persistence leaves
the previously acquired witness lease blocking. This includes initial state checks,
temporary-file creation/write/readback/sync, root replacement, directory sync, and
owned-file cleanup. All owned descriptors are still closed. A failed operation
cannot release the lease and let a subsequent invocation silently reinterpret the
older on-disk state as its complete recovery knowledge.

The prior implementation poisoned the in-process handle on some write errors, but
then removed the cross-process lease. A failed temporary-file sync could therefore
leave the old witness readable by a fresh operation. A regression over real files
and signatures demonstrates that the old implementation allowed the integrated
recovery path to download and invoke its native-schema verifier for the older
checkpoint; the corrected implementation refuses before those effects.

The original filesystem error remains primary even if temporary cleanup also
fails; `witness_cleanup_error` records the secondary error. The error carries
`witness_lock_retained: true` and `witness_publication_state`:

- `not_published`: root replacement was not submitted;
- `publication_unknown`: replacement was submitted but did not return success;
- `visible_completion_incomplete`: replacement returned success, but the operation
  did not finish all required readback, synchronization or cleanup.

A failed rename is not treated as proof that it made no change. Its temporary and
root names are left for inspection, not automatically deleted or rolled back.
There is no lock stealing, PID/age heuristic, automatic reset or unsigned repair.
Normal commands continue to refuse a retained lease. The operator must resolve
storage and retained-evidence uncertainty independently before resuming; merely
removing the lock is not evidence that an older checkpoint is acceptable.

## Ownership and ordinary failures

Returning from a consumer callback stops acceptance of new observations, but an
already owned observation is drained through its verification and persistence
before the lease is released. An unawaited write is not cancelled just because the
callback returned. A persistence failure during drain remains a failure and keeps
the lease. Any already returned consumer result is retained in `completed_result`,
not discarded as though its effects were rolled back.

Invalid signatures do not become persistence obligations. Ordinary consumer,
network, or cancellation errors **after successful witness persistence** continue
to release the lease after owned work drains. Recorded high-water evidence still
blocks older checkpoints. The change does not turn every acquisition failure
into a permanently locked witness.

The `recover_repository_backup.mjs` error protocol includes the witness publication
state alongside retained-lock and cleanup information. Its native completion and
exit-code rules remain unchanged: a witness write error alone is not native
completion and does not authorize restore.

## Evidence scope

Run `node --test scripts/tests/repository-backup-witness-durability.test.mjs`.
The tests use actual private files, Ed25519 signatures, fresh CLI processes and
bounded fault injection at filesystem boundaries. They include valid retries,
newer/conflicting/floor write failures, primary/secondary error preservation,
ambiguous replacement, descriptor closure and owned-write drain. Fault injection
is test-only; production accepts no injected storage adapter or fake receipt.

These are trusted-local filesystem/operator guarantees under the existing stable
owner-controlled-directory assumptions. They do not prove physical power-loss
survival, a hostile administrator's inability to replace witness storage, remote
currentness, Rust/native authority behavior or complete capsule/forge restoration.
The native subprocess used by the integration fixture is explicitly not Rust fg.

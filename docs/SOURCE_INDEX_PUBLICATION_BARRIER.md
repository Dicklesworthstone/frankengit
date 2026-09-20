# Write-ahead source-index publication

The native `build_source_index_guarded_local_in`,
`refresh_source_index_guarded_local_in`, and
`reconcile_source_index_guarded_local_in` entrypoints expose the original
candidate before any index payload staging or root publication by that
invocation. The caller supplies a bounded synchronous callback which must
finish its durable write-ahead recording before returning `Ok(())`.

The source tree, postings, catalogs, source stamp and candidate are prepared
and verified by the same implementations used by the existing APIs. The
callback receives the derived generation identity by value and cannot change
the source, explicit predecessor, or prepared bytes. Returning an error stops
before all successor puts. A current-index reconciliation no-op does not call
the barrier at all. Existing APIs delegate with a no-op callback and preserve
their original contracts; HTTP search acquires no write capability.

A successful callback is not evidence of activation. All subsequent publication
errors retain `SourceIndexPublication { candidate, error }`, including cancellation
before the first put. A confirmed activation has no subsequent callback, await,
or cancellation probe. Original-candidate recovery remains necessary after an
uncertain reply. No negative history observation becomes rollback evidence.

This closes the missing-candidate crash window for a controller that durably
records the barrier before allowing publication. It does not itself manage
process ownership, progress files, durable source retention, retry a candidate,
or promise automatic recovery from every crash. A callback must not claim a
successful durable write before its storage contract has completed. Callback
I/O is synchronous and bounded by the operator; it is not preemptible or a
new asynchronous runtime.

Six native integration tests in `source_index_checkpoint.rs` cover SHA-1/SHA-256
barrier rejection and success, lost activation receipts with a saved candidate
and actual reopen, callback-triggered cancellation, refresh and no-op behavior,
stale reconciliation, and unpolled/invalid/exhausted preparation. They use the
existing native node and file-backed authority harness, not a replacement store.
Rust/Cargo are unavailable in the implementation environment: these tests and
native compilation have not been executed here. Static diff/blob checks do not
substitute for native, durable, full-workspace or release verification.

```bash
cargo test --locked -p fgit-node --test source_index_checkpoint
cargo check --locked -p fgit-node --all-targets
```

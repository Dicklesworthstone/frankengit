# Checkpointed symbol-index maintenance

`fg-index-maintain --symbols` maintains `rust-declaration-tables-v1` indexes for
an explicit set of visible refs in an existing node. It uses the same bounded
foreground controller, progress codec, exclusive ownership, write-ahead barrier
and cancellation-drain loop as lexical maintenance. It is not a second daemon,
a new async runtime, a repository transaction, or an HTTP write capability.

## Run and resume

```bash
cargo build --locked -p fgit-node --bin fg-index-maintain
install -d -m 0700 "$SYMBOL_STATE_DIR"
# Initialize durable progress and reconcile one pass.
fg-index-maintain --symbols "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  "$SYMBOL_STATE_DIR" init 1 0 refs/heads/main
# Resume the same ref set, making 60 bounded passes 30 seconds apart.
fg-index-maintain --symbols "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  "$SYMBOL_STATE_DIR" resume 60 30 refs/heads/main
# In another shell, request cancellation and drain without killing the process.
touch "$SYMBOL_STATE_DIR/stop"
```

Use `sha256` for that repository format. The leading `--symbols` is explicit;
omitting it retains lexical maintenance and its existing command grammar.
Each invocation admits 1-32 full refs, 1-3600 passes and at most 24 hours of
scheduled waits. A multi-pass invocation requires a positive interval. A host
scheduler can start subsequent finite `resume` invocations after the previous
process has exited; overlapping invocations refuse the existing `run.lock`.
There is no implicit ref discovery, scope widening or automatic initialization
of missing resume progress. A retained `stop` file prevents work until the
operator removes it after the previous process has quiesced.

## Independent identity and durable responsibility

Use a separate private state directory for each index profile. Lexical progress
keeps its exact existing namespace and v1/v2 bytes. Symbol progress adds the
`symbols1` profile binding to tenant, repository, incarnation and native object
format. Resuming either profile with the other's checkpoint fails before any
index work, even when the ref set and generation digest width are identical.
The index generation itself still authenticates the parser/index profile and
source namespace. Local progress never grants repository authority.

For each reference, reconciliation authenticates current canonical visibility
and resolves the retained index checkpoint before choosing one of three paths:

- Genuinely uninitialized, without a checkpoint: build genesis.
- Current source-bound manifest: return the existing activation without staging,
  reading source blobs, or advancing the generation.
- Stale index: incrementally refresh the exact observed predecessor against the
  pinned source, reusing verified unchanged-blob tables.

Current no-op observations verify the generation and manifest, not every table;
they are not a full corruption audit. Refresh verifies every distinct predecessor
table. Missing/corrupt backing, unavailable checkpoints, source movement and
limits remain errors, not cache misses or permission to switch to a new basis.
Explicit `fg-symbol-index build` and `refresh INDEX_TOKEN` retain their existing
semantics; reads never perform maintenance.

The worker persists `preparing` before invoking native reconciliation. A native
publication barrier durably replaces it with the original candidate before any
table/manifest write or index-root update. Confirmed activation is acknowledged
only after durably recording the new checkpoint. Stop handling cancels the
existing request and continues polling its future until the native owner returns;
it does not drop an in-flight operation or renew its request budget.

On restart, recorded candidates use the symbol owner's read-only recovery path.
Confirmed active/superseded candidates can be acknowledged; uninitialized or
not-in-selected-history observations stay pending and do not trigger a rebuild.
Recovery and new preparation are separate attempts. Ambiguity and cancellation
never prove rollback. Only a definite failed-precondition/CAS result from that
same invocation permits clearing its matching recorded candidate. A checkpoint
write failure or unexpected post-barrier error preserves the lock for inspection.
Stale locks and interrupted checkpoint replacements are not automatically removed.

## Output and validation

JSON lines retain `type: index_maintenance`, add `index_kind: symbols` (or
`lexical`), identify the raw ref as hex, and distinguish `observed_current`,
`recovered`, `pending`, `refused`, `recovery_unavailable` and
`preparation_recovered`. Successful observations include the independent index
token/number and source token/commit. `repository_transaction_created` is false.
A pending/refused pass returns a failing process status without erasing its
checkpoint. Successful shutdown and progress release are explicit.

```bash
bash scripts/verify_symbol_index.sh native
bash scripts/verify_symbol_index.sh maintenance
```

The native group covers symbol reconciliation and the existing source/index
suite. The maintenance group executes the actual worker binary, progress codec,
real symbol restart tests and retained lexical worker/restart tests. It covers
source edits, stable no-op checkpoints, cross-profile refusal, lost activation
acknowledgements, unpublished candidates remaining pending, stop controls and
stale locks in real file-backed nodes. Lost replies are simulated; this is not a
power-loss or adversarial storage campaign. Results must be read at their exact
revision; test presence is not evidence of execution.

This connects the maintenance worker previously listed as a remaining symbol
integration gap in `PERSISTENT_SYMBOL_INDEX.md`. In-file incremental parsing,
global postings, compaction, richer language semantics and broader FG-032
requirements remain separate. FG-032 is not closed by this slice.

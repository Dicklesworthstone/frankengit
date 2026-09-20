# Bounded automatic source-index maintenance

`fg-index-maintain` reconciles explicitly configured references against canonical
current source, with bounded foreground polling, operator-owned durable progress,
anti-rollback checkpoints and cooperative stop/drain. It is not an outbox event
consumer: several source writes may coalesce into one refresh, and intermediate
revisions need not be indexed. Repository refs/events/decisions and outbox
acknowledgements are untouched. Search requests remain read-only. FG-032 is open.

## Run an explicit scope

The worker opens an EXISTING node. Its progress directory must already exist,
be a real private directory (0700), and be protected from other writers. The
progress-storage profile is Unix-only and uses SHA-256 generation identities
at canonical codec v1; unsupported profiles refuse instead of falling back.

```bash
cargo build --locked -p fgit-node --bin fg-index-maintain
mkdir -m 700 "$PROGRESS_DIR"
fg-index-maintain "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  "$PROGRESS_DIR" init 60 10 refs/heads/main refs/heads/release
```

This runs at most 60 passes with a 10-second delay AFTER each completed pass,
in raw reference order. Use `sha256` for that repository format. A single pass
uses `1 0`. Limits remain 32 unique refs, 3600 passes, 3600 seconds per delay and
24 hours of configured inter-pass waits. These are schedule/work bounds, not a
total-runtime guarantee. Every attempt uses one original finite node-owned
BackgroundController context; a draining attempt never renews its context.

Use `resume` with the same directory and EXACT ref set after a clean stop.
Namespace binding includes tenant, repository, incarnation and object format.
Missing, malformed, foreign, reordered or truncated progress refuses; `init`
refuses an existing checkpoint. No repository is created or reset.

Create `$PROGRESS_DIR/stop` for cooperative stop. Neither its contents nor any
symlink target is read. The controller checks between attempts, during runtime
waits, and while a native future is pending. It cancels the original context,
continues polling the same future, and explicitly shuts down the node. It never
drops an active operation. Confirmed publication wins over a later stop. The
250 ms timer is not a latency SLO: bounded synchronous work is not preemptible.
SIGKILL/default OS termination is not this drain protocol.

## Candidate recording BEFORE publication

Maintenance now calls `reconcile_source_index_guarded_local_in`, which carries
one write-ahead barrier through both native build and refresh. After complete
verified preparation, and BEFORE any successor index put or root write, the
barrier durably records the ORIGINAL candidate. A failed barrier prevents those
native effects and stops the worker, preserving the lock and suspect files.
The existing explicit build/refresh/query APIs and HTTP permissions are unchanged.

The progress codec is `frankengit-index-worker-v2`. It retains the same namespace,
ordered references, exact generation floor and original position, and separates:

* **Preparing (`p`)**: the guarded attempt has not passed its durable candidate
  barrier. After exclusive process ownership is independently recovered, resume
  may abandon this phase without lowering the floor, report
  `preparation_recovered`, and begin a fresh bounded attempt.
* **Pending candidate**: the candidate was synchronized before the first possible
  index effect. A lost activation reply therefore cannot lose its recovery ID.
  Direct success must name that exact candidate; verified recovery may instead
  acknowledge a newer head substantiating its superseded membership.
* **Legacy running (`1`)**: an older unguarded attempt may already have published
  without recording a candidate. It remains blocked for operator inspection,
  never reclassified as safe preparation. Idle remains marker `0` without a
  pending candidate. Contradictory states are refused.

Strict v1 checkpoints are accepted without changing their floor, pending ID or
legacy-running meaning. The next successful save emits v2. Old readers refuse
that new version; downgrading cannot silently reinterpret guarded preparation.
No repository or lexical-index wire schema changes are involved.

Before native work, the worker saves Preparing. Within the native barrier it
replaces that marker with Pending and synchronizes the replacement file and its
directory before returning success. Only then can native staging/publication
begin. After confirmed publication or a no-op, it saves the verified checkpoint
before emitting the JSON acknowledgement. A failed save is fatal, not a normal
refusal permitting further work. Output/shutdown failures never imply rollback.

A returned definitive failed-precondition/CAS result can clear this invocation's
matching candidate, preserving its floor. Other publication failures keep the
already durable pending ID; they no longer depend on saving an ID after an
error returns. Unexpected failures after candidate recording also retain it.

Later pending passes perform original-candidate read-only recovery. Active or
superseded membership permits checkpoint advancement and clearing Pending.
Uninitialized or `NotInSelectedHistory` results do NOT prove cancellation of an
earlier write: Pending remains and that ref receives no new build. Other refs
can continue. Recovery and fresh native publication are separate attempts.
A candidate recorded before an effect that never happened may consequently need
operator intervention; this change does not promise all-crash automatic recovery.

## Ownership, freshness and remaining deployment limits

`run.lock` excludes another progress writer; it is not an index lease or
repository authority. It is never stolen or expired. A crash leaves it behind.
An operator must independently establish that the previous process is dead and
inspect `checkpoint` and any `checkpoint.next` before recovering ownership.
Leftover replacement files are never silently overwritten. The new Preparing
semantics do not authorize deleting a live owner's lock or resetting a floor.
The directory is trusted operator state, not a hostile same-user filesystem
sandbox. Simultaneous live-server/worker use of the same backend remains an
integration scenario requiring the real backend lane.

Current canonical visibility precedes index disclosure. A verified current index
is a no-op, without source-blob or posting scans or an index-root advance; it is
not a full segment-integrity scrub. An uninitialized index builds; a stale one
refreshes with exact path/blob posting reuse. Source movement or a conflicting
checkpoint refuses rather than selecting a new basis inside that attempt. HTTP
queries remain stale until maintenance catches up. `observed_current` describes
the selected observation, not guaranteed freshness when stdout is written.

Output is bounded JSON per result, with raw reference hex and available source/
index identities. `preparation_recovered` is not itself an index-freshness claim.
Any refusal, unresolved candidate, controller or shutdown failure yields nonzero
exit status. Holding a checkpoint does not pin source/index payloads against GC.

## Verification

The standalone command executes the actual std-only production progress module:
12 retained tests plus 8 new tests for v1 migration, guarded phases, exact
candidate acknowledgement, all prefix truncations, synchronized arm/reopen,
failed checkpoint writes and independent ref progress. Six native barrier tests
and four new operator-restart tests cover native lost replies, restartable
preparation, legacy refusal and pending-without-publication behavior. The latter
reuse real node/TreeFS/Fsqlite and progress-file implementations; lost replies
are explicit simulations, not a power-loss or hostile-filesystem campaign.

Rust/Cargo are unavailable locally. Native tests, native compilation, runtime
drain, durable-backend, Clippy and full-workspace/release gates remain unverified.
The repository-owned standalone progress lane may run independently on the
pinned nightly; its result is not a native-node/full-system pass.

```bash
./scripts/verify_index_maintenance.sh
cargo test --locked -p fgit-node --test source_index_checkpoint --test source_index_worker_checkpoint
cargo test --locked -p fgit-node --bin fg-index-maintain
cargo test --locked -p fgit-node --test source_index_reconcile --test source_index_worker
cargo check --locked -p fgit-node --all-targets
```

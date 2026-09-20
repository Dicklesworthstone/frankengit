# Bounded automatic source-index maintenance

`fg-index-maintain` composes the native reconciler with a foreground polling
controller, operator-owned durable progress, anti-rollback checkpoints, and
cooperative stop/drain. It keeps explicitly configured references indexed after
source or forge writes without granting index writes to search requests.

This is a current-state catch-up controller, not an outbox event consumer.
Several source writes can coalesce into one refresh. It does not acknowledge
outbox entries, claim to index every intermediate revision, or modify repository
refs/events/decisions. FG-032 remains open.

## Run an explicitly bounded scope

The worker opens an EXISTING node. The progress directory must already exist,
be a real private directory (mode 0700), and be protected from other writers.
The initial profile is Unix-only and uses generation codec v1/SHA-256. It rejects
unsupported platforms/profiles; no weaker checkpoint fallback is selected.

```bash
cargo build --locked -p fgit-node --bin fg-index-maintain
mkdir -m 700 "$PROGRESS_DIR"
fg-index-maintain "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  "$PROGRESS_DIR" init 60 10 refs/heads/main refs/heads/release
```

This runs at most 60 passes with a 10-second delay AFTER each completed pass,
over the two named refs in raw-byte order. Use `sha256` for that repository
format. A single pass uses `1 0`. There are at most 32 unique configured refs,
3600 passes, 3600 seconds per delay, and 24 hours of configured inter-pass waits.
These are work/schedule bounds, not a guarantee about total elapsed runtime;
each native attempt additionally has its finite background-controller budget.
No work is spawned outside the node-owned runtime.

Restart a cleanly stopped worker with the same directory and EXACT reference
set, using `resume` instead of `init`. Namespace binding includes tenant,
repository, incarnation and object format. Resume refuses missing, malformed,
foreign, truncated, reordered or mismatched progress rather than resetting it.
Init refuses an existing checkpoint. The tool never creates a repository.

Create `$PROGRESS_DIR/stop` to stop cooperatively. The file's contents and any
symlink target are never read. The controller checks between attempts, during
runtime-owned waits, and while an awaited native operation is pending. It
requests cancellation on that operation's original context and continues
polling until the node returns; it does not drop an in-flight future. A confirmed
publication wins over a later stop. Synchronous bounded work cannot be forcibly
interrupted by a timer, so the 250 ms check interval is not a stop-latency SLO.

The worker then explicitly shuts down the node. SIGKILL/default OS termination
is not this drain protocol and leaves local responsibility markers behind.
No signal-handler or crash-containment guarantee is claimed.

## Checkpoints and unresolved responsibility

The local `checkpoint` is controller progress, never repository authority.
All authority and source facts are independently revalidated by native APIs.
It retains a minimum generation identity AND original authority position for
each configured ref. A missing index under a retained floor cannot cause a new
genesis, and an older or conflicting index cannot be acknowledged as current.

Before invoking maintenance, the worker records a write-ahead `running` marker.
After success, it persists the verified checkpoint before writing the JSON
acknowledgement. Replacement writes a new bounded file, synchronizes it, renames
it over the old checkpoint, and synchronizes the containing directory. A
checkpoint-write error stops the worker and leaves its ownership lock; it does
not claim rollback of an already confirmed index activation.

A publication error retains the exact candidate as `pending`, except for the
three explicitly identified failed-precondition/CAS-race outcomes. Those are
returned as refusals and can be reconsidered in a LATER independent pass, never
by refreshing the predecessor inside an in-flight operation.

For a pending candidate, later passes perform read-only original-candidate
recovery. Active or superseded membership permits clearing that pending record
and retaining the verified current head as the new floor. An uninitialized head
or `NotInSelectedHistory` is NOT proof that an earlier in-flight write failed:
the candidate remains pending, and that reference receives no new build. Other
configured references can continue. Recovery and a new build are separate passes.
Unexpected publication failures are conservatively retained, which can require
operator intervention even when a lower-level failure preceded the root write.

The controller uses `run.lock` solely to exclude another progress writer. It
never steals or expires a lock. A crash leaves it behind. After independently
establishing that the prior process is no longer running, an operator must
inspect its checkpoint and any `checkpoint.next` before deciding how to recover
local ownership. A durable `running` marker without a candidate blocks automatic
resumption: the API does not yet expose a pre-publication candidate hook that
would let the worker resolve every such crash automatically. Do not erase or
lower checkpoints to make a refusal disappear. Interrupted replacement files
are never silently overwritten.

Progress locking is not a distributed index lease or a replacement for the
index authority CAS. The directory is trusted operator state, not a sandbox for
hostile same-user filesystem races. Multi-process live-node serving alongside
this worker remains an integration scenario requiring the real backend lane;
this implementation session has not established that deployment claim.

## What each pass does

Current source/index metadata produces a no-op, with no source-blob scan or
index-root advance. An uninitialized index builds its verified native inventory;
a stale index refreshes with exact path/blob posting reuse. Current hidden-ref
policy precedes index disclosure, and build/refresh retain exact source pins.
A current-metadata no-op is NOT a full segment-integrity scrub.

Each attempt uses one original finite background-controller context. An expired
context is not renewed while work drains. Fresh contexts belong to separately
configured attempts/passes. HTTP search remains read-only and continues to
refuse stale indexes until a maintenance activation catches up. Existing
explicit-predecessor `fg-index build`, `refresh`, `query`, and `recover` contracts
are unchanged.

Output is one bounded JSON line per observed result, with raw reference hex,
source/index identities when available, and an explicit state. `observed_current`
means current at the selected source observation, not an assertion that source
could not change before printing. Exit status is nonzero after any refusal,
unresolved candidate, controller failure or shutdown failure. Progress/output
failures and stop requests cannot turn confirmed publication into rollback.

## Verification boundary

The production std-only progress module has twelve tests covering exact codec
roundtrips, namespace/ref-set binding, all prefix truncations, malformed records,
monotone checkpoints, write-ahead and pending states, real filesystem save/reopen,
exclusive/stale locks, interrupted replacement and symlink refusal. Four binary
unit tests cover bounded arguments, identity conversion and race classification.
Three native binary integration tests execute the actual operator against the
file-backed node for both hash formats, restart/no-op, stop, missing resume and
stale-lock refusal. The native reconciler has seven separate integration tests.

The implementation environment has no Rust/Cargo. These Rust tests, compilation,
rustfmt, Clippy, native-runtime drain, durable-backend behavior and full-workspace/
release gates were not executed here. Shell syntax, source inspection and Git
blob comparisons do not substitute for them. The standalone lane below executes
the actual progress module, not a rewritten model or a substitute native store:

```bash
./scripts/verify_index_maintenance.sh
cargo test --locked -p fgit-node --bin fg-index-maintain
cargo test --locked -p fgit-node --test source_index_reconcile --test source_index_worker
cargo check --locked -p fgit-node --all-targets
```

The accompanying Actions file is only an optional adapter to the repository-owned
standalone command on the pinned nightly. It is not a dependency for correctness
or release, and a progress-module pass is not a native-node or full-system pass.

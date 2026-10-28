# Bounded automatic source-index maintenance

`fg-index-maintain` and the opt-in HTTP maintenance service reconcile explicitly
configured references against canonical current source. They share one bounded
native controller, operator-owned durable progress, anti-rollback checkpoints
and cooperative stop/drain. Polling does not consume outbox events: several
source writes may coalesce into one refresh, and intermediate revisions need
not be indexed. Repository refs/events/decisions and outbox acknowledgements
are untouched. Search requests remain read-only. FG-032 remains open.

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

## Maintain indexes while serving HTTP

The HTTP server can own lexical and Rust-symbol controllers throughout its
serving lifetime. Enable one profile or both, with a fixed set of refs. Each
controller opens a separate node-owned database/request lane against the same
existing repository, using the listener's exact repository incarnation and
inherited runtime policy.

```bash
mkdir -m 700 "$PROGRESS_DIR"
fg serve-http "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" 127.0.0.1:8080 \
  --trusted-local --credentials-file "$CREDENTIALS_FILE" \
  --allow-source --allow-receive --continuous --stop-file "$HTTP_STOP_FILE" \
  --index-state-dir "$PROGRESS_DIR" --index-state init \
  --index-profile lexical --index-format sha1 \
  --index-ref refs/heads/main --index-ref refs/heads/release \
  --index-interval-secs 5 --index-attempt-timeout-secs 300
```

Use `--index-profile symbols` for Rust declarations, and `sha256` for that
repository's object format. The source grant and scoped credential table remain
required. This configuration does not grant remote index writes. Use
`--index-state resume` after a clean stop, with the same directory, profile,
format and exact ref set. Do not reuse one progress directory for another
profile or run a second live maintenance owner against it.

### Keep combined lexical and symbol queries current

Select `--index-profile both` to maintain both channels in the same HTTP
service. Supply a separate existing private directory for each profile:

```bash
mkdir -m 700 "$LEXICAL_PROGRESS_DIR" "$SYMBOL_PROGRESS_DIR"
fg serve-http "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" 127.0.0.1:8080 \
  --trusted-local --credentials-file "$CREDENTIALS_FILE" \
  --allow-source --allow-receive --continuous --stop-file "$HTTP_STOP_FILE" \
  --index-profile both --index-format sha1 --index-state init \
  --index-state-dir "$LEXICAL_PROGRESS_DIR" \
  --index-symbol-state-dir "$SYMBOL_PROGRESS_DIR" \
  --index-ref refs/heads/main --index-interval-secs 5
```

`--index-state-dir` owns lexical progress in this mode, and
`--index-symbol-state-dir` owns symbol progress. The extra symbol directory is
required for `both` and rejected for a single profile. Neither directory is
created, cleared or repurposed by the server. The two controllers share the
explicit ref set, object format, init/resume choice, interval and attempt timeout;
their generation floors, pending candidates and ownership locks remain separate.
Resume uses the same two directories and the same scope.

To add symbols to an existing lexical deployment, stop the server, retain its
lexical progress and create the new private symbol directory. Initialize only
that missing profile with the finite worker, using the same object format and
complete ref set (this example has one SHA-1 ref):

```bash
fg-index-maintain --symbols "$NODE_ROOT" "$TENANT_HEX" "$REPOSITORY_HEX" sha1 \
  "$SYMBOL_PROGRESS_DIR" init 1 0 refs/heads/main
```

Then start HTTP with `--index-profile both --index-state resume`. If group
startup created one checkpoint before another profile refused, keep the existing
checkpoint, correct the refusal and initialize only the profile whose checkpoint
is missing. Omit `--symbols` when that missing profile is lexical. Existing
checkpoints, generation floors and pending candidates remain intact; `init`
continues to refuse an existing checkpoint.

Both controllers must authenticate and acquire their progress ownership before
the HTTP readiness callback runs. A launch barrier holds every controller until
that callback succeeds. Invalid second-profile progress or a readiness-output
failure therefore cannot start an index build in the first profile. Startup
failure, stop and runtime failure signal all owned controllers before joining
them, and cleanup errors remain visible alongside the original failure.

The generations still publish independently. During catch-up, a required-symbol
Initial query can refuse until both indexes match its selected source. The
service does not combine mismatched generations or turn readiness into a
freshness promise. Once both have caught up, combined search and agent-context
reads use the existing exact-source query contracts. A later source change
requires another pass.

The first pass starts after successful service readiness. The configured delay
follows a completed pass; `--index-interval-secs` accepts whole seconds from
1 through 3600 and defaults to 5. Each pass visits at most 32 references in
raw-byte order, one finite native attempt at a time. This is not a freshness
SLA: source movement, ordinary native refusals, index size/resource limits and
unresolved publication candidates may delay or prevent an index becoming
current. Queries never initiate builds themselves.

Each native attempt has a 300-second timeout ceiling by default. Use
`--index-attempt-timeout-secs` with a whole number from 1 through 3600 to select
another ceiling. The effective timeout is the smaller of that ceiling and the
inherited background-controller timeout, further met with the node root.
Existing poll, cost, priority, root and other-class limits remain unchanged.
Native checkpoints and drain observe the same original request context. A later
retry receives a new context only after the previous owner has returned.

One runtime-owned blocking child opens and runs each configured profile, with
at most two maintenance children. HTTP readiness is announced only after
repository authentication, profile/ref binding, exclusive progress ownership
and checkpoint loading succeed for every child. A missing or foreign resume
checkpoint, legacy unresolved attempt or existing stop marker prevents readiness;
it cannot silently disable a requested worker. Ordinary bounded reconcile
refusals are observations that permit a later independent pass. Fatal progress,
controller or shutdown errors retire acceptance and are returned to the owner.
The runtime must have capacity for every long-lived controller plus at least
one HTTP request lane; insufficient capacity refuses before starting workers.
The existing blocking-pool ceiling is never increased implicitly.

HTTP stop requests signal the controller, cancel its original active context
and continue polling the same future until its owner returns. The server joins
the controller before returning. Node shutdown precedes progress release, just
as in the finite command. Clean stop may retain an unresolved original candidate
for a later guarded recovery; it does not imply rollback. Service observations
use stderr so they do not corrupt the HTTP command's stdout receipt.

Embedded callers can use `fgit_node::index_maintenance::MaintenanceConfig::try_new`,
optionally select a tighter ceiling with `with_attempt_timeout`, and run
`run_service_with_ready` on their own runtime-owned blocking lane.
`MaintenanceControl::request_stop` is irreversible and cooperative; the owner
must still join the service result. The callback acknowledges startup before
any index attempt. It must not wait for this same lane to perform work.
`run_service` offers the same lifecycle without a startup callback.
`MaintenanceReceipt` counts started passes, attempts, current observations,
recoveries and refusals, plus references still pending at clean stop. These
observations are not a durable history or a promise of current source at return.
For HTTP, `MaintenanceGroup::try_new` accepts one or two configurations with
distinct profiles, separate progress directories and one object format. Existing
single-profile HTTP entrypoints accept a `MaintenanceConfig` or a group. The
`serve_repository_http_with_workflow_and_index_services_bounded` and
`serve_repository_http_with_workflow_and_index_services_until_stopped` methods
also compose a group with the native workflow controller; the original
single-profile workflow methods retain their signatures.

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

`owner.lock` is a permanent anchor with an exclusive nonblocking OS file lock;
`run.lock` is an inode-bound marker for that owner. Neither is an index lease or
repository authority. A matching crash marker can be resumed only after the
kernel grants exclusive ownership of the original anchor. Legacy, foreign or
corrupt markers still require inspection. The anchor is never unlinked, stolen
or expired, and a controller error retains its locked descriptor until process
termination. Normal release removes only the run marker after native shutdown.
Leftover checkpoint replacement files are never silently overwritten. Preparing
semantics do not authorize deleting a live owner's marker or resetting a floor.
The directory is trusted operator state, not a hostile same-user filesystem
sandbox. Live HTTP maintenance uses the same durable backend and recovery path
as the standalone worker; neither receives a second publication authority.

Current canonical visibility precedes index disclosure. A verified current index
is a no-op, without source-blob or posting scans or an index-root advance; it is
not a full segment-integrity scrub. An uninitialized index builds; a stale one
refreshes with exact path/blob posting reuse. Source movement or a conflicting
checkpoint refuses rather than selecting a new basis inside that attempt. A
changed Git source remains stale for indexed HTTP queries until maintenance
catches up. Default revalidated search may continue across forge-only authority
changes after it proves the indexed commit is still current; explicit exact
queries retain their stricter source-head pin. `observed_current` describes the
selected observation, not guaranteed freshness when the observation is emitted.

Output is bounded JSON per result, with raw reference hex and available source/
index identities. `preparation_recovered` is not itself an index-freshness claim.
The finite command yields nonzero exit status on refusal, unresolved candidate,
controller or shutdown failure. The continuous service instead retains ordinary
refusals for the next bounded pass and returns fatal lifecycle failures to the
HTTP owner. Holding a checkpoint does not pin source/index payloads against GC.

## Verification

The standalone command executes the actual std-only production progress module:
12 retained tests plus 8 new tests for v1 migration, guarded phases, exact
candidate acknowledgement, all prefix truncations, synchronized arm/reopen,
failed checkpoint writes and independent ref progress. Six native barrier tests
and four new operator-restart tests cover native lost replies, restartable
preparation, legacy refusal and pending-without-publication behavior. The latter
reuse real node/TreeFS/Fsqlite and progress-file implementations; lost replies
are explicit simulations, not a power-loss or hostile-filesystem campaign.

The in-process service has scope, budget and lifecycle cases for exact
profile/format readiness, bad or foreign resume refusal, effect-free startup
failure, and cancellation that keeps polling the original owner. Group cases
cover conflicting owners, blocking-pool capacity and startup stop with pending
recovery preserved. Timeout coverage checks inherited shorter, longer and absent
time limits without replacing other budget dimensions or classes. The HTTP
integration lane exercises both profiles simultaneously through required-symbol
Initial queries in both Git formats, native source changes, resume without
generation churn, a live second owner and global readiness-output failure before
either index can publish. CLI cases cover explicit dual-profile scope and reject
missing, duplicate, conflicting or ignored progress options.

The original standalone-worker implementation recorded no local native build
or execution. Native compilation, runtime drain, durable-backend, Clippy and
full-workspace/release claims require their own revision-bound results. The
repository-owned standalone progress lane can run independently on the pinned
nightly; its result is not a native-node/full-system pass.

```bash
./scripts/verify_index_maintenance.sh
cargo test --locked -p fgit-node --test source_index_checkpoint --test source_index_worker_checkpoint
cargo test --locked -p fgit-node --bin fg-index-maintain
cargo test --locked -p fgit-node --lib index_maintenance::service
cargo test --locked -p fgit-node --test source_index_service_http
cargo test --locked -p fgit-cli --bin fg smart_http_server::tests
cargo test --locked -p fgit-node --test source_index_reconcile --test source_index_worker
cargo check --locked -p fgit-node --all-targets
```

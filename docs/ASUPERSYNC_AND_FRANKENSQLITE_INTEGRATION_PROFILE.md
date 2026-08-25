# Asupersync and FrankenSQLite Integration Profile

**Status:** binding construction profile for planning and dependency admission; no implementation claim  
**Last source review:** 2026-08-20; §1 `fastapi_rust` and `sqlmodel_rust` rows re-audited against crates.io-published artifacts on 2026-08-23 (FG-093a); `sqlmodel_rust` re-audited 2026-08-25 against the published v0.4.1 family — prerequisite below is now satisfied (FG-093a admission)
**Owners:** `fgit-runtime`, `fgit-authority`, `fgit-projection`, and the dependency-constellation gate

This document turns the repository's “one runtime,” adopted FrankenSuite product stack, and embedded FrankenSQLite decisions into an integration contract. It complements, and does not weaken, the dependency constitution, normative protocol contracts, or the single-authority rules. Asupersync, FrankenSQLite, `fastapi_rust`, `sqlmodel_rust`, and FrankenTUI are settled architectural adoptions. If a reviewed upstream revision cannot yet satisfy this profile, FrankenGit integration remains blocked until that owned sibling is updated and re-audited; FrankenGit does not substitute another framework, create a second runtime or authority, commit an unpublished path dependency, or add a local unsafe exception.

## 1. Reviewed source snapshot and evidence boundary

The following local source snapshots were inspected to plan the first dependency constellation. They are observations of work that must converge before integration, not the final admitted pins:

| Project | Reviewed revision | Observed package/runtime constraint | Planning consequence |
|---|---|---|---|
| Asupersync | `9eb0600e6ef4d17633dff3dc43ad99c64e72adbe` | current crate release `0.4.9` | planning baseline for the one runtime; the exact integrated revision and features belong in `constellation.lock` |
| FrankenSQLite | `f99d639b019c1400e55135c8ee4ba988f2587df9` | workspace `0.3.7`; Asupersync `>=0.4.3,<0.5`, default features disabled at the workspace edge | compatible in principle with an Asupersync 0.4.x constellation, subject to the caller-profile and conformance gates below |
| fastapi_rust | `531456a62e4484d74378c7f99b822eacae66043d`; published family v0.4.3 (facade crate is `fastapi-rust`) | workspace now pins Asupersync `0.4.9` `default-features = false` — runtime convergence done; but every published `fastapi-core` 0.4.x (re-verified 2026-08-23 against 0.4.3) declares `futures-executor` as a non-optional normal dependency, an alternate runtime the constellation preflight refuses | adopted gateway; one precise prerequisite remains: upstream must make the executor optional or drop it. Gate: `suites/checker/fastapi_admission_gate.sh` FA-006 |
| sqlmodel_rust | `23da90cdfe057162d436417bbc4af7ec206ed48e`; published family v0.4.0 (`aa1c6ec`), superseded by v0.4.1 family published 2026-08-25 | v0.4.0 was runtime-converged (all 8 family crates request Asupersync `^0.4.9` `default-features = false`, no `[patch]`/absolute paths) but NOT caller-profile-converged: its facade requested the fsqlite family without `default-features = false`. **v0.4.1 (re-audited on crates.io 2026-08-25, AmberFox): `sqlmodel-frankensqlite` requests `fsqlite ^0.3.7` with `default-features = false` + `{native, async-api}`, `fsqlite-core`/`fsqlite-types` `default-features = false`; closure surface is regex/serde/serde_json/tracing plus the fsqlite family; no second runtime, no build scripts in the sqlmodel crates themselves** | adopted projection substrate; the §3.2 prerequisite is satisfied and admission proceeds through `check_sqlmodel_substrate_feature_profile` + `suites/admission/sqlmodel_dependency_admission.sh` (positive converged case) with the 0.4.0 refusal retained as the discriminating negative |
| FrankenTUI | `a136062fa3e4f325a45414d00f35e39a0de27870` | optional Asupersync executor requires `0.3.9` | adopted TUI; its owned upstream must advance to the selected one-runtime constellation before FrankenGit integration |

### 1.1 The pin of record is the crates.io checksum, not the git revision

The "Reviewed revision" column above is a **non-binding human reference**. It
names the tree a human read; it does not name what the build consumes, and
nothing verifies the two are the same artifact.

The **binding pin for FrankenSQLite is the crates.io content checksum recorded
in `Cargo.lock`**:

| Crate | Version | Binding pin (crates.io checksum) |
|---|---|---|
| `fsqlite` | `0.3.7` | `sha256:0b7b5b479b155c0c6f32a4e725d33b5b7fc89303a821566ddb0711238883847c` |

Why the checksum and not the revision, stated so this is not re-litigated: the
checksum is content-addressed and exact, cargo enforces it on every build, and a
mismatch fails closed. **The revision is published but not enforceable, and the
distinction is the whole reason it cannot be the pin.**

`cargo package` writes `.cargo_vcs_info.json` into every published crate, and
fsqlite's is present:

```json
{ "git": { "sha1": "9b1d3ed7b3cbb03675a8eeeb136099cecdf6ed0a" },
  "path_in_vcs": "crates/fsqlite" }
```

So a revision-to-release linkage does exist. It is nevertheless **a publisher
claim, not a cryptographic binding**: cargo writes that field from whatever
checkout the publisher ran it in, so anyone able to publish mislabelled bytes is
equally able to write a mislabelled revision beside them. Nothing a consumer can
compute checks it. The checksum, by contrast, *is* the bytes. Treating a
publisher assertion as a pin would record provenance the project cannot verify,
which §10 forbids.

Two measured facts a later reader should not have to rediscover, both checked
against the artifacts in the local registry rather than inferred:

- **Asupersync agrees.** `asupersync-0.4.9`'s recorded revision is
  `9eb0600e6ef4d17633dff3dc43ad99c64e72adbe`, which is exactly the reviewed
  revision in §1's table. That agreement is what makes the comparison
  meaningful; without a case that can return a match, a mismatch elsewhere would
  be indistinguishable from a broken method.
- **FrankenSQLite does not.** The table reviews
  `f99d639b019c1400e55135c8ee4ba988f2587df9`; the artifact records
  `9b1d3ed7b3cbb03675a8eeeb136099cecdf6ed0a`. The two are divergent rather than
  sequential and differ over `crates/fsqlite` by one file and one hunk —
  workspace dependencies gaining explicit versions so the crate is publishable —
  with `default-features = false` preserved on both sides. So the reviewed tree
  is close to, but is not, the built tree. That costs nothing here precisely
  because the checksum and not the revision is what binds.

Consequences, so the distinction is operational rather than decorative:

- an audit that cites the revision alone has **not** identified the admitted
  artifact; it must cite the checksum;
- a checksum change is a dependency change and requires re-admission through
  `registries/dependency_policy.tsv`, whatever the revision says;
- a revision change with an unchanged checksum changes nothing that binds;
- `registries/dependency_policy.tsv` already keys its fsqlite rows (DEP-176
  onward) on the version rather than a revision, so no registry row asserts a
  revision pin and none needed amending for this ruling.

**Retirement condition, tightened deliberately.** This paragraph is retired only
if a revision-to-release linkage becomes **verifiable by a consumer** — that is,
checkable from the artifact without trusting the publisher's own assertion about
it. Publication alone does not satisfy it and never did; the original wording
said "publishes a verifiable linkage" and could be read as met the moment
someone noticed `.cargo_vcs_info.json` exists, which is exactly the misreading
this sentence now forecloses. Even then the revision may be recorded *alongside*
the checksum, never instead of it. Ruled by GoldLotus on bead
`frankengit-z4ly`, following FG-005 bullet 7; the false premise in the original
reason was found by ChartreuseHorizon and corrected on `frankengit-aofy`.

Cargo can install multiple semver-incompatible 0.x versions, but FrankenGit may not: two Asupersync versions are two runtime/type universes even if Cargo resolves both. “The resolver found a build” is therefore not an admission result. The adopted stack cannot enter FrankenGit until repository-owned probes compile every exact feature closure against one selected Asupersync and the dependency checker verifies the resulting lockfile. Failure leaves the integration beads blocked pending sibling updates; it does not reopen the architecture decision.

The snapshots above can drift. An implementation bead must re-audit the live source and record the exact selected revisions, public-contract fingerprints, features, licenses, build scripts, proc macros, transitive unsafe, native code, and removal/port path. No release-facing FrankenGit crate may commit an absolute or unpublished sibling path.

## 2. Asupersync production profile

### 2.1 Runtime-owned contexts and capability narrowing

- The node creates production request contexts through the owning `Runtime` or `RuntimeHandle` using `request_cx_with_budget` / `try_request_cx_with_budget`. Test-only or detached constructors such as `Cx::for_testing` are not production entry points.
- Every effectful owned API accepts `&Cx` first. Callers narrow capabilities at subsystem and request boundaries; a child cannot regain a capability that its parent masked.
- Ambient wall clock, entropy, environment, network, filesystem, process, secret, billing, and publication authority are forbidden inside canonical evaluation. Where these effects are permitted, the capability and receipt are explicit.
- `Cx` identity, runtime profile identity, effective budget, cancellation reason, and relevant capability-set fingerprint are available to evidence without serializing secret material.

### 2.2 Budgets and outcomes are semantic, not decorative

- A child budget is the meet of parent and requested deadline, poll, cost, and priority limits. Code may tighten but never widen inherited limits.
- `Budget::INFINITE` is limited to a named node-root/service-root policy. Requests, parsers, transfers, repairs, projection work, database commands, and shutdown cleanup receive finite, profile-owned budgets.
- The four-way `Outcome<T, E>` distinction survives through service internals: success, domain error/refusal, cancellation, and panic/containment failure are not prematurely collapsed into `Result`.
- At protocol edges, cancellation includes commit-ambiguity metadata. After a possible head CAS or externally observed effect, callers resolve the immutable outcome instead of reporting “not committed.”

### 2.3 Ownership shapes and node lifecycle

- The long-lived node is described by `AppSpec` (or its current admitted successor), compiled before start, and owned through an explicit handle whose stop/join path reaches quiescence.
- Request fan-out uses a child `Scope`; dynamic homogeneous work uses a bounded `JoinSet`; stateful protocols use actors/`GenServer`; resource-specific cleanup uses RAII plus an obligation. These shapes are selected by ownership semantics, not convenience.
- No detached task may retain publication, object, database, network, secret, runner, or billing authority. Transfer to a longer-lived supervisor is an explicit, receipted ownership transition.
- The current library proves live restart behavior per actor. FrankenGit must not claim an unimplemented tree-wide compiled-supervisor restart contract; higher-level restart and dependency ordering remain explicit until upstream evidence exists.

### 2.4 Cancellation, obligations, and shutdown

- Cancellation is request, then drain, then finalize. Dropping a future is never the cleanup protocol.
- Effects that acquire responsibility use reserve/commit/abort and, when externally observable, acknowledge/reconcile. Region close must report zero unresolved obligations or a typed containment failure naming the owner and durable evidence.
- Runtime obligation-leak policy is configured rather than inherited accidentally. Verification/release profiles use fail-fast `Panic`. An availability-oriented service may use `Recover` only with a durable leak record, bounded cleanup, health degradation, and an escalation threshold; `Silent` is forbidden and `Log` alone cannot satisfy closure.
- Shutdown ordering is dependency-aware: stop admission, request cancellation, drain sessions and database commands, finalize/transfer obligations, close FrankenSQLite workers explicitly, flush evidence, then join the node root.

### 2.5 Runtime controls and evidence

- Worker count, queue bounds, blocking-pool limits, stack size, parking, scheduler/cohort policy, and admission mode are named profile inputs. Host-derived parallelism is an explicit opt-in and never part of replay identity by accident.
- Deterministic tests pin worker/scheduler values and record seed, virtual time, schedule identity, runtime revision/features, capability profile, and budget profile.
- Lab evidence covers logical schedule/cancellation semantics. Native evidence separately covers parked workers, OS threads, real files/sockets, blocking-pool joins, signals, and process teardown; neither substitutes for the other.
- Browser/native-WASM support is admitted by exact support class. Preview or host-driven surfaces are not described as production parity with native server primitives.

## 3. FrankenSQLite caller profile

### 3.1 Authority boundary

FrankenSQLite has two permitted roles:

1. implement the embedded `AuthorityStore` contract over the same immutable bodies and exact predecessor-token head replacement used by every backend; and
2. store disposable local projections whose rows identify the canonical head/RCR/generation through which they are complete.

It never becomes an independent repository truth source. A successful SQL commit does not publish repository state unless it is the embedded implementation of the exact authority operation. Projection tables, queues, caches, and indexes cannot authorize mutations, infer commit, extend retention, or decide deletion.

### 3.2 Minimal feature and dependency surface

- The authority adapter uses `fsqlite` with `default-features = false` and the smallest native asynchronous feature set proven by the admission gate. JSON, FTS, RTree, ICU, miscellaneous extensions, session support, RaptorQ, C API, and WASM are off unless a named consumer proves marginal need.
- Linux io_uring is a target-specific profile, not an unconditional semantic dependency. Portable fallbacks run the same contract suite. **Admission-note (2026-08-25, FG-093a):** upstream `fsqlite-vfs` 0.3.x derives `linux-asupersync-uring` from its `native` profile unconditionally, and the admitted authority-adapter closure (`fsqlite` `async-api,native`) already resolves it; the substrate caller-profile gate therefore enforces the semantic surfaces above (extensions, session, WASM) and treats the io_uring feature as in-profile parity, not a refusal reason.
- The FrankenSQLite C API and concurrent stock-SQLite access are excluded from production. Upstream SQLite/rusqlite may appear only in pinned, non-production differential lanes.
- `sqlmodel-frankensqlite` is the adopted projection convenience layer, not authority. Its exact crates and derive/query/migration behavior must pass the closed-dependency, code-generation, runtime, cancellation, and rebuild tests before integration; a failure blocks that integration pending an owned upstream correction.

### 3.3 Context, connection, and worker ownership

- Production uses the asynchronous API with a runtime-owned `&Cx`; synchronous constructors and ad-hoc runtimes are not request-path shortcuts.
- A raw `Connection` is `!Send + !Sync`. It stays on one owning worker/local lane. `AsyncConnection` owns a dedicated worker and bounded command channel; it is pooled per declared service/lane, not opened without bound per request.
- Every connection/worker has an owner, capacity limit, shutdown budget, and explicit `close(&Cx)`/join path. Drop-triggered cleanup is a backstop and cannot prove quiescent shutdown.
- A transaction is finalized by awaited `commit` or `rollback`. Drop rollback is deferred cleanup, not successful abort evidence.
- Database work inherits the request/service budget and cancellation cause. Cancellation while a command or commit may have executed returns typed ambiguity and performs the required state/outcome lookup.

### 3.4 Transaction and retry law

- Retry wraps the whole logical SQL transaction from a fresh snapshot; individual statements are not replayed into an unknown transaction state.
- Same-attempt bounded retry is limited to the reviewed transient family: `Busy`, `BusyRecovery`, `BusySnapshot`, `DatabaseLocked`, `WriteConflict`, `SerializationFailure`, and `PageBufferCapacityExhausted`, subject to operation idempotency and the remaining budget.
- `SnapshotTooOld` requires a fresh transaction/snapshot decision and is not blindly retried in place. Corruption, schema/constraint errors, invariant failures, cancellation, panic, resource ceilings, and permanent I/O errors are not converted into “busy.”
- Backoff is bounded, cancellation-aware, seeded/receipted where jitter is used, and stops before the parent deadline. Exhaustion returns a stable refusal with attempts, elapsed budget, last error class, and remediation.
- The current engine serializes part of commit validation/write/publication through a commit guard. FrankenGit may exploit parallel preparation and readers, but it does not claim lock-free or unconstrained multiwriter commit.

### 3.5 Declared concurrency envelope

The admitted caller profile publishes an explicit support matrix for:

- one connection and one writer;
- multiple connections with readers plus bounded writers;
- same-process authority CAS contenders;
- projection rebuild plus live reads/writes;
- checkpoint under load; and
- process crash/reopen/recovery.

The reviewed upstream contract does not yet support a blanket claim for ten or more concurrent implicit-autocommit writers. FrankenGit therefore caps/admission-controls its writer topology to a proven envelope or waits for the upstream four-scenario gate; it does not extrapolate from smaller tests. Multi-process writer and checkpoint claims are likewise limited to the exact tested profile.

## 4. Adopted projection substrate contract

All projection implementations expose:

- source head, RCR/decision range, schema generation, and rebuild status;
- deterministic destroy-and-rebuild behavior from canonical inputs;
- single-writer or bounded-writer ownership matching the admitted FrankenSQLite envelope;
- read snapshot/watermark semantics for APIs;
- cancellation-safe command/transaction cleanup;
- migrations as versioned derived-state rebuild operations, never canonical-history rewrites; and
- an authority-negative API: no projection handle can publish a repository decision.

The `sqlmodel_rust` integration must document its total dependency surface, proc-macro/build risk, generated-code auditability, runtime-version convergence, query determinism, connection ownership, transaction retry semantics, migration/rebuild behavior, cancellation, performance, and removal cost. These are hardening and acceptance obligations for the adopted substrate, not a framework-selection contest.

## 5. Verification obligations

### 5.1 Unit and deterministic tests

- production-context construction and capability narrowing, including planted widening attempts;
- child-budget meet, deadline/cost/poll exhaustion, and no unbounded request budget;
- four-way outcome preservation and commit-ambiguity mapping;
- `AppSpec` compile/start/stop ordering, child ownership, obligation leaks, and bounded `JoinSet`/actor mailboxes;
- cancellation at every declared await/yield and exact request → drain → finalize ordering;
- FrankenSQLite transient-error classification, whole-transaction retry, fresh-snapshot handling, explicit commit/rollback, connection affinity, pool bounds, and explicit close;
- authority CAS races with exactly one winner and stable outcome lookup;
- projection watermark, migration, wipe/rebuild, and authority-negative behavior; and
- scalar/reference equivalence and deterministic replay under fixed runtime profiles.

### 5.2 Native, crash, and end-to-end scripts

Repository-owned E2E scripts must include at least:

- runtime profile lifecycle under real worker parking, cancellation, shutdown, and obligation-leak injection;
- embedded authority kill/restart at body write, sync, CAS, acknowledgement, checkpoint, and close boundaries;
- bounded multi-connection readers/writers and CAS contenders at every claimed concurrency point;
- projection build, concurrent watermark reads, wipe, deterministic rebuild, migration failure, cancellation, and worker teardown;
- dependency-constellation probes that plant a second Asupersync, Tokio, an absolute path patch, a forbidden backend, an unsafe/build-script/proc-macro drift, and an unsupported feature; and
- cross-target feature probes for every released native/WASM target.

Each script uses the shared E2E harness, emits step-level NDJSON to stderr and an artifact file, records source/toolchain/constellation/runtime/FrankenSQLite/profile identities, commands, exit codes, durations, seeds/schedules/fault points, expected-versus-actual assertions, and artifact digests, and produces a final summary. On failure it preserves the minimal replay command, relevant state inventory, process logs, and crashpack. Skipped, unsupported, or unexercised matrix cells are terminal non-pass states.

## 6. Admission and stop conditions

Integration fails closed if any adopted path:

- resolves more than one Asupersync version or introduces Tokio/another executor;
- requires an unpublished/absolute path dependency or network acquisition during build;
- requires first-party unsafe, FFI, a native database/runtime, or a local lint exception;
- cannot accept a runtime-owned `Cx`, finite budget, explicit cancellation, and quiescent close;
- hides connection ownership, retry scope, transaction completion, or worker cleanup;
- claims a concurrency, restart, browser, or durability support class not proved by the exact selected revision/features; or
- lets a database/model/projection result become repository authority.

Passing compilation is necessary and insufficient. The gate closes only with the dependency evidence, unit/deterministic/native/crash/E2E campaigns, and exact local release-lane integration described above. A failed gate pauses FrankenGit integration and names the required sibling-project update; it does not authorize a substitute framework.

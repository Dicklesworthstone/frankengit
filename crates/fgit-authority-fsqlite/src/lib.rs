#![forbid(unsafe_code)]
//! The embedded `FrankenSQLite` profile of the `AuthorityStore` contract.
//!
//! `docs/ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md` §3.1 gives
//! `FrankenSQLite` exactly two permitted roles, and this crate is the first
//! one: implement the embedded `AuthorityStore` over the *same* immutable
//! bodies and the *same* exact-predecessor-token head replacement every other
//! backend uses. It is emphatically not the second role — nothing here stores a
//! projection, and no SQL commit in this crate publishes repository state
//! except the one that *is* the embedded authority operation.
//!
//! # What is here
//!
//! The engine-independent half of the profile:
//!
//! * `schema` — the exact DDL and the exact parameterized statement set;
//! * `token` — per-write, ABA-safe version tokens that survive kill/reopen;
//! * `retry` — the whole-transaction retry law and the closed transient family;
//! * `envelope` — the declared concurrency envelope and its admission refusal;
//!
//! and, since the `fsqlite` closure was admitted at `ffcf5f6`, the engine
//! binding itself: [`FsqliteAuthorityStore`], which executes that statement set
//! over an `AsyncConnection`.
//!
//! # What this crate does and does not claim about [`AuthorityStore`]
//!
//! The binding's operations are **async inherent methods**, because the engine
//! is async: `Connection` is `!Send`, so `fsqlite` owns it on a dedicated
//! worker and every operation is a round trip through a command channel. The
//! [`AuthorityStore`] trait is synchronous by design — it is the semantic
//! contract, and the linearizability checker must call it without a runtime.
//!
//! Those two are bridged by a blocking adapter in this crate's **test** tree,
//! and the placement bounds what may be claimed. A `block_on`-per-operation
//! bridge cannot model cancellation arriving *during* an operation. So the
//! honest claim this crate supports is that **the unchanged FG-004 suite passes
//! against the fsqlite binding under a synchronous harness** — not that the
//! binding is conformant under cancellation. Cancellation behaviour is fg005b's
//! crash and equivalence matrix, and it needs a harness that can actually
//! deliver a cancel mid-operation.
//!
//! # The measured dependency this crate is waiting on
//!
//! `fsqlite = { version = "0.3.7", default-features = false, features = ["native", "async-api"] }`
//!
//! `native` for the engine; `async-api` because it is the only source of
//! `AsyncConnection`, which §3.3 requires (a raw `Connection` is `!Send` and
//! must stay on its owning worker). `json`, `fts3`, `fts5`, `rtree`, `icu`,
//! `misc`, `session`, `raptorq` and `wasm` are off, and so is `mvcc` — an empty
//! feature with no `cfg` site in the engine's source, so enabling it would
//! imply a concurrency claim §3.5 forbids extrapolating.
//!
//! # `linux-asupersync-uring` cannot actually be turned off, and saying so
//!
//! It is off in *our* dependency line and that is not sufficient.
//! `fsqlite-vfs` defines `native = ["fsqlite-types/native",
//! "linux-asupersync-uring"]`, so `fsqlite/native` reaches
//! `fsqlite-vfs/linux-asupersync-uring` transitively; the resolved graph shows
//! `fsqlite-vfs` with `FEATURES=[linux-asupersync-uring, native]`. At 0.3.7
//! there is no way to have a native VFS without it.
//!
//! §3.2 is therefore half satisfied, and the halves are worth keeping apart:
//!
//! * the io-uring **crate** is declared
//!   `[target.'cfg(target_os = "linux")'.dependencies]`, so it really is
//!   target-specific — a non-Linux target resolves without it entirely;
//! * the **feature** is not optional on Linux, so the portable fallback cannot
//!   be exercised on Linux hardware, and any claim that both paths pass the
//!   same contract suite would be false on this host.
//!
//! That bounds what may be claimed rather than blocking the dependency, and the
//! crash and equivalence matrix must record that the Linux lane exercises the
//! uring VFS only.
//!
//! # Where the runtime enters
//!
//! Every engine operation takes a runtime-owned `&Cx`. Synchronous
//! constructors and ad-hoc runtimes are not request-path shortcuts (§3.3), and
//! the engine's `close_sync` / `close_without_checkpoint_sync` are Drop
//! backstops that cannot prove quiescent shutdown — the awaited `close(&Cx)` is
//! the only path this crate will use.
//!
//! # Journal mode, and why the checkpoint cell does not apply
//!
//! **This store never enables WAL.** It runs on the default rollback journal,
//! so there is no write-ahead log, nothing to checkpoint, and §3.5's
//! checkpoint-under-load scenario does not describe this configuration at all.
//!
//! Each link is a positive observation rather than a failed search, which
//! matters because two earlier versions of this section were wrong and both
//! rested on *not finding* something:
//!
//! * `fsqlite-pager`'s `JournalMode` declares `#[default] Delete`, documented
//!   as "the default mode";
//! * `AsyncConnection::open` delegates to `open_with_env` with
//!   `ConnectionEnv::default()`;
//! * `ConnectionEnv` carries a runtime, a page-buffer ceiling, a memory-VFS
//!   config, a strict-multi-process flag and a bounded-writer write-set
//!   ceiling — and **no journal-mode field**;
//! * this crate's complete statement set is 17 statements — 4 `CREATE TABLE`,
//!   4 `INSERT`, 7 `SELECT`, 1 `UPDATE` — and contains no `PRAGMA`.
//!
//! ## Two retracted claims, kept because the sequence is the lesson
//!
//! **First** this section said the sole checkpoint trigger was
//! `Command::Close { checkpoint }`, so the cell was unreachable by
//! construction. That came from scanning the `fsqlite` facade and calling it
//! exhaustive; `fsqlite` is a facade over fifteen crates and the WAL lives in
//! `fsqlite-wal`. *Exhaustive* is a claim about a search boundary, and the
//! boundary has to be proved before the scan means anything.
//!
//! **Then** it said checkpoints happen automatically under load, via
//! `maybe_run_adaptive_autocheckpoint`. That machinery is real — but it acts on
//! a WAL, and this store has none. Correcting one absence-scan with another
//! produced a second wrong answer in the opposite direction.
//!
//! Still true from both attempts: `Cx::checkpoint()` and
//! `checkpoint_or_interrupt` are **cancellation** polls (§3.3), unrelated to
//! the WAL. Counting them as coverage here would be a false green.
//!
//! ## What this leaves open
//!
//! The real question is upstream of the checkpoint cell: **is a rollback
//! journal intended for a durable authority store?** §3.5's envelope — several
//! connections, readers alongside bounded writers, checkpoint-under-load as a
//! listed scenario — is derived from a profile that presumes WAL concurrency,
//! and [`ConcurrencyEnvelope`] admits topologies against it. This crate does
//! not answer that, and does not assume it away.
//!
//! Recorded as `NEG-022`. If the store ever issues `PRAGMA journal_mode=WAL`,
//! the cell becomes both live *and* driveable — `PRAGMA wal_checkpoint(…)` is
//! supported and returns `busy`, `log` and `checkpointed` — and the honest
//! outcome then is a real drill, not a non-claim.
//!
//! Deliberately **not** claimed: behaviour when handed a pre-existing
//! WAL-mode database file. Journal mode is persistent in the SQLite header,
//! and whether that is detected on open was not established here.
//!
//! [`AuthorityStore`]: fgit_authority::AuthorityStore
//! [`FsqliteAuthorityStore`]: crate::FsqliteAuthorityStore
//! [`ConcurrencyEnvelope`]: crate::ConcurrencyEnvelope

mod classify;
mod engine;
mod envelope;
mod interpret;
mod lifecycle;
mod marshal;
mod portable;
mod retry;
mod schema;
mod token;

pub use crate::classify::{classify_franken_error, is_retryable_engine_error};
pub use crate::engine::{EngineError, FsqliteAuthorityStore, run_with_retry};
pub use crate::envelope::{
    ConcurrencyEnvelope, EnvelopeRefusal, MAX_ADMITTED_AUTOCOMMIT_WRITERS, WriterTopology,
};
pub use crate::interpret::{
    CasStep, DisambiguationRefusal, HeadInitStep, ObservedHead, PutStep, compare_stored_body,
    disambiguate_compare_exchange, interpret_compare_exchange, interpret_head_create,
    interpret_put_if_absent,
};
pub use crate::lifecycle::{
    CANCELLATION_PHASES, CancellationOutcome, CancellationPhase, LifecycleError, TransactionEvent,
    TransactionState, WorkerEvent, WorkerState, classify_cancellation,
};
pub use crate::marshal::{
    MarshalError, blob, read_blob, read_optional_unsigned, read_unsigned, unsigned,
};
pub use crate::portable::{
    BundleRefusal, ExportBundle, ExportedBody, ExportedHead, ExportedIssuance, MAX_EXPORT_BODIES,
    MAX_EXPORT_ISSUANCE, bundle_head_generation, export_bundle, import_bundle,
};
pub use crate::retry::{
    BackoffPlan, MAX_TRANSIENT_ATTEMPTS, RetryBudget, RetryExhausted, RetryOutcome, RetryVerdict,
    TransientClass, classify_is_retryable, decide_after_failure, retry_whole_transaction,
};
pub use crate::schema::{
    HEAD_SLOT_TABLE, IMMUTABLE_BODY_TABLE, SCHEMA_VERSION, STORE_IDENTITY_TABLE, SchemaStatement,
    VERSION_ISSUANCE_TABLE, ddl_statements, operation_statement, operation_statements,
};
pub use crate::token::{
    IssuanceRecord, IssuanceSequence, TokenMintError, mint_token, next_issuance_after,
    token_instance,
};

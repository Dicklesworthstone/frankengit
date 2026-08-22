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
//! # Journal mode: WAL, measured -- and three readings that said otherwise
//!
//! This store runs on **WAL**. Checkpoint-under-load is therefore a *live*
//! scenario, and NPC 5.2 requires that cell be exercised rather than
//! documented away.
//!
//! That single sentence took four attempts, and the first three are kept here
//! because they are the more useful half.
//!
//! ## The measurement
//!
//! `PRAGMA journal_mode` against a database created by this crate's own open
//! path answers `wal`. Upstream pins it: `fsqlite-core`'s
//! `test_pragma_journal_mode_default_is_wal_for_new_file_database` asserts both
//! the text `wal` and `pager.journal_mode() == JournalMode::Wal` for a new file
//! database (the `:memory:` counterpart reports its own mode, which is why an
//! in-memory probe would answer a different question).
//!
//! ## The three retracted readings
//!
//! 1. *"The sole checkpoint trigger is `Command::Close { checkpoint }`, so the
//!    cell is unreachable."* Scanned the `fsqlite` facade and called it
//!    exhaustive. `fsqlite` is a facade over ~15 crates and the WAL lives in
//!    `fsqlite-wal`.
//! 2. *"Checkpoints happen automatically under load."* Right mechanism,
//!    asserted without establishing the mode.
//! 3. *"There is no WAL at all."* Built on `fsqlite-pager`'s `JournalMode`
//!    being `#[default] Delete`. That is a **type** default at the pager layer,
//!    not the mode a new file database receives -- the connection layer decides,
//!    and chooses WAL.
//!
//! Reading 3 is the instructive one. It was positively enumerated over four
//! links, every link individually correct, and independently re-derived by a
//! second pane -- and still wrong, because **re-deriving a chain inherits the
//! premise the chain rests on.** Two careful people confirming each other is
//! weaker evidence than it feels like.
//!
//! The tell everyone walked past: `tests/crash_equivalence.rs` cleans up `-wal`
//! and `-shm` sidecars, which a rollback-journal store never produces.
//!
//! **The rule, stated where the next reader will need it: for a question about
//! runtime behaviour, ask the running system.** Four readings were spent on
//! something one `PRAGMA` settled.
//!
//! ## What remains open
//!
//! This crate never *states* a journal mode -- it inherits one, because journal
//! mode persists in the SQLite header and is detected on reopen. So a store
//! handed an existing file adopts that file's durability semantics rather than
//! its own. Whichever mode is right, being handed it by a file is not a design
//! decision; tracked as `frankengit-zru1`.
//!
//! Still true from the retracted readings: `Cx::checkpoint()` and
//! `checkpoint_or_interrupt` are **cancellation** polls (3.3), unrelated to the
//! WAL. Counting them as coverage here would be a false green.
//!
//! Recorded as `NEG-022`.
//!
//! [`AuthorityStore`]: fgit_authority::AuthorityStore
//! [`FsqliteAuthorityStore`]: crate::FsqliteAuthorityStore

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
    observable_cancellation_phase,
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

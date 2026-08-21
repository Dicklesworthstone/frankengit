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
//! # Permanent non-claim: checkpoint under load
//!
//! This crate makes **no claim of any strength** about WAL checkpointing while
//! the store is under load, and it never will at this dependency version. The
//! §3.5 envelope matrix lists checkpoint-under-load as one of its six
//! scenarios; that cell is **externally undriveable**, and the reason is in
//! `fsqlite`, not in this crate's surface.
//!
//! Measured against `fsqlite` 0.3.7 (exhaustive scan of every occurrence of
//! `checkpoint` in its sources):
//!
//! * the sole WAL-checkpoint trigger is `Command::Close { checkpoint: bool }`;
//! * `Command::Checkpoint` does not exist;
//! * the only public function whose name contains `checkpoint` is
//!   `close_without_checkpoint_sync`, which *suppresses* it;
//!   `close_sync_with_checkpoint` is private.
//!
//! So **every public path that checkpoints also terminates the connection, and
//! terminating it ends the load.** The scenario is not one we declined to
//! expose — it is unreachable by construction, and no method added to
//! [`FsqliteAuthorityStore`] could reach it. Adding one would be a surface that
//! cannot do what its name says.
//!
//! Two things this non-claim deliberately does *not* say. It does not say
//! checkpointing is untested — `fsqlite` tests its own close-time paths. And it
//! does not say checkpoints never occur under load; it says we cannot **drive**
//! one, so we cannot observe or bound the behaviour, and an unobservable
//! behaviour earns no claim.
//!
//! Not the same mechanism, despite the shared word: `Cx::checkpoint()` and
//! `checkpoint_or_interrupt` in `fsqlite` are **cancellation** polls (§3.3).
//! They have nothing to do with the WAL, and reading them as coverage of this
//! cell would be a false green.
//!
//! Recorded as `NEG-022` in `registries/negative_evidence.tsv` with its revisit
//! condition: if `fsqlite` ever publishes a checkpoint operation callable on an
//! open connection, this non-claim is retired and the under-load drill joins
//! the FG-005b matrix. Until then, a reader who infers coverage of this cell
//! from anything in this crate is reading something that is not here.
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

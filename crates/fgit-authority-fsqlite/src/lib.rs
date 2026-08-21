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
//! # What is here, and what is deliberately not here yet
//!
//! The backend binding needs `fsqlite`, whose transitive closure has to be
//! admitted to the closed dependency universe before it may enter the build.
//! That admission is in flight, so this crate currently contains the half of
//! the profile that does not depend on the engine at all:
//!
//! * [`schema`] — the exact DDL and the exact parameterized statement set;
//! * [`token`] — per-write, ABA-safe version tokens that survive kill/reopen;
//! * [`retry`] — the whole-transaction retry law and the closed transient family;
//! * [`envelope`] — the declared concurrency envelope and its admission refusal.
//!
//! Each is a real, tested vertical slice with its final shape, not a
//! placeholder waiting to be filled in. The remaining piece — the
//! `AsyncConnection`-owning worker that executes the statement set — lands in
//! one commit together with the `fsqlite` dependency and its registry rows.
//! **This crate does not implement [`AuthorityStore`] yet**, and says so rather
//! than shipping a stub that claims to.
//!
//! # The measured dependency this crate is waiting on
//!
//! `fsqlite = { version = "0.3.7", default-features = false, features = ["native", "async-api"] }`
//!
//! `native` for the engine; `async-api` because it is the only source of
//! `AsyncConnection`, which §3.3 requires (a raw `Connection` is `!Send` and
//! must stay on its owning worker). Every other feature is off, including
//! `linux-asupersync-uring` (§3.2 makes io_uring a target-specific profile, not
//! an unconditional dependency) and `mvcc` (an empty feature with no `cfg` site
//! in the engine's source, so enabling it would imply a concurrency claim §3.5
//! forbids extrapolating).
//!
//! # Where the runtime enters
//!
//! Every engine operation takes a runtime-owned `&Cx`. Synchronous
//! constructors and ad-hoc runtimes are not request-path shortcuts (§3.3), and
//! the engine's `close_sync` / `close_without_checkpoint_sync` are Drop
//! backstops that cannot prove quiescent shutdown — the awaited `close(&Cx)` is
//! the only path this crate will use.
//!
//! [`AuthorityStore`]: fgit_authority::AuthorityStore

mod envelope;
mod retry;
mod schema;
mod token;

pub use crate::envelope::{
    ConcurrencyEnvelope, EnvelopeRefusal, MAX_ADMITTED_AUTOCOMMIT_WRITERS, WriterTopology,
};
pub use crate::retry::{
    BackoffPlan, MAX_TRANSIENT_ATTEMPTS, RetryBudget, RetryExhausted, RetryOutcome, TransientClass,
    classify_is_retryable, retry_whole_transaction,
};
pub use crate::schema::{
    HEAD_SLOT_TABLE, IMMUTABLE_BODY_TABLE, SCHEMA_VERSION, STORE_IDENTITY_TABLE, SchemaStatement,
    VERSION_ISSUANCE_TABLE, ddl_statements, operation_statement, operation_statements,
};
pub use crate::token::{
    IssuanceRecord, IssuanceSequence, TokenMintError, mint_token, next_issuance_after,
    token_instance,
};

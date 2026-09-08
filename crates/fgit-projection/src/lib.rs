#![forbid(unsafe_code)]
//! Watermarked derived-state projection substrate (FG-093b).
//!
//! `fgit-projection` turns a caller-supplied canonical decision stream into
//! queryable derived state on the admitted [`sqlmodel_frankensqlite`] stack.
//! It cannot publish repository authority, decide retention, or authorize a
//! caller. Authorize the repository before serving a projection read.
//!
//! # Identity, reads and lifecycle
//!
//! [`ProjectionIdentity`] names the installation binding: source incarnation,
//! authority head and generation, projection/schema generations and build
//! identity. The stored watermark supplies current completeness. The identity
//! receipt's range is still its installation range; it is not an advancing
//! completeness receipt.
//!
//! [`ensure_schema_generation`] installs or reconciles a session atomically.
//! Schema, identity receipt and the empty watermark are published together.
//! Repeating an empty bootstrap is safe, and foreign source bindings are never
//! wiped. A schema change requires a matching new identity, not merely a new
//! number in an old session's request. [`ensure_schema_generation_on`] provides
//! the same reconciliation before a caller wraps its owned connection in a
//! newly bound session.
//!
//! [`apply_batch`] inserts contiguous decision records and advances the
//! watermark in the same transaction. Matching replays are no-ops; conflicting
//! digests, stale snapshots, gaps and foreign bindings refuse. Every acquired
//! transaction is explicitly finalized on the normal async return paths.
//!
//! [`read_applied_page`] reads its watermark and rows in one SQL statement,
//! verifies the source/head/generation/schema binding, and bounds result rows
//! before allocation. Orphan rows cannot extend the applied prefix. The legacy
//! [`read_applied_range`] shares these checks but returns the whole intersecting
//! range; prefer pages at service boundaries.
//!
//! # Bounded pagination
//!
//! ```no_run
//! use std::num::NonZeroU16;
//! use asupersync::Cx;
//! use sqlmodel_core::Connection;
//! use fgit_projection::{
//!     AppliedDecisionPage, ProjectionError, ProjectionPosition,
//!     ProjectionSession, read_applied_page,
//! };
//!
//! async fn first_page<C: Connection>(
//!     session: &ProjectionSession<C>,
//!     cx: &Cx,
//! ) -> Result<AppliedDecisionPage, ProjectionError> {
//!     read_applied_page(
//!         session,
//!         cx,
//!         ProjectionPosition::new(1),
//!         ProjectionPosition::new(u64::MAX),
//!         NonZeroU16::new(128).expect("positive page size"),
//!     ).await
//! }
//! ```
//!
//! Continue with the returned `next_start`, the same session binding and an
//! upper bound no greater than the FIRST page's watermark. Keeping that upper
//! bound fixed prevents a growing stream from changing the requested prefix.
//! A position cursor is not an authorization token.
//!
//! # Failure and ownership contract
//!
//! Cancellation and panic retain distinct variants and their runtime payloads.
//! [`ProjectionError::RollbackFailed`] retains the operation and cleanup
//! failures: contain and retire the connection rather than reusing it as if
//! abort succeeded. [`ProjectionError::CommitUncertain`] is not evidence of
//! non-commit: reconcile the stored prefix on a healthy connection before
//! deciding whether to replay. There are no statement-level or automatic
//! whole-transaction retries.
//!
//! The caller supplies every runtime-owned `&Cx`. [`ProjectionSession::close`]
//! consumes the session and awaits the driver's explicit close operation;
//! Drop is not shutdown evidence. A dropped future still needs the owner's
//! cancellation/drain/containment protocol.
//!
//! # Remaining integration boundaries
//!
//! This crate does not traverse chronicle/authority, produce consumer-owned
//! issue/PR/inbox/search rows, or implement a connection-pool topology. The
//! caller supplies verified [`DecisionRecord`] values; the current row model
//! indexes their sequence and digest. These APIs do not constitute an
//! end-to-end forge or a durable forge-merge publication path.

pub mod boundary;
pub mod catchup;
pub mod identity;
pub mod model;
pub mod rebuild;
pub mod session;
pub mod store;
pub mod watermark;

pub use catchup::{DecisionRecord, ProjectionConflict, apply_batch};
pub use identity::{ProjectionIdentity, ProjectionPosition};
pub use model::{AppliedDecision, AppliedDecisionPage, read_applied_page, read_applied_range};
pub use rebuild::{SchemaReconciliation, ensure_schema_generation, ensure_schema_generation_on};
pub use session::{ProjectionError, ProjectionSession};
pub use store::install_schema_statements;
pub use watermark::{Watermark, WatermarkRefusal, WatermarkState};

/// Test-only constructor so integration fixtures can build identities without
/// depending on this crate's private test modules.
#[doc(hidden)]
#[must_use]
pub fn __test_build_identity() -> identity::BuildIdentity {
    identity::BuildIdentity::current()
}

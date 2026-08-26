#![forbid(unsafe_code)]
//! Watermarked derived-state projection substrate (FG-093b).
//!
//! `fgit-projection` turns the canonical decision stream into queryable read
//! models on the admitted [`sqlmodel_frankensqlite`] stack. It is DERIVED
//! state by construction: nothing in this crate can publish repository
//! authority, decide retention, or answer authorization questions. The
//! authority-negative boundary is structural — the crate does not depend on
//! any truth-process crate, and its public surface exposes only reads over
//! watermarks it advanced itself from caller-supplied decision records.
//!
//! # The four load-bearing types
//!
//! - [`identity::ProjectionIdentity`] names the exact derived generation a
//!   session reads: source incarnation, bound authority head, the closed
//!   decision range folded so far, and projection/schema/build generations.
//!   Every read is answered from one identity; mixing generations is a typed
//!   refusal, never a silent union.
//! - [`watermark::Watermark`] is the completeness state machine. Positions
//!   advance monotonically; regressions and gaps are typed refusals, because
//!   a projection that skipped a decision would look complete while lying.
//! - [`session::ProjectionSession`] owns the transactional envelope over any
//!   [`sqlmodel_core::Connection`]: schema install, watermark advance, and
//!   catch-up application commit together, so no reader can observe rows
//!   without the watermark that makes them authoritative-as-derived.
//! - [`catchup::apply_batch`] folds caller-supplied decision records
//!   idempotently: re-delivery of an applied sequence with the same digest is
//!   a no-op, a conflicting digest is a typed conflict, and a gap refuses
//!   instead of skipping.
//!
//! # What this crate deliberately does not do
//!
//! - No chronicle/authority traversal here: callers feed [`catchup::DecisionRecord`]
//!   values from wherever the canonical stream lives.
//! - No pool management policy beyond what [`session::ProjectionSession`]
//!   wraps; connection worker topology belongs to the integration profile.
//! - No rebuild/migration campaign tooling yet: schema generation bumps are
//!   modeled in identity, and wipe/rebuild drives land with their evidence
//!   bead (FG-093c) rather than as untested scaffolds.

pub mod catchup;
pub mod identity;
pub mod session;
pub mod store;
pub mod watermark;

pub use catchup::{DecisionRecord, ProjectionConflict, apply_batch};
pub use identity::{ProjectionIdentity, ProjectionPosition};
pub use session::ProjectionSession;
pub use store::install_schema_statements;
pub use watermark::{Watermark, WatermarkRefusal, WatermarkState};

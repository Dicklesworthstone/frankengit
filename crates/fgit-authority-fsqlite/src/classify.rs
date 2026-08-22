//! Classifying the engine's real errors into the closed transient family.
//!
//! [`crate::TransientClass`] states the *law*; this states the *mapping*, and
//! the mapping is where a retry policy actually goes wrong. §3.4 admits exactly
//! seven classes for a bounded same-attempt retry and then says what must not
//! happen to everything else:
//!
//! > Corruption, schema/constraint errors, invariant failures, cancellation,
//! > panic, resource ceilings, and permanent I/O errors are not converted into
//! > "busy."
//!
//! The failure mode is a catch-all arm that treats anything unrecognised as
//! retryable, because that turns a corrupt database into an infinite loop. So
//! the default here is [`TransientClass::Permanent`] and every retryable class
//! is named explicitly. A new engine error variant is permanent until someone
//! deliberately admits it, which is the safe direction to be wrong in.
//!
//! `SnapshotTooOld` is named separately rather than folded into either group:
//! §3.4 requires a fresh transaction and snapshot decision, so it maps to
//! [`TransientClass::FreshSnapshotRequired`] and the retry loop surfaces it to
//! the caller instead of absorbing it.

use fsqlite::FrankenError;

use crate::TransientClass;

/// Classify one engine error against the closed transient family.
///
/// Deliberately exhaustive-by-default rather than exhaustive-by-match:
/// `FrankenError` is a large upstream enum that will grow, and a `match` with
/// an arm per variant would either fail to compile on every upstream release or
/// tempt someone into a retryable catch-all. Naming the seven admitted classes
/// and defaulting everything else to permanent is both stable across upstream
/// growth and safe when it is wrong.
#[must_use]
pub const fn classify_franken_error(error: &FrankenError) -> TransientClass {
    match error {
        // The seven §3.4 admits, and only these.
        FrankenError::Busy => TransientClass::Busy,
        FrankenError::BusyRecovery => TransientClass::BusyRecovery,
        FrankenError::BusySnapshot { .. } => TransientClass::BusySnapshot,
        FrankenError::DatabaseLocked { .. } => TransientClass::DatabaseLocked,
        FrankenError::WriteConflict { .. } => TransientClass::WriteConflict,
        FrankenError::SerializationFailure { .. } => TransientClass::SerializationFailure,
        FrankenError::PageBufferCapacityExhausted { .. } => {
            TransientClass::PageBufferCapacityExhausted
        }
        // Not retryable in place: the caller must take a fresh snapshot and
        // decide again, or a stale read becomes an unbounded spin.
        FrankenError::SnapshotTooOld { .. } => TransientClass::FreshSnapshotRequired,
        // The engine explicitly declines to say whether the effect happened.
        // Neither a retry nor a failure: retrying may double-apply, and calling
        // it a failure claims a non-commit the engine refused to claim.
        FrankenError::DatabaseImagePublicationOutcomeIndeterminate { .. } => {
            TransientClass::OutcomeIndeterminate
        }
        // Everything else. Corruption, schema and constraint errors, invariant
        // failures, cancellation, resource ceilings and permanent I/O all land
        // here, and none of them is a retry.
        _ => TransientClass::Permanent,
    }
}

/// Whether the engine error may be absorbed by a bounded whole-transaction retry.
#[must_use]
pub const fn is_retryable_engine_error(error: &FrankenError) -> bool {
    classify_franken_error(error).is_retryable()
}

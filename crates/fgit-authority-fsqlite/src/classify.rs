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

/// The immutable-body key as the engine names it in a unique-index error.
///
/// This store writes that table only through `INSERT ... ON CONFLICT
/// (body_key) DO NOTHING`, so a transaction never violates the key it can
/// see. A violation therefore means one thing: a concurrent writer committed
/// the same key after this transaction's snapshot, where `DO NOTHING` could
/// not apply. That is a write conflict on one key, not a constraint the data
/// broke, and a whole-transaction retry from a fresh snapshot decides it
/// exactly (identical body: present; different body: conflict). Observed on
/// the x2mv.4.27 16-writer campaign, where it reached HTTP as a 503. Every
/// other constraint, including this column under any other name, stays
/// permanent (section 3.4).
const IMMUTABLE_BODY_KEY_COLUMNS: &[u8] = b"fgit_immutable_body.body_key";

const fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

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
        FrankenError::UniqueViolation { columns }
            if same_bytes(columns.as_bytes(), IMMUTABLE_BODY_KEY_COLUMNS) =>
        {
            TransientClass::WriteConflict
        }
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
        // Cancellation of the caller's own context. Named rather than left to
        // the catch-all because the catch-all reaches the caller as
        // `Refused(Unavailable)`, which asserts non-commit -- and §5.2 says
        // cancellation never proves non-commit. `frankengit-w1ik`.
        //
        // `Interrupt` covers both the pre-dispatch and the after-dispatch
        // cancel: `tests/cancellation_error_probe.rs` measures fsqlite
        // returning the same value for both, because the cancel is observed by
        // the caller's await rather than inside the engine. `Abort` is
        // deliberately NOT included -- it is a general engine code produced at
        // 83 sites across the fsqlite crates, and claiming all of them "may
        // have committed" would be the same error in the other direction.
        FrankenError::Interrupt => TransientClass::Cancelled,
        // Everything else. Corruption, schema and constraint errors, invariant
        // failures, resource ceilings and permanent I/O all land here, and none
        // of them is a retry.
        _ => TransientClass::Permanent,
    }
}

/// Whether the engine error may be absorbed by a bounded whole-transaction retry.
#[must_use]
pub const fn is_retryable_engine_error(error: &FrankenError) -> bool {
    classify_franken_error(error).is_retryable()
}

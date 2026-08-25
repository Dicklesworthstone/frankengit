//! Revocation evidence: the typed answer to "did you check?".
//!
//! This type is shared by every credential in this crate rather than
//! reimplemented beside each one. A deploy key and a token are revoked for the
//! same reason and by the same administrator, and giving them two vocabularies
//! for one fact is how the two halves of a revocation drift apart. This crate
//! has already paid for duplicate vocabulary twice — `PrincipalId` and
//! `PrincipalSnapshot` were each nearly rebuilt because the existing one was
//! not found — so the second consumer of a concept moves it here rather than
//! copying it.
//!
//! # Why the caller passes this in
//!
//! Nothing here consults a revocation record: this crate computes, records and
//! refuses, and the record lives above it. What the type buys is that the
//! *question* cannot be skipped silently. A caller that did not look has
//! exactly one way to say so — [`RevocationEvidence::NotChecked`] — and every
//! high-impact authorization in this crate refuses that answer instead of
//! treating it as permission.

/// Whether the caller consulted the revocation record, and what it said.
///
/// This exists so the obligation is discharged at the type level rather than by
/// a comment asking callers to remember. A comment asking callers to remember
/// is the rule that rots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationEvidence {
    /// The revocation record was consulted and this credential is live.
    Live,
    /// The revocation record was consulted and this credential is revoked.
    Revoked,
    /// The revocation record was not consulted.
    NotChecked,
}

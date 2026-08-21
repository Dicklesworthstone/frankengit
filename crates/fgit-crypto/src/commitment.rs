//! Native Git identity bound to its stronger internal commitment.
//!
//! Plan section 11.6 asks for four things from SHA-1 repositories: compute the
//! native identity exactly, run it through a collision-detecting profile, bind
//! object type, length, and exact bytes to a stronger internal payload
//! commitment, and fail closed on suspicious collision evidence.
//!
//! This module is the third and part of the fourth. The pieces already existed
//! separately — `GitOid::of_object` and `git_payload_commitment` — but nothing
//! held them together, so "bind" was left to every caller's memory.
//! [`GitObjectCommitment`] computes both from one pass over the same bytes and
//! keeps them in one value, and [`GitObjectCommitment::check_consistent_with`]
//! turns the second observation of an identity into a typed refusal when the
//! two observations do not commit to the same bytes.
//!
//! # What this does and does not detect
//!
//! It detects a collision **that has actually been observed twice**: a store
//! that records commitments alongside identities refuses the moment a second
//! object claims an identity it already holds under a different commitment.
//! Since SHA-256 is the commitment construction, producing two objects that
//! agree on both digests is not a SHA-1 attack but a SHA-256 one.
//!
//! It does **not** inspect a single message for collision evidence. That is
//! the `sha1dc`-class detector behind [`crate::Sha1CollisionDetector`], which
//! this crate does not yet ship — see that module for the reason. The two are
//! complements, not substitutes: a detecting profile catches the first half of
//! a collision pair on arrival, while this catches any pair a store ever holds
//! both halves of, including pairs produced by an attack nobody has published
//! disturbance vectors for.

use core::fmt;

use fgit_types::identity::InternalObjectId;
use fgit_types::numeric::CodecVersion;

use crate::body_identity::{git_payload_body, git_payload_commitment, lowercase_hex};
use crate::native::{GitHashAlgorithm, GitObjectKind, NativeObjectIdentity};

/// A disagreement between two observations of one native object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeCommitmentError {
    /// Two observations share a native identity but commit to different bytes.
    ///
    /// This is collision evidence. For a SHA-1 repository it means the native
    /// identity has been forged; the objects are not interchangeable and
    /// neither may silently replace the other.
    IdentityCollision {
        /// The native identity both observations claim.
        identity: String,
        /// Commitment of the object already held.
        held: String,
        /// Commitment of the object just observed.
        observed: String,
    },
    /// The two observations are of different objects.
    ///
    /// Not collision evidence — a caller compared two unrelated objects, which
    /// is a question this type refuses rather than answers.
    DifferentIdentities {
        /// Identity of the object already held.
        held: String,
        /// Identity of the object just observed.
        observed: String,
    },
}

impl fmt::Display for NativeCommitmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityCollision {
                identity,
                held,
                observed,
            } => write!(
                formatter,
                "native identity {identity} was observed with two different payload commitments: held {held}, observed {observed}"
            ),
            Self::DifferentIdentities { held, observed } => write!(
                formatter,
                "these observations are different objects: held {held}, observed {observed}"
            ),
        }
    }
}

impl std::error::Error for NativeCommitmentError {}

/// One Git object's native identity together with the stronger internal
/// commitment over the same framed bytes.
///
/// The commitment covers the object type, the decimal length, and the exact
/// content, because its canonical body *is* Git's framed object preimage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GitObjectCommitment<A: GitHashAlgorithm> {
    identity: A::Oid,
    commitment: InternalObjectId,
    kind: GitObjectKind,
    length: u64,
}

impl<A: GitHashAlgorithm> GitObjectCommitment<A> {
    /// Compute both identities over one object.
    #[must_use]
    pub fn of_object(kind: GitObjectKind, content: &[u8], codec_version: CodecVersion) -> Self {
        let length = u64::try_from(content.len())
            .expect("a slice length always fits in u64 on supported targets");
        Self {
            identity: A::Oid::of_object(kind, content),
            commitment: git_payload_commitment(kind, content, codec_version),
            kind,
            length,
        }
    }

    /// Reconstruct a commitment recorded earlier.
    ///
    /// A store reads these back; it does not recompute them from bytes it may
    /// no longer hold.
    #[must_use]
    pub const fn from_parts(
        identity: A::Oid,
        commitment: InternalObjectId,
        kind: GitObjectKind,
        length: u64,
    ) -> Self {
        Self {
            identity,
            commitment,
            kind,
            length,
        }
    }

    /// The native Git identity.
    #[must_use]
    pub const fn identity(&self) -> &A::Oid {
        &self.identity
    }

    /// The stronger internal commitment over the framed object.
    #[must_use]
    pub const fn commitment(&self) -> &InternalObjectId {
        &self.commitment
    }

    /// The object type committed to.
    #[must_use]
    pub const fn kind(&self) -> GitObjectKind {
        self.kind
    }

    /// The content length committed to.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Check a newly observed object against one already held.
    ///
    /// Fails closed on collision evidence rather than choosing a winner: a
    /// caller that holds two objects under one identity must not silently keep
    /// either.
    pub fn check_consistent_with(&self, observed: &Self) -> Result<(), NativeCommitmentError> {
        if self.identity != observed.identity {
            return Err(NativeCommitmentError::DifferentIdentities {
                held: lowercase_hex(self.identity.digest_bytes()),
                observed: lowercase_hex(observed.identity.digest_bytes()),
            });
        }
        if self.commitment == observed.commitment {
            return Ok(());
        }
        Err(NativeCommitmentError::IdentityCollision {
            identity: lowercase_hex(self.identity.digest_bytes()),
            held: lowercase_hex(self.commitment.digest().as_bytes()),
            observed: lowercase_hex(observed.commitment.digest().as_bytes()),
        })
    }

    /// Verify that this commitment describes exactly these bytes.
    ///
    /// Recomputes both identities. A store uses this when it still has the
    /// bytes and wants to know that neither identity drifted from them.
    pub fn verify_against(
        &self,
        content: &[u8],
        codec_version: CodecVersion,
    ) -> Result<(), NativeCommitmentError> {
        let recomputed = Self::of_object(self.kind, content, codec_version);
        self.check_consistent_with(&recomputed)
    }
}

/// The framed bytes a commitment covers, for a caller that wants to re-derive
/// the preimage without going through the identity type.
#[must_use]
pub fn committed_bytes(kind: GitObjectKind, content: &[u8]) -> Vec<u8> {
    git_payload_body(kind, content)
}

#[cfg(test)]
mod tests {
    use fgit_types::numeric::CodecVersion;

    use super::{GitObjectCommitment, NativeCommitmentError};
    use crate::native::{GitObjectKind, NativeObjectIdentity, Sha1, Sha256};

    const CODEC: CodecVersion = CodecVersion::new(1, 0);

    #[test]
    fn the_pair_is_computed_from_one_object_and_agrees_with_the_separate_calls() {
        let content = b"hello world\n";
        let pair = GitObjectCommitment::<Sha1>::of_object(GitObjectKind::Blob, content, CODEC);
        assert_eq!(
            *pair.identity(),
            <Sha1 as crate::GitHashAlgorithm>::Oid::of_object(GitObjectKind::Blob, content)
        );
        assert_eq!(
            *pair.commitment(),
            crate::git_payload_commitment(GitObjectKind::Blob, content, CODEC)
        );
        assert_eq!(pair.kind(), GitObjectKind::Blob);
        assert_eq!(pair.length(), 12);
    }

    #[test]
    fn the_same_object_observed_twice_is_consistent() {
        let content = b"hello world\n";
        let held = GitObjectCommitment::<Sha1>::of_object(GitObjectKind::Blob, content, CODEC);
        let observed = GitObjectCommitment::<Sha1>::of_object(GitObjectKind::Blob, content, CODEC);
        assert_eq!(held.check_consistent_with(&observed), Ok(()));
        assert_eq!(held.verify_against(content, CODEC), Ok(()));
    }

    #[test]
    fn a_shared_identity_with_a_different_commitment_is_collision_evidence() {
        // A genuine SHA-1 collision pair is not something this crate can
        // produce, so the pathological pair is constructed directly: one
        // identity, two commitments. That is exactly the observation a store
        // makes when the second half of a collision pair arrives, which is the
        // input this check exists to refuse.
        let first = GitObjectCommitment::<Sha1>::of_object(GitObjectKind::Blob, b"one", CODEC);
        let second = GitObjectCommitment::<Sha1>::of_object(GitObjectKind::Blob, b"two", CODEC);
        let forged = GitObjectCommitment::<Sha1>::from_parts(
            *first.identity(),
            *second.commitment(),
            first.kind(),
            first.length(),
        );

        let refusal = first
            .check_consistent_with(&forged)
            .expect_err("one identity with two commitments must fail closed");
        match refusal {
            NativeCommitmentError::IdentityCollision {
                identity,
                held,
                observed,
            } => {
                assert_eq!(identity, first.identity().to_string());
                assert_ne!(held, observed);
            }
            NativeCommitmentError::DifferentIdentities { .. } => {
                panic!("the two observations share an identity, so this is a collision")
            }
        }
    }

    #[test]
    fn two_unrelated_objects_are_refused_as_different_identities_not_as_a_collision() {
        let first = GitObjectCommitment::<Sha1>::of_object(GitObjectKind::Blob, b"one", CODEC);
        let second = GitObjectCommitment::<Sha1>::of_object(GitObjectKind::Blob, b"two", CODEC);
        assert!(matches!(
            first.check_consistent_with(&second),
            Err(NativeCommitmentError::DifferentIdentities { .. })
        ));
    }

    #[test]
    fn the_commitment_binds_object_type_and_length_not_only_content() {
        let content = b"";
        let blob = GitObjectCommitment::<Sha1>::of_object(GitObjectKind::Blob, content, CODEC);
        let tree = GitObjectCommitment::<Sha1>::of_object(GitObjectKind::Tree, content, CODEC);
        assert_ne!(blob.commitment(), tree.commitment());
        assert_ne!(blob.identity(), tree.identity());

        // Same type, different length.
        let longer = GitObjectCommitment::<Sha1>::of_object(GitObjectKind::Blob, b"x", CODEC);
        assert_ne!(blob.commitment(), longer.commitment());
    }

    #[test]
    fn tampered_bytes_are_refused_by_verify_against() {
        let held = GitObjectCommitment::<Sha1>::of_object(GitObjectKind::Blob, b"original", CODEC);
        assert!(held.verify_against(b"tampered", CODEC).is_err());
        assert_eq!(held.verify_against(b"original", CODEC), Ok(()));
    }

    #[test]
    fn the_commitment_is_sha256_in_both_repository_formats() {
        // The stronger digest does not weaken to match the native format: a
        // SHA-1 repository still gets a SHA-256 commitment, which is the whole
        // point of it being independent evidence.
        let narrow = GitObjectCommitment::<Sha1>::of_object(GitObjectKind::Blob, b"x", CODEC);
        let wide = GitObjectCommitment::<Sha256>::of_object(GitObjectKind::Blob, b"x", CODEC);
        assert_eq!(narrow.commitment().digest().len(), 32);
        assert_eq!(narrow.identity().as_bytes().len(), 20);
        assert_eq!(wide.identity().as_bytes().len(), 32);
        // Same bytes, same commitment, regardless of the native format.
        assert_eq!(narrow.commitment(), wide.commitment());
    }
}

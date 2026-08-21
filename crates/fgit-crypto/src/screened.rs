//! Native SHA-1 Git identity computed through a collision-detecting profile.
//!
//! Plan section 11.6 requires SHA-1 repositories to compute the native
//! identity exactly, run it through a collision-detecting path, and fail
//! closed on suspicious evidence. This module is that path. It reuses the
//! same SHA-1 core as the unscreened entry point, so a screened identity and
//! an unscreened identity of the same object are byte-identical whenever the
//! detector reports the message clean; screening adds evidence, it never
//! changes the visible identity.

use crate::defense::{
    BlockVerdict, CollisionDefenseError, CollisionVerdict, DetectorObserver, Sha1CollisionDetector,
};
use crate::hashing::Sha1Hasher;
use crate::native::{GitObjectKind, GitOid, Sha1, object_header};

/// Which SHA-1 identity path a caller is asking for.
///
/// [`Self::Unscreened`] exists so that "no detector is installed" is a value a
/// caller can hold and pass, rather than a silent default. Asking for a
/// screened identity while holding it is refused.
pub enum Sha1IdentityProfile<'d> {
    /// No collision-detecting profile is installed.
    Unscreened,
    /// The supplied detector screens every compression block.
    Screened(&'d mut dyn Sha1CollisionDetector),
}

/// Compute a native SHA-1 Git identity under a collision-defense profile.
///
/// Fails closed in both directions: with no detector installed the identity is
/// refused as unscreened, and with a detector that reports evidence the
/// identity is refused as suspected. It never returns an identity that was not
/// actually screened.
pub fn sha1_git_oid_with_profile(
    kind: GitObjectKind,
    content: &[u8],
    profile: Sha1IdentityProfile<'_>,
) -> Result<GitOid<Sha1>, CollisionDefenseError> {
    match profile {
        Sha1IdentityProfile::Unscreened => Err(CollisionDefenseError::DetectorUnavailable),
        Sha1IdentityProfile::Screened(detector) => screened_sha1_git_oid(kind, content, detector),
    }
}

/// Compute a native SHA-1 Git identity with an installed detector.
pub fn screened_sha1_git_oid(
    kind: GitObjectKind,
    content: &[u8],
    detector: &mut dyn Sha1CollisionDetector,
) -> Result<GitOid<Sha1>, CollisionDefenseError> {
    let length = u64::try_from(content.len())
        .expect("a slice length always fits in u64 on supported targets");
    let header = object_header(kind, length);
    let digest = screened_sha1_over_parts(&[&header, content], detector)?;
    Ok(GitOid::from_digest(digest))
}

/// Compute a screened SHA-1 digest over a raw message.
pub fn screened_sha1_digest(
    message: &[u8],
    detector: &mut dyn Sha1CollisionDetector,
) -> Result<[u8; 20], CollisionDefenseError> {
    screened_sha1_over_parts(&[message], detector)
}

fn screened_sha1_over_parts(
    parts: &[&[u8]],
    detector: &mut dyn Sha1CollisionDetector,
) -> Result<[u8; 20], CollisionDefenseError> {
    let mut observer = DetectorObserver { detector };
    let mut hasher = Sha1Hasher::new();
    for part in parts {
        if let BlockVerdict::Suspected(evidence) = hasher.update_observed(part, &mut observer) {
            return Err(CollisionDefenseError::Suspected(evidence));
        }
    }
    let digest = hasher
        .finish_observed(&mut observer)
        .map_err(CollisionDefenseError::Suspected)?;
    match observer.detector.finish() {
        CollisionVerdict::Clean => Ok(digest),
        CollisionVerdict::Suspected(evidence) => Err(CollisionDefenseError::Suspected(evidence)),
    }
}

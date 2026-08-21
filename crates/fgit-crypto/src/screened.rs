//! Native SHA-1 Git identity computed through a collision-detecting profile.
//!
//! Plan section 11.6 requires SHA-1 repositories to compute the native
//! identity exactly, run it through a collision-detecting path, and fail
//! closed on suspicious evidence. This module is that path. It reuses the
//! same SHA-1 core as the unscreened entry point, so a screened identity and
//! an unscreened identity of the same object are byte-identical whenever the
//! detector reports the message clean; screening adds evidence, it never
//! changes the visible identity.

use fgit_types::native::GitOidSha1;

use crate::defense::{
    BlockVerdict, CollisionDefenseError, CollisionVerdict, DetectorObserver, Sha1CollisionDetector,
};
use crate::hashing::Sha1Hasher;
use crate::native::{GitObjectKind, object_header};

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
) -> Result<GitOidSha1, CollisionDefenseError> {
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
) -> Result<GitOidSha1, CollisionDefenseError> {
    let length = u64::try_from(content.len())
        .expect("a slice length always fits in u64 on supported targets");
    let header = object_header(kind, length);
    let digest = screened_sha1_over_parts(&[&header, content], detector)?;
    Ok(GitOidSha1::from_bytes(digest))
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

#[cfg(test)]
mod tests {
    use fgit_types::native::GitOidSha1;

    use super::{
        Sha1IdentityProfile, screened_sha1_digest, screened_sha1_git_oid, sha1_git_oid_with_profile,
    };
    use crate::defense::{CollisionDefenseError, Sha1CollisionDetector};
    use crate::hashing::sha1_digest;
    use crate::native::{GitObjectKind, NativeObjectIdentity};
    use crate::testing::{CleanDouble, RecordingDouble, SuspectAtBlock, SuspectAtFinish};

    const EMPTY_BLOB: &str = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";

    #[test]
    fn screening_without_a_detector_is_refused() {
        let refused =
            sha1_git_oid_with_profile(GitObjectKind::Blob, b"", Sha1IdentityProfile::Unscreened);
        assert_eq!(refused, Err(CollisionDefenseError::DetectorUnavailable));
    }

    #[test]
    fn screening_with_a_detector_proceeds_to_the_same_identity() {
        // The permitted counterpart of the refusal above: identical call, one
        // detector installed. Screening must add evidence, never change the
        // visible identity.
        let mut detector = CleanDouble::new();
        let screened = sha1_git_oid_with_profile(
            GitObjectKind::Blob,
            b"",
            Sha1IdentityProfile::Screened(&mut detector),
        )
        .expect("a clean detector permits the identity");
        assert_eq!(screened.to_string(), EMPTY_BLOB);
        assert_eq!(screened, GitOidSha1::of_object(GitObjectKind::Blob, b""));
        assert_eq!(detector.blocks(), 1, "the empty blob is one padded block");
        assert!(
            detector.finished(),
            "the whole-message verdict is requested"
        );
    }

    #[test]
    fn screened_and_unscreened_agree_across_block_boundaries() {
        for length in [0_usize, 1, 55, 56, 63, 64, 65, 119, 120, 200] {
            let content = vec![b'a'; length];
            let mut detector = CleanDouble::new();
            let screened = screened_sha1_git_oid(GitObjectKind::Blob, &content, &mut detector)
                .expect("a clean detector permits the identity");
            assert_eq!(
                screened,
                GitOidSha1::of_object(GitObjectKind::Blob, &content),
                "length {length}"
            );
        }
    }

    #[test]
    fn block_evidence_fails_closed() {
        let content = [b'a'; 200];
        let mut detector = SuspectAtBlock::new(1);
        let refused = screened_sha1_git_oid(GitObjectKind::Blob, &content, &mut detector)
            .expect_err("evidence must refuse the identity");
        match refused {
            CollisionDefenseError::Suspected(evidence) => assert_eq!(evidence.block_index, 1),
            CollisionDefenseError::DetectorUnavailable => {
                panic!("a detector was installed, so this is not an availability refusal")
            }
        }
    }

    #[test]
    fn whole_message_evidence_fails_closed() {
        let mut detector = SuspectAtFinish::new();
        let refused = screened_sha1_digest(b"abc", &mut detector)
            .expect_err("whole-message evidence must refuse the digest");
        assert!(matches!(refused, CollisionDefenseError::Suspected(_)));
    }

    #[test]
    fn a_detector_that_never_fires_permits_the_same_digest() {
        let mut detector = SuspectAtBlock::new(99);
        let digest = screened_sha1_digest(b"abc", &mut detector)
            .expect("evidence configured for a block this message never reaches");
        assert_eq!(digest, sha1_digest(b"abc"));
    }

    #[test]
    fn the_hook_exposes_real_compression_state() {
        // A detector that could not see genuine internal state would be a
        // decorative hook. This asserts the first chaining value is the FIPS
        // 180-4 SHA-1 initial state, that the schedule holds the padded
        // message words, and that the expansion recurrence holds.
        let mut detector = RecordingDouble::new();
        screened_sha1_digest(b"abc", &mut detector).expect("a recording detector is clean");
        let observed = detector.observed();
        assert_eq!(
            observed.len(),
            1,
            "a three-byte message is one padded block"
        );

        let block = &observed[0];
        assert_eq!(block.block_index, 0);
        assert_eq!(
            block.chaining_value,
            [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0
            ],
            "the first block enters with the published initial hash value"
        );
        assert_eq!(
            block.schedule[0], 0x6162_6380,
            "`abc` followed by the padding bit"
        );
        for word in &block.schedule[1..15] {
            assert_eq!(*word, 0, "the padding between the message and the length");
        }
        assert_eq!(block.schedule[15], 24, "three bytes is twenty-four bits");
        for index in 16..80 {
            let expected = (block.schedule[index - 3]
                ^ block.schedule[index - 8]
                ^ block.schedule[index - 14]
                ^ block.schedule[index - 16])
                .rotate_left(1);
            assert_eq!(block.schedule[index], expected, "expansion at {index}");
        }
    }

    #[test]
    fn a_multi_block_message_is_shown_to_the_detector_in_order() {
        let content = [b'a'; 200];
        let mut detector = RecordingDouble::new();
        screened_sha1_digest(&content, &mut detector).expect("a recording detector is clean");
        let observed = detector.observed();
        assert_eq!(observed.len(), 4, "200 bytes plus padding is four blocks");
        for (index, block) in observed.iter().enumerate() {
            assert_eq!(
                block.block_index,
                u64::try_from(index).expect("a block index fits in u64"),
                "block indices are consecutive"
            );
        }
        assert_ne!(
            observed[1].chaining_value, observed[0].chaining_value,
            "each block enters with the previous block's output"
        );
    }

    #[test]
    fn a_detector_is_a_trait_object_so_a_real_profile_can_replace_the_double() {
        let mut double = CleanDouble::new();
        let detector: &mut dyn Sha1CollisionDetector = &mut double;
        let digest = screened_sha1_digest(b"abc", detector).expect("a clean detector permits");
        assert_eq!(digest, sha1_digest(b"abc"));
    }
}

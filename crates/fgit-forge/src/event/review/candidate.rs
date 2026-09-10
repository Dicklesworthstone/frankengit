//! Exact candidate bindings are additive to the established source-only review
//! profile. They name the actual commit (including metadata and resulting tree),
//! not just the PR's two tips or a caller-supplied diff summary.
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefusalCode};
use super::{ForgeEvent, ForgeEventPayload, ReviewCommand, ReviewSubject, invalid_native};

pub const CANDIDATE_REVIEW_PROFILE: &str = "exact-merge-candidate-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateBinding {
    pub merge_base: GitOid,
    pub commit: GitOid,
}
impl CandidateBinding {
    pub fn validate(&self, subject: &ReviewSubject) -> Result<(), CodecRefusal> {
        subject.validate()?;
        if self.merge_base.is_zero() || self.commit.is_zero()
            || self.merge_base.algorithm() != subject.source_tip.algorithm()
            || self.commit.algorithm() != subject.source_tip.algorithm()
            || self.commit == subject.source_tip || self.commit == subject.target_tip
            || subject.source_tip == subject.target_tip
        { return Err(invalid_native("review.candidate")); }
        Ok(())
    }
    pub fn merge(&self, subject: &ReviewSubject) -> super::super::NativeMerge {
        super::super::NativeMerge {
            source_ref: subject.source_ref.clone(), source_tip: subject.source_tip,
            target_ref: subject.target_ref.clone(), target_tip_before: subject.target_tip,
            base_tip: self.merge_base, merge_commit: self.commit,
        }
    }
    pub(super) fn write(&self, out: &mut Encoder) {
        out.write_git_oid(&self.merge_base);
        out.write_git_oid(&self.commit);
    }
    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self { merge_base: input.read_git_oid()?, commit: input.read_git_oid()? })
    }
}

/// The caller freezes the candidate and PR version independently of the bundle.
/// Admission supplies the reviewer and validates the actual candidate bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateReviewCommand {
    pub review: ReviewCommand,
    pub candidate: CandidateBinding,
}
impl CandidateReviewCommand {
    pub fn proposed_event(&self, reviewer: PrincipalId, format: GitHashAlgorithm) -> Result<ForgeEvent, RefusalCode> {
        self.candidate.validate(&self.review.subject).map_err(|_| RefusalCode::EvidenceInvalid)?;
        let mut event = self.review.proposed_event(reviewer, format)?;
        let ForgeEventPayload::PullRequestReviewedNative(review) = &mut event.payload else {
            return Err(RefusalCode::InternalInvariantBreach);
        };
        review.candidate = Some(self.candidate);
        review.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AggregateVersion, ExpectedVersion, PullRequestNumber};
    use super::super::{ReviewDecision, validate_review_transition};
    use fgit_types::{PolicyEpoch, RefName};
    use fgit_codec::{DecodeLimits, decode_body, encode_body};
    fn command(format: GitHashAlgorithm) -> CandidateReviewCommand {
        let oid = |digit: &str| GitOid::from_hex(format, &digit.repeat(format.digest_len() * 2)).unwrap();
        CandidateReviewCommand {
            review: ReviewCommand { expected_version: ExpectedVersion::NewStream,
                subject: ReviewSubject { pull_request: PullRequestNumber::FIRST,
                    pull_request_version: AggregateVersion::FIRST,
                    source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
                    target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                    source_tip: oid("a"), target_tip: oid("b"), policy_epoch: PolicyEpoch::FIRST },
                decision: ReviewDecision::Approve, reason: "Reviewed actual merge bytes".into() },
            candidate: CandidateBinding { merge_base: oid("c"), commit: oid("d") },
        }
    }
    #[test]
    fn both_profiles_roundtrip_and_candidates_are_identity_material() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let command = command(format); let actor = PrincipalId::from_bytes([1; 16]);
            let source_only = command.review.proposed_event(actor, format).unwrap();
            let candidate = command.proposed_event(actor, format).unwrap();
            let old = encode_body(&source_only).unwrap(); let exact = encode_body(&candidate).unwrap();
            assert_ne!(old, exact);
            for (event, bytes) in [(source_only, old), (candidate, exact.clone())] {
                let decoded = decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap();
                assert_eq!(decoded, event); assert_eq!(encode_body(&decoded).unwrap(), bytes);
            }
            for field in 0..2 {
                let mut changed = command.clone();
                let other = GitOid::from_hex(format, &"e".repeat(format.digest_len() * 2)).unwrap();
                if field == 0 { changed.candidate.commit = other; } else { changed.candidate.merge_base = other; }
                assert_ne!(encode_body(&changed.proposed_event(actor, format).unwrap()).unwrap(), exact);
            }
            for end in 0..exact.len() { assert!(decode_body::<ForgeEvent>(&exact[..end], DecodeLimits::DEFAULT).is_err()); }
        }
    }
    #[test]
    fn source_only_or_different_candidate_cannot_withdraw_an_exact_vote() {
        let format = GitHashAlgorithm::Sha256; let actor = PrincipalId::from_bytes([1; 16]);
        let mut command = command(format); let old = command.proposed_event(actor, format).unwrap();
        command.review.expected_version = ExpectedVersion::Exactly(old.version);
        command.review.decision = ReviewDecision::Withdraw; command.review.reason = "withdraw exact vote".into();
        let exact = command.proposed_event(actor, format).unwrap();
        validate_review_transition(Some(&old), &exact).unwrap();
        assert!(validate_review_transition(Some(&old), &command.review.proposed_event(actor, format).unwrap()).is_err());
        command.candidate.commit = GitOid::from_hex(format, &"e".repeat(64)).unwrap();
        assert!(validate_review_transition(Some(&old), &command.proposed_event(actor, format).unwrap()).is_err());
    }
    #[test]
    fn candidate_domains_and_parent_aliases_are_rejected() {
        let mut command = command(GitHashAlgorithm::Sha1);
        command.candidate.commit = command.review.subject.source_tip;
        assert!(command.proposed_event(PrincipalId::from_bytes([1; 16]), GitHashAlgorithm::Sha1).is_err());
        command.candidate.commit = GitOid::from_hex(GitHashAlgorithm::Sha256, &"d".repeat(64)).unwrap();
        assert!(command.proposed_event(PrincipalId::from_bytes([1; 16]), GitHashAlgorithm::Sha1).is_err());
    }
}

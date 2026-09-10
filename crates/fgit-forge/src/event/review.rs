//! Immutable PR review decisions. Source-only profile 1 retains its exact
//! historical bytes. Profile 2 additionally binds the ACTUAL merge candidate
//! and base. Neither a vote nor its text grants repository or reviewer access.

pub mod candidate;
pub use candidate::{CandidateBinding, CandidateReviewCommand, CANDIDATE_REVIEW_PROFILE};

use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{GitHashAlgorithm, GitOid, PolicyEpoch, PrincipalId, RefName, RefusalCode};
use crate::aggregate::{AggregateId, AggregateVersion, ExpectedVersion, PullRequestNumber};
use super::{ForgeEvent, ForgeEventPayload, invalid_native};
use super::pull_request::PullRequestAction;

pub const MAX_REVIEW_REASON_BYTES: usize = 16 * 1024;
pub const REVIEW_PROFILE: &str = "full-tree-direct-path-myers-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewDecision { Approve, RequestChanges, Withdraw }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewSubject {
    pub pull_request: PullRequestNumber,
    pub pull_request_version: AggregateVersion,
    pub source_ref: RefName,
    pub target_ref: RefName,
    pub source_tip: GitOid,
    pub target_tip: GitOid,
    pub policy_epoch: PolicyEpoch,
}
impl ReviewSubject {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        if self.source_ref == self.target_ref
            || !self.source_ref.as_bytes().starts_with(b"refs/heads/")
            || !self.target_ref.as_bytes().starts_with(b"refs/heads/")
            || self.source_tip.is_zero() || self.target_tip.is_zero()
            || self.source_tip.algorithm() != self.target_tip.algorithm()
        { return Err(invalid_native("review.subject")); }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeReviewEvent {
    pub reviewer: PrincipalId,
    pub subject: ReviewSubject,
    pub decision: ReviewDecision,
    /// None is explicitly a source-only review and cannot authorize a merge
    /// under the exact-candidate publication profile.
    pub candidate: Option<CandidateBinding>,
    /// Untrusted explanation, never an instruction or authorization rule.
    pub reason: String,
}
impl NativeReviewEvent {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        self.subject.validate()?;
        if let Some(candidate) = self.candidate { candidate.validate(&self.subject)?; }
        if self.reason.len() > MAX_REVIEW_REASON_BYTES || self.reason.contains('\0')
            || (self.decision != ReviewDecision::Approve && self.reason.trim().is_empty())
        { return Err(invalid_native("review.reason")); }
        Ok(())
    }
    pub fn aggregate(&self) -> AggregateId {
        AggregateId::PullRequestReview { pull_request: self.subject.pull_request, reviewer: self.reviewer }
    }
    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_scalar(if self.candidate.is_some() { 2_u32 } else { 1_u32 });
        out.write_bytes("reviewer", self.reviewer.as_bytes())?;
        out.write_scalar(self.subject.pull_request.get());
        out.write_scalar(self.subject.pull_request_version.get());
        out.write_bytes("source_ref", self.subject.source_ref.as_bytes())?;
        out.write_bytes("target_ref", self.subject.target_ref.as_bytes())?;
        out.write_git_oid(&self.subject.source_tip);
        out.write_git_oid(&self.subject.target_tip);
        out.write_scalar(self.subject.policy_epoch.get());
        out.write_scalar(match self.decision {
            ReviewDecision::Approve => 1_u32, ReviewDecision::RequestChanges => 2, ReviewDecision::Withdraw => 3,
        });
        out.write_bytes("review.reason", self.reason.as_bytes())?;
        if let Some(candidate) = self.candidate { candidate.write(out); }
        Ok(())
    }
    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let offset = input.offset();
        let profile = input.read_scalar::<u32>("review.profile")?;
        if profile != 1 && profile != 2 {
            return Err(CodecRefusal::VariantUnknown { field: "review.profile", observed: profile, offset });
        }
        let reviewer = PrincipalId::from_bytes(input.read_bytes("reviewer")?.try_into()
            .map_err(|_| invalid_native("review.reviewer"))?);
        let pull_request = PullRequestNumber::try_new(input.read_scalar::<u64>("review.pull_request")?)
            .ok_or_else(|| invalid_native("review.pull_request"))?;
        let pull_request_version = AggregateVersion::try_new(input.read_scalar::<u64>("review.pull_request_version")?)
            .ok_or_else(|| invalid_native("review.pull_request_version"))?;
        let source_ref = RefName::try_new(input.read_bytes("source_ref")?).map_err(CodecRefusal::from)?;
        let target_ref = RefName::try_new(input.read_bytes("target_ref")?).map_err(CodecRefusal::from)?;
        let source_tip = input.read_git_oid()?;
        let target_tip = input.read_git_oid()?;
        let policy_epoch = PolicyEpoch::try_new(input.read_scalar::<u64>("review.policy_epoch")?).map_err(CodecRefusal::from)?;
        let offset = input.offset();
        let decision = match input.read_scalar::<u32>("review.decision")? {
            1 => ReviewDecision::Approve, 2 => ReviewDecision::RequestChanges, 3 => ReviewDecision::Withdraw,
            observed => return Err(CodecRefusal::VariantUnknown { field: "review.decision", observed, offset }),
        };
        let bytes = input.read_bytes("review.reason")?;
        if bytes.len() > MAX_REVIEW_REASON_BYTES { return Err(invalid_native("review.reason_limit")); }
        let reason = std::str::from_utf8(bytes).map_err(|_| invalid_native("review.reason_utf8"))?.to_owned();
        let candidate = if profile == 2 { Some(CandidateBinding::read(input)?) } else { None };
        let event = Self { reviewer, subject: ReviewSubject { pull_request, pull_request_version,
            source_ref, target_ref, source_tip, target_tip, policy_epoch }, decision, candidate, reason };
        event.validate()?;
        Ok(event)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewCommand {
    /// Version of THIS reviewer's stream, independent of the PR's version.
    pub expected_version: ExpectedVersion,
    pub subject: ReviewSubject,
    pub decision: ReviewDecision,
    pub reason: String,
}
impl ReviewCommand {
    pub fn proposed_event(&self, reviewer: PrincipalId, format: GitHashAlgorithm) -> Result<ForgeEvent, RefusalCode> {
        self.subject.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
        if self.subject.source_tip.algorithm() != format || self.reason.len() > MAX_REVIEW_REASON_BYTES
            || (self.decision == ReviewDecision::Withdraw && self.expected_version == ExpectedVersion::NewStream)
        { return Err(RefusalCode::EvidenceInvalid); }
        let event = NativeReviewEvent { reviewer, subject: self.subject.clone(), decision: self.decision,
            candidate: None, reason: self.reason.clone() };
        event.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
        let version = match self.expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(previous) => previous.next().map_err(|_| RefusalCode::ResourceBudgetExceeded)?,
        };
        Ok(ForgeEvent { aggregate: event.aggregate(), version, payload: ForgeEventPayload::PullRequestReviewedNative(event) })
    }
}

/// Compare-and-replace one reviewer's vote. Withdrawal must name the exact old
/// subject AND candidate, and can retract a stale vote after the PR closes.
pub fn validate_review_transition(previous: Option<&ForgeEvent>, next: &ForgeEvent) -> Result<(), RefusalCode> {
    let ForgeEventPayload::PullRequestReviewedNative(review) = &next.payload else { return Err(RefusalCode::EvidenceInvalid); };
    review.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
    if review.aggregate() != next.aggregate { return Err(RefusalCode::EvidenceInvalid); }
    match previous {
        None if next.version == AggregateVersion::FIRST && review.decision != ReviewDecision::Withdraw => Ok(()),
        None => Err(RefusalCode::EvidenceStale),
        Some(previous) => {
            if previous.aggregate != next.aggregate || !previous.version.is_immediate_predecessor_of(next.version) {
                return Err(RefusalCode::EvidenceStale);
            }
            let ForgeEventPayload::PullRequestReviewedNative(old) = &previous.payload else { return Err(RefusalCode::EvidenceInvalid); };
            old.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
            if old.aggregate() != previous.aggregate { return Err(RefusalCode::EvidenceInvalid); }
            if review.decision == ReviewDecision::Withdraw
                && (old.decision == ReviewDecision::Withdraw || old.subject != review.subject || old.candidate != review.candidate)
            { return Err(RefusalCode::EvidenceStale); }
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewFreshness { Current, Withdrawn, PullRequestUnavailable, PullRequestClosed,
    PullRequestChanged, SourceMoved, TargetMoved, PolicyChanged }

pub fn review_freshness(
    review: &NativeReviewEvent, current: Option<&ForgeEvent>, policy_epoch: PolicyEpoch,
    source_tip: Option<GitOid>, target_tip: Option<GitOid>,
) -> ReviewFreshness {
    if review.decision == ReviewDecision::Withdraw { return ReviewFreshness::Withdrawn; }
    let Some(current) = current else { return ReviewFreshness::PullRequestUnavailable; };
    if current.aggregate != AggregateId::PullRequest(review.subject.pull_request) {
        return ReviewFreshness::PullRequestUnavailable;
    }
    let ForgeEventPayload::PullRequestChangedNative(change) = &current.payload else {
        return ReviewFreshness::PullRequestClosed;
    };
    if change.action == PullRequestAction::Close { return ReviewFreshness::PullRequestClosed; }
    let subject = &review.subject;
    if current.version != subject.pull_request_version || change.data.source_ref != subject.source_ref
        || change.data.target_ref != subject.target_ref || change.data.source_tip != subject.source_tip
        || change.data.target_tip != subject.target_tip
    { return ReviewFreshness::PullRequestChanged; }
    if policy_epoch != subject.policy_epoch { return ReviewFreshness::PolicyChanged; }
    if source_tip != Some(subject.source_tip) { return ReviewFreshness::SourceMoved; }
    if target_tip != Some(subject.target_tip) { return ReviewFreshness::TargetMoved; }
    ReviewFreshness::Current
}

#[cfg(test)]
mod tests;

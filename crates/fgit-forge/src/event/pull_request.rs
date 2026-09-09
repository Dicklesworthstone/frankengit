//! Native same-repository PR commands and full, versioned lifecycle events.
//! A proposed event is not accepted state. Admission owns ref/policy checks,
//! expected-version evaluation, the seal, and the coupled outbox publication.

use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RefusalCode};
use crate::aggregate::{AggregateId, AggregateVersion, ExpectedVersion, PullRequestNumber};
use super::{ForgeEvent, ForgeEventPayload, NativeMerge, invalid_native};

pub const MAX_TITLE_BYTES: usize = 256;
pub const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PullRequestAction { Open, Update, Close }

/// Desired PR content. Updates cannot change branch identities. Tip changes
/// explicitly refresh the compared source/base. Text is untrusted UTF-8 data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestData {
    pub source_ref: RefName,
    pub target_ref: RefName,
    pub source_tip: GitOid,
    pub target_tip: GitOid,
    pub title: String,
    pub body: String,
}
impl PullRequestData {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        if self.source_ref == self.target_ref
            || !self.source_ref.as_bytes().starts_with(b"refs/heads/")
            || !self.target_ref.as_bytes().starts_with(b"refs/heads/")
            || self.source_tip.is_zero() || self.target_tip.is_zero()
            || self.source_tip.algorithm() != self.target_tip.algorithm()
        { return Err(invalid_native("pull_request.coordinates")); }
        if self.title.trim().is_empty() || self.title.len() > MAX_TITLE_BYTES
            || self.title.chars().any(char::is_control)
            || self.body.len() > MAX_BODY_BYTES || self.body.contains('\0')
        { return Err(invalid_native("pull_request.text")); }
        Ok(())
    }
    #[must_use]
    pub fn matches_merge(&self, merge: &NativeMerge) -> bool {
        self.source_ref == merge.source_ref && self.target_ref == merge.target_ref
            && self.source_tip == merge.source_tip && self.target_tip == merge.target_tip_before
    }
}

/// Each transition carries complete current data, allowing authenticated
/// frontier reads without a mutable PR database. Admission supplies `actor`.
/// The original opener and creation basis remain in immutable event/RCR history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePullRequestEvent {
    pub action: PullRequestAction,
    pub actor: PrincipalId,
    pub data: PullRequestData,
}
impl NativePullRequestEvent {
    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.data.validate()?;
        out.write_scalar(match self.action {
            PullRequestAction::Open => 1_u32,
            PullRequestAction::Update => 2,
            PullRequestAction::Close => 3,
        });
        out.write_bytes("actor", self.actor.as_bytes())?;
        out.write_bytes("source_ref", self.data.source_ref.as_bytes())?;
        out.write_bytes("target_ref", self.data.target_ref.as_bytes())?;
        out.write_git_oid(&self.data.source_tip);
        out.write_git_oid(&self.data.target_tip);
        out.write_bytes("title", self.data.title.as_bytes())?;
        out.write_bytes("body", self.data.body.as_bytes())?;
        Ok(())
    }
    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let offset = input.offset();
        let action = match input.read_scalar::<u32>("pull_request.action")? {
            1 => PullRequestAction::Open, 2 => PullRequestAction::Update, 3 => PullRequestAction::Close,
            observed => return Err(CodecRefusal::VariantUnknown { field: "pull_request.action", observed, offset }),
        };
        let actor: [u8; 16] = input.read_bytes("actor")?.try_into()
            .map_err(|_| invalid_native("pull_request.actor"))?;
        let source_ref = RefName::try_new(input.read_bytes("source_ref")?).map_err(CodecRefusal::from)?;
        let target_ref = RefName::try_new(input.read_bytes("target_ref")?).map_err(CodecRefusal::from)?;
        let source_tip = input.read_git_oid()?;
        let target_tip = input.read_git_oid()?;
        let title = bounded_text(input.read_bytes("title")?, MAX_TITLE_BYTES)?;
        let body = bounded_text(input.read_bytes("body")?, MAX_BODY_BYTES)?;
        let data = PullRequestData { source_ref, target_ref, source_tip, target_tip, title, body };
        data.validate()?;
        Ok(Self { action, actor: PrincipalId::from_bytes(actor), data })
    }
}
fn bounded_text(bytes: &[u8], maximum: usize) -> Result<String, CodecRefusal> {
    if bytes.len() > maximum { return Err(invalid_native("pull_request.text_limit")); }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_native("pull_request.utf8"))?;
    Ok(text.to_owned())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestCommand {
    pub number: PullRequestNumber,
    pub expected_version: ExpectedVersion,
    pub action: PullRequestAction,
    pub data: PullRequestData,
}
impl PullRequestCommand {
    /// Freeze submitted semantics; no latest-tip lookup, clock, retry count,
    /// authority-head basis, or regenerated metadata enters the event identity.
    pub fn proposed_event(&self, actor: PrincipalId, format: GitHashAlgorithm) -> Result<ForgeEvent, RefusalCode> {
        self.data.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
        if self.data.source_tip.algorithm() != format { return Err(RefusalCode::EvidenceInvalid); }
        let version = match self.expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(previous) => previous.next().map_err(|_| RefusalCode::ResourceBudgetExceeded)?,
        };
        if (self.action == PullRequestAction::Open) != (self.expected_version == ExpectedVersion::NewStream) {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(ForgeEvent { aggregate: AggregateId::PullRequest(self.number), version,
            payload: ForgeEventPayload::PullRequestChangedNative(NativePullRequestEvent {
                action: self.action, actor, data: self.data.clone(),
            }),
        })
    }
}

/// Evaluate against the exact prior event selected by authority. Updates
/// cannot retarget, resurrect a terminal stream, or erase data during closure.
pub fn validate_transition(previous: Option<&ForgeEvent>, next: &ForgeEvent) -> Result<(), RefusalCode> {
    let ForgeEventPayload::PullRequestChangedNative(change) = &next.payload else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    change.data.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
    if !matches!(next.aggregate, AggregateId::PullRequest(_)) { return Err(RefusalCode::EvidenceInvalid); }
    let Some(previous) = previous else {
        return if change.action == PullRequestAction::Open && next.version == AggregateVersion::FIRST {
            Ok(())
        } else { Err(RefusalCode::EvidenceStale) };
    };
    if previous.aggregate != next.aggregate || !previous.version.is_immediate_predecessor_of(next.version) {
        return Err(RefusalCode::EvidenceStale);
    }
    let ForgeEventPayload::PullRequestChangedNative(old) = &previous.payload else {
        return Err(RefusalCode::ProtectedRefTransitionDenied);
    };
    if old.action == PullRequestAction::Close || change.action == PullRequestAction::Open {
        return Err(RefusalCode::ProtectedRefTransitionDenied);
    }
    if old.data.source_ref != change.data.source_ref || old.data.target_ref != change.data.target_ref {
        return Err(RefusalCode::ProtectedRefTransitionDenied);
    }
    if change.action == PullRequestAction::Close && old.data != change.data {
        return Err(RefusalCode::EvidenceStale);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_codec::{DecodeLimits, decode_body, encode_body};
    fn command(format: GitHashAlgorithm) -> PullRequestCommand {
        let width = format.digest_len() * 2;
        PullRequestCommand { number: PullRequestNumber::FIRST, expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open, data: PullRequestData {
                source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
                target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                source_tip: GitOid::from_hex(format, &"a".repeat(width)).unwrap(),
                target_tip: GitOid::from_hex(format, &"b".repeat(width)).unwrap(),
                title: "Native PR".into(), body: "untrusted <script>\nUnicode: é".into(),
            } }
    }
    fn actor() -> PrincipalId { PrincipalId::from_bytes([7; 16]) }
    #[test]
    fn native_lifecycle_roundtrips_both_domains_and_preserves_text() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let mut command = command(format);
            let mut previous: Option<ForgeEvent> = None;
            for action in [PullRequestAction::Open, PullRequestAction::Update, PullRequestAction::Close] {
                command.action = action;
                if let Some(prior) = &previous { command.expected_version = ExpectedVersion::Exactly(prior.version); }
                let event = command.proposed_event(actor(), format).unwrap();
                validate_transition(previous.as_ref(), &event).unwrap();
                let frame = encode_body(&event).unwrap();
                assert_eq!(decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(), event);
                previous = Some(event);
            }
        }
    }
    #[test]
    fn semantic_fields_change_event_bytes_and_actor_is_not_a_command_field() {
        let original = command(GitHashAlgorithm::Sha1);
        let event = original.proposed_event(actor(), GitHashAlgorithm::Sha1).unwrap();
        let bytes = encode_body(&event).unwrap();
        let mut title = original.clone(); title.data.title.push('!');
        let mut body = original.clone(); body.data.body.push('!');
        let mut tip = original.clone(); tip.data.source_tip = original.data.target_tip;
        let mut number = original.clone(); number.number = PullRequestNumber::try_new(2).unwrap();
        for changed in [title, body, tip, number] {
            assert_ne!(encode_body(&changed.proposed_event(actor(), GitHashAlgorithm::Sha1).unwrap()).unwrap(), bytes);
        }
        assert_ne!(encode_body(&original.proposed_event(PrincipalId::from_bytes([8; 16]), GitHashAlgorithm::Sha1).unwrap()).unwrap(), bytes);
    }
    #[test]
    fn stale_versions_retargeting_and_terminal_resurrection_refuse() {
        let mut command = command(GitHashAlgorithm::Sha1);
        let opened = command.proposed_event(actor(), GitHashAlgorithm::Sha1).unwrap();
        command.action = PullRequestAction::Update;
        command.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        let updated = command.proposed_event(actor(), GitHashAlgorithm::Sha1).unwrap();
        validate_transition(Some(&opened), &updated).unwrap();
        assert!(validate_transition(Some(&updated), &updated).is_err());
        command.data.target_ref = RefName::try_new(b"refs/heads/other").unwrap();
        assert!(validate_transition(Some(&opened), &command.proposed_event(actor(), GitHashAlgorithm::Sha1).unwrap()).is_err());
        command.data = match &updated.payload { ForgeEventPayload::PullRequestChangedNative(e) => e.data.clone(), _ => unreachable!() };
        command.action = PullRequestAction::Close;
        command.expected_version = ExpectedVersion::Exactly(updated.version);
        let closed = command.proposed_event(actor(), GitHashAlgorithm::Sha1).unwrap();
        validate_transition(Some(&updated), &closed).unwrap();
        command.action = PullRequestAction::Update;
        command.expected_version = ExpectedVersion::Exactly(closed.version);
        assert!(validate_transition(Some(&closed), &command.proposed_event(actor(), GitHashAlgorithm::Sha1).unwrap()).is_err());
    }
    #[test]
    fn bounds_domains_and_command_shape_refuse_before_publication() {
        let valid = command(GitHashAlgorithm::Sha1);
        let mut huge = valid.clone(); huge.data.body = "x".repeat(MAX_BODY_BYTES + 1);
        let mut blank = valid.clone(); blank.data.title = " \t".into();
        let mut mixed = valid.clone(); mixed.data.source_tip = GitOid::from_hex(GitHashAlgorithm::Sha256, &"a".repeat(64)).unwrap();
        let mut nul = valid.clone(); nul.data.body.push('\0');
        let mut wrong = valid.clone(); wrong.action = PullRequestAction::Close;
        for invalid in [huge, blank, mixed, nul, wrong] {
            assert!(invalid.proposed_event(actor(), GitHashAlgorithm::Sha1).is_err());
        }
        assert!(valid.proposed_event(actor(), GitHashAlgorithm::Sha256).is_err());
    }
}

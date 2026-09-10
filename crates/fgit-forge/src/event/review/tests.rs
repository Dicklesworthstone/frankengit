use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};
use fgit_codec::wire::canonical_body_bytes;
use crate::event::pull_request::{NativePullRequestEvent, PullRequestData};

fn actor() -> PrincipalId { PrincipalId::from_bytes([7; 16]) }
fn command(format: GitHashAlgorithm) -> ReviewCommand {
    let width = format.digest_len() * 2;
    ReviewCommand { expected_version: ExpectedVersion::NewStream, subject: ReviewSubject {
        pull_request: PullRequestNumber::try_new(17).unwrap(),
        pull_request_version: AggregateVersion::try_new(4).unwrap(),
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: GitOid::from_hex(format, &"a".repeat(width)).unwrap(),
        target_tip: GitOid::from_hex(format, &"b".repeat(width)).unwrap(),
        policy_epoch: PolicyEpoch::FIRST,
    }, decision: ReviewDecision::Approve, reason: "Reviewed exact bytes: é\n<script>".into() }
}
fn payload(event: &ForgeEvent) -> &NativeReviewEvent {
    let ForgeEventPayload::PullRequestReviewedNative(review) = &event.payload else { panic!("review event"); };
    review
}
fn current(review: &NativeReviewEvent) -> ForgeEvent {
    let s = &review.subject;
    ForgeEvent { aggregate: AggregateId::PullRequest(s.pull_request), version: s.pull_request_version,
        payload: ForgeEventPayload::PullRequestChangedNative(NativePullRequestEvent {
            action: PullRequestAction::Update, actor: PrincipalId::from_bytes([9; 16]), data: PullRequestData {
                source_ref: s.source_ref.clone(), target_ref: s.target_ref.clone(), source_tip: s.source_tip,
                target_tip: s.target_tip, title: "A real PR".into(), body: "Metadata is not a review".into(),
            },
        }) }
}

#[test]
fn decisions_roundtrip_both_hash_formats_and_keep_historical_pr_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut command = command(format);
        let mut previous: Option<ForgeEvent> = None;
        for decision in [ReviewDecision::Approve, ReviewDecision::RequestChanges, ReviewDecision::Withdraw, ReviewDecision::Approve] {
            command.decision = decision;
            if let Some(prior) = &previous { command.expected_version = ExpectedVersion::Exactly(prior.version); }
            let event = command.proposed_event(actor(), format).unwrap();
            validate_review_transition(previous.as_ref(), &event).unwrap();
            let bytes = encode_body(&event).unwrap();
            assert_eq!(decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(), event);
            assert_eq!(encode_body(&decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap()).unwrap(), bytes);
            previous = Some(event);
        }
    }
    let old = ForgeEvent { aggregate: AggregateId::PullRequest(PullRequestNumber::try_new(7).unwrap()),
        version: AggregateVersion::try_new(3).unwrap(), payload: ForgeEventPayload::PullRequestClosed { withdrawn: true } };
    assert_eq!(canonical_body_bytes(&old).unwrap(), [7_u64.to_be_bytes().as_slice(),
        3_u64.to_be_bytes().as_slice(), 4_u32.to_be_bytes().as_slice(), &[1]].concat());
}

#[test]
fn every_semantic_input_and_reviewer_changes_the_event_identity_input() {
    let original = command(GitHashAlgorithm::Sha1);
    let bytes = encode_body(&original.proposed_event(actor(), GitHashAlgorithm::Sha1).unwrap()).unwrap();
    for field in 0..10 {
        let mut changed = original.clone();
        match field {
            0 => changed.subject.pull_request = PullRequestNumber::try_new(18).unwrap(),
            1 => changed.subject.pull_request_version = AggregateVersion::try_new(5).unwrap(),
            2 => changed.subject.source_ref = RefName::try_new(b"refs/heads/other-source").unwrap(),
            3 => changed.subject.target_ref = RefName::try_new(b"refs/heads/other-target").unwrap(),
            4 => changed.subject.source_tip = GitOid::from_hex(GitHashAlgorithm::Sha1, &"c".repeat(40)).unwrap(),
            5 => changed.subject.target_tip = GitOid::from_hex(GitHashAlgorithm::Sha1, &"d".repeat(40)).unwrap(),
            6 => changed.subject.policy_epoch = PolicyEpoch::try_new(2).unwrap(),
            7 => changed.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST),
            8 => changed.decision = ReviewDecision::RequestChanges,
            _ => changed.reason.push('!'),
        }
        assert_ne!(encode_body(&changed.proposed_event(actor(), GitHashAlgorithm::Sha1).unwrap()).unwrap(), bytes, "field {field}");
    }
    assert_ne!(encode_body(&original.proposed_event(PrincipalId::from_bytes([8; 16]), GitHashAlgorithm::Sha1).unwrap()).unwrap(), bytes);
}

#[test]
fn reviewer_streams_are_separate_bounded_and_non_spoofable() {
    let command = command(GitHashAlgorithm::Sha1);
    let first = command.proposed_event(actor(), GitHashAlgorithm::Sha1).unwrap();
    let second = command.proposed_event(PrincipalId::from_bytes([8; 16]), GitHashAlgorithm::Sha1).unwrap();
    assert_ne!(first.aggregate, second.aggregate);
    let mut forged = first.clone();
    if let ForgeEventPayload::PullRequestReviewedNative(review) = &mut forged.payload { review.reviewer = PrincipalId::from_bytes([8; 16]); }
    assert!(encode_body(&forged).is_err());
    forged = first.clone(); forged.aggregate = AggregateId::PullRequest(command.subject.pull_request);
    assert!(encode_body(&forged).is_err());
    forged = first; forged.payload = ForgeEventPayload::PullRequestClosed { withdrawn: false };
    assert!(encode_body(&forged).is_err());
    let label = AggregateId::PullRequestReview { pull_request: PullRequestNumber::try_new(u64::MAX).unwrap(), reviewer: actor() }.to_string();
    assert_eq!(label.len(), 60);
    assert!(fgit_types::AsciiSlug::try_new("review stream", label.as_bytes()).is_ok());
}

#[test]
fn withdrawals_require_the_exact_previous_vote_and_explicit_reason() {
    let mut command = command(GitHashAlgorithm::Sha256);
    let original = command.proposed_event(actor(), GitHashAlgorithm::Sha256).unwrap();
    command.decision = ReviewDecision::Withdraw;
    assert!(command.proposed_event(actor(), GitHashAlgorithm::Sha256).is_err());
    command.expected_version = ExpectedVersion::Exactly(original.version);
    command.reason = "The old code has changed".into();
    let withdrawn = command.proposed_event(actor(), GitHashAlgorithm::Sha256).unwrap();
    validate_review_transition(Some(&original), &withdrawn).unwrap();
    assert!(validate_review_transition(Some(&withdrawn), &withdrawn).is_err());
    command.subject.pull_request_version = AggregateVersion::try_new(5).unwrap();
    assert!(validate_review_transition(Some(&original), &command.proposed_event(actor(), GitHashAlgorithm::Sha256).unwrap()).is_err());
    command.subject = payload(&original).subject.clone();
    command.expected_version = ExpectedVersion::Exactly(withdrawn.version);
    assert!(validate_review_transition(Some(&withdrawn), &command.proposed_event(actor(), GitHashAlgorithm::Sha256).unwrap()).is_err());
    command.reason.clear(); assert!(command.proposed_event(actor(), GitHashAlgorithm::Sha256).is_err());
}

#[test]
fn freshness_binds_pr_version_both_refs_and_policy_without_erasing_history() {
    let event = command(GitHashAlgorithm::Sha1).proposed_event(actor(), GitHashAlgorithm::Sha1).unwrap();
    let review = payload(&event);
    let pr = current(review);
    let epoch = review.subject.policy_epoch;
    let source = Some(review.subject.source_tip);
    let target = Some(review.subject.target_tip);
    assert_eq!(review_freshness(review, Some(&pr), epoch, source, target), ReviewFreshness::Current);
    assert_eq!(review_freshness(review, None, epoch, source, target), ReviewFreshness::PullRequestUnavailable);
    assert_eq!(review_freshness(review, Some(&pr), PolicyEpoch::try_new(2).unwrap(), source, target), ReviewFreshness::PolicyChanged);
    assert_eq!(review_freshness(review, Some(&pr), epoch, None, target), ReviewFreshness::SourceMoved);
    assert_eq!(review_freshness(review, Some(&pr), epoch, source, None), ReviewFreshness::TargetMoved);
    let mut changed = pr.clone(); changed.version = changed.version.next().unwrap();
    assert_eq!(review_freshness(review, Some(&changed), epoch, source, target), ReviewFreshness::PullRequestChanged);
    changed = pr;
    if let ForgeEventPayload::PullRequestChangedNative(change) = &mut changed.payload { change.action = PullRequestAction::Close; }
    assert_eq!(review_freshness(review, Some(&changed), epoch, source, target), ReviewFreshness::PullRequestClosed);
    let mut withdrawn = review.clone(); withdrawn.decision = ReviewDecision::Withdraw;
    assert_eq!(review_freshness(&withdrawn, Some(&changed), epoch, None, None), ReviewFreshness::Withdrawn);
}

#[test]
fn malformed_text_domains_and_exhausted_versions_refuse() {
    let original = command(GitHashAlgorithm::Sha1);
    for field in 0..6 {
        let mut bad = original.clone();
        match field {
            0 => bad.reason = "x".repeat(MAX_REVIEW_REASON_BYTES + 1),
            1 => bad.reason.push('\0'),
            2 => { bad.decision = ReviewDecision::RequestChanges; bad.reason = " \t\n".into(); }
            3 => bad.subject.source_tip = GitOid::from_hex(GitHashAlgorithm::Sha256, &"a".repeat(64)).unwrap(),
            4 => bad.subject.source_ref = bad.subject.target_ref.clone(),
            _ => bad.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(u64::MAX).unwrap()),
        }
        assert!(bad.proposed_event(actor(), GitHashAlgorithm::Sha1).is_err(), "invalid field {field}");
    }
    assert!(original.proposed_event(actor(), GitHashAlgorithm::Sha256).is_err());
}

#[test]
fn truncated_frames_and_unknown_review_profiles_never_decode_as_approvals() {
    let event = command(GitHashAlgorithm::Sha256).proposed_event(actor(), GitHashAlgorithm::Sha256).unwrap();
    let bytes = encode_body(&event).unwrap();
    for end in 0..bytes.len() { assert!(decode_body::<ForgeEvent>(&bytes[..end], DecodeLimits::DEFAULT).is_err()); }
    let payload = canonical_body_bytes(&event).unwrap();
    // Aggregate escape(8), kind(4), PR(8), opaque reviewer(16), version(8), event kind(4).
    assert_eq!(&payload[..12], &[0_u64.to_be_bytes().as_slice(), 3_u32.to_be_bytes().as_slice()].concat());
    assert_eq!(&payload[48..52], &1_u32.to_be_bytes());
    let at = bytes.windows(payload.len()).position(|part| part == payload).unwrap();
    let mut bad = bytes.clone(); bad[at + 48..at + 52].copy_from_slice(&99_u32.to_be_bytes());
    assert!(matches!(decode_body::<ForgeEvent>(&bad, DecodeLimits::DEFAULT), Err(CodecRefusal::VariantUnknown { field: "review.profile", .. })));
    assert_eq!(decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(), event);
}

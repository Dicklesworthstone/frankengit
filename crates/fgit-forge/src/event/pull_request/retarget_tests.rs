//! An explicit target change extends the native lifecycle without weakening
//! Update/Reopen or changing any historical action bytes.
use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn opening(format: GitHashAlgorithm) -> PullRequestCommand {
    PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: RefName::try_new(b"refs/heads/topic\xff").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: GitOid::from_hex(format, &"a".repeat(format.digest_len() * 2)).unwrap(),
            target_tip: GitOid::from_hex(format, &"b".repeat(format.digest_len() * 2)).unwrap(),
            title: "Keep this PR".into(),
            body: "Literal é\r\n<script>not authority</script>".into(),
        },
    }
}
fn actor() -> PrincipalId {
    PrincipalId::from_bytes([7; 16])
}
fn event(command: &PullRequestCommand, format: GitHashAlgorithm) -> ForgeEvent {
    command.proposed_event(actor(), format).unwrap()
}
fn retarget(open: &PullRequestCommand) -> PullRequestCommand {
    let mut next = open.clone();
    next.action = PullRequestAction::Retarget;
    next.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    next.data.target_ref = RefName::try_new(b"refs/heads/release\xfe").unwrap();
    next
}

#[test]
fn retarget_roundtrips_and_retains_source_and_open_lifecycle_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let open = opening(format);
        let previous = event(&open, format);
        let mut command = retarget(&open);
        // Explicit tip refresh is permitted only after admission verifies it.
        command.data.source_tip = command.data.target_tip;
        let next = event(&command, format);
        validate_transition(Some(&previous), &next).unwrap();
        let bytes = encode_body(&next).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
            next
        );
        assert_eq!(event(&command, format), next);
        assert_eq!(command.data.source_ref, open.data.source_ref);
        for action in [PullRequestAction::Update, PullRequestAction::Close] {
            let mut follow = command.clone();
            follow.action = action;
            follow.expected_version = ExpectedVersion::Exactly(next.version);
            validate_transition(Some(&next), &event(&follow, format)).unwrap();
        }
        // A later explicit retarget can return to the original branch.
        command.expected_version = ExpectedVersion::Exactly(next.version);
        command.data.target_ref = open.data.target_ref;
        validate_transition(Some(&next), &event(&command, format)).unwrap();
    }
}

#[test]
fn only_retarget_changes_target_and_it_never_changes_source_or_resumes_a_closed_pr() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let open = opening(format);
        let previous = event(&open, format);
        let command = retarget(&open);
        validate_transition(Some(&previous), &event(&command, format)).unwrap();
        for action in [
            PullRequestAction::Update,
            PullRequestAction::Close,
            PullRequestAction::Reopen,
        ] {
            let mut implicit = command.clone();
            implicit.action = action;
            assert_eq!(
                validate_transition(Some(&previous), &event(&implicit, format)),
                Err(RefusalCode::ProtectedRefTransitionDenied)
            );
        }
        for source_change in [false, true] {
            let mut invalid = command.clone();
            if source_change {
                invalid.data.source_ref = RefName::try_new(b"refs/heads/other").unwrap();
            } else {
                invalid.data.target_ref = open.data.target_ref.clone();
            }
            assert_eq!(
                validate_transition(Some(&previous), &event(&invalid, format)),
                Err(RefusalCode::ProtectedRefTransitionDenied)
            );
        }
        let mut close = open.clone();
        close.action = PullRequestAction::Close;
        close.expected_version = ExpectedVersion::Exactly(previous.version);
        let closed = event(&close, format);
        let mut invalid = command.clone();
        invalid.expected_version = ExpectedVersion::Exactly(closed.version);
        assert_eq!(
            validate_transition(Some(&closed), &event(&invalid, format)),
            Err(RefusalCode::ProtectedRefTransitionDenied)
        );
        invalid.action = PullRequestAction::Reopen;
        assert_eq!(
            validate_transition(Some(&closed), &event(&invalid, format)),
            Err(RefusalCode::ProtectedRefTransitionDenied)
        );
        invalid.data.target_ref = open.data.target_ref;
        validate_transition(Some(&closed), &event(&invalid, format)).unwrap();
    }
}

#[test]
fn retarget_requires_existing_exact_native_stream_and_distinct_sealed_action() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let open = opening(format);
        let mut previous = event(&open, format);
        let mut command = retarget(&open);
        let next = event(&command, format);
        assert_eq!(
            validate_transition(None, &next),
            Err(RefusalCode::EvidenceStale)
        );
        command.expected_version = ExpectedVersion::NewStream;
        assert_eq!(
            command.proposed_event(actor(), format),
            Err(RefusalCode::EvidenceInvalid)
        );
        command.expected_version = ExpectedVersion::Exactly(next.version);
        assert_eq!(
            validate_transition(Some(&previous), &event(&command, format)),
            Err(RefusalCode::EvidenceStale)
        );
        command = retarget(&open);
        let bytes = encode_body(&next).unwrap();
        for action in [
            PullRequestAction::Update,
            PullRequestAction::Close,
            PullRequestAction::Reopen,
        ] {
            command.action = action;
            assert_ne!(encode_body(&event(&command, format)).unwrap(), bytes);
        }
        previous.payload = ForgeEventPayload::MergeCommittedNative(NativeMerge {
            source_ref: open.data.source_ref.clone(),
            source_tip: open.data.source_tip,
            target_ref: open.data.target_ref.clone(),
            target_tip_before: open.data.target_tip,
            base_tip: open.data.target_tip,
            merge_commit: open.data.source_tip,
        });
        assert_eq!(
            validate_transition(Some(&previous), &next),
            Err(RefusalCode::ProtectedRefTransitionDenied)
        );
        previous.payload = ForgeEventPayload::PullRequestClosed { withdrawn: true };
        assert_eq!(
            validate_transition(Some(&previous), &next),
            Err(RefusalCode::ProtectedRefTransitionDenied)
        );
    }
}

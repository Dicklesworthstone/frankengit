//! Reopen extends the existing native lifecycle; it is not an Update alias.
use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn command(format: GitHashAlgorithm) -> PullRequestCommand {
    PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: RefName::try_new(b"refs/heads/topic\xff").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: GitOid::from_hex(format, &"a".repeat(format.digest_len() * 2)).unwrap(),
            target_tip: GitOid::from_hex(format, &"b".repeat(format.digest_len() * 2)).unwrap(),
            title: "Resume review".into(),
            body: "Original description: é\n<script>data</script>".into(),
        },
    }
}

fn actor() -> PrincipalId {
    PrincipalId::from_bytes([7; 16])
}

fn advance(
    command: &mut PullRequestCommand,
    previous: &ForgeEvent,
    action: PullRequestAction,
    format: GitHashAlgorithm,
) -> ForgeEvent {
    command.action = action;
    command.expected_version = ExpectedVersion::Exactly(previous.version);
    command.proposed_event(actor(), format).unwrap()
}

fn closed(format: GitHashAlgorithm) -> (PullRequestCommand, ForgeEvent) {
    let mut command = command(format);
    let open = command.proposed_event(actor(), format).unwrap();
    let close = advance(&mut command, &open, PullRequestAction::Close, format);
    validate_transition(Some(&open), &close).unwrap();
    (command, close)
}

#[test]
fn reopen_roundtrips_both_native_domains_and_can_update_close_and_reopen_again() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut command, mut previous) = closed(format);
        // An explicit refreshed tip is part of the request, never a lookup
        // during retry. Live-ref membership is the admission layer's check.
        command.data.source_tip =
            GitOid::from_hex(format, &"c".repeat(format.digest_len() * 2)).unwrap();
        command.data.body.push_str("\nRevised proposal");
        for action in [
            PullRequestAction::Reopen,
            PullRequestAction::Update,
            PullRequestAction::Close,
            PullRequestAction::Reopen,
        ] {
            let next = advance(&mut command, &previous, action, format);
            validate_transition(Some(&previous), &next).unwrap();
            let bytes = encode_body(&next).unwrap();
            assert_eq!(decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(), next);
            assert_eq!(command.proposed_event(actor(), format).unwrap(), next);
            previous = next;
        }
    }
}

#[test]
fn every_closed_and_active_transition_has_an_explicit_permitted_or_refused_result() {
    let format = GitHashAlgorithm::Sha1;
    let mut command = command(format);
    let open = command.proposed_event(actor(), format).unwrap();
    let update = advance(&mut command, &open, PullRequestAction::Update, format);
    let close = advance(&mut command, &update, PullRequestAction::Close, format);
    let reopen = advance(&mut command, &close, PullRequestAction::Reopen, format);
    for previous in [open, update, close, reopen] {
        let ForgeEventPayload::PullRequestChangedNative(old) = &previous.payload else {
            panic!("native lifecycle fixture");
        };
        for action in [
            PullRequestAction::Open,
            PullRequestAction::Update,
            PullRequestAction::Close,
            PullRequestAction::Reopen,
        ] {
            let mut next = previous.clone();
            next.version = previous.version.next().unwrap();
            next.payload = ForgeEventPayload::PullRequestChangedNative(NativePullRequestEvent {
                action,
                actor: actor(),
                data: old.data.clone(),
            });
            let allowed = if old.action == PullRequestAction::Close {
                action == PullRequestAction::Reopen
            } else {
                matches!(action, PullRequestAction::Update | PullRequestAction::Close)
            };
            assert_eq!(
                validate_transition(Some(&previous), &next),
                if allowed { Ok(()) } else { Err(RefusalCode::ProtectedRefTransitionDenied) },
                "{:?} -> {action:?}", old.action,
            );
        }
    }
}

#[test]
fn merged_native_and_legacy_streams_cannot_be_reopened() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut command, mut previous) = closed(format);
        let next = advance(&mut command, &previous, PullRequestAction::Reopen, format);
        validate_transition(Some(&previous), &next).unwrap();
        previous.payload = ForgeEventPayload::MergeCommittedNative(NativeMerge {
            source_ref: command.data.source_ref.clone(),
            source_tip: command.data.source_tip,
            target_ref: command.data.target_ref.clone(),
            target_tip_before: command.data.target_tip,
            base_tip: command.data.target_tip,
            merge_commit: GitOid::from_hex(format, &"d".repeat(format.digest_len() * 2)).unwrap(),
        });
        assert_eq!(validate_transition(Some(&previous), &next), Err(RefusalCode::ProtectedRefTransitionDenied));
        previous.payload = ForgeEventPayload::PullRequestClosed { withdrawn: true };
        assert_eq!(validate_transition(Some(&previous), &next), Err(RefusalCode::ProtectedRefTransitionDenied));
        let digest = fgit_codec::harness::digest_of(1);
        previous.payload = ForgeEventPayload::MergeCommitted {
            merge_commit: digest, target_ref: b"refs/heads/main".to_vec(),
            target_tip_before: digest, target_tip_after: digest,
        };
        assert_eq!(validate_transition(Some(&previous), &next), Err(RefusalCode::ProtectedRefTransitionDenied));
    }
}

#[test]
fn reopening_cannot_retarget_branches_or_skip_the_expected_version() {
    let format = GitHashAlgorithm::Sha1;
    let (mut command, previous) = closed(format);
    let permitted = advance(&mut command, &previous, PullRequestAction::Reopen, format);
    validate_transition(Some(&previous), &permitted).unwrap();
    for source in [false, true] {
        let mut changed = command.clone();
        if source {
            changed.data.source_ref = RefName::try_new(b"refs/heads/other").unwrap();
        } else {
            changed.data.target_ref = RefName::try_new(b"refs/heads/other").unwrap();
        }
        let next = changed.proposed_event(actor(), format).unwrap();
        assert_eq!(validate_transition(Some(&previous), &next), Err(RefusalCode::ProtectedRefTransitionDenied));
    }
    let mut stale = permitted.clone();
    stale.version = previous.version;
    assert_eq!(validate_transition(Some(&previous), &stale), Err(RefusalCode::EvidenceStale));
    stale.version = permitted.version.next().unwrap();
    assert_eq!(validate_transition(Some(&previous), &stale), Err(RefusalCode::EvidenceStale));
    assert_eq!(validate_transition(None, &permitted), Err(RefusalCode::EvidenceStale));
    stale = permitted;
    stale.aggregate = AggregateId::PullRequest(PullRequestNumber::try_new(2).unwrap());
    assert_eq!(validate_transition(Some(&previous), &stale), Err(RefusalCode::EvidenceStale));
}

#[test]
fn reopen_is_not_creation_and_first_version_forgery_cannot_encode() {
    let format = GitHashAlgorithm::Sha1;
    let mut command = command(format);
    command.action = PullRequestAction::Reopen;
    assert_eq!(command.proposed_event(actor(), format), Err(RefusalCode::EvidenceInvalid));
    command.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    let mut event = command.proposed_event(actor(), format).unwrap();
    assert!(encode_body(&event).is_ok());
    event.version = AggregateVersion::FIRST;
    assert!(encode_body(&event).is_err());
    command.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(u64::MAX).unwrap());
    assert_eq!(command.proposed_event(actor(), format), Err(RefusalCode::ResourceBudgetExceeded));
}

#[test]
fn action_actor_and_refreshed_data_remain_distinct_retry_identity_material() {
    let format = GitHashAlgorithm::Sha256;
    let (mut command, previous) = closed(format);
    let reopen = advance(&mut command, &previous, PullRequestAction::Reopen, format);
    let bytes = encode_body(&reopen).unwrap();
    assert_eq!(encode_body(&command.proposed_event(actor(), format).unwrap()).unwrap(), bytes);
    for action in [PullRequestAction::Update, PullRequestAction::Close] {
        let mut different = command.clone();
        different.action = action;
        assert_ne!(encode_body(&different.proposed_event(actor(), format).unwrap()).unwrap(), bytes);
    }
    assert_ne!(encode_body(&command.proposed_event(PrincipalId::from_bytes([8; 16]), format).unwrap()).unwrap(), bytes);
    command.data.body.push('!');
    assert_ne!(encode_body(&command.proposed_event(actor(), format).unwrap()).unwrap(), bytes);
}

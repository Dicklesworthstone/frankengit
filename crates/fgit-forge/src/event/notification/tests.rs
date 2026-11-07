use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn event(action: NotificationAction, before: u64) -> ForgeEvent {
    NotificationCommand {
        target: NotificationTarget::Issue(IssueNumber::FIRST),
        expected_version: if before == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(before).unwrap())
        },
        action,
    }
    .proposed_event(PrincipalId::from_bytes([3; 16]))
    .unwrap()
}

#[test]
fn canonical_notification_roundtrips_and_refuses_truncation_or_forged_actor() {
    for action in [
        NotificationAction::SetMode(NotificationMode::Participating),
        NotificationAction::SetMode(NotificationMode::Subscribed),
        NotificationAction::SetMode(NotificationMode::Muted),
        NotificationAction::SetReadThrough(None),
        NotificationAction::SetReadThrough(Some(AggregateVersion::FIRST)),
    ] {
        let event = event(action, 0);
        let bytes = encode_body(&event).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
            event
        );
        for length in 0..bytes.len() {
            assert!(decode_body::<ForgeEvent>(&bytes[..length], DecodeLimits::DEFAULT).is_err());
        }
        let mut forged = event.clone();
        let ForgeEventPayload::NotificationPreferenceChangedNative(change) = &mut forged.payload
        else {
            unreachable!()
        };
        change.actor = PrincipalId::from_bytes([4; 16]);
        assert!(encode_body(&forged).is_err());
        assert_eq!(
            apply_event(None, &forged),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
}

#[test]
fn modes_and_read_prefix_change_independently_and_require_contiguous_self_stream() {
    let read = apply_event(
        None,
        &event(
            NotificationAction::SetReadThrough(Some(AggregateVersion::try_new(9).unwrap())),
            0,
        ),
    )
    .unwrap();
    assert_eq!(read.mode, NotificationMode::Participating);
    let muted = apply_event(
        Some(&read),
        &event(NotificationAction::SetMode(NotificationMode::Muted), 1),
    )
    .unwrap();
    assert_eq!(muted.read_through, read.read_through);
    let unread = apply_event(
        Some(&muted),
        &event(NotificationAction::SetReadThrough(None), 2),
    )
    .unwrap();
    assert_eq!(unread.mode, NotificationMode::Muted);
    assert_eq!(unread.read_through, None);
    assert!(
        apply_event(
            Some(&unread),
            &event(NotificationAction::SetMode(NotificationMode::Subscribed), 2)
        )
        .is_err()
    );
    assert!(
        apply_event(
            None,
            &event(NotificationAction::SetMode(NotificationMode::Subscribed), 1)
        )
        .is_err()
    );
    let mut other = unread.clone();
    other.principal = PrincipalId::from_bytes([4; 16]);
    assert!(
        apply_event(
            Some(&other),
            &event(NotificationAction::SetMode(NotificationMode::Subscribed), 3)
        )
        .is_err()
    );
    let label = AggregateId::NotificationPreference {
        principal: read.principal,
        issue: IssueNumber::try_new(u64::MAX).unwrap(),
    }
    .to_string();
    assert!(label.len() <= 64);
    assert!(fgit_types::AsciiSlug::try_new("notification", label.as_bytes()).is_ok());
}

#[test]
fn required_wire_codes_do_not_reuse_existing_aggregates_or_events() {
    let notification = event(NotificationAction::SetMode(NotificationMode::Subscribed), 0);
    assert_eq!(notification.payload.kind(), 23);
    let mut encoded = Encoder::new();
    super::super::write_aggregate(&mut encoded, notification.aggregate);
    let mut expected = Vec::new();
    expected.extend(0u64.to_be_bytes());
    expected.extend(10u32.to_be_bytes());
    expected.extend([3u8; 16]);
    expected.extend(1u64.to_be_bytes());
    assert_eq!(encoded.as_bytes(), expected);
    let mut mixed = notification;
    mixed.aggregate = AggregateId::Issue(IssueNumber::FIRST);
    assert!(encode_body(&mixed).is_err());
}

#[test]
fn discussion_preferences_have_distinct_identity_and_preserve_the_issue_wire_profile() {
    let owner = PrincipalId::from_bytes([3; 16]);
    for action in [
        NotificationAction::SetMode(NotificationMode::Participating),
        NotificationAction::SetMode(NotificationMode::Subscribed),
        NotificationAction::SetMode(NotificationMode::Muted),
        NotificationAction::SetReadThrough(None),
        NotificationAction::SetReadThrough(Some(AggregateVersion::FIRST)),
    ] {
        let issue = event(action, 0);
        let discussion = NotificationCommand {
            target: NotificationTarget::Discussion(DiscussionNumber::FIRST),
            expected_version: ExpectedVersion::NewStream,
            action,
        }
        .proposed_event(owner)
        .unwrap();
        let admission = crate::event::admission::classify_event(
            &discussion,
            crate::event::admission::ForgeCommandProfile::ExactVersion,
        );
        assert_eq!(
            admission,
            fgit_calm::forge_admission_rule(
                fgit_calm::ForgeOperation::NotificationPreferenceChange
            )
        );
        assert_eq!(
            admission.replan,
            fgit_calm::ForgeReplanPolicy::PreservePreconditions
        );
        assert_eq!(discussion.payload.kind(), 23);
        let issue_bytes = encode_body(&issue).unwrap();
        let bytes = encode_body(&discussion).unwrap();
        assert_ne!(bytes, issue_bytes);
        // The aggregate discriminator is the only wire difference for equal
        // owner, number, version and action. Existing issue bytes remain exact.
        let mut expected = fgit_codec::canonical_body_bytes(&issue).unwrap();
        expected[8..12].copy_from_slice(&12_u32.to_be_bytes());
        assert_eq!(
            fgit_codec::canonical_body_bytes(&discussion).unwrap(),
            expected
        );
        assert_eq!(
            decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
            discussion
        );
        for length in 0..bytes.len() {
            assert!(decode_body::<ForgeEvent>(&bytes[..length], DecodeLimits::DEFAULT).is_err());
        }
        let issue_state = apply_event(None, &issue).unwrap();
        let mut next = discussion.clone();
        next.version = AggregateVersion::FIRST.next().unwrap();
        assert_eq!(
            apply_event(Some(&issue_state), &next),
            Err(RefusalCode::EvidenceStale)
        );
        let state = apply_event(None, &discussion).unwrap();
        assert_eq!(
            state.target,
            NotificationTarget::Discussion(DiscussionNumber::FIRST)
        );
        assert_eq!(state.principal, owner);
        let mut forged = discussion;
        forged.aggregate = AggregateId::DiscussionNotificationPreference {
            principal: PrincipalId::from_bytes([4; 16]),
            discussion: DiscussionNumber::FIRST,
        };
        assert!(encode_body(&forged).is_err());
        assert_eq!(
            apply_event(None, &forged),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
    let target = NotificationTarget::Discussion(DiscussionNumber::try_new(u64::MAX).unwrap());
    let aggregate = target.preference_aggregate(owner);
    let label = aggregate.to_string();
    assert_eq!(label, format!("dnotify/{owner}/{}", u64::MAX));
    assert!(fgit_types::AsciiSlug::try_new("notification", label.as_bytes()).is_ok());
    assert_eq!(
        NotificationTarget::from_preference_aggregate(aggregate),
        Some((owner, target))
    );
    assert_eq!(target.kind().name(), "discussion");
    assert_eq!(target.number(), u64::MAX);
}

#[test]
fn pull_request_activity_preferences_preserve_older_bytes_and_private_owner_identity() {
    let owner = PrincipalId::from_bytes([3; 16]);
    let target = NotificationTarget::PullRequest(PullRequestNumber::FIRST);
    for action in [
        NotificationAction::SetMode(NotificationMode::Participating),
        NotificationAction::SetMode(NotificationMode::Subscribed),
        NotificationAction::SetMode(NotificationMode::Muted),
        NotificationAction::SetReadThrough(None),
        NotificationAction::SetReadThrough(Some(AggregateVersion::try_new(9).unwrap())),
    ] {
        let pull = NotificationCommand {
            target,
            expected_version: ExpectedVersion::NewStream,
            action,
        }
        .proposed_event(owner)
        .unwrap();
        assert_eq!(
            pull.payload.kind(),
            23,
            "existing private preference payload"
        );
        let issue = event(action, 0);
        let mut expected = fgit_codec::canonical_body_bytes(&issue).unwrap();
        expected[8..12].copy_from_slice(&14u32.to_be_bytes());
        assert_eq!(fgit_codec::canonical_body_bytes(&pull).unwrap(), expected);
        let bytes = encode_body(&pull).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
            pull
        );
        for length in 0..bytes.len() {
            assert!(decode_body::<ForgeEvent>(&bytes[..length], DecodeLimits::DEFAULT).is_err());
        }
        let mut next = pull.clone();
        next.version = AggregateVersion::FIRST.next().unwrap();
        for other in [
            NotificationTarget::Issue(IssueNumber::FIRST),
            NotificationTarget::Discussion(DiscussionNumber::FIRST),
            NotificationTarget::PullRequest(PullRequestNumber::try_new(2).unwrap()),
        ] {
            let other_event = NotificationCommand {
                target: other,
                expected_version: ExpectedVersion::NewStream,
                action,
            }
            .proposed_event(owner)
            .unwrap();
            assert_ne!(encode_body(&other_event).unwrap(), bytes);
            assert_eq!(
                apply_event(Some(&apply_event(None, &other_event).unwrap()), &next),
                Err(RefusalCode::EvidenceStale)
            );
        }
        let state = apply_event(None, &pull).unwrap();
        assert_eq!(state.target, target);
        assert_eq!(state.principal, owner);
        let mut forged = pull.clone();
        forged.aggregate = target.preference_aggregate(PrincipalId::from_bytes([9; 16]));
        assert!(encode_body(&forged).is_err());
        assert_eq!(
            apply_event(None, &forged),
            Err(RefusalCode::EvidenceInvalid)
        );
        assert_eq!(
            crate::event::admission::classify_event(
                &pull,
                crate::event::admission::ForgeCommandProfile::ExactVersion
            )
            .replan,
            fgit_calm::ForgeReplanPolicy::PreservePreconditions,
        );
    }
    let target = NotificationTarget::PullRequest(PullRequestNumber::try_new(u64::MAX).unwrap());
    let aggregate = target.preference_aggregate(owner);
    assert_eq!(
        aggregate.to_string(),
        format!("pnotify/{owner}/{}", u64::MAX)
    );
    assert!(
        fgit_types::AsciiSlug::try_new("notification", aggregate.to_string().as_bytes()).is_ok()
    );
    assert_eq!(
        NotificationTarget::from_preference_aggregate(aggregate),
        Some((owner, target))
    );
    assert_eq!(target.kind().name(), "pull_request");
    assert_eq!(target.number(), u64::MAX);
}

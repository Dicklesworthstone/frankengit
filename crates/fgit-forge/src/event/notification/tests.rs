use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn event(action: NotificationAction, before: u64) -> ForgeEvent {
    NotificationCommand {
        number: IssueNumber::FIRST,
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

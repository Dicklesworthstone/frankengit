use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

#[test]
fn milestone_action_tags_bind_both_selected_numbers_and_versions() {
    let action = IssueAction::SetMilestone {
        milestone: MilestoneNumber::try_new(7).unwrap(),
        expected_milestone_version: AggregateVersion::try_new(12).unwrap(),
    };
    let expected = [
        10u32.to_be_bytes().as_slice(),
        7u64.to_be_bytes().as_slice(),
        12u64.to_be_bytes().as_slice(),
    ]
    .concat();
    for (action, literal) in [
        (action, expected),
        (IssueAction::ClearMilestone, 11u32.to_be_bytes().to_vec()),
    ] {
        let mut encoder = Encoder::new();
        action.write(&mut encoder).unwrap();
        assert_eq!(encoder.as_bytes(), literal);
        let mut decoder = Decoder::new(&literal, DecodeLimits::DEFAULT);
        assert_eq!(IssueAction::read(&mut decoder).unwrap(), action);
        decoder.finish().unwrap();
        for end in 0..literal.len() {
            assert!(
                IssueAction::read(&mut Decoder::new(&literal[..end], DecodeLimits::DEFAULT))
                    .is_err()
            );
        }
        let event = IssueCommand {
            number: IssueNumber::FIRST,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action,
        }
        .proposed_event(PrincipalId::from_bytes([7; 16]))
        .unwrap();
        let frame = encode_body(&event).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(),
            event
        );
        for end in 0..frame.len() {
            assert!(decode_body::<ForgeEvent>(&frame[..end], DecodeLimits::DEFAULT).is_err());
        }
        let mut trailing = literal;
        trailing.push(0);
        let mut decoder = Decoder::new(&trailing, DecodeLimits::DEFAULT);
        IssueAction::read(&mut decoder).unwrap();
        assert!(decoder.finish().is_err());
    }
    for (number, version) in [(0u64, 1u64), (1, 0)] {
        let bytes = [
            10u32.to_be_bytes().as_slice(),
            number.to_be_bytes().as_slice(),
            version.to_be_bytes().as_slice(),
        ]
        .concat();
        assert!(IssueAction::read(&mut Decoder::new(&bytes, DecodeLimits::DEFAULT)).is_err());
    }
}

#[test]
fn legacy_opening_bytes_keep_membership_absent_and_new_selection_changes_identity() {
    let actor = PrincipalId::from_bytes([9; 16]);
    let opening = IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: "Release task".into(),
            body: String::new(),
            labels: Vec::new(),
        },
    }
    .proposed_event(actor)
    .unwrap();
    let bytes = encode_body(&opening).unwrap();
    let restored = decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(encode_body(&restored).unwrap(), bytes);
    assert_eq!(apply_event(None, &restored).unwrap().milestone, None);
    let mut encodings = std::collections::BTreeSet::new();
    for (number, version) in [(1, 1), (1, 2), (2, 1)] {
        let event = IssueCommand {
            number: IssueNumber::FIRST,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: IssueAction::SetMilestone {
                milestone: MilestoneNumber::try_new(number).unwrap(),
                expected_milestone_version: AggregateVersion::try_new(version).unwrap(),
            },
        }
        .proposed_event(actor)
        .unwrap();
        assert!(encodings.insert(encode_body(&event).unwrap()));
    }
}

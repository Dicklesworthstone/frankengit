use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn intent(assignees: Vec<PrincipalId>) -> IssueAssigneesIntent {
    IssueAssigneesIntent {
        number: IssueNumber::FIRST,
        assignees,
    }
}
fn principal(value: u8) -> PrincipalId {
    PrincipalId::from_bytes([value; 16])
}

#[test]
fn additive_commitment_reuses_legacy_assign_bytes_at_a_fixed_non_open_position() {
    let actor = principal(7);
    let intent = intent(vec![principal(2), principal(3)]);
    let template = intent.commitment_event(actor).unwrap();
    assert_eq!(template.version.get(), 2);
    let legacy = IssueCommand {
        number: intent.number,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
        action: IssueAction::Assign {
            assignees: intent.assignees,
        },
    }
    .proposed_event(actor)
    .unwrap();
    let bytes = encode_body(&template).unwrap();
    assert_eq!(bytes, encode_body(&legacy).unwrap());
    assert_eq!(
        decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
        template
    );
    let mut invalid = template;
    invalid.version = AggregateVersion::FIRST;
    assert!(encode_body(&invalid).is_err());
}

#[test]
fn additive_assignees_require_a_nonempty_sorted_unique_bounded_set() {
    for assignees in [
        vec![],
        vec![principal(1), principal(1)],
        vec![principal(2), principal(1)],
        (0..=super::super::MAX_ASSIGNEES as u8)
            .map(principal)
            .collect(),
    ] {
        let intent = intent(assignees);
        assert!(intent.validate().is_err());
        assert_eq!(
            intent.commitment_event(principal(7)),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
    for assignees in [
        vec![principal(1)],
        (0..super::super::MAX_ASSIGNEES as u8)
            .map(principal)
            .collect(),
    ] {
        let intent = intent(assignees);
        intent.validate().unwrap();
        assert!(encode_body(&intent.commitment_event(principal(7)).unwrap()).is_ok());
    }
}

#[test]
fn additions_preserve_existing_assignees_and_enforce_the_current_union_limit() {
    use super::super::{MAX_ASSIGNEES, apply_event};

    let actor = principal(7);
    let opened = IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: "Shared assignment".into(),
            body: String::new(),
            labels: vec![],
        },
    }
    .proposed_event(actor)
    .unwrap();
    let mut issue = apply_event(None, &opened).unwrap();
    let first = intent(vec![principal(1)]).commitment_event(actor).unwrap();
    issue = apply_event(Some(&issue), &first).unwrap();
    let overlapping = ForgeEvent {
        version: issue.version.next().unwrap(),
        ..intent(vec![principal(1), principal(2)])
            .commitment_event(actor)
            .unwrap()
    };
    issue = apply_event(Some(&issue), &overlapping).unwrap();
    assert_eq!(issue.assignees, vec![principal(1), principal(2)]);

    let maximum = intent((1..=MAX_ASSIGNEES as u8).map(principal).collect());
    let fill = ForgeEvent {
        version: issue.version.next().unwrap(),
        ..maximum.commitment_event(actor).unwrap()
    };
    issue = apply_event(Some(&issue), &fill).unwrap();
    assert_eq!(issue.assignees.len(), MAX_ASSIGNEES);
    let already_present = ForgeEvent {
        version: issue.version.next().unwrap(),
        ..maximum.commitment_event(actor).unwrap()
    };
    let repeated = apply_event(Some(&issue), &already_present).unwrap();
    assert_eq!(repeated.assignees, issue.assignees);
    let overflow = ForgeEvent {
        version: issue.version.next().unwrap(),
        ..intent(vec![principal(MAX_ASSIGNEES as u8 + 1)])
            .commitment_event(actor)
            .unwrap()
    };
    assert_eq!(
        apply_event(Some(&issue), &overflow),
        Err(RefusalCode::ResourceBudgetExceeded)
    );
}

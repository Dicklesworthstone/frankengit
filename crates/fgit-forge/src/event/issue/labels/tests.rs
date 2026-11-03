use super::super::{
    IssueEdit, IssueSnapshot, IssueState, MAX_LABEL_BYTES, MAX_LABELS, apply_event,
};
use super::*;
use fgit_codec::{DecodeLimits, Decoder, Encoder, decode_body, encode_body};

fn actor() -> PrincipalId {
    PrincipalId::from_bytes([7; 16])
}
fn intent(labels: &[&str]) -> IssueLabelsIntent {
    IssueLabelsIntent {
        number: IssueNumber::FIRST,
        labels: labels.iter().map(|label| (*label).into()).collect(),
    }
}
fn opened(labels: Vec<String>) -> IssueSnapshot {
    let event = IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: "Concurrent triage".into(),
            body: "Exact body é\r\n".into(),
            labels,
        },
    }
    .proposed_event(actor())
    .unwrap();
    apply_event(None, &event).unwrap()
}
fn apply(issue: &IssueSnapshot, action: IssueAction) -> Result<IssueSnapshot, RefusalCode> {
    let event = IssueCommand {
        number: issue.number,
        expected_version: ExpectedVersion::Exactly(issue.version),
        action,
    }
    .proposed_event(actor())
    .unwrap();
    apply_event(Some(issue), &event)
}

#[test]
fn label_addition_has_tag_twelve_and_a_fixed_non_open_commitment_position() {
    let intent = intent(&["a", "é"]);
    let event = intent.commitment_event(actor()).unwrap();
    assert_eq!(event.version.get(), 2);
    let action = IssueAction::AddLabels {
        labels: intent.labels,
    };
    assert_eq!(action.name(), "add-labels");
    let mut encoder = Encoder::new();
    action.write(&mut encoder).unwrap();
    let expected = [
        0, 0, 0, 12, 0, 0, 0, 2, 0, 0, 0, 1, b'a', 0, 0, 0, 2, 0xc3, 0xa9,
    ];
    assert_eq!(encoder.as_bytes(), expected);
    let mut decoder = Decoder::new(&expected, DecodeLimits::DEFAULT);
    assert_eq!(IssueAction::read(&mut decoder).unwrap(), action);
    decoder.finish().unwrap();
    for end in 0..expected.len() {
        assert!(
            IssueAction::read(&mut Decoder::new(&expected[..end], DecodeLimits::DEFAULT)).is_err()
        );
    }
    let bytes = encode_body(&event).unwrap();
    assert_eq!(
        decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
        event
    );
    let mut opening = event;
    opening.version = AggregateVersion::FIRST;
    assert!(encode_body(&opening).is_err());
    for count in [33u32, u32::MAX] {
        let invalid = [12u32.to_be_bytes(), count.to_be_bytes()].concat();
        assert!(matches!(
            IssueAction::read(&mut Decoder::new(&invalid, DecodeLimits::DEFAULT)),
            Err(CodecRefusal::CountBoundExceeded { field: "issue.labels", observed, limit: 32 })
                if observed == u64::from(count)
        ));
    }
}

#[test]
fn added_labels_are_nonempty_distinct_canonical_and_bounded_by_utf8_bytes() {
    for labels in [
        vec![],
        vec!["a".into(), "a".into()],
        vec!["b".into(), "a".into()],
        vec![" ".into()],
        vec!["bad\nlabel".into()],
        vec!["é".repeat(33)],
        (0..=MAX_LABELS).map(|n| format!("label-{n:02}")).collect(),
    ] {
        let value = IssueLabelsIntent {
            number: IssueNumber::FIRST,
            labels,
        };
        assert!(value.validate().is_err());
        assert_eq!(
            value.commitment_event(actor()),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
    for labels in [
        vec!["é".repeat(MAX_LABEL_BYTES / 2)],
        (0..MAX_LABELS).map(|n| format!("label-{n:02}")).collect(),
    ] {
        let value = IssueLabelsIntent {
            number: IssueNumber::FIRST,
            labels,
        };
        value.validate().unwrap();
        assert!(value.commitment_event(actor()).is_ok());
    }
}

#[test]
fn label_union_is_commutative_idempotent_and_preserves_unrelated_issue_fields() {
    let initial = opened(vec!["keep".into()]);
    let additions = [
        intent(&["bug", "shared"]),
        intent(&["feature", "shared"]),
        intent(&["é"]),
    ];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut selected = initial.clone();
        for index in order {
            selected = apply(
                &selected,
                IssueAction::AddLabels {
                    labels: additions[index].labels.clone(),
                },
            )
            .unwrap();
        }
        assert_eq!(selected.labels, ["bug", "feature", "keep", "shared", "é"]);
        assert_eq!(selected.version.get(), 4);
        let repeated = apply(
            &selected,
            IssueAction::AddLabels {
                labels: selected.labels.clone(),
            },
        )
        .unwrap();
        assert_eq!(repeated.labels, selected.labels);
        assert_eq!(repeated.version.get(), 5);
        selected.labels = initial.labels.clone();
        selected.version = initial.version;
        assert_eq!(selected, initial);
    }
    let closed = apply(&initial, IssueAction::Close).unwrap();
    let locked = apply(&closed, IssueAction::Lock).unwrap();
    let added = apply(
        &locked,
        IssueAction::AddLabels {
            labels: vec!["triage".into()],
        },
    )
    .unwrap();
    assert!(added.locked);
    assert_eq!(added.state, IssueState::Closed);
    assert_eq!(added.labels, ["keep", "triage"]);
}

#[test]
fn union_capacity_is_checked_before_publication_and_exact_replacement_still_replaces() {
    let labels: Vec<String> = (0..MAX_LABELS - 1)
        .map(|n| format!("label-{n:02}"))
        .collect();
    let before = opened(labels);
    let filled = apply(
        &before,
        IssueAction::AddLabels {
            labels: vec!["last".into()],
        },
    )
    .unwrap();
    assert_eq!(filled.labels.len(), MAX_LABELS);
    assert_eq!(
        apply(
            &filled,
            IssueAction::AddLabels {
                labels: vec!["extra".into(), "last".into()]
            }
        ),
        Err(RefusalCode::ResourceBudgetExceeded)
    );
    let overlap = apply(
        &filled,
        IssueAction::AddLabels {
            labels: vec!["last".into()],
        },
    )
    .unwrap();
    assert_eq!(overlap.labels, filled.labels);
    let replaced = apply(
        &overlap,
        IssueAction::Edit(IssueEdit {
            labels: Some(vec!["replacement".into()]),
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(replaced.labels, ["replacement"]);
    let cleared = apply(
        &replaced,
        IssueAction::Edit(IssueEdit {
            labels: Some(vec![]),
            ..Default::default()
        }),
    )
    .unwrap();
    assert!(cleared.labels.is_empty());
    assert_eq!(cleared.title, before.title);
    assert_eq!(cleared.body, before.body);
    assert_eq!(cleared.opened_by, before.opened_by);
}

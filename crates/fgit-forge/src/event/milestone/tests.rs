use super::*;
use crate::IssueNumber;
use crate::event::issue::{self, IssueAction, IssueCommand, IssueQuery, MilestoneFilter};
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn actor(n: u8) -> PrincipalId {
    PrincipalId::from_bytes([n; 16])
}
fn command(version: u64, action: MilestoneAction) -> MilestoneCommand {
    MilestoneCommand {
        number: MilestoneNumber::FIRST,
        expected_version: if version == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
        },
        action,
    }
}
fn opened() -> MilestoneSnapshot {
    let event = command(
        0,
        MilestoneAction::Open {
            title: "Release é".into(),
            body: "exact\r\nbody".into(),
            due_at: Some(MAX_DUE_AT),
        },
    )
    .proposed_event(actor(1))
    .unwrap();
    let frame = encode_body(&event).unwrap();
    assert_eq!(
        decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(),
        event
    );
    apply_event(None, &event).unwrap()
}
fn apply(
    state: &MilestoneSnapshot,
    action: MilestoneAction,
) -> Result<MilestoneSnapshot, RefusalCode> {
    apply_event(
        Some(state),
        &command(state.version.get(), action)
            .proposed_event(actor(2))
            .unwrap(),
    )
}

#[test]
fn lifecycle_preserves_exact_fields_and_explicit_date_edit_semantics() {
    let state = opened();
    assert_eq!(state.number, MilestoneNumber::FIRST);
    assert_eq!(state.state, MilestoneState::Open);
    let edited = apply(
        &state,
        MilestoneAction::Edit(MilestoneEdit {
            title: Some("Ready".into()),
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(edited.due_at, Some(MAX_DUE_AT));
    assert_eq!(edited.body, state.body);
    let cleared = apply(
        &edited,
        MilestoneAction::Edit(MilestoneEdit {
            due_at: Some(None),
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(cleared.due_at, None);
    let epoch = apply(
        &cleared,
        MilestoneAction::Edit(MilestoneEdit {
            due_at: Some(Some(0)),
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(epoch.due_at, Some(0));
    let closed = apply(&epoch, MilestoneAction::Close).unwrap();
    assert_eq!(closed.state, MilestoneState::Closed);
    assert_eq!(
        apply(&closed, MilestoneAction::Close),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
    let updated_closed = apply(
        &closed,
        MilestoneAction::Edit(MilestoneEdit {
            body: Some("closed metadata".into()),
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(updated_closed.state, MilestoneState::Closed);
    let reopened = apply(&updated_closed, MilestoneAction::Reopen).unwrap();
    assert_eq!(reopened.state, MilestoneState::Open);
    assert_eq!(reopened.due_at, Some(0));
    assert_eq!(reopened.opened_by, actor(1));
    assert_eq!(reopened.last_actor, actor(2));
    assert_eq!(
        apply(&reopened, MilestoneAction::Reopen),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
}

#[test]
fn malformed_commands_missing_or_stale_predecessors_and_exhaustion_refuse() {
    for action in [
        MilestoneAction::Open {
            title: " ".into(),
            body: String::new(),
            due_at: None,
        },
        MilestoneAction::Open {
            title: "x".repeat(MAX_TITLE_BYTES + 1),
            body: String::new(),
            due_at: None,
        },
        MilestoneAction::Open {
            title: "title".into(),
            body: "bad\0body".into(),
            due_at: None,
        },
        MilestoneAction::Open {
            title: "title".into(),
            body: "x".repeat(MAX_BODY_BYTES + 1),
            due_at: None,
        },
        MilestoneAction::Open {
            title: "title".into(),
            body: String::new(),
            due_at: Some(MAX_DUE_AT + 1),
        },
        MilestoneAction::Edit(MilestoneEdit::default()),
    ] {
        assert!(action.validate().is_err());
    }
    for action in [MilestoneAction::Close, MilestoneAction::Reopen] {
        assert_eq!(
            command(0, action.clone()).proposed_event(actor(1)),
            Err(RefusalCode::EvidenceInvalid)
        );
        let event = command(1, action.clone()).proposed_event(actor(1)).unwrap();
        assert_eq!(apply_event(None, &event), Err(RefusalCode::EvidenceStale));
        assert_eq!(
            command(u64::MAX, action).proposed_event(actor(1)),
            Err(RefusalCode::ResourceBudgetExceeded)
        );
    }
    let state = opened();
    let edited = apply(
        &state,
        MilestoneAction::Edit(MilestoneEdit {
            body: Some("changed".into()),
            ..Default::default()
        }),
    )
    .unwrap();
    let stale = command(1, MilestoneAction::Close)
        .proposed_event(actor(2))
        .unwrap();
    assert_eq!(
        apply_event(Some(&edited), &stale),
        Err(RefusalCode::EvidenceStale)
    );
}

#[test]
fn required_code_points_and_roundtrips_do_not_reuse_existing_tags() {
    let mut aggregate = Encoder::new();
    super::super::write_aggregate(
        &mut aggregate,
        AggregateId::Milestone(MilestoneNumber::FIRST),
    );
    assert_eq!(
        aggregate.as_bytes(),
        [
            0u64.to_be_bytes().as_slice(),
            9u32.to_be_bytes().as_slice(),
            1u64.to_be_bytes().as_slice()
        ]
        .concat()
    );
    for (version, action, tag) in [
        (
            0,
            MilestoneAction::Open {
                title: "release".into(),
                body: String::new(),
                due_at: None,
            },
            1u32,
        ),
        (
            1,
            MilestoneAction::Edit(MilestoneEdit {
                body: Some("é\r\n".into()),
                due_at: Some(None),
                ..Default::default()
            }),
            2,
        ),
        (1, MilestoneAction::Close, 3),
        (2, MilestoneAction::Reopen, 4),
    ] {
        let mut action_bytes = Encoder::new();
        action.write(&mut action_bytes).unwrap();
        assert_eq!(&action_bytes.as_bytes()[..4], tag.to_be_bytes());
        let event = command(version, action).proposed_event(actor(3)).unwrap();
        assert_eq!(event.payload.kind(), 22);
        let bytes = encode_body(&event).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
            event
        );
        for end in 0..bytes.len() {
            assert!(decode_body::<ForgeEvent>(&bytes[..end], DecodeLimits::DEFAULT).is_err());
        }
        let mut wrong = event;
        wrong.aggregate = AggregateId::Issue(IssueNumber::FIRST);
        assert!(encode_body(&wrong).is_err());
    }
}

#[test]
fn issue_membership_is_independent_metadata_with_strict_selected_version_bytes() {
    let opening = IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: "issue".into(),
            body: "body".into(),
            labels: vec![],
        },
    }
    .proposed_event(actor(1))
    .unwrap();
    let mut state = issue::apply_event(None, &opening).unwrap();
    assert_eq!(
        state.milestone, None,
        "historical issue bytes derive no membership"
    );
    for action in [
        IssueAction::Close,
        IssueAction::Lock,
        IssueAction::SetMilestone {
            milestone: MilestoneNumber::FIRST,
            expected_milestone_version: AggregateVersion::FIRST,
        },
    ] {
        let event = IssueCommand {
            number: state.number,
            expected_version: ExpectedVersion::Exactly(state.version),
            action,
        }
        .proposed_event(actor(2))
        .unwrap();
        let bytes = encode_body(&event).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
            event
        );
        state = issue::apply_event(Some(&state), &event).unwrap();
    }
    assert_eq!(state.milestone, Some(MilestoneNumber::FIRST));
    assert_eq!(state.state, issue::IssueState::Closed);
    assert!(state.locked);
    for (filter, matches) in [
        (None, true),
        (Some(MilestoneFilter::Unassigned), false),
        (Some(MilestoneFilter::Number(MilestoneNumber::FIRST)), true),
        (
            Some(MilestoneFilter::Number(
                MilestoneNumber::try_new(2).unwrap(),
            )),
            false,
        ),
    ] {
        assert_eq!(
            IssueQuery {
                milestone: filter,
                ..Default::default()
            }
            .compile()
            .unwrap()
            .matches(&state)
            .unwrap(),
            matches
        );
    }
    let event = IssueCommand {
        number: state.number,
        expected_version: ExpectedVersion::Exactly(state.version),
        action: IssueAction::ClearMilestone,
    }
    .proposed_event(actor(3))
    .unwrap();
    let cleared = issue::apply_event(Some(&state), &event).unwrap();
    assert_eq!(cleared.milestone, None);
    assert_eq!(cleared.title, state.title);
    assert_eq!(cleared.body, state.body);
    assert_eq!(cleared.state, state.state);
    assert_eq!(cleared.locked, state.locked);
}

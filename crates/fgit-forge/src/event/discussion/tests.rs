use super::*;
use crate::event::admission::{ForgeCommandProfile, ForgeReplanPolicy, classify_event};
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn actor(n: u8) -> PrincipalId {
    PrincipalId::from_bytes([n; 16])
}

fn command(version: u64, action: DiscussionAction) -> DiscussionCommand {
    DiscussionCommand {
        number: DiscussionNumber::FIRST,
        expected_version: if version == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
        },
        action,
    }
}

fn open_action() -> DiscussionAction {
    DiscussionAction::Open {
        title: "Design é".into(),
        body: "exact\r\nbody".into(),
    }
}

fn opened() -> DiscussionSnapshot {
    apply_event(
        None,
        &command(0, open_action()).proposed_event(actor(1)).unwrap(),
    )
    .unwrap()
}

fn apply(
    state: &DiscussionSnapshot,
    action: DiscussionAction,
) -> Result<DiscussionSnapshot, RefusalCode> {
    let event = command(state.version.get(), action)
        .proposed_event(actor(2))
        .unwrap();
    let frame = encode_body(&event).unwrap();
    let decoded = decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(decoded, event);
    apply_event(Some(state), &decoded)
}

#[test]
fn lifecycle_and_comments_preserve_body_actor_and_independent_moderation() {
    let open = opened();
    assert_eq!(open.state, DiscussionState::Open);
    assert_eq!(open.comments, 0);
    assert!(!open.locked);
    assert_eq!(open.body, "exact\r\nbody");
    let commented = apply(
        &open,
        DiscussionAction::Comment {
            body: "reply\r\né".into(),
        },
    )
    .unwrap();
    assert_eq!(commented.comments, 1);
    assert_eq!(commented.body, open.body);
    let closed = apply(&commented, DiscussionAction::Close).unwrap();
    assert_eq!(closed.state, DiscussionState::Closed);
    assert_eq!(
        apply(&closed, DiscussionAction::Close),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
    let after_close = apply(
        &closed,
        DiscussionAction::Comment {
            body: "closed remains discussable".into(),
        },
    )
    .unwrap();
    assert_eq!(after_close.comments, 2);
    let locked = apply(&after_close, DiscussionAction::Lock).unwrap();
    assert!(locked.locked);
    assert_eq!(
        apply(
            &locked,
            DiscussionAction::Comment {
                body: "refused".into()
            }
        ),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
    assert_eq!(
        apply(&locked, DiscussionAction::Lock),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
    let edited = apply(
        &locked,
        DiscussionAction::Edit(DiscussionEdit {
            title: Some("Updated".into()),
            body: Some(String::new()),
        }),
    )
    .unwrap();
    assert!(edited.locked);
    assert_eq!(edited.state, DiscussionState::Closed);
    assert_eq!(edited.comments, 2);
    assert!(edited.body.is_empty());
    let reopened = apply(&edited, DiscussionAction::Reopen).unwrap();
    assert!(reopened.locked);
    assert_eq!(reopened.state, DiscussionState::Open);
    assert_eq!(
        apply(&reopened, DiscussionAction::Reopen),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
    let unlocked = apply(&reopened, DiscussionAction::Unlock).unwrap();
    assert!(!unlocked.locked);
    assert_eq!(
        apply(&unlocked, DiscussionAction::Unlock),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
    let final_state = apply(
        &unlocked,
        DiscussionAction::Comment {
            body: "accepted again".into(),
        },
    )
    .unwrap();
    assert_eq!(final_state.comments, 3);
    assert_eq!(final_state.opened_by, actor(1));
    assert_eq!(final_state.last_actor, actor(2));
    assert_eq!(final_state.version.get(), 9);
}

#[test]
fn commands_and_folds_require_exact_positive_predecessors_and_nonaliasing_identity() {
    assert!(DiscussionNumber::try_new(0).is_none());
    assert_eq!(
        AggregateId::Discussion(DiscussionNumber::FIRST).to_string(),
        "discussion/1"
    );
    assert_ne!(
        AggregateId::Discussion(DiscussionNumber::FIRST),
        AggregateId::Issue(crate::IssueNumber::FIRST)
    );
    assert_eq!(
        command(1, open_action()).proposed_event(actor(1)),
        Err(RefusalCode::EvidenceInvalid)
    );
    let state = opened();
    for action in [
        DiscussionAction::Edit(DiscussionEdit {
            body: Some(String::new()),
            ..Default::default()
        }),
        DiscussionAction::Comment {
            body: "strict comment".into(),
        },
        DiscussionAction::Close,
        DiscussionAction::Reopen,
        DiscussionAction::Lock,
        DiscussionAction::Unlock,
    ] {
        assert_eq!(
            command(0, action.clone()).proposed_event(actor(2)),
            Err(RefusalCode::EvidenceInvalid)
        );
        let event = command(1, action.clone()).proposed_event(actor(2)).unwrap();
        assert_eq!(apply_event(None, &event), Err(RefusalCode::EvidenceStale));
        assert_eq!(
            command(u64::MAX, action.clone()).proposed_event(actor(2)),
            Err(RefusalCode::ResourceBudgetExceeded)
        );
        let gap = command(2, action).proposed_event(actor(2)).unwrap();
        assert_eq!(
            apply_event(Some(&state), &gap),
            Err(RefusalCode::EvidenceStale)
        );
        for profile in [
            ForgeCommandProfile::ExactVersion,
            ForgeCommandProfile::Unknown,
            ForgeCommandProfile::AppendIssueCommentV1,
            ForgeCommandProfile::AddIssueAssigneesV1,
            ForgeCommandProfile::AddIssueLabelsV1,
            ForgeCommandProfile::AppendPullRequestCommentV1,
        ] {
            assert_eq!(
                classify_event(&event, profile).replan,
                ForgeReplanPolicy::PreservePreconditions
            );
        }
    }
    let newer = apply(&state, DiscussionAction::Comment { body: "one".into() }).unwrap();
    let stale = command(1, DiscussionAction::Comment { body: "two".into() })
        .proposed_event(actor(2))
        .unwrap();
    assert_eq!(
        apply_event(Some(&newer), &stale),
        Err(RefusalCode::EvidenceStale)
    );
    let mut wrong_number = command(1, DiscussionAction::Close)
        .proposed_event(actor(2))
        .unwrap();
    wrong_number.aggregate = AggregateId::Discussion(DiscussionNumber::try_new(2).unwrap());
    assert_eq!(
        apply_event(Some(&state), &wrong_number),
        Err(RefusalCode::EvidenceStale)
    );
    let mut exhausted = state;
    exhausted.comments = u64::MAX;
    assert_eq!(
        apply(
            &exhausted,
            DiscussionAction::Comment {
                body: "overflow".into()
            }
        ),
        Err(RefusalCode::ResourceBudgetExceeded)
    );
}

#[test]
fn text_validation_uses_utf8_bytes_and_preserves_explicit_empty_edits() {
    let title = "é".repeat(MAX_TITLE_BYTES / 2);
    let body = "é".repeat(MAX_BODY_BYTES / 2);
    let valid = DiscussionAction::Open {
        title: title.clone(),
        body: body.clone(),
    };
    assert!(valid.validate().is_ok());
    let event = command(0, valid).proposed_event(actor(1)).unwrap();
    let bytes = encode_body(&event).unwrap();
    assert_eq!(
        decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
        event
    );
    for invalid in [
        DiscussionAction::Open {
            title: String::new(),
            body: String::new(),
        },
        DiscussionAction::Open {
            title: " \r\n".into(),
            body: String::new(),
        },
        DiscussionAction::Open {
            title: format!("{title}x"),
            body: String::new(),
        },
        DiscussionAction::Open {
            title: "bad\nline".into(),
            body: String::new(),
        },
        DiscussionAction::Open {
            title: "title".into(),
            body: format!("{body}x"),
        },
        DiscussionAction::Open {
            title: "title".into(),
            body: "bad\0body".into(),
        },
        DiscussionAction::Edit(DiscussionEdit::default()),
        DiscussionAction::Edit(DiscussionEdit {
            title: Some(String::new()),
            body: None,
        }),
        DiscussionAction::Comment {
            body: " \r\n".into(),
        },
        DiscussionAction::Comment {
            body: "bad\0comment".into(),
        },
        DiscussionAction::Comment {
            body: format!("{body}x"),
        },
    ] {
        assert!(invalid.validate().is_err(), "{invalid:?}");
    }
    let state = opened();
    let kept = apply(
        &state,
        DiscussionAction::Edit(DiscussionEdit {
            title: Some("Kept".into()),
            body: None,
        }),
    )
    .unwrap();
    assert_eq!(kept.body, state.body);
    let cleared = apply(
        &kept,
        DiscussionAction::Edit(DiscussionEdit {
            title: None,
            body: Some(String::new()),
        }),
    )
    .unwrap();
    assert_eq!(cleared.title, kept.title);
    assert!(cleared.body.is_empty());
}

#[test]
fn required_wire_tags_exact_action_bytes_and_every_decode_boundary_are_checked() {
    let mut aggregate = Encoder::new();
    super::super::write_aggregate(
        &mut aggregate,
        AggregateId::Discussion(DiscussionNumber::FIRST),
    );
    assert_eq!(
        aggregate.as_bytes(),
        [
            0u64.to_be_bytes().as_slice(),
            11u32.to_be_bytes().as_slice(),
            1u64.to_be_bytes().as_slice()
        ]
        .concat()
    );
    for (version, action, expected) in [
        (
            0,
            DiscussionAction::Open {
                title: "A".into(),
                body: "B".into(),
            },
            b"\x00\x00\x00\x01\x00\x00\x00\x01A\x00\x00\x00\x01B".as_slice(),
        ),
        (
            1,
            DiscussionAction::Edit(DiscussionEdit {
                title: None,
                body: Some(String::new()),
            }),
            b"\x00\x00\x00\x02\x00\x01\x00\x00\x00\x00".as_slice(),
        ),
        (1, DiscussionAction::Close, b"\x00\x00\x00\x03".as_slice()),
        (1, DiscussionAction::Reopen, b"\x00\x00\x00\x04".as_slice()),
        (
            1,
            DiscussionAction::Comment { body: "C".into() },
            b"\x00\x00\x00\x05\x00\x00\x00\x01C".as_slice(),
        ),
        (1, DiscussionAction::Lock, b"\x00\x00\x00\x06".as_slice()),
        (1, DiscussionAction::Unlock, b"\x00\x00\x00\x07".as_slice()),
    ] {
        let mut encoder = Encoder::new();
        action.write(&mut encoder).unwrap();
        assert_eq!(encoder.as_bytes(), expected);
        let event = command(version, action).proposed_event(actor(3)).unwrap();
        assert_eq!(event.payload.kind(), 24);
        let frame = encode_body(&event).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(),
            event
        );
        for end in 0..frame.len() {
            assert!(decode_body::<ForgeEvent>(&frame[..end], DecodeLimits::DEFAULT).is_err());
        }
        let mut trailing = frame;
        trailing.push(0);
        assert!(decode_body::<ForgeEvent>(&trailing, DecodeLimits::DEFAULT).is_err());
        let mut wrong = event.clone();
        wrong.aggregate = AggregateId::Issue(crate::IssueNumber::FIRST);
        assert!(encode_body(&wrong).is_err());
        wrong = event;
        wrong.version = if version == 0 {
            AggregateVersion::try_new(2).unwrap()
        } else {
            AggregateVersion::FIRST
        };
        assert!(encode_body(&wrong).is_err());
    }
    for tag in [0u32, 8, u32::MAX] {
        assert!(
            matches!(DiscussionAction::read(&mut Decoder::new(&tag.to_be_bytes(), DecodeLimits::DEFAULT)),
            Err(CodecRefusal::VariantUnknown { field: "discussion.action", observed, .. }) if observed == tag)
        );
    }
    for malformed in [
        b"\x00\x00\x00\x01\x00\x00\x00\x01\xff\x00\x00\x00\x00".as_slice(),
        b"\x00\x00\x00\x02\x02".as_slice(),
        b"\x00\x00\x00\x05\x00\x00\x00\x01\x00".as_slice(),
    ] {
        assert!(
            DiscussionAction::read(&mut Decoder::new(malformed, DecodeLimits::DEFAULT)).is_err()
        );
    }
}

#[test]
fn existing_issue_milestone_and_pull_request_event_bytes_remain_identical() {
    use crate::event::issue::{IssueAction, IssueCommand};
    use crate::event::milestone::{MilestoneAction, MilestoneCommand};
    let issue = IssueCommand {
        number: crate::IssueNumber::FIRST,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
        action: IssueAction::Close,
    }
    .proposed_event(actor(3))
    .unwrap();
    let milestone = MilestoneCommand {
        number: crate::MilestoneNumber::FIRST,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
        action: MilestoneAction::Close,
    }
    .proposed_event(actor(3))
    .unwrap();
    for (event, aggregate_tag, payload_tag) in [(issue, 4u32, 8u32), (milestone, 9u32, 22u32)] {
        let mut out = Encoder::new();
        super::super::write_event(&mut out, &event).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&0u64.to_be_bytes());
        expected.extend_from_slice(&aggregate_tag.to_be_bytes());
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.extend_from_slice(&2u64.to_be_bytes());
        expected.extend_from_slice(&payload_tag.to_be_bytes());
        expected.extend_from_slice(&[3; 16]);
        expected.extend_from_slice(&3u32.to_be_bytes());
        assert_eq!(out.as_bytes(), expected);
    }
    let legacy = ForgeEvent {
        aggregate: AggregateId::PullRequest(crate::PullRequestNumber::FIRST),
        version: AggregateVersion::FIRST,
        payload: ForgeEventPayload::PullRequestClosed { withdrawn: false },
    };
    let mut out = Encoder::new();
    super::super::write_event(&mut out, &legacy).unwrap();
    assert_eq!(
        out.as_bytes(),
        [
            1u64.to_be_bytes().as_slice(),
            1u64.to_be_bytes().as_slice(),
            4u32.to_be_bytes().as_slice(),
            &[0]
        ]
        .concat()
    );
}

#[test]
fn wire_aggregate_zero_and_mismatched_payloads_are_rejected_on_decode() {
    let mut zero = Encoder::new();
    zero.write_scalar(0u64);
    zero.write_scalar(11u32);
    zero.write_scalar(0u64);
    assert!(
        super::super::read_aggregate(&mut Decoder::new(zero.as_bytes(), DecodeLimits::DEFAULT))
            .is_err()
    );

    let event = command(0, open_action()).proposed_event(actor(1)).unwrap();
    let mut out = Encoder::new();
    super::super::write_event(&mut out, &event).unwrap();
    let mut bytes = out.as_bytes().to_vec();
    bytes[8..12].copy_from_slice(&4u32.to_be_bytes());
    assert!(super::super::read_event(&mut Decoder::new(&bytes, DecodeLimits::DEFAULT)).is_err());
    bytes[8..12].copy_from_slice(&13u32.to_be_bytes());
    assert!(matches!(
        super::super::read_event(&mut Decoder::new(&bytes, DecodeLimits::DEFAULT)),
        Err(CodecRefusal::VariantUnknown {
            field: "aggregate.kind",
            observed: 13,
            ..
        })
    ));
    bytes[8..12].copy_from_slice(&11u32.to_be_bytes());
    bytes[28..32].copy_from_slice(&25u32.to_be_bytes());
    assert!(matches!(
        super::super::read_event(&mut Decoder::new(&bytes, DecodeLimits::DEFAULT)),
        Err(CodecRefusal::VariantUnknown {
            field: "kind",
            observed: 25,
            ..
        })
    ));
}

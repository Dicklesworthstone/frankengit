use super::*;
use fgit_codec::{DecodeLimits, decode_body, encode_body};

fn actor(byte: u8) -> PrincipalId {
    PrincipalId::from_bytes([byte; 16])
}
fn opening() -> ForgeEvent {
    IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: "Moderated issue".into(),
            body: "Original exact body é\r\n".into(),
            labels: vec!["triage".into()],
        },
    }
    .proposed_event(actor(1))
    .unwrap()
}
fn following(state: &IssueSnapshot, action: IssueAction) -> ForgeEvent {
    IssueCommand {
        number: state.number,
        expected_version: ExpectedVersion::Exactly(state.version),
        action,
    }
    .proposed_event(actor(2))
    .unwrap()
}
fn roundtrip(event: &ForgeEvent) -> ForgeEvent {
    let frame = encode_body(event).unwrap();
    let decoded = decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(&decoded, event);
    decoded
}

#[test]
fn lock_action_goldens_are_new_payloadless_tags_with_strict_decode_boundaries() {
    let state = apply_event(None, &opening()).unwrap();
    for (action, expected, name) in [
        (IssueAction::Lock, [0, 0, 0, 8], "lock"),
        (IssueAction::Unlock, [0, 0, 0, 9], "unlock"),
    ] {
        assert_eq!(action.name(), name);
        let mut encoder = Encoder::new();
        action.write(&mut encoder).unwrap();
        assert_eq!(encoder.as_bytes(), expected);
        let mut decoder = Decoder::new(&expected, DecodeLimits::DEFAULT);
        assert_eq!(IssueAction::read(&mut decoder).unwrap(), action);
        decoder.finish().unwrap();
        for end in 0..expected.len() {
            assert!(
                IssueAction::read(&mut Decoder::new(&expected[..end], DecodeLimits::DEFAULT))
                    .is_err()
            );
        }
        let trailing = [expected.as_slice(), &[0]].concat();
        let mut decoder = Decoder::new(&trailing, DecodeLimits::DEFAULT);
        assert_eq!(IssueAction::read(&mut decoder).unwrap(), action);
        assert!(
            decoder.finish().is_err(),
            "payloadless actions consume exactly four bytes"
        );

        let event = following(&state, action);
        roundtrip(&event);
        let frame = encode_body(&event).unwrap();
        for end in 0..frame.len() {
            assert!(decode_body::<ForgeEvent>(&frame[..end], DecodeLimits::DEFAULT).is_err());
        }
        let mut invalid = event;
        invalid.version = AggregateVersion::FIRST;
        assert!(
            encode_body(&invalid).is_err(),
            "a lock cannot create an issue"
        );
    }
    for tag in [0u32, 12, u32::MAX] {
        assert!(matches!(
            IssueAction::read(&mut Decoder::new(&tag.to_be_bytes(), DecodeLimits::DEFAULT)),
            Err(CodecRefusal::VariantUnknown { field: "issue.action", observed, .. }) if observed == tag
        ));
    }
}

#[test]
fn locks_and_unlocks_require_existing_exact_positive_predecessors() {
    let state = apply_event(None, &opening()).unwrap();
    for action in [IssueAction::Lock, IssueAction::Unlock] {
        let mut command = IssueCommand {
            number: state.number,
            expected_version: ExpectedVersion::NewStream,
            action,
        };
        assert_eq!(
            command.proposed_event(actor(2)),
            Err(RefusalCode::EvidenceInvalid)
        );
        command.expected_version = ExpectedVersion::Exactly(state.version);
        let event = command.proposed_event(actor(2)).unwrap();
        assert_eq!(apply_event(None, &event), Err(RefusalCode::EvidenceStale));
        for version in [1, 3, u64::MAX] {
            let mut wrong = event.clone();
            wrong.version = AggregateVersion::try_new(version).unwrap();
            assert_eq!(
                apply_event(Some(&state), &wrong),
                Err(RefusalCode::EvidenceStale)
            );
        }
        let mut wrong = event;
        wrong.aggregate = AggregateId::Issue(IssueNumber::try_new(2).unwrap());
        assert_eq!(
            apply_event(Some(&state), &wrong),
            Err(RefusalCode::EvidenceStale)
        );
        command.expected_version =
            ExpectedVersion::Exactly(AggregateVersion::try_new(u64::MAX).unwrap());
        assert_eq!(
            command.proposed_event(actor(2)),
            Err(RefusalCode::ResourceBudgetExceeded)
        );
    }
}

#[test]
fn lock_state_is_independent_of_open_closed_state_and_repeated_transitions_refuse() {
    let open = apply_event(None, &opening()).unwrap();
    assert!(!open.locked, "old opening bytes begin an unlocked history");
    let closed = apply_event(Some(&open), &following(&open, IssueAction::Close)).unwrap();
    for initial in [open, closed] {
        assert_eq!(
            apply_event(Some(&initial), &following(&initial, IssueAction::Unlock)),
            Err(RefusalCode::ProtectedRefTransitionDenied)
        );
        let lock = following(&initial, IssueAction::Lock);
        let locked = apply_event(Some(&initial), &roundtrip(&lock)).unwrap();
        let mut expected = initial.clone();
        expected.locked = true;
        expected.version = lock.version;
        expected.last_actor = actor(2);
        assert_eq!(
            locked, expected,
            "locking changes no issue content or counters"
        );
        assert_eq!(
            apply_event(Some(&locked), &following(&locked, IssueAction::Lock)),
            Err(RefusalCode::ProtectedRefTransitionDenied)
        );
        let unlock = following(&locked, IssueAction::Unlock);
        let unlocked = apply_event(Some(&locked), &roundtrip(&unlock)).unwrap();
        expected.locked = false;
        expected.version = unlock.version;
        assert_eq!(unlocked, expected);
        assert_eq!(
            apply_event(Some(&unlocked), &following(&unlocked, IssueAction::Unlock)),
            Err(RefusalCode::ProtectedRefTransitionDenied)
        );
        assert_eq!(
            apply_event(Some(&unlocked), &lock),
            Err(RefusalCode::EvidenceStale)
        );
    }
}

#[test]
fn strict_and_append_comment_events_share_the_lock_gate_without_counter_or_text_changes() {
    let open = apply_event(None, &opening()).unwrap();
    let locked = apply_event(Some(&open), &following(&open, IssueAction::Lock)).unwrap();
    let intent = IssueCommentIntent {
        number: locked.number,
        body: "Exact new comment é\r\n".into(),
    };
    let template = intent.commitment_event(actor(2)).unwrap();
    let closed = apply_event(Some(&locked), &following(&locked, IssueAction::Close)).unwrap();
    for state in [&locked, &closed] {
        let strict = following(
            state,
            IssueAction::Comment {
                body: intent.body.clone(),
            },
        );
        let append = ForgeEvent {
            version: strict.version,
            ..template.clone()
        };
        assert_eq!(
            strict, append,
            "both admitted profiles reduce the same canonical event"
        );
        for event in [&strict, &append] {
            assert_eq!(
                apply_event(Some(state), event),
                Err(RefusalCode::ProtectedRefTransitionDenied)
            );
        }
        assert_eq!(state.comments, 0);
        assert_eq!(state.title, "Moderated issue");
        assert_eq!(state.body, "Original exact body é\r\n");
        let unlocked = apply_event(Some(state), &following(state, IssueAction::Unlock)).unwrap();
        let comment = following(
            &unlocked,
            IssueAction::Comment {
                body: intent.body.clone(),
            },
        );
        let after = apply_event(Some(&unlocked), &comment).unwrap();
        assert_eq!(after.comments, 1);
        assert!(!after.locked);
        assert_eq!(after.state, state.state);
        assert_eq!(after.body, state.body);
    }
    let mut saturated = locked;
    saturated.comments = u64::MAX;
    let comment = following(
        &saturated,
        IssueAction::Comment {
            body: "bounded".into(),
        },
    );
    assert_eq!(
        apply_event(Some(&saturated), &comment),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
    let unlocked = apply_event(
        Some(&saturated),
        &following(&saturated, IssueAction::Unlock),
    )
    .unwrap();
    assert_eq!(
        apply_event(
            Some(&unlocked),
            &following(
                &unlocked,
                IssueAction::Comment {
                    body: "bounded".into()
                }
            )
        ),
        Err(RefusalCode::ResourceBudgetExceeded)
    );
}

#[test]
fn maintenance_never_implicitly_unlocks_and_codec_replay_rebuilds_the_exact_state() {
    let first = roundtrip(&opening());
    let mut history = vec![first.clone()];
    let mut state = apply_event(None, &first).unwrap();
    for action in [
        IssueAction::Lock,
        IssueAction::Edit(IssueEdit {
            title: Some("Maintained while locked".into()),
            body: Some("New description".into()),
            labels: Some(vec!["reviewed".into()]),
        }),
        IssueAction::Assign {
            assignees: vec![actor(3), actor(4)],
        },
        IssueAction::Close,
        IssueAction::Unassign {
            assignees: vec![actor(3)],
        },
        IssueAction::Reopen,
    ] {
        let event = roundtrip(&following(&state, action));
        state = apply_event(Some(&state), &event).unwrap();
        assert!(state.locked);
        assert_eq!(state.comments, 0);
        assert_eq!(state.opened_by, actor(1));
        history.push(event);
    }
    assert_eq!(state.title, "Maintained while locked");
    assert_eq!(state.body, "New description");
    assert_eq!(state.labels, ["reviewed"]);
    assert_eq!(state.assignees, [actor(4)]);
    assert_eq!(state.state, IssueState::Open);
    let mut rebuilt = None;
    for event in &history {
        rebuilt = Some(apply_event(rebuilt.as_ref(), &roundtrip(event)).unwrap());
    }
    assert_eq!(rebuilt, Some(state.clone()));
    let unlock = roundtrip(&following(&state, IssueAction::Unlock));
    state = apply_event(Some(&state), &unlock).unwrap();
    let comment = roundtrip(&following(
        &state,
        IssueAction::Comment {
            body: "Resumed".into(),
        },
    ));
    state = apply_event(Some(&state), &comment).unwrap();
    assert_eq!(state.comments, 1);
    assert!(!state.locked);
    assert_eq!(state.assignees, [actor(4)]);
}

// Included by the real evaluator's private test module.
#[test]
fn discussion_effect_encoding_is_distinct_without_reassigning_existing_tags() {
    let entity = ForgeEntityId::new(label("discussion/7"));
    let event = ForgeEventKind::DiscussionChanged { discussion: entity };
    let mut out = Encoder::new();
    write_forge_event(&mut out, &event).unwrap();
    assert_eq!(out.as_bytes(), b"\x0d\0\0\0\x0cdiscussion/7");
    let discussion_bytes = out.into_bytes();
    for (legacy, tag) in [
        (ForgeEventKind::IssueChanged { issue: entity }, 6u8),
        (ForgeEventKind::MilestoneChanged { milestone: entity }, 11),
        (
            ForgeEventKind::NotificationPreferenceChanged { preference: entity },
            12,
        ),
        (
            ForgeEventKind::PullRequestCommented {
                conversation: entity,
            },
            9,
        ),
    ] {
        let mut encoded = Encoder::new();
        write_forge_event(&mut encoded, &legacy).unwrap();
        assert_eq!(encoded.as_bytes()[0], tag);
        assert_eq!(&encoded.as_bytes()[1..], &discussion_bytes[1..]);
        assert_ne!(encoded.as_bytes(), discussion_bytes);
    }
    let mut other = Encoder::new();
    write_forge_event(
        &mut other,
        &ForgeEventKind::DiscussionChanged {
            discussion: ForgeEntityId::new(label("discussion/8")),
        },
    )
    .unwrap();
    assert_ne!(other.as_bytes(), discussion_bytes);
}

#[test]
fn ordered_discussion_publication_folds_with_its_delivery_and_preserves_preconditions() {
    let stream = ForgeStreamId::new(label("discussion/7"));
    let event = ForgeEventKind::DiscussionChanged {
        discussion: ForgeEntityId::new(label("discussion/7")),
    };
    let delivery = OutboxDeliveryKey::new(label("discussion-delivery"));
    let mut mint = IdentityMint::new(93);
    let parameters = mint.digest();
    let request = request(vec![Statement {
        mismatch_policy: MismatchPolicy::TxnAbort,
        intents: vec![
            Intent::Forge(ForgeIntent {
                stream,
                expected_position: ForgeStreamPosition::GENESIS,
                event: event.clone(),
            }),
            Intent::Forge(ForgeIntent {
                stream,
                expected_position: ForgeStreamPosition::new(1),
                event: event.clone(),
            }),
            Intent::Outbox(OutboxIntent {
                delivery_key: delivery,
                parameters,
            }),
        ],
    }]);
    let (refs, mut forge, retention, outbox) = empty_basis();
    let evaluator = IntentEvaluator::new();
    let report = evaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
    evaluator.validate_report(&request, &report).unwrap();
    let effects = report.effects().unwrap();
    assert_eq!(
        effects.forge.get(&stream),
        Some(&vec![event.clone(), event.clone()])
    );
    assert_eq!(effects.outbox.get(&delivery), Some(&parameters));
    assert!(effects.refs.is_empty() && effects.retention.is_empty());
    let canonical = canonical_fold_bytes(&request, &report).unwrap();
    let again = evaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
    assert_eq!(canonical, canonical_fold_bytes(&request, &again).unwrap());
    let applied = apply_net_effects(&Workspace::default(), effects);
    assert_eq!(
        applied.forge.get(&stream),
        Some(&vec![event.clone(), event])
    );
    assert_eq!(applied.outbox.get(&delivery), Some(&parameters));
    assert!(applied.refs.is_empty() && applied.retention.is_empty());

    // Contention cannot silently restamp either predecessor or leave an orphan
    // delivery. One canonical refusal replaces the whole transaction's effects.
    forge.insert(stream, ForgeStreamPosition::new(1));
    let stale = evaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
    evaluator.validate_report(&request, &stale).unwrap();
    assert!(matches!(
        stale.outcome,
        FoldOutcome::Aborted {
            code: RefusalCode::ForgeTransitionInvalid,
            ..
        }
    ));
    assert!(stale.effects().is_none());
    assert_ne!(canonical, canonical_fold_bytes(&request, &stale).unwrap());
}

#[test]
fn discussion_effect_commitment_cannot_alias_an_issue_with_the_same_entity_label() {
    let stream = ForgeStreamId::new(label("aggregate"));
    let entity = ForgeEntityId::new(label("entity-7"));
    let (refs, forge, retention, outbox) = empty_basis();
    let mut encodings = BTreeSet::new();
    for event in [
        ForgeEventKind::DiscussionChanged { discussion: entity },
        ForgeEventKind::IssueChanged { issue: entity },
        ForgeEventKind::MilestoneChanged { milestone: entity },
        ForgeEventKind::PullRequestCommented {
            conversation: entity,
        },
        ForgeEventKind::DiscussionChanged {
            discussion: ForgeEntityId::new(label("entity-8")),
        },
    ] {
        let request = request(vec![Statement {
            mismatch_policy: MismatchPolicy::TxnAbort,
            intents: vec![Intent::Forge(ForgeIntent {
                stream,
                expected_position: ForgeStreamPosition::GENESIS,
                event,
            })],
        }]);
        let report =
            IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
        assert!(encodings.insert(canonical_effect_bytes(report.effects().unwrap()).unwrap()));
    }
    assert_eq!(encodings.len(), 5);
}

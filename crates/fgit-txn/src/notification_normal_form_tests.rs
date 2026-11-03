// Included by the real evaluator's private test module.
#[test]
fn notification_effect_tag_is_new_and_retains_the_exact_entity() {
    let event = ForgeEventKind::NotificationPreferenceChanged {
        preference: ForgeEntityId::new(label("notify/7")),
    };
    let mut out = Encoder::new();
    write_forge_event(&mut out, &event).unwrap();
    assert_eq!(out.as_bytes(), b"\x0c\0\0\0\x08notify/7");
    for other in [
        ForgeEventKind::IssueChanged {
            issue: event.entity(),
        },
        ForgeEventKind::PullRequestClosed {
            pull_request: event.entity(),
        },
        ForgeEventKind::NotificationPreferenceChanged {
            preference: ForgeEntityId::new(label("notify/8")),
        },
    ] {
        let mut encoded = Encoder::new();
        write_forge_event(&mut encoded, &other).unwrap();
        assert_ne!(encoded.as_bytes(), out.as_bytes());
    }
}

#[test]
fn notification_folding_preserves_exact_predecessors_without_refs_or_retention_effects() {
    let stream = ForgeStreamId::new(label("notify/7"));
    let event = ForgeEventKind::NotificationPreferenceChanged {
        preference: ForgeEntityId::new(label("notify/7")),
    };
    let delivery = OutboxDeliveryKey::new(label("notification-delivery"));
    let mut mint = IdentityMint::new(91);
    let parameters = mint.digest();
    let request = request(vec![Statement {
        mismatch_policy: MismatchPolicy::TxnAbort,
        intents: vec![
            Intent::Forge(ForgeIntent {
                stream,
                expected_position: ForgeStreamPosition::GENESIS,
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
    assert_eq!(effects.forge.get(&stream), Some(&vec![event]));
    assert_eq!(effects.outbox.get(&delivery), Some(&parameters));
    assert!(effects.refs.is_empty() && effects.retention.is_empty());
    assert!(!canonical_fold_bytes(&request, &report).unwrap().is_empty());
    forge.insert(stream, ForgeStreamPosition::new(1));
    let stale = evaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
    assert!(matches!(
        stale.outcome,
        FoldOutcome::Aborted {
            code: RefusalCode::ForgeTransitionInvalid,
            ..
        }
    ));
    assert!(stale.effects().is_none());
}

#[test]
fn discussion_preferences_preserve_kind_and_owner_in_effects_and_exact_stream_preconditions() {
    let issue = label("notify/03030303030303030303030303030303/7");
    let discussion = label("dnotify/03030303030303030303030303030303/7");
    let other_owner = label("dnotify/04040404040404040404040404040404/7");
    let (refs, mut forge, retention, outbox) = empty_basis();
    // Existing issue preferences do not advance the equal-number discussion's
    // stream, including when both subjects are owned by the same principal.
    forge.insert(ForgeStreamId::new(issue), ForgeStreamPosition::new(9));
    let mut identities = BTreeSet::new();
    for label in [issue, discussion, other_owner] {
        let stream = ForgeStreamId::new(label);
        let event = ForgeEventKind::NotificationPreferenceChanged {
            preference: ForgeEntityId::new(label),
        };
        let request = request(vec![Statement {
            mismatch_policy: MismatchPolicy::TxnAbort,
            intents: vec![Intent::Forge(ForgeIntent {
                stream,
                expected_position: forge
                    .get(&stream)
                    .copied()
                    .unwrap_or(ForgeStreamPosition::GENESIS),
                event: event.clone(),
            })],
        }]);
        let report =
            IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
        IntentEvaluator.validate_report(&request, &report).unwrap();
        let effects = report.effects().unwrap();
        assert_eq!(effects.forge.get(&stream), Some(&vec![event]));
        assert!(effects.refs.is_empty() && effects.retention.is_empty());
        assert!(identities.insert(canonical_effect_bytes(effects).unwrap()));
        if label == discussion {
            let mut changed = forge.clone();
            changed.insert(stream, ForgeStreamPosition::new(1));
            let stale =
                IntentEvaluator.evaluate(basis_of(&refs, &changed, &retention, &outbox), &request);
            assert!(matches!(
                stale.outcome,
                FoldOutcome::Aborted {
                    code: RefusalCode::ForgeTransitionInvalid,
                    ..
                }
            ));
            assert!(stale.effects().is_none());
        }
    }
    assert_eq!(identities.len(), 3);
}

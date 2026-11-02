// Included by the real evaluator's private test module.
#[test]
fn milestone_effect_tag_is_new_and_retains_the_exact_entity() {
    let event = ForgeEventKind::MilestoneChanged {
        milestone: ForgeEntityId::new(label("milestone/7")),
    };
    let mut out = Encoder::new();
    write_forge_event(&mut out, &event).unwrap();
    assert_eq!(out.as_bytes(), b"\x0b\0\0\0\x0bmilestone/7");
    for other in [
        ForgeEventKind::IssueChanged {
            issue: event.entity(),
        },
        ForgeEventKind::PullRequestClosed {
            pull_request: event.entity(),
        },
        ForgeEventKind::MilestoneChanged {
            milestone: ForgeEntityId::new(label("milestone/8")),
        },
    ] {
        let mut encoded = Encoder::new();
        write_forge_event(&mut encoded, &other).unwrap();
        assert_ne!(encoded.as_bytes(), out.as_bytes());
    }
}

#[test]
fn milestone_folding_preserves_exact_predecessors_without_refs_or_retention_effects() {
    let stream = ForgeStreamId::new(label("milestone/7"));
    let event = ForgeEventKind::MilestoneChanged {
        milestone: ForgeEntityId::new(label("milestone/7")),
    };
    let delivery = OutboxDeliveryKey::new(label("milestone-delivery"));
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

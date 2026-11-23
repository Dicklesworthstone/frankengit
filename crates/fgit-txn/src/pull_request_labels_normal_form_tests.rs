#[test]
fn labels_normal_form_uses_new_tag_and_no_ref_effect() {
    let entity = ForgeEntityId::new(label("pull-request-labels/7"));
    let event = ForgeEventKind::PullRequestLabelsChanged { labels: entity };
    let mut encoded = Encoder::new();
    write_forge_event(&mut encoded, &event).unwrap();
    assert_eq!(encoded.as_bytes(), b"\x0f\0\0\0\x15pull-request-labels/7");
    assert_eq!(event.entity(), entity);
    assert!(event.required_ref_effect().is_none());
    let stream = ForgeStreamId::new(entity.label());
    let mut mint = IdentityMint::new(95);
    let delivery = OutboxDeliveryKey::new(label("labels-delivery"));
    let parameters = mint.digest();
    let request = request(vec![Statement {
        mismatch_policy: MismatchPolicy::TxnAbort,
        intents: vec![
            Intent::Forge(ForgeIntent {
                stream,
                expected_position: ForgeStreamPosition::new(0),
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
    forge.insert(stream, ForgeStreamPosition::new(1));
    let stale = evaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
    assert!(matches!(
        stale.outcome,
        FoldOutcome::Aborted {
            code: RefusalCode::ForgeTransitionInvalid,
            ..
        }
    ));
}

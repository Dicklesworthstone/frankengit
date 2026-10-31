// Included by lib.rs tests to share the evaluator and reference fixtures.
fn queue_event(queue: &str, target: &str) -> ForgeEventKind {
    ForgeEventKind::MergeQueueChanged {
        queue: ForgeEntityId::new(label(queue)),
        target: name(target),
    }
}

#[test]
fn queue_normal_form_has_tag_ten_and_binds_both_queue_identity_and_target() {
    let event = queue_event("queue/1", "refs/heads/main");
    let mut bytes = Encoder::new();
    write_forge_event(&mut bytes, &event).unwrap();
    assert_eq!(
        bytes.as_bytes(),
        b"\x0a\0\0\0\x07queue/1\0\0\0\x0frefs/heads/main"
    );
    assert_eq!(event.required_ref_effect(), None);
    for changed in [
        queue_event("queue/2", "refs/heads/main"),
        queue_event("queue/1", "refs/heads/next"),
        ForgeEventKind::IssueChanged {
            issue: event.entity(),
        },
    ] {
        let mut other = Encoder::new();
        write_forge_event(&mut other, &changed).unwrap();
        assert_ne!(bytes.as_bytes(), other.as_bytes());
    }
}

#[test]
fn queue_fold_couples_delivery_without_ref_effect_and_detects_stale_position() {
    let queue = ForgeStreamId::new(label("queue/1"));
    let pull = ForgeStreamId::new(label("pull-request/1"));
    let key = OutboxDeliveryKey::new(label("queue-delivery"));
    let parameters = IdentityMint::new(95_041).digest();
    let event = queue_event("queue/1", "refs/heads/main");
    let req = request(vec![Statement {
        mismatch_policy: MismatchPolicy::TxnAbort,
        intents: vec![
            Intent::Forge(ForgeIntent {
                stream: queue,
                expected_position: ForgeStreamPosition::GENESIS,
                event: event.clone(),
            }),
            Intent::Outbox(OutboxIntent {
                delivery_key: key,
                parameters,
            }),
        ],
    }]);
    let (mut refs, mut positions, retention, outbox) = empty_basis();
    refs.insert(name("refs/heads/main"), oid(1));
    positions.insert(pull, ForgeStreamPosition::new(3));
    let report = IntentEvaluator.evaluate(basis_of(&refs, &positions, &retention, &outbox), &req);
    IntentEvaluator.validate_report(&req, &report).unwrap();
    let effects = report.effects().unwrap();
    assert_eq!(effects.forge, BTreeMap::from([(queue, vec![event])]));
    assert_eq!(effects.outbox, BTreeMap::from([(key, parameters)]));
    assert!(effects.refs.is_empty() && effects.retention.is_empty());
    let original = canonical_fold_bytes(&req, &report).unwrap();
    assert_eq!(
        original,
        canonical_fold_bytes(
            &req,
            &IntentEvaluator.evaluate(basis_of(&refs, &positions, &retention, &outbox), &req)
        )
        .unwrap()
    );
    let mut changed = req.clone();
    let Intent::Forge(forge) = &mut changed.statements[0].intents[0] else {
        unreachable!()
    };
    forge.event = queue_event("queue/1", "refs/heads/next");
    let other =
        IntentEvaluator.evaluate(basis_of(&refs, &positions, &retention, &outbox), &changed);
    assert_ne!(original, canonical_fold_bytes(&changed, &other).unwrap());
    positions.insert(queue, ForgeStreamPosition::new(1));
    let stale = IntentEvaluator.evaluate(basis_of(&refs, &positions, &retention, &outbox), &req);
    assert!(matches!(
        stale.outcome,
        FoldOutcome::Aborted {
            code: RefusalCode::ForgeTransitionInvalid,
            ..
        }
    ));
    assert!(stale.effects().is_none());
    assert!(
        stale
            .mappings
            .iter()
            .all(|m| m.disposition == IntentDisposition::TransactionAborted)
    );
}

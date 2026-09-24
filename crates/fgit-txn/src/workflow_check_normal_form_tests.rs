// Included in lib.rs tests: use the existing evaluator and reference fixtures.
fn workflow_event(entity: &str, source: &str) -> ForgeEventKind {
    ForgeEventKind::WorkflowCheckObserved {
        check: ForgeEntityId::new(label(entity)), source: name(source),
    }
}

#[test]
fn workflow_normal_form_tag_preserves_exact_entity_and_source_bytes() {
    let mut encoder = Encoder::new();
    write_forge_event(&mut encoder, &workflow_event("check/one", "refs/heads/main")).unwrap();
    assert_eq!(encoder.as_bytes(), b"\x08\0\0\0\x09check/one\0\0\0\x0frefs/heads/main");
    let mut distinct = BTreeSet::new();
    for event in [
        workflow_event("check/one", "refs/heads/main"),
        workflow_event("check/two", "refs/heads/main"),
        workflow_event("check/one", "refs/heads/topic"),
        ForgeEventKind::IssueChanged { issue: ForgeEntityId::new(label("check/one")) },
    ] {
        let mut out = Encoder::new();
        write_forge_event(&mut out, &event).unwrap();
        assert!(distinct.insert(out.into_bytes()));
        assert_eq!(event.required_ref_effect(), None);
    }
}

#[test]
fn workflow_observation_and_delivery_fold_without_moving_a_ref() {
    let stream = ForgeStreamId::new(label("check/one"));
    let event = workflow_event("check/one", "refs/heads/main");
    let mut mint = IdentityMint::new(9511);
    let parameters = mint.digest();
    let key = OutboxDeliveryKey::new(label("check-delivery"));
    let req = request(vec![Statement {
        mismatch_policy: MismatchPolicy::TxnAbort,
        intents: vec![
            Intent::Forge(ForgeIntent { stream, expected_position: ForgeStreamPosition::GENESIS, event: event.clone() }),
            Intent::Outbox(OutboxIntent { delivery_key: key, parameters }),
        ],
    }]);
    let (mut refs, positions, retention, outbox) = empty_basis();
    refs.insert(name("refs/heads/main"), oid(1));
    let report = IntentEvaluator.evaluate(basis_of(&refs, &positions, &retention, &outbox), &req);
    IntentEvaluator.validate_report(&req, &report).unwrap();
    let effects = report.effects().unwrap();
    assert_eq!(effects.forge, BTreeMap::from([(stream, vec![event])]));
    assert_eq!(effects.outbox, BTreeMap::from([(key, parameters)]));
    assert!(effects.refs.is_empty() && effects.retention.is_empty());
    let before = Workspace { refs: refs.clone(), ..Workspace::default() };
    assert_eq!(apply_net_effects(&before, effects).refs, refs);
    canonical_fold_bytes(&req, &report).unwrap();
}

#[test]
fn occupied_workflow_stream_aborts_its_coupled_delivery() {
    let stream = ForgeStreamId::new(label("check/one"));
    let mut mint = IdentityMint::new(9512);
    let req = request(vec![Statement {
        mismatch_policy: MismatchPolicy::TxnAbort,
        intents: vec![
            Intent::Forge(ForgeIntent { stream, expected_position: ForgeStreamPosition::GENESIS,
                event: workflow_event("check/one", "refs/heads/main") }),
            Intent::Outbox(OutboxIntent { delivery_key: OutboxDeliveryKey::new(label("check-delivery")), parameters: mint.digest() }),
        ],
    }]);
    let (refs, mut positions, retention, outbox) = empty_basis();
    positions.insert(stream, ForgeStreamPosition::new(1));
    let report = IntentEvaluator.evaluate(basis_of(&refs, &positions, &retention, &outbox), &req);
    assert!(matches!(report.outcome, FoldOutcome::Aborted { code: RefusalCode::ForgeTransitionInvalid, .. }));
    assert!(report.effects().is_none());
    assert!(report.mappings.iter().all(|m| m.disposition == IntentDisposition::TransactionAborted));
}

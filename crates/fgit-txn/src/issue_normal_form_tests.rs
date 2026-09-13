// Included by lib.rs's private test module to reuse its real evaluator fixtures.
#[test]
fn issue_event_encoding_appends_tag_six_without_changing_existing_event_tags() {
    let entity = ForgeEntityId::new(label("issue-17"));
    let target = name("refs/heads/main");
    let events = [
        ForgeEventKind::PullRequestOpened { pull_request: entity, target: target.clone() },
        ForgeEventKind::PullRequestMerged { pull_request: entity, target: target.clone() },
        ForgeEventKind::PullRequestClosed { pull_request: entity },
        ForgeEventKind::PullRequestUpdated { pull_request: entity, target: target.clone() },
        ForgeEventKind::PullRequestReviewed { review: entity, target: target.clone() },
        ForgeEventKind::IssueChanged { issue: entity },
    ];
    let mut seen = BTreeSet::new();
    for (i, event) in events.iter().enumerate() {
        let mut out = Encoder::new();
        write_forge_event(&mut out, event).unwrap();
        let actual = out.into_bytes();
        let mut expected = Encoder::new();
        expected.write_raw_byte(u8::try_from(i + 1).unwrap());
        expected.write_text("ForgeEntityId", entity.label().as_str()).unwrap();
        if !matches!(event, ForgeEventKind::PullRequestClosed { .. } | ForgeEventKind::IssueChanged { .. }) {
            expected.write_ref_name(&target).unwrap();
        }
        assert_eq!(actual, expected.into_bytes());
        assert!(seen.insert(actual), "issue and PR events cannot share an encoding");
    }
    let mut out = Encoder::new();
    write_forge_event(&mut out, &ForgeEventKind::IssueChanged { issue: ForgeEntityId::new(label("issue-18")) }).unwrap();
    assert!(seen.insert(out.into_bytes()), "the issue identity is part of evidence");
}

#[test]
fn ordered_issue_updates_and_delivery_survive_canonical_fold_and_application() {
    let stream = ForgeStreamId::new(label("issue-stream"));
    let event = ForgeEventKind::IssueChanged { issue: ForgeEntityId::new(label("issue-17")) };
    let delivery = OutboxDeliveryKey::new(label("issue-delivery"));
    let mut mint = IdentityMint::new(27);
    let parameters = mint.digest();
    let request = request(vec![Statement {
        mismatch_policy: MismatchPolicy::TxnAbort,
        intents: vec![
            Intent::Forge(ForgeIntent { stream, expected_position: ForgeStreamPosition::GENESIS, event: event.clone() }),
            Intent::Forge(ForgeIntent { stream, expected_position: ForgeStreamPosition::new(1), event: event.clone() }),
            Intent::Outbox(OutboxIntent { delivery_key: delivery, parameters }),
        ],
    }]);
    let (refs, forge, retention, outbox) = empty_basis();
    let evaluator = IntentEvaluator::new();
    let report = evaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
    evaluator.validate_report(&request, &report).unwrap();
    let effects = report.effects().expect("issue changes are real forge effects");
    assert_eq!(effects.forge.get(&stream), Some(&vec![event.clone(), event.clone()]));
    assert!(effects.refs.is_empty() && effects.retention.is_empty());
    assert_eq!(effects.outbox.get(&delivery), Some(&parameters));
    let canonical = canonical_fold_bytes(&request, &report).unwrap();
    assert!(!canonical.is_empty());
    let again = evaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
    assert_eq!(canonical, canonical_fold_bytes(&request, &again).unwrap());
    let applied = apply_net_effects(&Workspace::default(), effects);
    assert_eq!(applied.forge.get(&stream), Some(&vec![event.clone(), event]));
    assert_eq!(applied.outbox.get(&delivery), Some(&parameters));
    assert!(applied.refs.is_empty() && applied.retention.is_empty());
}

#[test]
fn canonical_issue_effects_do_not_alias_other_entities_or_pull_request_effects() {
    let stream = ForgeStreamId::new(label("aggregate"));
    let same = ForgeEntityId::new(label("entity-17"));
    let events = [
        ForgeEventKind::IssueChanged { issue: same },
        ForgeEventKind::IssueChanged { issue: ForgeEntityId::new(label("entity-18")) },
        ForgeEventKind::PullRequestClosed { pull_request: same },
    ];
    let (refs, forge, retention, outbox) = empty_basis();
    let mut encodings = BTreeSet::new();
    for event in events {
        let request = request(vec![Statement { mismatch_policy: MismatchPolicy::TxnAbort,
            intents: vec![Intent::Forge(ForgeIntent { stream, expected_position: ForgeStreamPosition::GENESIS, event })] }]);
        let report = IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
        let effects = report.effects().unwrap();
        assert!(encodings.insert(canonical_effect_bytes(effects).unwrap()));
        assert!(!canonical_fold_bytes(&request, &report).unwrap().is_empty());
    }
    assert_eq!(encodings.len(), 3);
}

#[test]
fn issue_staleness_preserves_each_statement_policy_and_its_permitted_twin() {
    let stream = ForgeStreamId::new(label("issue-stale"));
    let event = ForgeEventKind::IssueChanged { issue: ForgeEntityId::new(label("issue-17")) };
    for policy in MismatchPolicy::ALL {
        let request = request(vec![Statement { mismatch_policy: *policy,
            intents: vec![Intent::Forge(ForgeIntent { stream, expected_position: ForgeStreamPosition::GENESIS, event: event.clone() })] }]);
        let (refs, mut forge, retention, outbox) = empty_basis();
        let permitted = IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
        assert_eq!(permitted.effects().unwrap().forge.get(&stream), Some(&vec![event.clone()]));
        let allowed_bytes = canonical_fold_bytes(&request, &permitted).unwrap();
        forge.insert(stream, ForgeStreamPosition::new(1));
        let stale = IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
        assert_ne!(canonical_fold_bytes(&request, &stale).unwrap(), allowed_bytes);
        assert!(stale.effects().is_none_or(|effects| effects.forge.is_empty() && effects.outbox.is_empty()));
        match policy {
            MismatchPolicy::NoOp => assert_eq!(stale.mappings[0].disposition, IntentDisposition::Absorbed(AbsorptionReason::PreconditionMismatchNoOp)),
            MismatchPolicy::StatementError => assert_eq!(stale.mappings[0].disposition, IntentDisposition::StatementError(RefusalCode::ForgeTransitionInvalid)),
            MismatchPolicy::TxnAbort => assert!(matches!(stale.outcome, FoldOutcome::Aborted { code: RefusalCode::ForgeTransitionInvalid, .. })),
        }
    }
}

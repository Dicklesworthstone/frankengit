// Included in lib.rs tests; the evaluator and reference fixtures are shared.
fn comment_event() -> ForgeEventKind {
    ForgeEventKind::PullRequestCommented {
        conversation: ForgeEntityId::new(label("conversation/1")),
    }
}

#[test]
fn conversation_normal_form_has_a_distinct_literal_tag_without_a_ref() {
    let event = comment_event();
    let mut out = Encoder::new();
    write_forge_event(&mut out, &event).unwrap();
    assert_eq!(out.as_bytes(), b"\x09\0\0\0\x0econversation/1");
    assert_eq!(event.required_ref_effect(), None);
    let mut old = Encoder::new();
    write_forge_event(
        &mut old,
        &ForgeEventKind::IssueChanged {
            issue: event.entity(),
        },
    )
    .unwrap();
    assert_ne!(out.as_bytes(), old.as_bytes());
}

#[test]
fn comment_and_delivery_fold_without_touching_refs_pr_metadata_or_reviews() {
    let conversation = ForgeStreamId::new(label("conversation/1"));
    let pull = ForgeStreamId::new(label("pull-request/1"));
    let review = ForgeStreamId::new(label("review/1/reviewer"));
    let key = OutboxDeliveryKey::new(label("comment-delivery"));
    let parameters = IdentityMint::new(95_031).digest();
    let req = request(vec![Statement {
        mismatch_policy: MismatchPolicy::TxnAbort,
        intents: vec![
            Intent::Forge(ForgeIntent {
                stream: conversation,
                expected_position: ForgeStreamPosition::GENESIS,
                event: comment_event(),
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
    positions.insert(review, ForgeStreamPosition::new(2));
    let report = IntentEvaluator.evaluate(basis_of(&refs, &positions, &retention, &outbox), &req);
    IntentEvaluator.validate_report(&req, &report).unwrap();
    let effects = report.effects().unwrap();
    assert_eq!(
        effects.forge,
        BTreeMap::from([(conversation, vec![comment_event()])])
    );
    assert_eq!(effects.outbox, BTreeMap::from([(key, parameters)]));
    assert!(effects.refs.is_empty() && effects.retention.is_empty());
    assert_eq!(
        canonical_fold_bytes(&req, &report).unwrap(),
        canonical_fold_bytes(
            &req,
            &IntentEvaluator.evaluate(basis_of(&refs, &positions, &retention, &outbox), &req)
        )
        .unwrap()
    );
    positions.insert(conversation, ForgeStreamPosition::new(1));
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

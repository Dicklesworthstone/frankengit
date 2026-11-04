// Included by the real evaluator's private test module.
#[test]
fn agent_credential_normal_form_uses_tag_fourteen_and_binds_its_exact_entity() {
    let entity = ForgeEntityId::new(label("entity-7"));
    let event = ForgeEventKind::AgentCredentialChanged { credential: entity };
    let mut out = Encoder::new();
    write_forge_event(&mut out, &event).unwrap();
    assert_eq!(out.as_bytes(), b"\x0e\0\0\0\x08entity-7");
    assert_eq!(event.entity(), entity);
    assert!(event.required_ref_effect().is_none());
    let credential_bytes = out.into_bytes();
    for (legacy, tag) in [
        (ForgeEventKind::IssueChanged { issue: entity }, 6u8),
        (
            ForgeEventKind::ReviewProtectionChanged { policy: entity },
            7,
        ),
        (ForgeEventKind::DiscussionChanged { discussion: entity }, 13),
        (
            ForgeEventKind::PullRequestClosed {
                pull_request: entity,
            },
            3,
        ),
        (
            ForgeEventKind::PullRequestMerged {
                pull_request: entity,
                target: name("refs/heads/main"),
            },
            2,
        ),
    ] {
        let mut encoded = Encoder::new();
        write_forge_event(&mut encoded, &legacy).unwrap();
        assert_eq!(encoded.as_bytes()[0], tag);
        assert_ne!(encoded.as_bytes(), credential_bytes);
    }
    let mut other = Encoder::new();
    write_forge_event(
        &mut other,
        &ForgeEventKind::AgentCredentialChanged {
            credential: ForgeEntityId::new(label("entity-8")),
        },
    )
    .unwrap();
    assert_ne!(other.as_bytes(), credential_bytes);
}

#[test]
fn agent_credential_fold_carries_its_delivery_without_refs_and_refuses_stale_predecessors() {
    let stream = ForgeStreamId::new(label("agent/credential"));
    let event = ForgeEventKind::AgentCredentialChanged {
        credential: ForgeEntityId::new(stream.label()),
    };
    let delivery = OutboxDeliveryKey::new(label("credential-delivery"));
    let mut mint = IdentityMint::new(94);
    let parameters = mint.digest();
    let request = request(vec![Statement {
        mismatch_policy: MismatchPolicy::TxnAbort,
        intents: vec![
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
    forge.insert(stream, ForgeStreamPosition::new(1));
    let evaluator = IntentEvaluator::new();
    let report = evaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
    evaluator.validate_report(&request, &report).unwrap();
    let effects = report.effects().unwrap();
    assert_eq!(effects.forge.get(&stream), Some(&vec![event.clone()]));
    assert_eq!(effects.outbox.get(&delivery), Some(&parameters));
    assert!(effects.refs.is_empty() && effects.retention.is_empty());
    let canonical = canonical_fold_bytes(&request, &report).unwrap();
    let again = evaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
    assert_eq!(canonical, canonical_fold_bytes(&request, &again).unwrap());
    let applied = apply_net_effects(&Workspace::default(), effects);
    assert_eq!(applied.forge.get(&stream), Some(&vec![event]));
    assert_eq!(applied.outbox.get(&delivery), Some(&parameters));
    assert!(applied.refs.is_empty() && applied.retention.is_empty());

    forge.insert(stream, ForgeStreamPosition::new(2));
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

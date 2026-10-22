//! Historical retained-terminal publication uses the original public authority
//! protocol. It is a model migration fixture, not a second production sender.

use super::*;

fn publish_legacy_retained_terminal(fixture: &Fixture) -> CanonicalOutboxEffectState {
    fixture.stop_after(StopAfter::Terminal);
    assert!(
        fixture
            .deliver(&mut success(fixture.key), 3, MaterializationFault::None)
            .is_err()
    );
    fixture.resume();
    let deferred = fixture.effect();
    let progress = fixture.progress();
    let receipt = CanonicalOutboxDeliveryReceipt::try_new(
        fixture.context.repository_id,
        fixture.key,
        AsciiSlug::from_static("forge-projection"),
        deferred.payload_root(),
        storage::root(&deferred).unwrap(),
        OutboxDeliveryDisposition::Acknowledged,
        progress.evidence().to_vec(),
    )
    .unwrap();
    let effect = deferred
        .transition(
            LifecycleEvent::Acknowledge,
            Some(storage::root(&receipt).unwrap()),
        )
        .unwrap();
    let root = storage::root(&effect).unwrap();
    let semantic = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        fixture.context.object_format,
        true,
        Vec::new(),
        Vec::new(),
        vec![
            ScopedEntry::new(
                AsciiSlug::from_static("outbox"),
                AsciiSlug::from_static("runtime-successor"),
                root.bytes().as_bytes(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let mut context = fixture.context.clone();
    context.idempotency_key = fgit_authority::IdempotencyKey::new(
        format!(
            "outbox/{}",
            fgit_crypto::lowercase_hex(root.bytes().as_bytes())
        )
        .into_bytes(),
    )
    .unwrap();
    let attempt = SealAttempt {
        tenant_id: context.tenant_id,
        repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id,
        idempotency_key: context.idempotency_key.clone(),
        request: semantic.clone(),
    };
    let sealed = run(fgit_authority::seal_request_async(
        &fixture.store,
        &(),
        &attempt,
    ))
    .unwrap();
    let (basis, head, authenticated) = run(crate::read_basis_async(
        &fixture.store,
        &(),
        &context.head_key,
    ))
    .unwrap();
    let cumulative = run(fgit_authority::collect_cumulative_outcomes_async(
        &fixture.store,
        &(),
        &context.head_key,
    ))
    .unwrap();
    let projection = fixture.projection(MaterializationFault::None);
    let snapshot =
        run(projection.snapshot_async(&fixture.store, &(), &basis, &authenticated)).unwrap();
    let empty = PermittedObjectClosure::default();
    let closure = ValidatedClosure {
        objects: empty.objects().clone(),
        object_closure_root: crate::permitted_object_closure_root(&empty).unwrap(),
    };
    let lowered = LoweredRequest {
        semantic,
        idempotency_key: context.idempotency_key.clone(),
    };
    let PublicationPreparation::Commit(prepared) = crate::prepare_publication_from_snapshot(
        &context,
        &lowered,
        &closure,
        sealed.tx_id(),
        snapshot,
    )
    .unwrap() else {
        panic!("legacy fold")
    };
    let mut materialization = run(projection.materialize_commit_async(
        &fixture.store,
        &(),
        &basis,
        &prepared.request,
        &prepared.fold,
        &closure,
    ))
    .unwrap();
    let state = run(delivery::read_in(&fixture.store, &(), &basis, &|| false)).unwrap();
    let original = state.outbox.entry(fixture.key).unwrap();
    let retained = CanonicalOutboxState::try_new(
        context.repository_id,
        vec![CanonicalOutboxStateEntry::new(
            original.delivery_key(),
            original.effect_class(),
            original.destination(),
            original.payload_root(),
            original.tx_id(),
            original.predecessor_rcr_id(),
            root,
            Some(original.effect_state_root()),
        )],
    )
    .unwrap();
    run(storage::stage_body(
        &fixture.store,
        &(),
        context.repository_id,
        RECEIPT_NAMESPACE,
        &receipt,
    ))
    .unwrap();
    run(delivery::stage_effect_and_outbox_in(
        &fixture.store,
        &(),
        &retained,
        &effect,
        &|| false,
    ))
    .unwrap();
    run(stage_runtime_evidence(
        &fixture.store,
        &(),
        &context,
        &effect,
        &|| Ok(()),
    ))
    .unwrap();
    materialization.roots.outbox_root = storage::root(&retained).unwrap();
    materialization.record.invariant_evidence_root = root;
    materialization.record.outbox_effect_root = root;
    let mut plan = PublicationPlan::open(basis).unwrap();
    plan.commit(materialization.record);
    let publication = plan
        .seal(
            &CryptoBodyIdentity,
            materialization.roots,
            &cumulative,
            head.token(),
        )
        .unwrap();
    assert_eq!(
        run(publication::publish_owned(
            &fixture.store,
            &(),
            &context,
            head.token(),
            &publication,
            sealed.tx_id()
        ))
        .unwrap(),
        Some(true)
    );
    effect
}

#[test]
fn legacy_terminal_is_retired_under_a_distinct_seal_without_another_send() {
    let fixture = Fixture::new();
    let effect = publish_legacy_retained_terminal(&fixture);
    let before = fixture.basis();
    assert!(
        run(delivery::read_in(&fixture.store, &(), &before, &|| false))
            .unwrap()
            .outbox
            .entry(fixture.key)
            .is_some()
    );
    let mut transport = Transport::new(fixture.key, []);
    assert_eq!(
        fixture
            .deliver(&mut transport, 3, MaterializationFault::None)
            .unwrap(),
        effect
    );
    let after = fixture.basis();
    assert_ne!(after.id(), before.id());
    assert!(
        run(delivery::read_in(&fixture.store, &(), &after, &|| false))
            .unwrap()
            .outbox
            .entries()
            .is_empty()
    );
    assert!(transport.calls.is_empty());
    assert_eq!(
        fixture
            .deliver(&mut transport, 3, MaterializationFault::None)
            .unwrap(),
        effect
    );
    assert_eq!(fixture.basis(), after);
    assert!(transport.calls.is_empty());
}

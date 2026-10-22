//! Historical retained-terminal publication uses the original public authority
//! protocol. It is a model migration fixture, not a second production sender.

use super::*;

fn publish_legacy_retained_terminal(fixture: &Fixture) -> CanonicalOutboxEffectState {
    publish_terminal_record(fixture, false)
}

// The negative builds an authenticated but semantically invalid history using
// the model authority's low-level publication interface. It deliberately does
// not use the production lifecycle stager for the forged terminal record.
fn publish_terminal_record(
    fixture: &Fixture,
    mismatched_audience: bool,
) -> CanonicalOutboxEffectState {
    if mismatched_audience {
        let basis = fixture.basis();
        let state = run(delivery::read_in(&fixture.store, &(), &basis, &|| false)).unwrap();
        let entry = state.outbox.entry(fixture.key).unwrap();
        let deferred = fixture
            .effect()
            .transition(LifecycleEvent::Defer, None)
            .unwrap();
        run(publish_mutation(
            &fixture.store,
            &(),
            &fixture.context,
            &fixture.projection(MaterializationFault::None),
            entry,
            RuntimeMutation::Lifecycle {
                next: &deferred,
                receipt: None,
                progress: None,
            },
            AdmissionLimits::default(),
            &|| Ok(()),
        ))
        .unwrap();
        let basis = fixture.basis();
        let state = run(delivery::read_in(&fixture.store, &(), &basis, &|| false)).unwrap();
        let entry = state.outbox.entry(fixture.key).unwrap();
        let initial = CanonicalOutboxProgress::start(
            fixture.context.repository_id,
            fixture.key,
            AsciiSlug::from_static("wrong-projection"),
            entry.payload_root(),
            entry.effect_state_root(),
            ReconcilePolicy::new(NonZeroU32::new(3).unwrap()),
        )
        .unwrap();
        let terminal = initial
            .observe(
                Observation::Probe(ProbeVerdict::Delivered),
                b"forged different-audience receipt".to_vec(),
            )
            .unwrap();
        for progress in [&initial, &terminal] {
            run(publish_mutation(
                &fixture.store,
                &(),
                &fixture.context,
                &fixture.projection(MaterializationFault::None),
                entry,
                RuntimeMutation::Progress(progress),
                AdmissionLimits::default(),
                &|| Ok(()),
            ))
            .unwrap();
        }
    } else {
        fixture.stop_after(StopAfter::Terminal);
        assert!(
            fixture
                .deliver(&mut success(fixture.key), 3, MaterializationFault::None)
                .is_err()
        );
        fixture.resume();
    }
    let deferred = fixture.effect();
    let progress = fixture.progress();
    let receipt = CanonicalOutboxDeliveryReceipt::try_new(
        fixture.context.repository_id,
        fixture.key,
        progress.destination(),
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
    let published = if mismatched_audience {
        // Bypass the writer's audience check ONLY to plant invalid canonical
        // input for the independent reader; no test transport is called.
        run(storage::stage_body(
            &fixture.store,
            &(),
            context.repository_id,
            delivery::EFFECT_NAMESPACE,
            &effect,
        ))
        .unwrap();
        let pruned = CanonicalOutboxState::try_new(context.repository_id, Vec::new()).unwrap();
        run(storage::stage_body(
            &fixture.store,
            &(),
            context.repository_id,
            delivery::OUTBOX_NAMESPACE,
            &pruned,
        ))
        .unwrap();
        pruned
    } else {
        run(delivery::stage_effect_and_outbox_in(
            &fixture.store,
            &(),
            &retained,
            &effect,
            &|| false,
        ))
        .unwrap();
        retained
    };
    run(stage_runtime_evidence(
        &fixture.store,
        &(),
        &context,
        &effect,
        &|| Ok(()),
    ))
    .unwrap();
    materialization.roots.outbox_root = storage::root(&published).unwrap();
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
fn a_matching_progress_and_receipt_cannot_retarget_a_retired_delivery() {
    let fixture = Fixture::new();
    let effect = publish_terminal_record(&fixture, true);
    let before = fixture.basis();
    let progress = fixture.progress();
    let frame = run(storage::read_frame(
        &fixture.store,
        &(),
        fixture.context.repository_id,
        RECEIPT_NAMESPACE,
        effect.evidence_root().unwrap(),
    ))
    .unwrap()
    .unwrap();
    let receipt =
        decode_body::<CanonicalOutboxDeliveryReceipt>(&frame, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(
        progress.destination(),
        AsciiSlug::from_static("wrong-projection")
    );
    assert_eq!(receipt.destination(), progress.destination());
    history::validate_terminal_progress(&progress, &effect, &receipt).unwrap();
    assert!(
        run(delivery::read_in(&fixture.store, &(), &before, &|| false))
            .unwrap()
            .outbox
            .entries()
            .is_empty()
    );
    assert!(matches!(
        run(history::retired_effect(
            &fixture.store,
            &(),
            &before,
            fixture.key,
            AsciiSlug::from_static("forge-projection"),
            &|| false
        )),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::EvidenceInvalid
        ))
    ));
    let mut transport = Transport::new(fixture.key, []);
    assert!(
        fixture
            .deliver(&mut transport, 3, MaterializationFault::None)
            .is_err()
    );
    assert!(transport.calls.is_empty());
    assert_eq!(fixture.basis(), before);
}

#[test]
fn legacy_terminal_is_retired_under_a_distinct_seal_without_another_send() {
    let fixture = Fixture::new();
    let effect = publish_legacy_retained_terminal(&fixture);
    let before = fixture.basis();
    let missing_entry =
        CanonicalOutboxState::try_new(fixture.context.repository_id, Vec::new()).unwrap();
    assert!(
        matches!(
            run(delivery::stage_effect_and_outbox_in(
                &fixture.store,
                &(),
                &missing_entry,
                &effect,
                &|| false,
            )),
            Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::EvidenceInvalid
            ))
        ),
        "retirement must not weaken the lifecycle stager's membership check"
    );
    assert_eq!(fixture.basis(), before);
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

#[test]
fn cancellation_after_pruned_body_staging_keeps_authority_live_and_resumes_without_resend() {
    let fixture = Fixture::new();
    fixture
        .store
        .stop_on_retirement_stage
        .store(true, Ordering::SeqCst);
    let mut first = success(fixture.key);
    assert!(matches!(
        fixture.deliver(&mut first, 3, MaterializationFault::None),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::CancellationInProgress
        ))
    ));
    assert_eq!(first.calls, [Call::Probe, Call::Deliver(2)]);
    assert_eq!(
        fixture.effect().state(),
        ObligationState::DeferredExternally
    );
    let staged_basis = fixture.basis();
    let active = run(delivery::read_in(
        &fixture.store,
        &(),
        &staged_basis,
        &|| false,
    ))
    .unwrap();
    assert_eq!(
        active.outbox.entries().len(),
        1,
        "a staged pruned map is not canonical retirement"
    );
    assert!(
        run(history::retired_effect(
            &fixture.store,
            &(),
            &staged_basis,
            fixture.key,
            AsciiSlug::from_static("forge-projection"),
            &|| false
        ))
        .is_err()
    );
    assert_eq!(
        fixture.progress().state(),
        ReconcileState::Delivered { attempt: 2 }
    );
    fixture.resume();
    let mut recovered = Transport::new(fixture.key, []);
    let terminal = fixture
        .deliver(&mut recovered, 3, MaterializationFault::None)
        .unwrap();
    assert_eq!(terminal.state(), ObligationState::Acknowledged);
    assert!(recovered.calls.is_empty());
    assert_ne!(fixture.basis().id(), staged_basis.id());
    assert!(
        run(delivery::read_in(
            &fixture.store,
            &(),
            &fixture.basis(),
            &|| false
        ))
        .unwrap()
        .outbox
        .entries()
        .is_empty()
    );
    assert_eq!(fixture.effect(), terminal);
}

//! Live authorization renewal for a host retaining unsubmitted object custody.
//! These tests exercise broker ownership and accounting, not a native dispatch.

use super::*;

fn alternate_chain(leaf_id: u128, quota: ResourceVector) -> VerifiedCapabilityChain {
    let operations = ClassSet::from_classes(&[OperationClass::PublishRefTransaction]);
    let root = Capability::issue(
        CapabilityId::new(1),
        operations,
        resources(8_192, 32),
        LogicalTime::new(0),
        LogicalTime::new(100),
    )
    .unwrap();
    let sealed_root = root.seal(ISSUER_KEY, None).unwrap();
    let leaf = root
        .attenuate(&AttenuationRequest {
            id: CapabilityId::new(leaf_id),
            operations,
            quota,
            not_before: LogicalTime::new(5),
            expires_at: LogicalTime::new(90),
        })
        .unwrap();
    let sealed_leaf = leaf.seal(ISSUER_KEY, Some(sealed_root.tag())).unwrap();
    VerifiedCapabilityChain::verify(&[sealed_root, sealed_leaf], ISSUER_KEY).unwrap()
}

fn settle(
    fixture: &Fixture,
    attempt: &SealAttempt,
    owner: CurrentAuthorityRevocationCheckedEffectBroker,
    pending: PendingRefTransactionSubmission,
    committed: bool,
) -> SettledRefTransactionSubmission {
    let binding = pending.binding().clone();
    let admission = seal_request(&fixture.store, attempt).unwrap();
    assert_eq!(admission.tx_id(), binding.tx_id());
    let terminal = fixture.decide(binding.tx_id(), committed);
    let view = AsyncView::new(&fixture.store);
    let RefTransactionResolution::Decided(settled) =
        poll_ready(pending.reconcile_async(&view, &(), &fixture.head_key)).unwrap()
    else {
        panic!("the original canonical terminal settles the retained responsibility");
    };
    assert_eq!(settled.observation().binding(), &binding);
    assert_eq!(settled.observation().terminal(), &terminal);
    view.assert_read_only();
    let fgit_resource::RegionCloseOutcome::Quiescent(closed) = owner.close() else {
        panic!("one resumed first dispatch must leave no second responsibility");
    };
    assert_eq!(closed.settled(), 1);
    assert_eq!(closed.consumed(), cost());
    settled
}

#[test]
fn retained_custody_reauthorization_preserves_the_paid_identity_and_original_journal() {
    for committed in [false, true] {
        let fixture = Fixture::new(810 + u64::from(committed));
        let attempt = seal_attempt(b"retained-first-dispatch");
        let binding = submission_binding(&fixture.run, &attempt)
            .with_custody_commitment([0xb1; 32])
            .unwrap();
        let (mut owner, capture) = broker(&fixture.run);
        let reserved = reserve(&fixture, &mut owner, &binding);
        let initial = reserved.initial_authorization();
        let mut pending = start(&fixture, &mut owner, reserved);
        let started = pending.start_authorization();
        let records = owner.records();
        let entries = owner.journal();
        let tail = owner.durable_position().unwrap();
        let head = fixture.store.read_head(&fixture.head_key).unwrap();
        assert_eq!(pending.run(), &fixture.run);

        let renewed = owner
            .reauthorize_retained_ref_transaction(
                &mut pending,
                &chain(OperationClass::PublishRefTransaction),
                &fixture.revocations(29),
                LogicalTime::new(30),
            )
            .unwrap();
        assert_ne!(renewed.authorization_id(), started.authorization_id());
        assert_eq!(
            renewed.authorization().authorized_at(),
            LogicalTime::new(30)
        );
        assert_eq!(pending.start_authorization(), renewed);
        assert_eq!(pending.binding(), &binding);
        assert_eq!(owner.authorizations().len(), 1);
        assert_eq!(owner.generic_authorizations().len(), 1);
        assert_eq!(owner.dispatch_authorizations(), &[started, renewed]);
        assert_eq!(owner.generic_dispatch_authorizations().len(), 2);
        assert_eq!(owner.records(), records);
        assert_eq!(owner.journal(), entries);
        assert_eq!(owner.durable_position().unwrap(), tail);
        assert_eq!(capture.decode(&fixture.run).unwrap().records(), records);
        assert_eq!(fixture.store.read_head(&fixture.head_key).unwrap(), head);
        assert!(
            fgit_authority::read_seal(&fixture.store, TENANT, REPOSITORY, binding.tx_id())
                .unwrap()
                .is_none(),
            "renewing authorization is not ordinary admission"
        );

        let settled = settle(&fixture, &attempt, owner, pending, committed);
        assert_eq!(settled.initial_authorization(), initial);
        assert_eq!(settled.start_authorization(), renewed);
    }
}

#[test]
fn retained_custody_needs_the_actual_owner_original_chain_and_unexpired_authority() {
    let fixture = Fixture::new(812);
    let attempt = seal_attempt(b"retained-owner-and-authority");
    let binding = submission_binding(&fixture.run, &attempt);
    let (mut owner, _) = broker(&fixture.run);
    let reserved = reserve(&fixture, &mut owner, &binding);
    let mut pending = start(&fixture, &mut owner, reserved);
    let started = pending.start_authorization();
    let records = owner.records();
    let entries = owner.journal();
    let tail = owner.durable_position().unwrap();
    let accepted = chain(OperationClass::PublishRefTransaction);
    let fresh = fixture.revocations(29);

    // Both brokers deliberately have identical run, region and agent IDs.
    let (mut impostor, _) = broker(&fixture.run);
    assert!(matches!(
        impostor.reauthorize_retained_ref_transaction(
            &mut pending,
            &accepted,
            &fresh,
            LogicalTime::new(30),
        ),
        Err(RefTransactionEffectRefusal::Binding)
    ));
    assert!(impostor.records().is_empty());
    assert!(impostor.dispatch_authorizations().is_empty());
    assert!(impostor.close().is_quiescent());

    assert!(matches!(
        owner.reauthorize_retained_ref_transaction(
            &mut pending,
            &alternate_chain(3, resources(4_096, 16)),
            &fresh,
            LogicalTime::new(30),
        ),
        Err(RefTransactionEffectRefusal::Binding)
    ));
    assert!(matches!(
        owner.reauthorize_retained_ref_transaction(
            &mut pending,
            &alternate_chain(2, resources(128, 1)),
            &fresh,
            LogicalTime::new(30),
        ),
        Err(RefTransactionEffectRefusal::FreshAuthorization(ref reason))
            if matches!(reason.as_ref(), CapabilityEffectAuthorizationRefusal::CapabilityQuotaExceeded { .. })
    ));
    assert!(matches!(
        owner.reauthorize_retained_ref_transaction(
            &mut pending,
            &chain(OperationClass::PreparePublication),
            &fresh,
            LogicalTime::new(30),
        ),
        Err(RefTransactionEffectRefusal::FreshAuthorization(ref reason))
            if matches!(reason.as_ref(), CapabilityEffectAuthorizationRefusal::OperationOutsideCapability { .. })
    ));
    assert!(matches!(
        owner.reauthorize_retained_ref_transaction(
            &mut pending,
            &accepted,
            &fixture.revocations(20),
            LogicalTime::new(21),
        ),
        Err(RefTransactionEffectRefusal::Binding)
    ));
    assert!(matches!(
        owner.reauthorize_retained_ref_transaction(
            &mut pending,
            &accepted,
            &fixture.revocations(89),
            LogicalTime::new(90),
        ),
        Err(RefTransactionEffectRefusal::FreshAuthorization(ref reason))
            if matches!(reason.as_ref(), CapabilityEffectAuthorizationRefusal::CapabilityNotValid { .. })
    ));
    assert!(matches!(
        owner.reauthorize_retained_ref_transaction(
            &mut pending,
            &accepted,
            &fresh,
            LogicalTime::new(100),
        ),
        Err(RefTransactionEffectRefusal::FreshAuthorization(_))
    ));
    assert_eq!(pending.start_authorization(), started);
    assert_eq!(pending.binding(), &binding);
    assert_eq!(owner.records(), records);
    assert_eq!(owner.journal(), entries);
    assert_eq!(owner.durable_position().unwrap(), tail);
    assert_eq!(owner.dispatch_authorizations(), &[started]);
    assert_eq!(owner.generic_dispatch_authorizations().len(), 1);

    // Refused probes did not consume or replace the original live obligation.
    owner
        .reauthorize_retained_ref_transaction(&mut pending, &accepted, &fresh, LogicalTime::new(30))
        .unwrap();
    let _settled = settle(&fixture, &attempt, owner, pending, false);
}

#[test]
fn a_successor_authority_head_cannot_refresh_the_original_prepared_basis() {
    for revoked in [false, true] {
        let fixture = Fixture::new(814 + u64::from(revoked));
        let attempt = seal_attempt(b"retained-exact-basis");
        let binding = submission_binding(&fixture.run, &attempt);
        let (mut owner, _) = broker(&fixture.run);
        let reserved = reserve(&fixture, &mut owner, &binding);
        let mut pending = start(&fixture, &mut owner, reserved);
        let started = pending.start_authorization();
        let entries = owner.journal();
        let revoked_ids = if revoked {
            vec![CapabilityId::new(2)]
        } else {
            Vec::new()
        };
        fixture.revoke(&revoked_ids);
        let changed = fixture.revocations(29);
        assert_ne!(
            changed.current_authority_head_id(),
            fixture
                .run
                .authority_read_receipt()
                .unwrap()
                .authority_head_id(),
        );
        assert!(matches!(
            owner.reauthorize_retained_ref_transaction(
                &mut pending,
                &chain(OperationClass::PublishRefTransaction),
                &changed,
                LogicalTime::new(30),
            ),
            Err(RefTransactionEffectRefusal::Binding)
        ));
        assert_eq!(pending.start_authorization(), started);
        assert_eq!(owner.journal(), entries);
        assert_eq!(owner.dispatch_authorizations(), &[started]);
        let _settled = settle(&fixture, &attempt, owner, pending, false);
    }
}

#[test]
fn retained_custody_authorization_attempts_have_a_finite_aggregate_bound() {
    let fixture = Fixture::new(816);
    let attempt = seal_attempt(b"retained-attempt-bound");
    let binding = submission_binding(&fixture.run, &attempt);
    let (mut owner, _) = broker(&fixture.run);
    let reserved = reserve(&fixture, &mut owner, &binding);
    let mut pending = start(&fixture, &mut owner, reserved);
    let entries = owner.journal();
    let records = owner.records();
    let tail = owner.durable_position().unwrap();
    let accepted = chain(OperationClass::PublishRefTransaction);
    let fresh = fixture.revocations(29);
    let limit = crate::effect_authorization::MAX_EFFECT_AUTHORIZATIONS;
    for _ in 1..limit {
        owner
            .reauthorize_retained_ref_transaction(
                &mut pending,
                &accepted,
                &fresh,
                LogicalTime::new(30),
            )
            .unwrap();
    }
    let last = pending.start_authorization();
    assert!(matches!(
        owner.reauthorize_retained_ref_transaction(
            &mut pending,
            &accepted,
            &fresh,
            LogicalTime::new(31),
        ),
        Err(RefTransactionEffectRefusal::AuthorizationLimit)
    ));
    assert_eq!(pending.start_authorization(), last);
    assert_eq!(owner.dispatch_authorizations().len(), limit);
    assert_eq!(owner.generic_dispatch_authorizations().len(), limit);
    assert_eq!(owner.records(), records);
    assert_eq!(owner.journal(), entries);
    assert_eq!(owner.durable_position().unwrap(), tail);
    let _settled = settle(&fixture, &attempt, owner, pending, false);
}

#[test]
fn a_failed_start_journal_cannot_be_reopened_by_live_reauthorization() {
    for (offset, point) in [FailurePoint::Commit, FailurePoint::Defer]
        .into_iter()
        .enumerate()
    {
        for after_write in [false, true] {
            let fixture = Fixture::new(817 + offset as u64 * 2 + u64::from(after_write));
            let binding = submission_binding(&fixture.run, &seal_attempt(b"retained-poisoned"));
            let (mut owner, capture) = broker(&fixture.run);
            let reserved = reserve(&fixture, &mut owner, &binding);
            capture.fail(point, after_write);
            let error = owner
                .start_ref_transaction(
                    reserved,
                    &chain(OperationClass::PublishRefTransaction),
                    &fixture.revocations(20),
                    LogicalTime::new(22),
                )
                .unwrap_err();
            let RefTransactionStartRefused::AfterStart { mut pending, .. } = error else {
                panic!("the journal failed after submission responsibility committed");
            };
            let started = pending.start_authorization();
            let records = owner.records();
            let entries = owner.journal();
            assert!(matches!(
                owner.reauthorize_retained_ref_transaction(
                    &mut pending,
                    &chain(OperationClass::PublishRefTransaction),
                    &fixture.revocations(29),
                    LogicalTime::new(30),
                ),
                Err(RefTransactionEffectRefusal::Journal(
                    EffectJournalRefusal::PersistencePoisoned
                ))
            ));
            assert_eq!(pending.start_authorization(), started);
            assert_eq!(owner.records(), records);
            assert_eq!(owner.journal(), entries);
            assert_eq!(owner.dispatch_authorizations(), &[started]);
            assert_eq!(owner.generic_dispatch_authorizations().len(), 1);
            assert!(owner.durable_position().is_err());
            assert!(
                fgit_authority::read_seal(&fixture.store, TENANT, REPOSITORY, binding.tx_id())
                    .unwrap()
                    .is_none()
            );
            drop(pending);
            assert!(
                !owner.close().is_quiescent(),
                "journal failure remains explicit debt"
            );
        }
    }
}

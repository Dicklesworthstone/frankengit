//! Squash uses the real native admission driver and faultable model authority.
//! The model store is not filesystem crash or deployed node evidence.
use super::*;

fn fixture(format: GitHashAlgorithm, prior: Prior) -> Fixture {
    let mut fixture = selected_pr_fixture(format, prior);
    let mut merge = fixture.intent.merge().unwrap().clone();
    let mut objects = Objects(fixture.objects.0.clone());
    let tree = objects
        .0
        .values()
        .find(|object| object.object_type() == ObjectType::Tree)
        .unwrap()
        .id();
    merge.merge_commit = objects.commit(tree, &[merge.target_tip_before], "reviewed squash");
    let ExpectedVersion::Exactly(version) = fixture.intent.expected_version() else {
        panic!("squash fixture must use a real selected PR version")
    };
    fixture.intent = NativeMergeIntent::squash(PullRequestNumber::FIRST, version, merge).unwrap();
    fixture.objects = Arc::new(objects);
    fixture
}

#[test]
fn squash_reuses_atomic_ref_pr_outbox_publication_and_exact_prior_state_checks() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for driver in [NativeDriver::Sync, NativeDriver::Async] {
            for prior in [
                Prior::Open,
                Prior::Update,
                Prior::Close,
                Prior::OtherSourceRef,
                Prior::OtherTargetRef,
                Prior::OtherSourceTip,
                Prior::OtherTargetTip,
            ] {
                let fixture = fixture(format, prior);
                let before = fixture.head();
                let terminal = driver
                    .run(&fixture, &fixture.context, &fixture.intent)
                    .unwrap();
                let after = fixture.head();
                if let Some(code) = prior.refusal() {
                    assert!(
                        matches!(terminal.outcome, DecisionOutcome::Refused { code: actual, .. } if actual == code),
                        "{prior:?}: {terminal:?}"
                    );
                    assert_eq!(after.ref_root, before.ref_root);
                    assert_eq!(after.forge_position_root, before.forge_position_root);
                    assert_eq!(after.outbox_root, before.outbox_root);
                    assert_eq!(
                        after.latest_committed_rcr_id,
                        before.latest_committed_rcr_id
                    );
                } else {
                    fixture.assert_committed(terminal);
                    let (refs, delivery) = selected_state(&fixture);
                    let merge = fixture.intent.merge().unwrap();
                    assert_eq!(refs.refs().get(&merge.source_ref), Some(&merge.source_tip));
                    assert_eq!(
                        refs.refs().get(&merge.target_ref),
                        Some(&merge.merge_commit)
                    );
                    assert_eq!(
                        delivery.forge.entries()[0].successor_position(),
                        fixture.intent.event().version.get()
                    );
                    let closure = validate_squash_objects(
                        fixture.objects.as_ref(),
                        merge,
                        MergeObjectLimits::default(),
                        &mut || true,
                    )
                    .unwrap();
                    let batch = read_decision_batch_body(
                        &fixture.store.backend,
                        after.decision_tail_id.unwrap(),
                    )
                    .unwrap();
                    assert_eq!(
                        batch.committed_rcrs[0].object_closure_root,
                        closure.object_closure_root
                    );
                }
                assert_eq!(
                    fixture.outcome(fixture.tx_id()),
                    OutcomeLookup::Decided(terminal)
                );
                assert_eq!(
                    driver
                        .other()
                        .run(&fixture, &fixture.context, &fixture.intent)
                        .unwrap(),
                    terminal
                );
                assert_eq!(fixture.head(), after);
                assert_eq!(fixture.store.publications.lock().unwrap().len(), 1);
            }
        }
    }
}

#[test]
fn synchronous_and_asynchronous_squash_publish_identical_canonical_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let left = fixture(format, Prior::Open);
        let right = fixture(format, Prior::Open);
        let sync = NativeDriver::Sync
            .run(&left, &left.context, &left.intent)
            .unwrap();
        let asynchronous = NativeDriver::Async
            .run(&right, &right.context, &right.intent)
            .unwrap();
        assert_eq!(sync, asynchronous);
        left.assert_committed(sync);
        right.assert_committed(asynchronous);
        assert_same_native_state(&left, &right);
    }
}

#[test]
fn squash_staging_crashes_leave_old_roots_and_cross_driver_retry_publishes_once() {
    for namespace in [
        EVENT_NAMESPACE,
        POSITION_NAMESPACE,
        delivery::OUTBOX_NAMESPACE,
        delivery::EFFECT_NAMESPACE,
    ] {
        for position in [FaultPosition::BeforeEffect, FaultPosition::AfterEffect] {
            let fixture = fixture(GitHashAlgorithm::Sha1, Prior::Open);
            let before = fixture.head();
            let tx = fixture.tx_id();
            *fixture.store.put_fault.lock().unwrap() = Some(PutFault {
                namespace,
                position,
            });
            assert!(fixture.run().is_err());
            assert_eq!(fixture.store.backend.fault_log().records().len(), 1);
            fixture.store.backend.restart();
            fixture.store.backend.install_fault_plan(FaultPlan::none());
            assert_eq!(fixture.head(), before);
            assert_eq!(fixture.outcome(tx), OutcomeLookup::Undecided);
            let terminal = NativeDriver::Sync
                .run(&fixture, &fixture.context, &fixture.intent)
                .unwrap();
            let after = fixture.assert_committed(terminal);
            assert_eq!(fixture.run().unwrap(), terminal);
            assert_eq!(fixture.head(), after);
            assert_eq!(fixture.store.publications.lock().unwrap().len(), 1);
        }
    }
}

#[test]
fn squash_cas_crash_and_lost_response_recover_the_original_complete_decision() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for fault in [
            FaultKind::Crash {
                position: FaultPosition::BeforeEffect,
            },
            FaultKind::Crash {
                position: FaultPosition::AfterEffect,
            },
            FaultKind::LoseRequest,
            FaultKind::LoseResponse,
            FaultKind::DuplicateRequest {
                deliver: DuplicateDelivery::Second,
            },
        ] {
            let fixture = fixture(format, Prior::Open);
            let before = fixture.head();
            let tx = fixture.tx_id();
            fixture
                .store
                .backend
                .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
                    0,
                    AuthorityOpKind::CompareExchangeHead,
                    fault,
                )]));
            let first = fixture.run();
            assert_eq!(fixture.store.backend.fault_log().records().len(), 1);
            if matches!(fault, FaultKind::Crash { .. }) {
                fixture.store.backend.restart();
            }
            fixture.store.backend.install_fault_plan(FaultPlan::none());
            if matches!(
                fault,
                FaultKind::Crash {
                    position: FaultPosition::BeforeEffect
                } | FaultKind::LoseRequest
            ) {
                assert!(first.is_err());
                assert_eq!(fixture.head(), before);
                assert_eq!(fixture.outcome(tx), OutcomeLookup::Undecided);
            } else {
                let OutcomeLookup::Decided(terminal) = fixture.outcome(tx) else {
                    panic!("an applied squash must retain its terminal decision")
                };
                fixture.assert_committed(terminal);
            }
            let terminal = NativeDriver::Sync
                .run(&fixture, &fixture.context, &fixture.intent)
                .unwrap();
            let after = fixture.assert_committed(terminal);
            assert_eq!(after.generation, before.generation.next().unwrap());
            assert_eq!(fixture.run().unwrap(), terminal);
            assert_eq!(fixture.head(), after);
        }
    }
}

#[test]
fn competing_squash_revalidates_moved_refs_and_never_duplicates_the_outbox() {
    let fixture = Arc::new(fixture(GitHashAlgorithm::Sha1, Prior::Open));
    let competitor = fixture.clone();
    let winner = Arc::new(Mutex::new(None));
    let observed = winner.clone();
    *fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
        let mut context = competitor.context.clone();
        context.idempotency_key = IdempotencyKey::new(b"competing-squash".to_vec()).unwrap();
        *observed.lock().unwrap() = Some(
            NativeDriver::Sync
                .run(&competitor, &context, &competitor.intent)
                .unwrap(),
        );
    }));
    let loser = fixture.run().unwrap();
    let winner = winner.lock().unwrap().unwrap();
    assert!(matches!(winner.outcome, DecisionOutcome::Committed { .. }));
    assert!(matches!(
        loser.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::TargetRefMoved,
            ..
        }
    ));
    let after = fixture.head();
    let batch =
        read_decision_batch_body(&fixture.store.backend, after.decision_tail_id.unwrap()).unwrap();
    assert!(batch.committed_rcrs.is_empty());
    let (refs, delivery) = selected_state(&fixture);
    assert_eq!(
        refs.refs().get(&fixture.intent.merge().unwrap().target_ref),
        Some(&fixture.intent.merge().unwrap().merge_commit)
    );
    assert_eq!(delivery.outbox.entries().len(), 1);
    assert_eq!(delivery.forge.entries().len(), 1);
    assert_ne!(delivery.outbox.entries()[0].tx_id(), fixture.tx_id());
    assert_eq!(fixture.run().unwrap(), loser);
    assert_eq!(fixture.head(), after);
}

/// Mirrors an older application adapter: all pre-existing operations forward,
/// but neither new squash hook is implemented. This must remain fail-closed.
struct LegacyProjection(Projection);
impl SyncNativeMergeProjection for LegacyProjection {
    fn merge_checkpoint(&self) -> Result<(), RefusalCode> {
        Ok(())
    }
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, ProjectionFailure> {
        SyncNativeMergeProjection::snapshot(&self.0, basis, authenticated)
    }
    fn resolve_merge_basis(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<NativeMergeBasis, ProjectionFailure> {
        self.0.resolved_basis(basis, authenticated)
    }
    fn validate_merge(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
        intent: &NativeMergeIntent,
    ) -> Result<ValidatedClosure, ProjectionFailure> {
        SyncNativeMergeProjection::validate_merge(&self.0, basis, authenticated, intent)
    }
    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &fgit_txn::TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure> {
        SyncNativeMergeProjection::materialize_commit(&self.0, basis, request, fold, closure)
    }
    fn materialize_refusal(
        &self,
        basis: &PublicationBasis,
        tx: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, ProjectionFailure> {
        SyncNativeMergeProjection::materialize_refusal(&self.0, basis, tx, code)
    }
}
impl AsyncAdmissionProjection<Model> for LegacyProjection {
    fn snapshot_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        self.0.snapshot_async(store, cx, basis, authenticated)
    }
    fn materialize_commit_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a fgit_txn::TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, ProjectionFailure>> + Send + 'a {
        self.0
            .materialize_commit_async(store, cx, basis, request, fold, closure)
    }
    fn materialize_refusal_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        tx: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        self.0.materialize_refusal_async(store, cx, basis, tx, code)
    }
}
impl NativeMergeProjection<Model> for LegacyProjection {
    fn resolve_merge_basis_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<NativeMergeBasis, ProjectionFailure>> + Send + 'a {
        self.0
            .resolve_merge_basis_async(store, cx, basis, authenticated)
    }
    fn validate_merge_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        self.0
            .validate_merge_async(store, cx, basis, authenticated, intent)
    }
}

#[test]
fn projections_without_explicit_squash_support_refuse_while_enabled_twins_commit() {
    for driver in [NativeDriver::Sync, NativeDriver::Async] {
        let fixture = fixture(GitHashAlgorithm::Sha1, Prior::Open);
        let before = fixture.head();
        let legacy = LegacyProjection(fixture.projection(&fixture.context));
        let result = match driver {
            NativeDriver::Sync => admit_native_merge(
                &SyncModel(fixture.store.as_ref()),
                &fixture.context,
                &fixture.intent,
                AdmissionLimits::default(),
                &legacy,
            ),
            NativeDriver::Async => poll_ready(admit_native_merge_async(
                fixture.store.as_ref(),
                &(),
                &fixture.context,
                &fixture.intent,
                AdmissionLimits::default(),
                &legacy,
            )),
        }
        .unwrap();
        assert!(matches!(
            result.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::PublicationPolicyRefused,
                ..
            }
        ));
        let after = fixture.head();
        assert_eq!(after.ref_root, before.ref_root);
        assert_eq!(after.forge_position_root, before.forge_position_root);
        assert_eq!(after.outbox_root, before.outbox_root);
        // A capability upgrade cannot reinterpret this already terminal key.
        assert_eq!(
            driver
                .other()
                .run(&fixture, &fixture.context, &fixture.intent)
                .unwrap(),
            result
        );
        let mut context = fixture.context.clone();
        context.idempotency_key = IdempotencyKey::new(b"explicit-squash-enabled".to_vec()).unwrap();
        let enabled = driver.run(&fixture, &context, &fixture.intent).unwrap();
        assert!(matches!(enabled.outcome, DecisionOutcome::Committed { .. }));
        assert_eq!(selected_state(&fixture).1.outbox.entries().len(), 1);
    }
}

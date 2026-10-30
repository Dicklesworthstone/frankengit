//! Object custody crosses its boundary only after complete native preparation.
//! The production driver and real Git validation run on the existing explicit
//! non-durable model store; no filesystem crash-durability claim is made.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct PublishingProjection {
    inner: Projection,
    calls: AtomicUsize,
    fail: AtomicBool,
    expired: AtomicBool,
}

impl PublishingProjection {
    fn new(fixture: &Fixture) -> Self {
        Self {
            inner: fixture.projection(&fixture.context),
            calls: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
            expired: AtomicBool::new(false),
        }
    }

    fn run(&self, fixture: &Fixture) -> Result<TerminalOutcome, AdmissionError> {
        poll_ready(admit_native_merge_async(
            fixture.store.as_ref(),
            &(),
            &fixture.context,
            &fixture.intent,
            AdmissionLimits::default(),
            self,
        ))
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl AsyncAdmissionProjection<Model> for PublishingProjection {
    fn snapshot_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        self.inner.snapshot_async(store, cx, basis, authenticated)
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
        self.inner
            .materialize_commit_async(store, cx, basis, request, fold, closure)
    }

    fn materialize_refusal_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner
            .materialize_refusal_async(store, cx, basis, tx_id, code)
    }
}

impl NativeMergeProjection<Model> for PublishingProjection {
    fn merge_publication_checkpoint(&self, _: &()) -> Result<(), RefusalCode> {
        if self.expired.load(Ordering::SeqCst) {
            Err(RefusalCode::CapabilityExpired)
        } else {
            Ok(())
        }
    }

    fn publish_merge_objects(&self, _: &()) -> Result<(), RefusalCode> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            Err(RefusalCode::ResourceBudgetExceeded)
        } else {
            Ok(())
        }
    }

    fn resolve_merge_basis_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<NativeMergeBasis, ProjectionFailure>> + Send + 'a {
        self.inner
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
        self.inner
            .validate_merge_async(store, cx, basis, authenticated, intent)
    }
}

#[test]
fn candidate_objects_precede_the_first_commit_frame_and_terminal_replay_needs_no_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new_for_format(format);
        let projection = PublishingProjection::new(&fixture);
        let tx = fixture.tx_id();
        // REF_NAMESPACE is the first dependency written by stage_prepared.
        // The real fault fires only there; the hook must have run before it.
        *fixture.store.put_fault.lock().unwrap() = Some(PutFault {
            namespace: REF_NAMESPACE,
            position: FaultPosition::BeforeEffect,
        });
        assert!(projection.run(&fixture).is_err());
        assert_eq!(projection.calls(), 1);
        assert!(fixture.store.backend.is_crashed());
        fixture.store.backend.restart();
        fixture.store.backend.install_fault_plan(FaultPlan::none());
        assert_eq!(fixture.head(), fixture.genesis);
        assert_eq!(fixture.outcome(tx), OutcomeLookup::Undecided);

        let committed = projection.run(&fixture).unwrap();
        assert_eq!(projection.calls(), 2);
        let head = fixture.assert_committed(committed);
        // A fresh owner whose current publication capability expired still
        // recovers the exact prior decision without touching object custody.
        let replay = PublishingProjection::new(&fixture);
        replay.expired.store(true, Ordering::SeqCst);
        replay.fail.store(true, Ordering::SeqCst);
        assert_eq!(replay.run(&fixture).unwrap(), committed);
        assert_eq!(replay.calls(), 0);
        assert_eq!(fixture.head(), head);
    }
}

#[test]
fn failed_object_placement_or_effect_time_expiry_stages_no_commit_and_remains_retryable() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for expired in [false, true] {
            let fixture = Fixture::new_for_format(format);
            let projection = PublishingProjection::new(&fixture);
            let tx = fixture.tx_id();
            projection.expired.store(expired, Ordering::SeqCst);
            projection.fail.store(!expired, Ordering::SeqCst);
            *fixture.store.put_fault.lock().unwrap() = Some(PutFault {
                namespace: REF_NAMESPACE,
                position: FaultPosition::BeforeEffect,
            });
            let expected = if expired {
                RefusalCode::CapabilityExpired
            } else {
                RefusalCode::ResourceBudgetExceeded
            };
            assert!(matches!(
                projection.run(&fixture),
                Err(AdmissionError::AsyncProjectionUnavailable(code)) if code == expected
            ));
            assert_eq!(projection.calls(), usize::from(!expired));
            assert!(!fixture.store.backend.is_crashed());
            assert!(fixture.store.put_fault.lock().unwrap().is_some());
            assert_eq!(fixture.head(), fixture.genesis);
            assert_eq!(fixture.outcome(tx), OutcomeLookup::Undecided);

            *fixture.store.put_fault.lock().unwrap() = None;
            projection.expired.store(false, Ordering::SeqCst);
            projection.fail.store(false, Ordering::SeqCst);
            let committed = projection.run(&fixture).unwrap();
            assert_eq!(projection.calls(), 1 + usize::from(!expired));
            fixture.assert_committed(committed);
        }
    }
}

#[test]
fn canonical_refusals_and_their_replays_never_release_private_candidate_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for fault in ["target", "parent", "forge"] {
            let mut fixture = Fixture::new_for_format(format);
            let mut merge = fixture.intent.merge().unwrap().clone();
            let expected = match fault {
                "target" => {
                    merge.target_tip_before = merge.base_tip;
                    ExpectedVersion::NewStream
                }
                "parent" => {
                    merge.merge_commit = merge.source_tip;
                    ExpectedVersion::NewStream
                }
                "forge" => ExpectedVersion::Exactly(fgit_forge::aggregate::AggregateVersion::FIRST),
                _ => unreachable!(),
            };
            fixture.intent =
                NativeMergeIntent::new(PullRequestNumber::FIRST, expected, merge).unwrap();
            let projection = PublishingProjection::new(&fixture);
            projection.fail.store(true, Ordering::SeqCst);
            let terminal = projection.run(&fixture).unwrap();
            assert!(matches!(terminal.outcome, DecisionOutcome::Refused { .. }));
            assert_eq!(projection.calls(), 0);
            let head = fixture.head();
            assert_eq!(head.ref_root, fixture.genesis.ref_root);
            assert_eq!(
                head.forge_position_root,
                fixture.genesis.forge_position_root
            );
            assert_eq!(head.outbox_root, fixture.genesis.outbox_root);
            projection.expired.store(true, Ordering::SeqCst);
            assert_eq!(projection.run(&fixture).unwrap(), terminal);
            assert_eq!(projection.calls(), 0);
            assert_eq!(fixture.head(), head);
        }
    }
}

#[test]
fn sealed_evidence_must_match_before_candidate_objects_are_published() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for valid in [false, true] {
            let fixture = Fixture::new_for_format(format);
            let projection = PublishingProjection::new(&fixture);
            let mut package = sealed_native_fixture(&fixture);
            if !valid {
                package.evidence.invariant_evidence_root = digest(99);
            }
            let terminal = poll_ready(admit_sealed_native_merge_async(
                fixture.store.as_ref(),
                &(),
                &fixture.context,
                &package.borrowed(),
                AdmissionLimits::default(),
                &projection,
            ))
            .unwrap();
            if valid {
                assert!(matches!(
                    terminal.outcome,
                    DecisionOutcome::Committed { .. }
                ));
                assert_eq!(projection.calls(), 1);
                assert_ne!(fixture.head().ref_root, fixture.genesis.ref_root);
            } else {
                assert!(matches!(
                    terminal.outcome,
                    DecisionOutcome::Refused {
                        code: RefusalCode::EvidenceInvalid,
                        ..
                    }
                ));
                assert_eq!(projection.calls(), 0);
                assert_eq!(fixture.head().ref_root, fixture.genesis.ref_root);
            }
        }
    }
}

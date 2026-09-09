//! Real native admission and reference-store publication with explicit snapshot
//! observations. These observations exercise the admission contract; node tests
//! own evidence that a live session supplies them through publication.

use std::sync::atomic::{AtomicUsize, Ordering};

use fgit_admission::merge::native::{
    admit_workspace_sealed_native_merge, admit_workspace_sealed_native_merge_async,
    workspace_seal_attempt_for,
};

use super::*;

struct WorkspaceProjection {
    inner: Projection,
    observed: Mutex<[u8; 32]>,
    observations: AtomicUsize,
    validations: AtomicUsize,
}

impl WorkspaceProjection {
    fn new(fixture: &Fixture, observed: [u8; 32]) -> Self {
        Self {
            inner: fixture.projection(&fixture.context),
            observed: Mutex::new(observed),
            observations: AtomicUsize::new(0),
            validations: AtomicUsize::new(0),
        }
    }

    fn observe(&self) -> Result<[u8; 32], ProjectionFailure> {
        self.observations.fetch_add(1, Ordering::SeqCst);
        Ok(*self.observed.lock().unwrap())
    }
}

impl SyncNativeMergeProjection for WorkspaceProjection {
    fn merge_checkpoint(&self) -> Result<(), RefusalCode> {
        SyncNativeMergeProjection::merge_checkpoint(&self.inner)
    }
    fn workspace_snapshot_digest(&self) -> Result<[u8; 32], ProjectionFailure> {
        self.observe()
    }
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, ProjectionFailure> {
        SyncNativeMergeProjection::snapshot(&self.inner, basis, authenticated)
    }
    fn validate_merge(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
        intent: &NativeMergeIntent,
    ) -> Result<ValidatedClosure, ProjectionFailure> {
        self.validations.fetch_add(1, Ordering::SeqCst);
        SyncNativeMergeProjection::validate_merge(&self.inner, basis, authenticated, intent)
    }
    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &fgit_txn::TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure> {
        SyncNativeMergeProjection::materialize_commit(&self.inner, basis, request, fold, closure)
    }
    fn materialize_refusal(
        &self,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, ProjectionFailure> {
        SyncNativeMergeProjection::materialize_refusal(&self.inner, basis, tx_id, code)
    }
}

impl AsyncAdmissionProjection<Model> for WorkspaceProjection {
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

impl NativeMergeProjection<Model> for WorkspaceProjection {
    fn merge_checkpoint(&self, cx: &()) -> Result<(), RefusalCode> {
        NativeMergeProjection::merge_checkpoint(&self.inner, cx)
    }
    fn workspace_snapshot_digest(&self) -> Result<[u8; 32], ProjectionFailure> {
        self.observe()
    }
    fn validate_merge_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        self.validations.fetch_add(1, Ordering::SeqCst);
        self.inner
            .validate_merge_async(store, cx, basis, authenticated, intent)
    }
}

fn run_native(
    fixture: &Fixture,
    projection: &WorkspaceProjection,
    synchronous: bool,
) -> Result<TerminalOutcome, AdmissionError> {
    if synchronous {
        admit_native_merge(
            &SyncModel(&fixture.store),
            &fixture.context,
            &fixture.intent,
            AdmissionLimits::default(),
            projection,
        )
    } else {
        poll_ready(admit_native_merge_async(
            fixture.store.as_ref(),
            &(),
            &fixture.context,
            &fixture.intent,
            AdmissionLimits::default(),
            projection,
        ))
    }
}

#[test]
fn bound_default_projection_is_unavailable_then_matching_observation_commits_and_retry_skips_hook()
{
    for synchronous in [false, true] {
        let mut fixture = Fixture::new();
        fixture.intent = fixture.intent.clone().with_workspace_snapshot([41; 32]);
        let default = fixture.projection(&fixture.context);
        let result = if synchronous {
            admit_native_merge(
                &SyncModel(&fixture.store),
                &fixture.context,
                &fixture.intent,
                AdmissionLimits::default(),
                &default,
            )
        } else {
            fixture.run()
        };
        assert!(matches!(
            result,
            Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::EvidenceMissing
            ))
        ));
        assert_eq!(fixture.head(), fixture.genesis);
        assert!(fixture.store.publications.lock().unwrap().is_empty());
        assert_eq!(fixture.outcome(fixture.tx_id()), OutcomeLookup::Undecided);

        let projection = WorkspaceProjection::new(&fixture, [41; 32]);
        let committed = run_native(&fixture, &projection, synchronous).unwrap();
        fixture.assert_committed(committed.clone());
        assert_eq!(projection.observations.load(Ordering::SeqCst), 1);
        assert_eq!(projection.validations.load(Ordering::SeqCst), 1);
        let head = fixture.head();
        *projection.observed.lock().unwrap() = [42; 32];
        assert_eq!(
            run_native(&fixture, &projection, synchronous).unwrap(),
            committed
        );
        assert_eq!(projection.observations.load(Ordering::SeqCst), 1);
        assert_eq!(projection.validations.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.head(), head);
    }
}

#[test]
fn a_different_observed_snapshot_is_terminally_stale_before_object_validation() {
    for synchronous in [false, true] {
        let mut fixture = Fixture::new();
        fixture.intent = fixture.intent.clone().with_workspace_snapshot([41; 32]);
        let projection = WorkspaceProjection::new(&fixture, [42; 32]);
        let refused = run_native(&fixture, &projection, synchronous).unwrap();
        assert!(matches!(
            refused.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        let head = fixture.head();
        assert_eq!(head.ref_root, fixture.genesis.ref_root);
        assert_eq!(
            head.forge_position_root,
            fixture.genesis.forge_position_root
        );
        assert_eq!(head.outbox_root, fixture.genesis.outbox_root);
        assert_eq!(projection.observations.load(Ordering::SeqCst), 1);
        assert_eq!(projection.validations.load(Ordering::SeqCst), 0);
        *projection.observed.lock().unwrap() = [41; 32];
        assert_eq!(
            run_native(&fixture, &projection, synchronous).unwrap(),
            refused
        );
        assert_eq!(projection.observations.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.head(), head);
    }
}

#[test]
fn losing_cas_rechecks_the_workspace_at_the_next_authenticated_basis() {
    for synchronous in [false, true] {
        let mut fixture = Fixture::new();
        let competing_intent = fixture.intent.clone();
        fixture.intent = fixture.intent.clone().with_workspace_snapshot([41; 32]);
        let projection = Arc::new(WorkspaceProjection::new(&fixture, [41; 32]));
        let mut competing_context = fixture.context.clone();
        competing_context.idempotency_key =
            IdempotencyKey::new(b"workspace-replan-winner".to_vec()).unwrap();
        let competing_projection = fixture.projection(&competing_context);
        let store = fixture.store.clone();
        let observation = projection.clone();
        *fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
            let winner = poll_ready(admit_native_merge_async(
                store.as_ref(),
                &(),
                &competing_context,
                &competing_intent,
                AdmissionLimits::default(),
                &competing_projection,
            ))
            .unwrap();
            assert!(matches!(winner.outcome, DecisionOutcome::Committed { .. }));
            *observation.observed.lock().unwrap() = [42; 32];
        }));

        let refused = run_native(&fixture, projection.as_ref(), synchronous).unwrap();
        assert!(matches!(
            refused.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        assert_eq!(projection.observations.load(Ordering::SeqCst), 2);
        assert_eq!(projection.validations.load(Ordering::SeqCst), 1);
        let head = fixture.head();
        let basis = PublicationBasis::new(
            fgit_authority::authority_head_identity(&head).unwrap(),
            head,
        );
        let selected = poll_ready(delivery::read_in(
            fixture.store.as_ref(),
            &(),
            &basis,
            &|| false,
        ))
        .unwrap();
        assert_eq!(selected.outbox.entries().len(), 1);
        assert_ne!(selected.outbox.entries()[0].tx_id(), fixture.tx_id());
        assert_eq!(
            fixture.outcome(fixture.tx_id()),
            OutcomeLookup::Decided(refused)
        );
    }
}

#[test]
fn original_package_workspace_profile_uses_augmented_evidence_in_the_same_sync_async_core() {
    let mut heads = Vec::new();
    for synchronous in [false, true] {
        let fixture = Fixture::new();
        let sealed = sealed_native_fixture_with_workspace(&fixture, Some([51; 32]));
        let bound =
            workspace_seal_attempt_for(&fixture.context, &sealed.borrowed(), [51; 32]).unwrap();
        let original = seal_attempt_for(&fixture.context, &sealed.borrowed()).unwrap();
        assert_ne!(bound.derive().unwrap().0, original.derive().unwrap().0);
        let projection = WorkspaceProjection::new(&fixture, [51; 32]);
        let run = || {
            if synchronous {
                admit_workspace_sealed_native_merge(
                    &SyncModel(&fixture.store),
                    &fixture.context,
                    &sealed.borrowed(),
                    [51; 32],
                    AdmissionLimits::default(),
                    &projection,
                )
            } else {
                poll_ready(admit_workspace_sealed_native_merge_async(
                    fixture.store.as_ref(),
                    &(),
                    &fixture.context,
                    &sealed.borrowed(),
                    [51; 32],
                    AdmissionLimits::default(),
                    &projection,
                ))
            }
        };
        let committed = run().unwrap();
        assert!(matches!(
            committed.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let tx_id = bound.derive().unwrap().0;
        assert_eq!(fixture.outcome(tx_id), OutcomeLookup::Decided(committed));
        let head = fixture.head();
        assert_ne!(head.ref_root, fixture.genesis.ref_root);
        assert_ne!(
            head.forge_position_root,
            fixture.genesis.forge_position_root
        );
        assert_ne!(head.outbox_root, fixture.genesis.outbox_root);
        let basis = PublicationBasis::new(
            fgit_authority::authority_head_identity(&head).unwrap(),
            head.clone(),
        );
        let delivered = poll_ready(delivery::read_in(
            fixture.store.as_ref(),
            &(),
            &basis,
            &|| false,
        ))
        .unwrap();
        assert_eq!(delivered.outbox.entries().len(), 1);
        assert_eq!(delivered.outbox.entries()[0].tx_id(), tx_id);
        *projection.observed.lock().unwrap() = [52; 32];
        assert_eq!(run().unwrap(), committed);
        assert_eq!(projection.observations.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.head(), head);
        heads.push(head);
    }
    assert_eq!(
        heads[0], heads[1],
        "both facades publish the same canonical head"
    );
}

//! Exact-head authorization must survive the async driver's object-authority
//! reuse optimization. These tests use the parent suite's canonical projection
//! and real seal, publication, outcome and CAS-replan paths.

use super::*;
use std::future::ready;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fgit_admission::{
    BasisBoundValidatedReceive, ReceiveValidationAuthority,
    admit_basis_bound_validated_receive_async, validate_receive_at_basis,
};
use fgit_codec::{CryptoBodyIdentity, body_id};
use fgit_types::RepositoryAuthorityHeadId;

fn current_basis(
    store: &MemoryAuthorityStore,
    context: &AdmissionContext,
) -> (PublicationBasis, AuthenticatedHead) {
    let HeadRead::Present(receipt) = store
        .read_head(&context.head_key)
        .expect("the canonical head reads")
    else {
        panic!("the fixture has an initialized head");
    };
    let authenticated = store
        .authenticate_head_receipt(&receipt)
        .expect("the store authenticates its own head receipt");
    let body = authenticated
        .body()
        .expect("the authenticated head decodes");
    let internal = body_id(&CryptoBodyIdentity, &body).expect("canonical head identity");
    let id = RepositoryAuthorityHeadId::from_internal_object_id(internal)
        .expect("the body has a repository head identity");
    (PublicationBasis::new(id, body), authenticated)
}

fn validation_authority(
    basis: &PublicationBasis,
    snapshot: &AdmissionSnapshot,
) -> ReceiveValidationAuthority {
    let empty_closure = PermittedObjectClosure::new(BTreeSet::new());
    let root = permitted_object_closure_root(&empty_closure).expect("empty closure root");
    let visible_roots = snapshot.refs.values().copied().collect();
    ReceiveValidationAuthority::new(basis, &root, &visible_roots)
}

struct CommittedValidator(ReceiveValidationAuthority);

impl QuarantineValidator for CommittedValidator {
    fn validate(
        &self,
        request: &ReceiveRequest,
        pack: Option<&fgit_pack::QuarantinedPack>,
        receipt: &QuarantineReceipt,
        deadline: &mut impl fgit_pack::Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        DeleteOnlyValidator.validate(request, pack, receipt, deadline)
    }

    fn validation_authority(&self) -> Option<ReceiveValidationAuthority> {
        Some(self.0)
    }
}

/// The unrelated transaction is refused because it names the wrong ref
/// predecessor. Its canonical decision advances the head while preserving the
/// ref state, object authority and policy that the receive validator used.
fn advance_head_without_changing_validation(
    store: &MemoryAuthorityStore,
    projection: &CanonicalAdmissionProjection<StagingStore, StubEvidence>,
) {
    let valid = delete_main();
    let mut request = valid.request().clone();
    request.commands[0].old = oid(OTHER_OID);
    let wrong_predecessor = validate_receive(
        &request,
        None,
        valid.receipt(),
        &DeleteOnlyValidator,
        &mut live_deadline(),
    )
    .expect("the rival delete is structurally valid");
    let result = admit_validated_receive(
        store,
        &context(b"exact-basis-unrelated-refusal"),
        &wrong_predecessor,
        AdmissionLimits::default(),
        projection,
    )
    .expect("the rival reaches a canonical terminal decision");
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::ExpectedOldRefMismatch,
            ..
        }
    ));
}

/// Reports the validation authority actually observed by each snapshot. The
/// optional one-shot rival runs after the initial snapshot, forcing a lost CAS
/// without changing the validator's object authority.
struct EquivalentAuthorityProjection {
    inner: CanonicalAdmissionProjection<StagingStore, StubEvidence>,
    observed: Mutex<Option<(RepositoryAuthorityHeadId, ReceiveValidationAuthority)>>,
    snapshots: AtomicUsize,
    race: AtomicBool,
    raced: AtomicBool,
}

impl EquivalentAuthorityProjection {
    fn new(inner: CanonicalAdmissionProjection<StagingStore, StubEvidence>, race: bool) -> Self {
        Self {
            inner,
            observed: Mutex::new(None),
            snapshots: AtomicUsize::new(0),
            race: AtomicBool::new(race),
            raced: AtomicBool::new(false),
        }
    }
}

impl AsyncAdmissionProjection<AsyncView> for EquivalentAuthorityProjection {
    fn snapshot_async<'a>(
        &'a self,
        authority: &'a AsyncView,
        _cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, AsyncProjectionFailure>> + Send + 'a {
        self.snapshots.fetch_add(1, Ordering::SeqCst);
        let snapshot = self
            .inner
            .snapshot(basis, authenticated)
            .map_err(AsyncProjectionFailure::Refuse);
        if let Ok(snapshot) = &snapshot {
            *self.observed.lock().expect("fixture authority lock") =
                Some((basis.id(), validation_authority(basis, snapshot)));
        }
        if self.race.swap(false, Ordering::SeqCst) {
            advance_head_without_changing_validation(&authority.0, &self.inner);
            self.raced.store(true, Ordering::SeqCst);
        }
        ready(snapshot)
    }

    fn materialize_commit_async<'a>(
        &'a self,
        _authority: &'a AsyncView,
        _cx: &'a (),
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a fgit_txn::TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, AsyncProjectionFailure>> + Send + 'a
    {
        ready(self.inner.materialize_commit(basis, request, fold, closure))
    }

    fn materialize_refusal_async<'a>(
        &'a self,
        _authority: &'a AsyncView,
        _cx: &'a (),
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, AsyncProjectionFailure>> + Send + 'a
    {
        ready(
            self.inner
                .materialize_refusal(basis, tx_id, code)
                .map_err(AsyncProjectionFailure::Refuse),
        )
    }

    fn validation_authority(&self, basis: &PublicationBasis) -> Option<ReceiveValidationAuthority> {
        self.observed
            .lock()
            .expect("fixture authority lock")
            .filter(|(head, _)| *head == basis.id())
            .map(|(_, authority)| authority)
    }
}

fn bound_receive(
    store: &MemoryAuthorityStore,
    context: &AdmissionContext,
    projection: &EquivalentAuthorityProjection,
) -> BasisBoundValidatedReceive {
    let (basis, authenticated) = current_basis(store, context);
    let snapshot = projection
        .inner
        .snapshot(&basis, &authenticated)
        .expect("the real canonical ref snapshot opens");
    let validator = CommittedValidator(validation_authority(&basis, &snapshot));
    let valid = delete_main();
    validate_receive_at_basis(
        valid.request(),
        None,
        valid.receipt(),
        &basis,
        &validator,
        &mut live_deadline(),
    )
    .expect("the receive binds its original validation authority")
}

fn admit(
    view: &AsyncView,
    context: &AdmissionContext,
    proof: &BasisBoundValidatedReceive,
    projection: &EquivalentAuthorityProjection,
) -> AdmissionResult {
    poll_ready(admit_basis_bound_validated_receive_async(
        view,
        &(),
        context,
        proof,
        AdmissionLimits::default(),
        projection,
    ))
    .expect("the receive reaches a canonical terminal decision")
}

fn assert_outcome(result: &AdmissionResult, strict_refusal: bool) {
    assert!(result.session.atomic);
    assert_eq!(result.commands.len(), 1);
    if strict_refusal {
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::AuthorityReceiptStale,
                ..
            }
        ));
    } else {
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
    }
}

#[test]
fn exact_basis_commits_when_fresh_and_recovers_its_terminal_before_freshness() {
    let context = context(b"exact-basis-fresh-and-retry");
    let (store, canonical) = setup(&context, Basis::NamedPredecessor);
    let projection = EquivalentAuthorityProjection::new(canonical, false);
    let original = bound_receive(&store, &context, &projection);
    let exact = original.clone().requiring_exact_publication_basis();
    assert!(original.validation_authority().is_some());
    assert_eq!(exact.validation_authority(), None);
    assert_eq!(exact.validation_basis(), original.validation_basis());
    assert_eq!(exact.request(), original.request());

    let view = AsyncView(store);
    let result = admit(&view, &context, &exact, &projection);
    assert_outcome(&result, false);
    let head = view.0.read_head(&context.head_key).expect("committed head");
    assert_ne!(
        current_basis(&view.0, &context).0.id(),
        exact.validation_basis()
    );
    let retry = admit(&view, &context, &exact, &projection);
    assert_eq!(retry, result);
    assert_eq!(
        view.0.read_head(&context.head_key).expect("retry head"),
        head
    );
    assert_eq!(projection.snapshots.load(Ordering::SeqCst), 1);
}

#[test]
fn exact_basis_refuses_a_changed_head_even_when_validation_authority_is_unchanged() {
    for strict in [false, true] {
        let context = context(b"exact-basis-stale-equivalent-authority");
        let (store, canonical) = setup(&context, Basis::NamedPredecessor);
        let projection = EquivalentAuthorityProjection::new(canonical, false);
        let original = bound_receive(&store, &context, &projection);
        advance_head_without_changing_validation(&store, &projection.inner);
        let (basis, authenticated) = current_basis(&store, &context);
        let snapshot = projection
            .inner
            .snapshot(&basis, &authenticated)
            .expect("the successor still selects the canonical refs");
        assert_ne!(basis.id(), original.validation_basis());
        assert_eq!(
            Some(validation_authority(&basis, &snapshot)),
            original.validation_authority()
        );
        let proof = if strict {
            original.requiring_exact_publication_basis()
        } else {
            original
        };
        let view = AsyncView(store);
        let result = admit(&view, &context, &proof, &projection);
        assert_outcome(&result, strict);
        assert_eq!(
            projection.snapshots.load(Ordering::SeqCst),
            usize::from(!strict)
        );

        let (basis, authenticated) = current_basis(&view.0, &context);
        let after = projection.inner.snapshot(&basis, &authenticated).unwrap();
        assert_eq!(
            after.refs.get(&RefName::try_new(MAIN_REF).unwrap()),
            strict.then(|| oid(MAIN_OID)).as_ref()
        );
    }
}

#[test]
fn exact_basis_refuses_the_cas_replan_while_equivalent_authority_can_reuse() {
    for strict in [false, true] {
        let context = context(b"exact-basis-cas-replan");
        let (store, canonical) = setup(&context, Basis::NamedPredecessor);
        let projection = EquivalentAuthorityProjection::new(canonical, true);
        let original = bound_receive(&store, &context, &projection);
        let proof = if strict {
            original.requiring_exact_publication_basis()
        } else {
            original
        };
        let view = AsyncView(store);
        let result = admit(&view, &context, &proof, &projection);
        assert!(projection.raced.load(Ordering::SeqCst));
        assert_outcome(&result, strict);
        assert_eq!(
            projection.snapshots.load(Ordering::SeqCst),
            if strict { 1 } else { 2 }
        );

        let head = view.0.read_head(&context.head_key).unwrap();
        assert_eq!(admit(&view, &context, &proof, &projection), result);
        assert_eq!(view.0.read_head(&context.head_key).unwrap(), head);
    }
}

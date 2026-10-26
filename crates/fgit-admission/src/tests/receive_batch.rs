//! Microbatch decision semantics against the existing sequential driver.
//! These are authority/model tests: native pack and transport evidence belongs
//! to the node suites. The canonical materializer and publication code are real.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fgit_authority::{
    AmbiguityReason, AsyncAuthorityStore, AuthorityLimits, CasOutcome, DuplicateAbsenceWitness,
    HeadInit, ImmutableKey, ImmutableRead, PutOutcome,
};

#[derive(Clone, Default)]
struct SharedCanonical {
    refs: Arc<Mutex<BTreeMap<Digest, CanonicalRefState>>>,
    closures: Arc<Mutex<BTreeMap<Digest, PermittedObjectClosure>>>,
    hidden: Arc<Mutex<RefVisibility>>,
}

impl CanonicalAdmissionStore for SharedCanonical {
    fn resolve_ref_state(&self, root: Digest) -> Result<CanonicalRefState, RefusalCode> {
        self.refs
            .lock()
            .unwrap()
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }
    fn stage_ref_state(&self, root: Digest, state: CanonicalRefState) -> Result<(), RefusalCode> {
        self.refs.lock().unwrap().insert(root, state);
        Ok(())
    }
    fn resolve_permitted_object_closure(
        &self,
        root: Digest,
    ) -> Result<PermittedObjectClosure, RefusalCode> {
        self.closures
            .lock()
            .unwrap()
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }
    fn stage_permitted_object_closure(
        &self,
        root: Digest,
        closure: PermittedObjectClosure,
    ) -> Result<(), RefusalCode> {
        self.closures.lock().unwrap().insert(root, closure);
        Ok(())
    }
    fn resolve_hidden_ref_policy(&self, _root: Digest) -> Result<RefVisibility, RefusalCode> {
        Ok(self.hidden.lock().unwrap().clone())
    }
}

struct Race {
    context: AdmissionContext,
    request: ValidatedReceive,
    staging: SharedCanonical,
    after_publication: bool,
}

impl Race {
    fn publish(self, store: &MemoryAuthorityStore) {
        let projection = CanonicalAdmissionProjection::new(self.staging, CanonicalFixtureEvidence);
        admit_validated_receive(
            store,
            &self.context,
            &self.request,
            AdmissionLimits::default(),
            &projection,
        )
        .expect("the competing real transaction publishes");
    }
}

struct AsyncMemory {
    inner: MemoryAuthorityStore,
    publications: AtomicUsize,
    lose_response: AtomicBool,
    race: Mutex<Option<Race>>,
    put_calls: AtomicUsize,
    interrupt_put_at: AtomicUsize,
    lose_put_response_at: AtomicUsize,
    immutable_created: AtomicUsize,
    immutable_reads: AtomicUsize,
    head_reads: AtomicUsize,
}

impl AsyncAuthorityStore for AsyncMemory {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId {
        self.inner.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.inner.limits()
    }
    fn put_if_absent(
        &self,
        _: &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        let ordinal = self.put_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if ordinal == self.interrupt_put_at.load(Ordering::SeqCst) {
            return std::future::ready(Err(AuthorityFailure::Ambiguous(
                AmbiguityReason::NoResponse,
            )));
        }
        let result = self.inner.put_if_absent(key, body);
        if matches!(result, Ok(PutOutcome::Created)) {
            self.immutable_created.fetch_add(1, Ordering::SeqCst);
        }
        std::future::ready(
            if ordinal == self.lose_put_response_at.load(Ordering::SeqCst) && result.is_ok() {
                Err(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse))
            } else {
                result
            },
        )
    }
    fn read_immutable(
        &self,
        _: &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        self.immutable_reads.fetch_add(1, Ordering::SeqCst);
        std::future::ready(self.inner.read_immutable(key))
    }
    fn initialize_head(
        &self,
        _: &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        std::future::ready(self.inner.initialize_head(key, generation, body))
    }
    fn read_head(
        &self,
        _: &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        self.head_reads.fetch_add(1, Ordering::SeqCst);
        std::future::ready(self.inner.read_head(key))
    }
    fn compare_exchange_head(
        &self,
        _: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        std::future::ready(
            self.inner
                .compare_exchange_head(key, expected, generation, body),
        )
    }
    fn publish_head_with_outcomes(
        &self,
        _: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        self.publications.fetch_add(1, Ordering::SeqCst);
        let after = match self.race.lock().unwrap().take() {
            Some(race) if !race.after_publication => {
                race.publish(&self.inner);
                None
            }
            after => after,
        };
        let result = self
            .inner
            .publish_head_with_outcomes(key, expected, generation, body, outcomes, witness);
        if matches!(result, Ok(CasOutcome::Committed(_))) {
            self.immutable_created
                .fetch_add(outcomes.len(), Ordering::SeqCst);
        }
        if let (Some(race), Ok(CasOutcome::Committed(_))) = (after, &result) {
            race.publish(&self.inner);
        }
        std::future::ready(
            if self.lose_response.swap(false, Ordering::SeqCst) && result.is_ok() {
                Err(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse))
            } else {
                result
            },
        )
    }
    fn authenticate_head_receipt(
        &self,
        _: &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::ready(self.inner.authenticate_head_receipt(receipt))
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("the reference store only returns ready futures"),
    }
}

struct Projection {
    inner: CanonicalAdmissionProjection<SharedCanonical, CanonicalFixtureEvidence>,
    snapshots: AtomicUsize,
    materializations: AtomicUsize,
    interrupt_at: AtomicUsize,
    protected: Option<RefName>,
    equivalent_authority: bool,
    authority_tracks_refs: bool,
}

impl Projection {
    fn check(&self, request: &TransactionRequest) -> Result<(), ProjectionFailure> {
        let ordinal = self.materializations.fetch_add(1, Ordering::SeqCst) + 1;
        if ordinal == self.interrupt_at.load(Ordering::SeqCst) {
            return Err(ProjectionFailure::Unavailable(
                RefusalCode::CancellationInProgress,
            ));
        }
        if self.protected.as_ref().is_some_and(|name| {
            request
                .statements
                .iter()
                .flat_map(|statement| &statement.intents)
                .any(|intent| match intent {
                    Intent::Ref(
                        RefIntent::Update { name: target, .. }
                        | RefIntent::Delete { name: target, .. },
                    ) => name == target,
                    _ => false,
                })
        }) {
            return Err(ProjectionFailure::Refuse(
                RefusalCode::ProtectedRefTransitionDenied,
            ));
        }
        Ok(())
    }
}

impl AdmissionSnapshotProjection for Projection {
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        head: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode> {
        self.inner.snapshot(basis, head)
    }
}
impl AdmissionProjection for Projection {
    // Keep the existing sequential driver as the oracle even though the inner
    // canonical materializer also supports the new blocking microbatch path.
    fn supports_ref_microbatching(&self) -> bool {
        false
    }

    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure> {
        self.check(request)?;
        self.inner.materialize_commit(basis, request, fold, closure)
    }
    fn materialize_refusal(
        &self,
        basis: &PublicationBasis,
        tx: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        self.inner.materialize_refusal(basis, tx, code)
    }
}
impl AsyncAdmissionProjection<AsyncMemory> for Projection {
    fn supports_ref_microbatching(&self) -> bool {
        true
    }
    fn validation_authority(&self, basis: &PublicationBasis) -> Option<ReceiveValidationAuthority> {
        if !self.equivalent_authority {
            return None;
        }
        if self.authority_tracks_refs {
            let state = self.inner.resolve_ref_state(basis.body().ref_root).unwrap();
            return Some(ReceiveValidationAuthority::new(
                basis,
                &digest(42),
                &state.refs().values().copied().collect(),
            ));
        }
        // Other model cases permit the same fixed bodies regardless of ref
        // moves. A distinct test omits its commitment and requires stale refusal.
        Some(ReceiveValidationAuthority([42; 32]))
    }
    async fn snapshot_async<'a>(
        &'a self,
        _: &'a AsyncMemory,
        _: &'a (),
        basis: &'a PublicationBasis,
        head: &'a AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, ProjectionFailure> {
        self.snapshots.fetch_add(1, Ordering::SeqCst);
        self.snapshot(basis, head)
            .map_err(ProjectionFailure::Refuse)
    }
    async fn materialize_commit_async<'a>(
        &'a self,
        _: &'a AsyncMemory,
        _: &'a (),
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure> {
        self.materialize_commit(basis, request, fold, closure)
    }
    async fn materialize_batch_commit_async<'a>(
        &'a self,
        _: &'a AsyncMemory,
        _: &'a (),
        state: &'a crate::microbatch::BatchRefState,
        request: &'a TransactionRequest,
        fold: &'a TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure> {
        self.check(request)?;
        crate::microbatch::materialize_canonical(
            &self.inner,
            state.basis(),
            state.refs().clone(),
            request,
            fold,
            closure,
        )
    }
    async fn materialize_refusal_async<'a>(
        &'a self,
        _: &'a AsyncMemory,
        _: &'a (),
        basis: &'a PublicationBasis,
        tx: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, ProjectionFailure> {
        self.materialize_refusal(basis, tx, code)
            .map_err(ProjectionFailure::Refuse)
    }
}

fn setup(initial: &[(&[u8], u8)]) -> (AsyncMemory, SharedCanonical, Projection) {
    let staging = SharedCanonical::default();
    let state = CanonicalRefState::new(
        initial
            .iter()
            .map(|(name, seed)| (RefName::try_new(name).unwrap(), oid(*seed)))
            .collect(),
    );
    let root = canonical_ref_state_root(&state).unwrap();
    staging.stage_ref_state(root, state).unwrap();
    let inner = MemoryAuthorityStore::new(StoreInstanceId::from_raw(112));
    initialize_repository(
        &inner,
        &context().head_key,
        &RepositoryAuthorityHeadBody {
            ref_root: root,
            ..genesis(&context())
        },
    )
    .unwrap();
    let projection = Projection {
        inner: CanonicalAdmissionProjection::new(staging.clone(), CanonicalFixtureEvidence),
        snapshots: AtomicUsize::new(0),
        materializations: AtomicUsize::new(0),
        interrupt_at: AtomicUsize::new(0),
        protected: None,
        equivalent_authority: true,
        authority_tracks_refs: false,
    };
    (
        AsyncMemory {
            inner,
            publications: AtomicUsize::new(0),
            lose_response: AtomicBool::new(false),
            race: Mutex::new(None),
            put_calls: AtomicUsize::new(0),
            interrupt_put_at: AtomicUsize::new(0),
            lose_put_response_at: AtomicUsize::new(0),
            immutable_created: AtomicUsize::new(0),
            immutable_reads: AtomicUsize::new(0),
            head_reads: AtomicUsize::new(0),
        },
        staging,
        projection,
    )
}
fn command(name: &str, old: u8, new: u8) -> ReceiveCommand {
    ReceiveCommand {
        old: oid(old),
        new: oid(new),
        ref_name: name.as_bytes().to_vec(),
    }
}
fn validated(
    store: &AsyncMemory,
    commands: Vec<ReceiveCommand>,
    equivalent: bool,
) -> BasisBoundValidatedReceive {
    let mut receive = completion(commands, false);
    receive.closure.object_closure_root = permitted_object_closure_root(
        &PermittedObjectClosure::new(receive.closure.objects.clone()),
    )
    .unwrap();
    receive.receipt.delete_only = receive.request.deletes_only();
    receive.receipt.object_count = receive.closure.objects.len() as u32;
    if receive.receipt.delete_only {
        receive.receipt.pack_bytes = 0;
    }
    BasisBoundValidatedReceive {
        validated: receive,
        validation_basis: read_basis(&store.inner, &context().head_key)
            .unwrap()
            .0
            .id(),
        validation_authority: equivalent.then_some(ReceiveValidationAuthority([42; 32])),
    }
}
fn current_refs(store: &AsyncMemory, staging: &SharedCanonical) -> BTreeMap<RefName, GitOid> {
    let basis = read_basis(&store.inner, &context().head_key).unwrap().0;
    staging
        .resolve_ref_state(basis.body().ref_root)
        .unwrap()
        .refs()
        .clone()
}
fn run(
    store: &AsyncMemory,
    projection: &Projection,
    receive: &BasisBoundValidatedReceive,
) -> Result<AdmissionResult, crate::policy_bridge::receive_session::InterruptedSession> {
    ready(crate::policy_bridge::receive_session::admit(
        store,
        &(),
        &context(),
        receive,
        AdmissionLimits::default(),
        projection,
    ))
}

#[test]
fn wire_ordered_mixed_batch_matches_sequential_ref_decisions_and_uses_one_cas() {
    let initial: &[(&[u8], u8)] = &[
        (b"refs/heads/tree", 1),
        (b"refs/heads/stale", 3),
        (b"refs/heads/removed", 4),
    ];
    let commands = vec![
        command("refs/heads/absent", 0, 0),
        command("refs/heads/tree", 1, 0),
        command("refs/heads/tree/child", 0, 2),
        command("refs/heads/stale", 9, 0),
        command("refs/heads/removed", 4, 0),
        command("refs/heads/protected", 0, 2),
        command("refs/private/secret", 0, 0),
        command("refs/heads/last", 0, 2),
    ];
    let (batched, staged, mut projection) = setup(initial);
    projection.protected = Some(RefName::try_new(b"refs/heads/protected").unwrap());
    staged
        .hidden
        .lock()
        .unwrap()
        .push_rule(b"refs/private", &fgit_wire::WireLimits::default())
        .unwrap();
    let receive = validated(&batched, commands.clone(), true);
    let result = run(&batched, &projection, &receive).unwrap();

    let (sequential, reference_staged, mut reference) = setup(initial);
    reference.protected = projection.protected.clone();
    *reference_staged.hidden.lock().unwrap() = staged.hidden.lock().unwrap().clone();
    let sequential_receive = validated(&sequential, commands, true);
    let expected = admit_validated_receive(
        &sequential.inner,
        &context(),
        &sequential_receive.validated,
        AdmissionLimits::default(),
        &reference,
    )
    .unwrap();
    assert_eq!(result.session, expected.session);
    assert_eq!(result.command_statuses(), expected.command_statuses());
    assert_eq!(
        current_refs(&batched, &staged),
        current_refs(&sequential, &reference_staged)
    );
    assert_eq!(batched.publications.load(Ordering::SeqCst), 1);
    assert_eq!(projection.snapshots.load(Ordering::SeqCst), 1);
    assert_eq!(
        result
            .command_statuses()
            .iter()
            .filter(|status| **status == ReceiveCommandStatus::Ok)
            .count(),
        5
    );
    let head = read_basis(&batched.inner, &context().head_key).unwrap().0;
    let batch = fgit_authority::read_decision_batch_body(
        &batched.inner,
        head.body().decision_tail_id.unwrap(),
    )
    .unwrap();
    assert_eq!(batch.decisions.len(), commands_len(&receive));
    assert_eq!(batch.committed_rcrs.len(), 5);
    for command in &result.commands {
        let OutcomeLookup::Decided(terminal) = resolve_outcome(
            &batched.inner,
            &context().head_key,
            context().tenant_id,
            context().repository_id,
            command.tx_id,
        )
        .unwrap() else {
            panic!("batch decision must resolve")
        };
        assert_eq!(terminal, command.terminal);
    }
    let first_head = head.id();
    assert_eq!(run(&batched, &projection, &receive).unwrap(), result);
    assert_eq!(
        read_basis(&batched.inner, &context().head_key)
            .unwrap()
            .0
            .id(),
        first_head
    );
}

fn commands_len(receive: &BasisBoundValidatedReceive) -> usize {
    receive.request().commands.len()
}

#[test]
fn oversized_descriptor_refuses_before_binding_keys_and_a_smaller_retry_can_publish() {
    let (store, staging, projection) = setup(&[]);
    let commands = (0..1024)
        .map(|index| {
            let name = format!("refs/heads/{index:04}-{}", "n".repeat(1008));
            assert_eq!(name.len(), fgit_types::MAX_REF_NAME_LEN);
            command(&name, 0, 1)
        })
        .collect();
    let receive = validated(&store, commands, false);
    let before = read_basis(&store.inner, &context().head_key).unwrap().0;
    let error = run(&store, &projection, &receive).unwrap_err();
    assert!(matches!(
        error.admission_error(),
        AdmissionError::SessionDescriptorBytesExceeded { limit, observed }
            if *limit == 1024 * 1024 && observed > limit
    ));
    assert!(error.completed_commands().is_empty());
    assert_eq!(store.publications.load(Ordering::SeqCst), 0);
    assert_eq!(
        read_basis(&store.inner, &context().head_key).unwrap().0,
        before
    );
    assert!(current_refs(&store, &staging).is_empty());
    let context = context();
    let keys = [
        context.idempotency_key.clone(),
        crate::non_atomic_key(&context.idempotency_key, 0).unwrap(),
        crate::non_atomic_key(&context.idempotency_key, 1023).unwrap(),
    ];
    for key in keys {
        let binding = fgit_authority::idempotency_binding_key(
            context.tenant_id,
            context.repository_id,
            context.principal_id,
            &key,
        )
        .unwrap();
        assert!(matches!(
            store.inner.read_immutable(&binding).unwrap(),
            ImmutableRead::Absent
        ));
    }
    // No key was reserved: the original client key can now carry a request
    // that fits, with its normal descriptor and unchanged admission identities.
    let allowed = validated(&store, vec![command("refs/heads/permitted", 0, 1)], false);
    let result = run(&store, &projection, &allowed).unwrap();
    assert_eq!(result.command_statuses(), vec![ReceiveCommandStatus::Ok]);
    assert_eq!(current_refs(&store, &staging).len(), 1);
    assert_eq!(run(&store, &projection, &allowed).unwrap(), result);
    assert_eq!(store.publications.load(Ordering::SeqCst), 1);
}

#[test]
fn multiple_chunks_continue_over_their_own_authenticated_batches() {
    let (store, staging, projection) = setup(&[]);
    let receive = validated(
        &store,
        (0..130)
            .map(|n| command(&format!("refs/heads/r{n:03}"), 0, 1))
            .collect(),
        false,
    );
    let result = run(&store, &projection, &receive).unwrap();
    assert!(
        result
            .command_statuses()
            .iter()
            .all(|status| *status == ReceiveCommandStatus::Ok)
    );
    assert_eq!(current_refs(&store, &staging).len(), 130);
    assert_eq!(store.publications.load(Ordering::SeqCst), 3);
    assert_eq!(projection.snapshots.load(Ordering::SeqCst), 3);
}

#[test]
fn cancelled_later_chunk_keeps_the_verified_prefix_and_retry_recovers_it() {
    for count in [65_usize, 130] {
        let (store, staging, projection) = setup(&[]);
        let completed = (count - 1) / 64 * 64;
        projection
            .interrupt_at
            .store(completed + 1, Ordering::SeqCst);
        let commands: Vec<_> = (0..count)
            .map(|n| command(&format!("refs/heads/r{n:03}"), 0, 1))
            .collect();
        let receive = validated(&store, commands.clone(), false);
        let error = run(&store, &projection, &receive).unwrap_err();
        assert_eq!(error.completed_commands().len(), completed);
        assert_eq!(current_refs(&store, &staging).len(), completed);
        assert_eq!(store.publications.load(Ordering::SeqCst), completed / 64);
        // The original validation witness is still at genesis. Recovering our
        // exact earlier batches must advance it to the unfinished final chunk.
        let retried = run(&store, &projection, &receive).unwrap();
        assert_eq!(&retried.commands[..completed], error.completed_commands());
        assert!(
            retried
                .command_statuses()
                .iter()
                .all(|status| *status == ReceiveCommandStatus::Ok)
        );
        assert_eq!(current_refs(&store, &staging).len(), count);
        assert_eq!(
            store.publications.load(Ordering::SeqCst),
            completed / 64 + 1
        );
        assert_eq!(
            run(&store, &projection, &validated(&store, commands, false)).unwrap(),
            retried
        );
    }
}

#[test]
fn cancellation_during_first_chunk_publishes_none_and_a_lost_response_still_recovers() {
    let (store, staging, projection) = setup(&[]);
    projection.interrupt_at.store(2, Ordering::SeqCst);
    let receive = validated(
        &store,
        vec![command("refs/heads/a", 0, 1), command("refs/heads/b", 0, 2)],
        true,
    );
    let error = run(&store, &projection, &receive).unwrap_err();
    assert!(error.completed_commands().is_empty());
    assert!(current_refs(&store, &staging).is_empty());
    assert_eq!(store.publications.load(Ordering::SeqCst), 0);
    store.lose_response.store(true, Ordering::SeqCst);
    assert!(run(&store, &projection, &receive).is_err());
    assert_eq!(current_refs(&store, &staging).len(), 2);
    let result = run(&store, &projection, &receive).unwrap();
    assert!(
        result
            .command_statuses()
            .iter()
            .all(|status| *status == ReceiveCommandStatus::Ok)
    );
    assert_eq!(
        store.publications.load(Ordering::SeqCst),
        1,
        "lost response retry must not publish any second decisions"
    );
}

#[test]
fn a_lost_cas_replans_under_the_original_validation_authority() {
    for equivalent in [false, true] {
        let (store, staging, mut projection) = setup(&[]);
        projection.equivalent_authority = equivalent;
        let receive = validated(
            &store,
            vec![command("refs/heads/a", 0, 1), command("refs/heads/b", 0, 2)],
            equivalent,
        );
        let mut raced =
            validated(&store, vec![command("refs/heads/racer", 0, 3)], equivalent).validated;
        raced.request.capabilities.push(Capability {
            name: b"atomic".to_vec(),
            value: None,
        });
        *store.race.lock().unwrap() = Some(Race {
            context: AdmissionContext {
                idempotency_key: IdempotencyKey::new(b"competing-session".to_vec()).unwrap(),
                ..context()
            },
            request: raced,
            staging: staging.clone(),
            after_publication: false,
        });
        let result = run(&store, &projection, &receive).unwrap();
        assert_eq!(store.publications.load(Ordering::SeqCst), 2);
        assert!(
            current_refs(&store, &staging)
                .contains_key(&RefName::try_new(b"refs/heads/racer").unwrap())
        );
        for outcome in &result.commands {
            match (equivalent, outcome.terminal.outcome) {
                (true, DecisionOutcome::Committed { .. }) => {}
                (
                    false,
                    DecisionOutcome::Refused {
                        code: RefusalCode::AuthorityReceiptStale,
                        ..
                    },
                ) => {}
                other => panic!("foreign basis must retain the validator guard: {other:?}"),
            }
        }
    }
}

#[test]
fn a_foreign_successor_between_chunks_cannot_clear_the_validation_witness() {
    let (store, staging, projection) = setup(&[]);
    let receive = validated(
        &store,
        (0..129)
            .map(|n| command(&format!("refs/heads/r{n:03}"), 0, 1))
            .collect(),
        false,
    );
    *store.race.lock().unwrap() = Some(Race {
        context: AdmissionContext {
            idempotency_key: IdempotencyKey::new(b"between-chunks".to_vec()).unwrap(),
            ..context()
        },
        request: validated(&store, vec![command("refs/heads/racer", 0, 3)], false).validated,
        staging: staging.clone(),
        after_publication: true,
    });
    let result = run(&store, &projection, &receive).unwrap();
    assert!(
        result.commands[..64]
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    assert!(result.commands[64..].iter().all(|command| matches!(
        command.terminal.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::AuthorityReceiptStale,
            ..
        }
    )));
    let refs = current_refs(&store, &staging);
    assert_eq!(refs.len(), 65);
    assert!(refs.contains_key(&RefName::try_new(b"refs/heads/racer").unwrap()));
    assert!(!refs.contains_key(&RefName::try_new(b"refs/heads/r064").unwrap()));
    assert_eq!(store.publications.load(Ordering::SeqCst), 3);
}

#[test]
fn a_recovered_sequential_prefix_advances_the_original_witness_and_finishes_the_session() {
    let (store, staging, projection) = setup(&[]);
    let commands: Vec<_> = (0..65)
        .map(|n| command(&format!("refs/heads/p{n:03}"), 0, 1))
        .collect();
    let receive = validated(&store, commands.clone(), false);
    let input = basis_bound_receive_input(&receive);
    let plan = plan_session(&context(), &input, AdmissionLimits::default()).unwrap();
    let mut original = Vec::new();
    for lowered in &plan.lowered[..3] {
        original.push(
            admit_one(
                &store.inner,
                &context(),
                input.closure,
                None,
                lowered,
                &projection,
                AdmissionLimits::default(),
            )
            .unwrap(),
        );
    }
    let result = run(&store, &projection, &receive).unwrap();
    assert_eq!(
        result.commands[..3]
            .iter()
            .map(|command| command.terminal)
            .collect::<Vec<_>>(),
        original
    );
    assert!(
        result
            .command_statuses()
            .iter()
            .all(|status| *status == ReceiveCommandStatus::Ok)
    );
    assert_eq!(current_refs(&store, &staging).len(), 65);
    assert_eq!(store.publications.load(Ordering::SeqCst), 2);
}

#[test]
fn interrupted_recovery_reports_only_the_previously_authenticated_prefix() {
    let (store, staging, projection) = setup(&[]);
    let commands = vec![
        command("refs/heads/a", 0, 1),
        command("refs/heads/b", 0, 2),
        command("refs/heads/c", 0, 3),
    ];
    let receive = validated(&store, commands.clone(), false);
    let input = basis_bound_receive_input(&receive);
    let plan = plan_session(&context(), &input, AdmissionLimits::default()).unwrap();
    let first = admit_one(
        &store.inner,
        &context(),
        input.closure,
        None,
        &plan.lowered[0],
        &projection,
        AdmissionLimits::default(),
    )
    .unwrap();
    projection.interrupt_at.store(3, Ordering::SeqCst);
    let error = run(&store, &projection, &validated(&store, commands, false)).unwrap_err();
    assert_eq!(error.completed_commands().len(), 1);
    assert_eq!(error.completed_commands()[0].terminal, first);
    assert_eq!(current_refs(&store, &staging).len(), 1);
    assert_eq!(store.publications.load(Ordering::SeqCst), 0);
}

#[test]
fn an_equivalent_foreign_cas_replan_continues_own_chunks_in_the_same_attempt() {
    for count in [65_usize, 130] {
        let (store, staging, mut projection) = setup(&[]);
        projection.authority_tracks_refs = true;
        let mut receive = validated(
            &store,
            (0..count)
                .map(|n| command(&format!("refs/heads/r{n:03}"), 0, 1))
                .collect(),
            true,
        );
        let basis = read_basis(&store.inner, &context().head_key).unwrap().0;
        receive.validation_authority = projection.validation_authority(&basis);
        // This unrelated real refusal changes the head while preserving the
        // validator inputs. Our accepted first chunk then changes visible refs,
        // so its successors must use the equivalent basis recognized on replan.
        *store.race.lock().unwrap() = Some(Race {
            context: AdmissionContext {
                idempotency_key: IdempotencyKey::new(b"equivalent-foreign-refusal".to_vec())
                    .unwrap(),
                ..context()
            },
            request: validated(&store, vec![command("refs/heads/absent", 9, 0)], true).validated,
            staging: staging.clone(),
            after_publication: false,
        });
        let result = run(&store, &projection, &receive).unwrap();
        assert!(
            result.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        assert_eq!(current_refs(&store, &staging).len(), count);
        assert_eq!(
            store.publications.load(Ordering::SeqCst),
            count.div_ceil(64) + 1
        );
    }
}

#[path = "receive_batch/large_session.rs"]
mod large_session;

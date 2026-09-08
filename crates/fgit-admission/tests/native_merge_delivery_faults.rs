#![forbid(unsafe_code)]
//! Deterministic model-store faults through the production native merge driver.
//! These tests do not claim filesystem crash durability. Git identities and
//! closure validation are real; only immutable storage and scheduling use the
//! explicitly non-durable MemoryAuthorityStore lane.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use fgit_admission::evidence::{
    DecisionEvidenceBodies, RefusalEvidenceBodies, evidence_root, principal_snapshot_id,
};
use fgit_admission::merge::native::objects::{MergeObjectLimits, validate_merge_objects};
use fgit_admission::merge::native::{
    NativeMergeIntent, NativeMergeProjection, admit_native_merge_async, delivery,
    legacy_genesis_root,
};
use fgit_admission::{
    AdmissionContext, AdmissionError, AdmissionEvidence, AdmissionLimits, AdmissionProjection,
    AdmissionSnapshot, AdmissionSnapshotProjection, AsyncAdmissionProjection,
    CanonicalAdmissionProjection, CanonicalAdmissionStore, CanonicalRefState, CommitEvidence,
    CommitMaterialization, PermittedObjectClosure, ProjectionFailure, RefusalMaterialization,
    ValidatedClosure, canonical_ref_state_root,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityOpKind,
    AuthorityStore, AuthorityVersionToken, CasOutcome, DuplicateAbsenceWitness, DuplicateDelivery,
    FaultDirective, FaultKind, FaultPlan, FaultPosition, FaultableAuthorityStore, HeadInit,
    HeadKey, HeadRead, HeadReadReceipt, IdempotencyKey, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore, OutcomeLookup, PutOutcome, StoreInstanceId, TerminalOutcome,
    initialize_repository, read_decision_batch_body, resolve_outcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::{
    CanonicalBody, DecodeLimits, RepositoryAuthorityHeadBody, decode_body, encode_body,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::aggregate::{ExpectedVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEventBatch, NativeMerge};
use fgit_git_object::ObjectType;
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_reference::intent::TransactionRequest;
use fgit_types::{
    DecisionOutcome, Digest, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid,
    HeadGeneration, PolicyEpoch, PrincipalId, RefName, RefusalCode, RegistryEpoch, RepositoryId,
    TenantId, TxId,
};
use fgit_wire::visibility::RefVisibility;

const REF_NAMESPACE: &[u8] = b"frankengit/admission/ref-state/v1/";
const CLOSURE_NAMESPACE: &[u8] = b"frankengit/admission/object-closure/v1/";
const EVENT_NAMESPACE: &[u8] = b"frankengit/admission/forge-event-batch/v1/";
const POSITION_NAMESPACE: &[u8] = b"frankengit/admission/forge-position-state/v1/";

fn digest(byte: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(2).unwrap(),
        DigestBytes::try_new(&[byte; 32]).unwrap(),
    )
}

fn name(bytes: &[u8]) -> RefName {
    RefName::try_new(bytes).unwrap()
}

fn key(namespace: &[u8], repository: RepositoryId, root: Digest) -> ImmutableKey {
    ImmutableKey::new(
        [
            namespace,
            repository.as_bytes(),
            &root.algorithm().code_point().to_be_bytes(),
            root.bytes().as_bytes(),
        ]
        .concat(),
    )
    .unwrap()
}

fn poll_ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => panic!("the model authority unexpectedly suspended"),
    }
}

/// Namespace selection arms the existing fault injector immediately before the
/// real put. It does not simulate the put or its crash behavior. All effects
/// and caller responses remain owned by MemoryAuthorityStore.
struct PutFault {
    namespace: &'static [u8],
    position: FaultPosition,
}

struct Model {
    backend: MemoryAuthorityStore,
    put_fault: Mutex<Option<PutFault>>,
    interrupted_key: Mutex<Option<ImmutableKey>>,
    before_publish: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Model {
    fn new() -> Self {
        Self {
            backend: MemoryAuthorityStore::new(StoreInstanceId::from_raw(51)),
            put_fault: Mutex::new(None),
            interrupted_key: Mutex::new(None),
            before_publish: Mutex::new(None),
        }
    }

    fn put(&self, key: &ImmutableKey, body: &[u8]) -> Result<PutOutcome, AuthorityFailure> {
        let target = {
            let mut armed = self.put_fault.lock().unwrap();
            let matches = armed.as_ref().is_some_and(|target| {
                key.as_bytes().starts_with(target.namespace)
                    && (target.namespace != EVENT_NAMESPACE
                        || decode_body::<ForgeEventBatch>(body, DecodeLimits::DEFAULT).is_ok())
            });
            if matches { armed.take() } else { None }
        };
        if let Some(target) = target {
            *self.interrupted_key.lock().unwrap() = Some(key.clone());
            self.backend.install_fault_plan(FaultPlan::explicit(vec![
                FaultDirective::nth_of_kind(
                    0,
                    AuthorityOpKind::PutIfAbsent,
                    FaultKind::Crash {
                        position: target.position,
                    },
                ),
            ]));
        }
        self.backend.put_if_absent(key, body)
    }

    fn stage<B: CanonicalBody>(
        &self,
        repo: RepositoryId,
        namespace: &[u8],
        body: &B,
    ) -> Result<Digest, RefusalCode> {
        let root = evidence_root(body)?;
        let frame = encode_body(body).map_err(|_| RefusalCode::CanonicalFramingInvalid)?;
        match self
            .put(&key(namespace, repo, root), &frame)
            .map_err(|_| RefusalCode::DurabilityProfileUnavailable)?
        {
            PutOutcome::Created | PutOutcome::IdenticalRetry => Ok(root),
            PutOutcome::Conflict => Err(RefusalCode::EvidenceInvalid),
        }
    }

    fn read<B: CanonicalBody>(
        &self,
        repo: RepositoryId,
        namespace: &[u8],
        root: Digest,
    ) -> Result<B, RefusalCode> {
        let ImmutableRead::Present(frame) = self
            .backend
            .read_immutable(&key(namespace, repo, root))
            .map_err(|_| RefusalCode::DurabilityProfileUnavailable)?
        else {
            return Err(RefusalCode::EvidenceMissing);
        };
        let body = decode_body::<B>(&frame, DecodeLimits::DEFAULT)
            .map_err(|_| RefusalCode::EvidenceInvalid)?;
        if evidence_root(&body)? != root {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(body)
    }
}

/// Immediate futures expose the async protocol over the existing model store;
/// they are not a production blocking-store adapter.
impl AsyncAuthorityStore for Model {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId {
        self.backend.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.backend.limits()
    }
    fn put_if_absent(
        &self,
        _: &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        std::future::ready(self.put(key, body))
    }
    fn read_immutable(
        &self,
        _: &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        std::future::ready(self.backend.read_immutable(key))
    }
    fn initialize_head(
        &self,
        _: &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        std::future::ready(self.backend.initialize_head(key, generation, body))
    }
    fn read_head(
        &self,
        _: &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        std::future::ready(self.backend.read_head(key))
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
            self.backend
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
        let interleave = self.before_publish.lock().unwrap().take();
        if let Some(interleave) = interleave {
            interleave();
        }
        std::future::ready(
            self.backend
                .publish_head_with_outcomes(key, expected, generation, body, outcomes, witness),
        )
    }
    fn authenticate_head_receipt(
        &self,
        _: &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::ready(self.backend.authenticate_head_receipt(receipt))
    }
}

#[derive(Clone)]
struct Commitments {
    store: Arc<Model>,
    repository: RepositoryId,
}

impl CanonicalAdmissionStore for Commitments {
    fn resolve_ref_state(&self, root: Digest) -> Result<CanonicalRefState, RefusalCode> {
        self.store.read(self.repository, REF_NAMESPACE, root)
    }
    fn stage_ref_state(&self, root: Digest, state: CanonicalRefState) -> Result<(), RefusalCode> {
        if self.store.stage(self.repository, REF_NAMESPACE, &state)? != root {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(())
    }
    fn resolve_permitted_object_closure(
        &self,
        root: Digest,
    ) -> Result<PermittedObjectClosure, RefusalCode> {
        self.store.read(self.repository, CLOSURE_NAMESPACE, root)
    }
    fn stage_permitted_object_closure(
        &self,
        root: Digest,
        closure: PermittedObjectClosure,
    ) -> Result<(), RefusalCode> {
        if self
            .store
            .stage(self.repository, CLOSURE_NAMESPACE, &closure)?
            != root
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(())
    }
    fn resolve_hidden_ref_policy(&self, _: Digest) -> Result<RefVisibility, RefusalCode> {
        Ok(RefVisibility::new()) // This model fixture has no hidden refs.
    }
}

struct DerivedEvidence {
    store: Arc<Model>,
    context: AdmissionContext,
}

impl AdmissionEvidence for DerivedEvidence {
    fn commit_evidence(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &fgit_txn::TransactionFoldReport,
    ) -> Result<CommitEvidence, RefusalCode> {
        let bodies = DecisionEvidenceBodies::derive(&self.context, basis, request, fold)?;
        let repo = self.context.repository_id;
        self.store.stage(
            repo,
            b"frankengit/admission/principal-snapshot/v1/",
            bodies.principal_snapshot(),
        )?;
        Ok(CommitEvidence {
            principal_snapshot_id: principal_snapshot_id(bodies.principal_snapshot())?,
            forge_event_batch_root: self.store.stage(
                repo,
                EVENT_NAMESPACE,
                bodies.forge_event_batch(),
            )?,
            policy_decision_root: self.store.stage(
                repo,
                b"frankengit/admission/policy-decision/v1/",
                bodies.policy_decision(),
            )?,
            invariant_evidence_root: self.store.stage(
                repo,
                b"frankengit/admission/invariant-evidence/v1/",
                bodies.invariant_evidence(),
            )?,
            outbox_effect_root: self.store.stage(
                repo,
                b"frankengit/admission/outbox-effect-batch/v1/",
                bodies.outbox_effect_batch(),
            )?,
            retention_delta_root: self.store.stage(
                repo,
                b"frankengit/admission/retention-delta/v1/",
                bodies.retention_delta(),
            )?,
        })
    }
    fn refusal_evidence(
        &self,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        let bodies = RefusalEvidenceBodies::derive(&self.context, basis, tx_id, code)?;
        self.store.stage(
            self.context.repository_id,
            b"frankengit/admission/principal-snapshot/v1/",
            bodies.principal_snapshot(),
        )?;
        Ok(RefusalMaterialization {
            policy_epoch: basis.body().policy_epoch,
            detail: format!("native merge model lane: {code:?}"),
            evidence_root: self.store.stage(
                self.context.repository_id,
                b"frankengit/admission/refusal-evidence/v1/",
                bodies.refusal_evidence(),
            )?,
        })
    }
}

#[derive(Default)]
struct Objects(BTreeMap<GitOid, CanonicalPackObject>);
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}
impl Objects {
    fn insert(&mut self, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let id = git_object_id(GitHashAlgorithm::Sha1, kind, &body);
        let object_type = match kind {
            GitObjectKind::Tree => ObjectType::Tree,
            GitObjectKind::Commit => ObjectType::Commit,
            _ => panic!("fixture kind"),
        };
        // Empty supplied edge metadata forces the production validator to
        // derive the graph from the actual hashed Git object bytes.
        self.0.insert(
            id,
            CanonicalPackObject::new(id, object_type, body, Vec::new(), 0, 0),
        );
        id
    }
    fn commit(&mut self, tree: GitOid, parents: &[GitOid], message: &str) -> GitOid {
        let parents: String = parents.iter().map(|id| format!("parent {id}\n")).collect();
        self.insert(GitObjectKind::Commit, format!("tree {tree}\n{parents}author Test <test@example.invalid> 0 +0000\ncommitter Test <test@example.invalid> 0 +0000\n\n{message}\n").into_bytes())
    }
}

struct Projection {
    canonical: CanonicalAdmissionProjection<Commitments, DerivedEvidence>,
    objects: Arc<Objects>,
}
impl AsyncAdmissionProjection<Model> for Projection {
    fn snapshot_async<'a>(
        &'a self,
        _: &'a Model,
        _: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        std::future::ready(
            self.canonical
                .snapshot(basis, authenticated)
                .map_err(ProjectionFailure::Unavailable),
        )
    }
    fn materialize_commit_async<'a>(
        &'a self,
        _: &'a Model,
        _: &'a (),
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a fgit_txn::TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, ProjectionFailure>> + Send + 'a {
        std::future::ready(
            self.canonical
                .materialize_commit(basis, request, fold, closure),
        )
    }
    fn materialize_refusal_async<'a>(
        &'a self,
        _: &'a Model,
        _: &'a (),
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        std::future::ready(
            self.canonical
                .materialize_refusal(basis, tx_id, code)
                .map_err(ProjectionFailure::Unavailable),
        )
    }
}
impl NativeMergeProjection<Model> for Projection {
    fn merge_checkpoint(&self, _: &()) -> Result<(), RefusalCode> {
        Ok(())
    }
    fn validate_merge_async<'a>(
        &'a self,
        _: &'a Model,
        _: &'a (),
        _: &'a PublicationBasis,
        _: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        std::future::ready(validate_merge_objects(
            self.objects.as_ref(),
            intent.merge().unwrap(),
            MergeObjectLimits::default(),
            &mut || true,
        ))
    }
}

struct Fixture {
    store: Arc<Model>,
    objects: Arc<Objects>,
    context: AdmissionContext,
    intent: NativeMergeIntent,
    genesis: RepositoryAuthorityHeadBody,
}
impl Fixture {
    fn new() -> Self {
        let context = AdmissionContext {
            head_key: HeadKey::new(b"native-merge-model/head".to_vec()).unwrap(),
            tenant_id: TenantId::from_bytes([1; 16]),
            repository_id: RepositoryId::from_bytes([2; 16]),
            principal_id: PrincipalId::from_bytes([3; 16]),
            idempotency_key: IdempotencyKey::new(b"first-merge".to_vec()).unwrap(),
            object_format: GitHashAlgorithm::Sha1,
        };
        let mut objects = Objects::default();
        let tree = objects.insert(GitObjectKind::Tree, Vec::new());
        let base = objects.commit(tree, &[], "base");
        let target = objects.commit(tree, &[base], "target");
        let source = objects.commit(tree, &[base], "source");
        let merged = objects.commit(tree, &[target, source], "reviewed merge");
        let intent = NativeMergeIntent::new(
            PullRequestNumber::try_new(1).unwrap(),
            ExpectedVersion::NewStream,
            NativeMerge {
                source_ref: name(b"refs/heads/topic"),
                source_tip: source,
                base_tip: base,
                target_ref: name(b"refs/heads/main"),
                target_tip_before: target,
                merge_commit: merged,
            },
        )
        .unwrap();
        let store = Arc::new(Model::new());
        let refs = CanonicalRefState::new_with_head_target(
            BTreeMap::from([
                (name(b"refs/heads/main"), target),
                (name(b"refs/heads/topic"), source),
            ]),
            name(b"refs/heads/main"),
        )
        .unwrap();
        let ref_root = canonical_ref_state_root(&refs).unwrap();
        assert_eq!(
            store
                .stage(context.repository_id, REF_NAMESPACE, &refs)
                .unwrap(),
            ref_root
        );
        let genesis = RepositoryAuthorityHeadBody {
            repository_id: context.repository_id,
            generation: HeadGeneration::FIRST,
            predecessor_head_id: None,
            decision_tail_id: None,
            latest_decision_sequence: None,
            latest_committed_rcr_id: None,
            latest_repository_sequence: None,
            ref_root,
            forge_position_root: legacy_genesis_root(context.repository_id, b"forge-position"),
            outcome_index_root: digest(16),
            retention_root: digest(17),
            outbox_root: legacy_genesis_root(context.repository_id, b"outbox"),
            configuration_root: digest(18),
            policy_epoch: PolicyEpoch::FIRST,
            format_registry_epoch: RegistryEpoch::FIRST,
            last_checkpoint_id: None,
        };
        initialize_repository(&store.backend, &context.head_key, &genesis).unwrap();
        Self {
            store,
            objects: Arc::new(objects),
            context,
            intent,
            genesis,
        }
    }
    fn projection(&self, context: &AdmissionContext) -> Projection {
        Projection {
            canonical: CanonicalAdmissionProjection::new(
                Commitments {
                    store: self.store.clone(),
                    repository: context.repository_id,
                },
                DerivedEvidence {
                    store: self.store.clone(),
                    context: context.clone(),
                },
            ),
            objects: self.objects.clone(),
        }
    }
    fn run(&self) -> Result<TerminalOutcome, AdmissionError> {
        poll_ready(admit_native_merge_async(
            self.store.as_ref(),
            &(),
            &self.context,
            &self.intent,
            AdmissionLimits::default(),
            &self.projection(&self.context),
        ))
    }
    fn head(&self) -> RepositoryAuthorityHeadBody {
        let HeadRead::Present(receipt) = self
            .store
            .backend
            .read_head(&self.context.head_key)
            .unwrap()
        else {
            panic!("head absent")
        };
        decode_body(receipt.body(), DecodeLimits::DEFAULT).unwrap()
    }
    fn tx_id(&self) -> TxId {
        fgit_authority::seal_request(
            &self.store.backend,
            &self.intent.seal_attempt(&self.context).unwrap(),
        )
        .unwrap()
        .tx_id()
    }
    fn outcome(&self, tx: TxId) -> OutcomeLookup {
        resolve_outcome(
            &self.store.backend,
            &self.context.head_key,
            self.context.tenant_id,
            self.context.repository_id,
            tx,
        )
        .unwrap()
    }
    fn assert_committed(&self, terminal: TerminalOutcome) -> RepositoryAuthorityHeadBody {
        assert!(
            matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
            "{terminal:?}"
        );
        let head = self.head();
        assert_ne!(head.ref_root, self.genesis.ref_root);
        assert_ne!(head.forge_position_root, self.genesis.forge_position_root);
        assert_ne!(head.outbox_root, self.genesis.outbox_root);
        let refs: CanonicalRefState = self
            .store
            .read(self.context.repository_id, REF_NAMESPACE, head.ref_root)
            .unwrap();
        assert_eq!(refs.head_target(), Some(&name(b"refs/heads/main")));
        assert_eq!(
            refs.refs().get(&name(b"refs/heads/main")),
            Some(&self.intent.merge().unwrap().merge_commit)
        );
        let HeadRead::Present(receipt) = self
            .store
            .backend
            .read_head(&self.context.head_key)
            .unwrap()
        else {
            panic!("head absent")
        };
        let authenticated = self
            .store
            .backend
            .authenticate_head_receipt(&receipt)
            .unwrap();
        assert_eq!(authenticated.body().unwrap(), head);
        let basis = PublicationBasis::new(
            fgit_authority::authority_head_identity(&head).unwrap(),
            head.clone(),
        );
        let selected = poll_ready(delivery::read_in(self.store.as_ref(), &(), &basis, &|| {
            false
        }))
        .unwrap();
        assert_eq!(selected.forge.entries().len(), 1);
        assert_eq!(selected.outbox.entries().len(), 1);
        let entry = &selected.outbox.entries()[0];
        assert_eq!(entry.tx_id(), self.tx_id());
        assert_eq!(
            entry.payload_root(),
            evidence_root(&ForgeEventBatch::of_one(self.intent.event().clone())).unwrap()
        );
        let batch =
            read_decision_batch_body(&self.store.backend, head.decision_tail_id.unwrap()).unwrap();
        assert_eq!(batch.committed_rcrs.len(), 1);
        let record = &batch.committed_rcrs[0];
        assert_eq!(record.forge_event_batch_root, entry.payload_root());
        assert_eq!(
            record.resulting_forge_position_root,
            head.forge_position_root
        );
        assert_eq!(batch.resulting_outbox_root, head.outbox_root);
        head
    }
}

#[test]
fn immutable_staging_crashes_leave_all_canonical_roots_old_then_retry_one_complete_merge() {
    for namespace in [
        EVENT_NAMESPACE,
        POSITION_NAMESPACE,
        delivery::OUTBOX_NAMESPACE,
        delivery::EFFECT_NAMESPACE,
    ] {
        for position in [FaultPosition::BeforeEffect, FaultPosition::AfterEffect] {
            let fixture = Fixture::new();
            let tx = fixture.tx_id();
            *fixture.store.put_fault.lock().unwrap() = Some(PutFault {
                namespace,
                position,
            });
            let interrupted = fixture.run();
            assert!(
                interrupted.is_err(),
                "staging crash must not decide: {interrupted:?}"
            );
            let faults = fixture.store.backend.fault_log();
            assert_eq!(
                faults.records().len(),
                1,
                "targeted staging fault must fire"
            );
            assert_eq!(faults.records()[0].op_kind, AuthorityOpKind::PutIfAbsent);
            assert_eq!(
                faults.records()[0].effect_reached,
                position == FaultPosition::AfterEffect
            );
            assert!(fixture.store.backend.is_crashed());
            fixture.store.backend.restart();
            let staged_key = fixture
                .store
                .interrupted_key
                .lock()
                .unwrap()
                .clone()
                .unwrap();
            let staged = fixture.store.backend.read_immutable(&staged_key).unwrap();
            assert_eq!(
                matches!(staged, ImmutableRead::Present(_)),
                position == FaultPosition::AfterEffect
            );
            fixture.store.backend.install_fault_plan(FaultPlan::none());
            assert_eq!(
                fixture.head(),
                fixture.genesis,
                "no half-published merge roots"
            );
            assert_eq!(fixture.outcome(tx), OutcomeLookup::Undecided);
            let committed = fixture.run().unwrap();
            let head = fixture.assert_committed(committed);
            assert_eq!(fixture.run().unwrap(), committed);
            assert_eq!(
                fixture.head(),
                head,
                "identical retry cannot append another merge"
            );
        }
    }
}

#[test]
fn crash_at_head_cas_distinguishes_unpublished_staging_from_complete_publication() {
    for position in [FaultPosition::BeforeEffect, FaultPosition::AfterEffect] {
        let fixture = Fixture::new();
        let tx = fixture.tx_id();
        fixture
            .store
            .backend
            .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
                0,
                AuthorityOpKind::CompareExchangeHead,
                FaultKind::Crash { position },
            )]));
        assert!(fixture.run().is_err());
        let faults = fixture.store.backend.fault_log();
        assert_eq!(faults.records().len(), 1);
        assert_eq!(
            faults.records()[0].effect_reached,
            position == FaultPosition::AfterEffect
        );
        fixture.store.backend.restart();
        fixture.store.backend.install_fault_plan(FaultPlan::none());
        if position == FaultPosition::BeforeEffect {
            assert_eq!(fixture.head(), fixture.genesis);
            assert_eq!(fixture.outcome(tx), OutcomeLookup::Undecided);
        } else {
            let OutcomeLookup::Decided(terminal) = fixture.outcome(tx) else {
                panic!("post-CAS crash erased decision")
            };
            fixture.assert_committed(terminal);
        }
        let terminal = fixture.run().unwrap();
        let head = fixture.assert_committed(terminal);
        assert_eq!(head.generation, HeadGeneration::FIRST.next().unwrap());
        assert_eq!(fixture.run().unwrap(), terminal);
        assert_eq!(fixture.head(), head);
    }
}

#[test]
fn ambiguous_and_duplicate_cas_responses_resolve_one_original_transaction() {
    for fault in [
        FaultKind::LoseRequest,
        FaultKind::LoseResponse,
        FaultKind::DuplicateRequest {
            deliver: DuplicateDelivery::Second,
        },
    ] {
        let fixture = Fixture::new();
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
        let faults = fixture.store.backend.fault_log();
        assert_eq!(
            faults.records().len(),
            1,
            "ambiguity injection must be observed"
        );
        assert_eq!(faults.records()[0].kind, fault);
        match fault {
            FaultKind::LoseRequest | FaultKind::LoseResponse => {
                let Err(AdmissionError::Outcome(outcome)) = &first else {
                    panic!("lost CAS response must preserve typed ambiguity: {first:?}");
                };
                let fgit_authority::OutcomeFailure::Seal(seal) = outcome.as_ref() else {
                    panic!("expected authority ambiguity: {outcome:?}");
                };
                assert!(matches!(
                    seal.as_ref(),
                    fgit_authority::SealFailure::Store(AuthorityFailure::Ambiguous(_))
                ));
                if fault == FaultKind::LoseRequest {
                    assert_eq!(fixture.head(), fixture.genesis);
                    assert_eq!(fixture.outcome(tx), OutcomeLookup::Undecided);
                } else {
                    let OutcomeLookup::Decided(terminal) = fixture.outcome(tx) else {
                        panic!("lost response cannot erase the applied merge");
                    };
                    fixture.assert_committed(terminal);
                }
            }
            FaultKind::DuplicateRequest { .. } => assert!(first.is_ok(), "{first:?}"),
            _ => unreachable!("closed fault corpus"),
        }
        let committed = fixture.run().unwrap();
        if let Ok(first) = first {
            assert_eq!(committed, first);
        }
        let head = fixture.assert_committed(committed);
        assert_eq!(head.generation, HeadGeneration::FIRST.next().unwrap());
        assert_eq!(fixture.outcome(tx), OutcomeLookup::Decided(committed));
        assert_eq!(fixture.run().unwrap(), committed);
        assert_eq!(fixture.head(), head);
    }
}

#[test]
fn competing_distinct_merge_replans_after_the_other_drivers_actual_cas() {
    let fixture = Arc::new(Fixture::new());
    let competitor = fixture.clone();
    let winner = Arc::new(Mutex::new(None));
    let observed = winner.clone();
    *fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
        let mut context = competitor.context.clone();
        context.idempotency_key = IdempotencyKey::new(b"competing-merge".to_vec()).unwrap();
        let terminal = poll_ready(admit_native_merge_async(
            competitor.store.as_ref(),
            &(),
            &context,
            &competitor.intent,
            AdmissionLimits::default(),
            &competitor.projection(&context),
        ))
        .unwrap();
        *observed.lock().unwrap() = Some(terminal);
    }));
    let loser = fixture.run().unwrap();
    let winner = winner.lock().unwrap().unwrap();
    assert!(matches!(winner.outcome, DecisionOutcome::Committed { .. }));
    assert!(
        matches!(
            loser.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::TargetRefMoved,
                ..
            }
        ),
        "{loser:?}"
    );
    assert_ne!(winner.decision_sequence, loser.decision_sequence);
    let head = fixture.head();
    assert_eq!(
        head.generation,
        HeadGeneration::FIRST.next().unwrap().next().unwrap()
    );
    let latest =
        read_decision_batch_body(&fixture.store.backend, head.decision_tail_id.unwrap()).unwrap();
    assert!(
        latest.committed_rcrs.is_empty(),
        "the losing decision is only a refusal"
    );
    let previous = fgit_authority::read_authority_head_body(
        &fixture.store.backend,
        head.predecessor_head_id.unwrap(),
    )
    .unwrap();
    assert_eq!(previous.ref_root, head.ref_root);
    assert_eq!(previous.forge_position_root, head.forge_position_root);
    assert_eq!(previous.outbox_root, head.outbox_root);
    let winning_batch =
        read_decision_batch_body(&fixture.store.backend, previous.decision_tail_id.unwrap())
            .unwrap();
    assert_eq!(winning_batch.committed_rcrs.len(), 1);
    assert_ne!(winning_batch.committed_rcrs[0].tx_id, fixture.tx_id());
    let refs: CanonicalRefState = fixture
        .store
        .read(fixture.context.repository_id, REF_NAMESPACE, head.ref_root)
        .unwrap();
    assert_eq!(
        refs.refs().get(&name(b"refs/heads/main")),
        Some(&fixture.intent.merge().unwrap().merge_commit)
    );
    let basis = PublicationBasis::new(
        fgit_authority::authority_head_identity(&head).unwrap(),
        head.clone(),
    );
    let selected = poll_ready(delivery::read_in(
        fixture.store.as_ref(),
        &(),
        &basis,
        &|| false,
    ))
    .unwrap();
    assert_eq!(selected.forge.entries().len(), 1);
    assert_eq!(selected.outbox.entries().len(), 1);
    assert_eq!(
        selected.outbox.entries()[0].tx_id(),
        winning_batch.committed_rcrs[0].tx_id
    );
    assert_eq!(fixture.run().unwrap(), loser);
    assert_eq!(fixture.head(), head);
}

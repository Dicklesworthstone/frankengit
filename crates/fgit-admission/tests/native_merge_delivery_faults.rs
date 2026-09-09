#![forbid(unsafe_code)]
//! Deterministic model-store faults through the production native merge driver.
//! These tests do not claim filesystem crash durability. Git identities and
//! closure validation are real; only immutable storage and scheduling use the
//! explicitly non-durable MemoryAuthorityStore lane.

#[path = "native_merge_delivery_faults/workspace.rs"]
mod workspace;

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex};

use fgit_admission::evidence::{
    DecisionEvidenceBodies, RefusalEvidenceBodies, evidence_root, principal_snapshot_id,
};
use fgit_admission::merge::native::objects::{MergeObjectLimits, validate_merge_objects};
use fgit_admission::merge::native::{
    NativeMergeIntent, NativeMergeProjection, SyncNativeMergeProjection, admit_native_merge,
    admit_native_merge_async, admit_sealed_native_merge, admit_sealed_native_merge_async, delivery,
    legacy_genesis_root,
};
use fgit_admission::merge::{SealedMerge, seal_attempt_for};
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
    CanonicalBody, DecodeLimits, OutboxDeliveryIdentityInput, RepositoryAuthorityHeadBody,
    decode_body, derive_outbox_delivery_key, encode_body,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::aggregate::{ExpectedVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEventBatch, NativeMerge};
use fgit_forge::{MergeAttempt, MergeEffectPackage, RefIntent as ForgeRefIntent, WorkspaceEpoch};
use fgit_git_object::ObjectType;
use fgit_lab::{LabSchedule, StepId};
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_reference::effect::FoldBasis;
use fgit_reference::intent::{
    DurabilityProfile, ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId,
    ForgeStreamPosition, IdempotencyKey as ModelKey, Intent, OutboxDeliveryKey, OutboxIntent,
    RefIntent, Statement, TransactionRequest,
};
use fgit_reference::refs::ExpectedRefState;
use fgit_types::{
    AsciiSlug, DecisionOutcome, Digest, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid,
    HeadGeneration, MismatchPolicy, PolicyEpoch, PrincipalId, PrincipalSnapshotId, RefName,
    RefusalCode, RegistryEpoch, RepositoryId, TenantId, TxId,
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
    publications: Mutex<Vec<(AuthorityVersionToken, CasOutcome)>>,
}

impl Model {
    fn new() -> Self {
        Self {
            backend: MemoryAuthorityStore::new(StoreInstanceId::from_raw(51)),
            put_fault: Mutex::new(None),
            interrupted_key: Mutex::new(None),
            before_publish: Mutex::new(None),
            publications: Mutex::new(Vec::new()),
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

    fn publish(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> Result<CasOutcome, AuthorityFailure> {
        let interleave = self.before_publish.lock().unwrap().take();
        if let Some(interleave) = interleave {
            interleave();
        }
        let result = self
            .backend
            .publish_head_with_outcomes(key, expected, generation, body, outcomes, witness);
        if let Ok(outcome) = &result {
            self.publications
                .lock()
                .unwrap()
                .push((expected, outcome.clone()));
        }
        result
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
        std::future::ready(self.publish(key, expected, generation, body, outcomes, witness))
    }
    fn authenticate_head_receipt(
        &self,
        _: &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::ready(self.backend.authenticate_head_receipt(receipt))
    }
}

/// The synchronous view forwards to the same existing reference store and
/// fault/scheduling hooks as the asynchronous fixture, without polling futures.
struct SyncModel<'a>(&'a Model);
impl AuthorityStore for SyncModel<'_> {
    fn instance_id(&self) -> StoreInstanceId {
        self.0.backend.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.0.backend.limits()
    }
    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.0.put(key, body)
    }
    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.0.backend.read_immutable(key)
    }
    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.0.backend.initialize_head(key, generation, body)
    }
    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.0.backend.read_head(key)
    }
    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.0
            .backend
            .compare_exchange_head(key, expected, generation, body)
    }
    fn publish_head_with_outcomes(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.0
            .publish(key, expected, generation, body, outcomes, witness)
    }
    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.0.backend.authenticate_head_receipt(receipt)
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
        self.insert(GitObjectKind::Commit, format!("tree {tree}\n{parents}author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{message}\n").into_bytes())
    }
}

struct Projection {
    canonical: CanonicalAdmissionProjection<Commitments, DerivedEvidence>,
    objects: Arc<Objects>,
}
impl SyncNativeMergeProjection for Projection {
    fn merge_checkpoint(&self) -> Result<(), RefusalCode> {
        Ok(())
    }
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, ProjectionFailure> {
        self.canonical
            .snapshot(basis, authenticated)
            .map_err(ProjectionFailure::Unavailable)
    }
    fn validate_merge(
        &self,
        _: &PublicationBasis,
        _: &AuthenticatedHead,
        intent: &NativeMergeIntent,
    ) -> Result<ValidatedClosure, ProjectionFailure> {
        validate_merge_objects(
            self.objects.as_ref(),
            intent.merge().unwrap(),
            MergeObjectLimits::default(),
            &mut || true,
        )
    }
    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &fgit_txn::TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure> {
        self.canonical
            .materialize_commit(basis, request, fold, closure)
    }
    fn materialize_refusal(
        &self,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, ProjectionFailure> {
        self.canonical
            .materialize_refusal(basis, tx_id, code)
            .map_err(ProjectionFailure::Unavailable)
    }
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
        let closure = validate_merge_objects(
            &objects,
            intent.merge().unwrap(),
            MergeObjectLimits::default(),
            &mut || true,
        )
        .expect("positive fault fixture must pass native validation before faults are armed");
        assert_eq!(
            closure.objects,
            objects
                .0
                .keys()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
        );
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

#[derive(Clone, Copy)]
enum NativeDriver {
    Sync,
    Async,
}
impl NativeDriver {
    fn other(self) -> Self {
        match self {
            Self::Sync => Self::Async,
            Self::Async => Self::Sync,
        }
    }
    fn run(
        self,
        fixture: &Fixture,
        context: &AdmissionContext,
        intent: &NativeMergeIntent,
    ) -> Result<TerminalOutcome, AdmissionError> {
        let projection = fixture.projection(context);
        match self {
            Self::Sync => admit_native_merge(
                &SyncModel(fixture.store.as_ref()),
                context,
                intent,
                AdmissionLimits::default(),
                &projection,
            ),
            Self::Async => poll_ready(admit_native_merge_async(
                fixture.store.as_ref(),
                &(),
                context,
                intent,
                AdmissionLimits::default(),
                &projection,
            )),
        }
    }
    fn sealed(
        self,
        fixture: &Fixture,
        package: &OwnedSealedMerge,
    ) -> Result<TerminalOutcome, AdmissionError> {
        let projection = fixture.projection(&fixture.context);
        match self {
            Self::Sync => admit_sealed_native_merge(
                &SyncModel(fixture.store.as_ref()),
                &fixture.context,
                &package.borrowed(),
                AdmissionLimits::default(),
                &projection,
            ),
            Self::Async => poll_ready(admit_sealed_native_merge_async(
                fixture.store.as_ref(),
                &(),
                &fixture.context,
                &package.borrowed(),
                AdmissionLimits::default(),
                &projection,
            )),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum NativeAnswer {
    Terminal(TerminalOutcome),
    Unavailable(RefusalCode),
}
fn native_answer(result: Result<TerminalOutcome, AdmissionError>) -> NativeAnswer {
    match result {
        Ok(terminal) => NativeAnswer::Terminal(terminal),
        Err(AdmissionError::AsyncProjectionUnavailable(code)) => NativeAnswer::Unavailable(code),
        other => panic!("unexpected native model result: {other:?}"),
    }
}

/// Compare selected canonical bytes, not just outcome labels or root counts.
fn assert_same_native_state(left: &Fixture, right: &Fixture) {
    let head = left.head();
    assert_eq!(head, right.head());
    for (namespace, root) in [
        (REF_NAMESPACE, head.ref_root),
        (POSITION_NAMESPACE, head.forge_position_root),
        (delivery::OUTBOX_NAMESPACE, head.outbox_root),
    ] {
        let key = key(namespace, left.context.repository_id, root);
        assert_eq!(
            left.store.backend.read_immutable(&key).unwrap(),
            right.store.backend.read_immutable(&key).unwrap()
        );
    }
    if let Some(tail) = head.decision_tail_id {
        let left_batch = read_decision_batch_body(&left.store.backend, tail).unwrap();
        let right_batch = read_decision_batch_body(&right.store.backend, tail).unwrap();
        assert_eq!(left_batch, right_batch);
        for record in &left_batch.committed_rcrs {
            for (namespace, root) in [
                (CLOSURE_NAMESPACE, record.object_closure_root),
                (EVENT_NAMESPACE, record.forge_event_batch_root),
                (
                    b"frankengit/admission/policy-decision/v1/".as_slice(),
                    record.policy_decision_root,
                ),
                (
                    b"frankengit/admission/invariant-evidence/v1/".as_slice(),
                    record.invariant_evidence_root,
                ),
                (
                    b"frankengit/admission/outbox-effect-batch/v1/".as_slice(),
                    record.outbox_effect_root,
                ),
                (
                    b"frankengit/admission/retention-delta/v1/".as_slice(),
                    record.retention_delta_root,
                ),
            ] {
                let key = key(namespace, left.context.repository_id, root);
                let frame = left.store.backend.read_immutable(&key).unwrap();
                assert!(
                    matches!(frame, ImmutableRead::Present(_)),
                    "committed evidence must exist"
                );
                assert_eq!(frame, right.store.backend.read_immutable(&key).unwrap());
            }
        }
    }
}

#[test]
fn native_sync_and_async_share_exact_commits_refusals_unavailability_and_retries() {
    for case in ["permitted", "stale-source", "missing-body"] {
        let mut left = Fixture::new();
        let mut right = Fixture::new();
        let mut removed = Vec::new();
        for fixture in [&mut left, &mut right] {
            if case == "stale-source" {
                let mut merge = fixture.intent.merge().unwrap().clone();
                merge.source_tip = merge.base_tip;
                fixture.intent = NativeMergeIntent::new(
                    PullRequestNumber::try_new(1).unwrap(),
                    ExpectedVersion::NewStream,
                    merge,
                )
                .unwrap();
            } else if case == "missing-body" {
                let candidate = fixture.intent.merge().unwrap().merge_commit;
                let object = Arc::get_mut(&mut fixture.objects)
                    .unwrap()
                    .0
                    .remove(&candidate)
                    .unwrap();
                removed.push((candidate, object));
            }
        }
        assert_eq!(
            left.intent.seal_attempt(&left.context).unwrap(),
            right.intent.seal_attempt(&right.context).unwrap()
        );
        let sync = native_answer(NativeDriver::Sync.run(&left, &left.context, &left.intent));
        let asynchronous =
            native_answer(NativeDriver::Async.run(&right, &right.context, &right.intent));
        assert_eq!(sync, asynchronous, "{case}");
        match (&sync, case) {
            (
                NativeAnswer::Terminal(TerminalOutcome {
                    outcome: DecisionOutcome::Committed { .. },
                    ..
                }),
                "permitted",
            ) => {}
            (
                NativeAnswer::Terminal(TerminalOutcome {
                    outcome:
                        DecisionOutcome::Refused {
                            code: RefusalCode::TargetRefMoved,
                            ..
                        },
                    ..
                }),
                "stale-source",
            ) => {}
            (NativeAnswer::Unavailable(RefusalCode::EvidenceMissing), "missing-body") => {}
            _ => panic!("the native equivalence corpus collapsed: {case}: {sync:?}"),
        }
        assert_same_native_state(&left, &right);
        let head = left.head();
        assert_eq!(
            native_answer(NativeDriver::Sync.run(&left, &left.context, &left.intent)),
            sync
        );
        assert_eq!(
            native_answer(NativeDriver::Async.run(&right, &right.context, &right.intent)),
            asynchronous
        );
        assert_eq!(left.head(), head);
        assert_same_native_state(&left, &right);
        if case == "missing-body" {
            assert_eq!(head, left.genesis);
            for (fixture, (id, object)) in [&mut left, &mut right].into_iter().zip(removed) {
                Arc::get_mut(&mut fixture.objects)
                    .unwrap()
                    .0
                    .insert(id, object);
            }
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
}

struct OwnedSealedMerge {
    package: MergeEffectPackage,
    attempt: MergeAttempt,
    closure: ValidatedClosure,
    evidence: CommitEvidence,
    workspace_epoch_now: WorkspaceEpoch,
}
impl OwnedSealedMerge {
    fn borrowed(&self) -> SealedMerge<'_> {
        SealedMerge {
            package: &self.package,
            attempt: &self.attempt,
            closure: &self.closure,
            evidence: self.evidence,
            workspace_epoch_now: self.workspace_epoch_now,
        }
    }
}

/// The public reference evaluator supplies real full-fold evidence. The seed
/// record is used only while deriving the seal, which excludes derived evidence.
fn sealed_native_fixture(fixture: &Fixture) -> OwnedSealedMerge {
    sealed_native_fixture_with_workspace(fixture, None)
}

fn sealed_native_fixture_with_workspace(
    fixture: &Fixture,
    workspace: Option<[u8; 32]>,
) -> OwnedSealedMerge {
    let context = &fixture.context;
    let merge = fixture.intent.merge().unwrap();
    let closure = validate_merge_objects(
        fixture.objects.as_ref(),
        merge,
        MergeObjectLimits::default(),
        &mut || true,
    )
    .unwrap();
    let seed = digest(27);
    let mut sealed = OwnedSealedMerge {
        package: MergeEffectPackage {
            objects: vec![merge.merge_commit],
            ref_intent: ForgeRefIntent {
                name: merge.target_ref.as_bytes().to_vec(),
                expected_tip: merge.target_tip_before,
                new_tip: merge.merge_commit,
            },
            event: fixture.intent.event().clone(),
        },
        attempt: MergeAttempt {
            pull_request: PullRequestNumber::try_new(1).unwrap(),
            source_ref: merge.source_ref.as_bytes().to_vec(),
            target_ref: merge.target_ref.as_bytes().to_vec(),
            source_tip: merge.source_tip,
            target_tip: merge.target_tip_before,
            base_tip: merge.base_tip,
            workspace_epoch: WorkspaceEpoch::from_u64(9),
        },
        closure,
        evidence: CommitEvidence {
            principal_snapshot_id: PrincipalSnapshotId::from_digest(
                seed.algorithm(),
                fgit_types::CANONICAL_CODEC_VERSION,
                *seed.bytes(),
            ),
            forge_event_batch_root: seed,
            policy_decision_root: seed,
            invariant_evidence_root: seed,
            outbox_effect_root: seed,
            retention_delta_root: seed,
        },
        workspace_epoch_now: WorkspaceEpoch::from_u64(9),
    };
    let attempt = match workspace {
        Some(digest) => fgit_admission::merge::native::workspace_seal_attempt_for(
            context,
            &sealed.borrowed(),
            digest,
        )
        .unwrap(),
        None => seal_attempt_for(context, &sealed.borrowed()).unwrap(),
    };
    let tx_id = attempt.derive().unwrap().0;
    let head = fixture.head();
    let basis = PublicationBasis::new(
        fgit_authority::authority_head_identity(&head).unwrap(),
        head.clone(),
    );
    let refs: CanonicalRefState = fixture
        .store
        .read(context.repository_id, REF_NAMESPACE, head.ref_root)
        .unwrap();
    let delivery = poll_ready(delivery::read_in(
        fixture.store.as_ref(),
        &(),
        &basis,
        &|| false,
    ))
    .unwrap();
    let event_root =
        evidence_root(&ForgeEventBatch::of_one(fixture.intent.event().clone())).unwrap();
    let label = AsciiSlug::from_static("pull-request/1");
    let key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
        context.repository_id,
        AsciiSlug::from_static("forge-event"),
        AsciiSlug::from_static("forge-projection"),
        event_root,
        tx_id,
        head.latest_committed_rcr_id,
    ))
    .unwrap();
    let request = TransactionRequest {
        tx_id,
        tenant: context.tenant_id,
        repository: context.repository_id,
        principal: context.principal_id,
        schema: attempt.request.request_schema(),
        idempotency_key: ModelKey::new(AsciiSlug::from_static("receive")),
        canonical_request_digest: fgit_authority::canonical_request_digest(&attempt.request)
            .unwrap(),
        statements: vec![Statement {
            intents: vec![
                Intent::Ref(RefIntent::Update {
                    name: merge.target_ref.clone(),
                    expected: ExpectedRefState::Exact(merge.target_tip_before),
                    new: merge.merge_commit,
                    force: false,
                }),
                Intent::Forge(ForgeIntent {
                    stream: ForgeStreamId::new(label),
                    expected_position: ForgeStreamPosition::GENESIS,
                    event: ForgeEventKind::PullRequestMerged {
                        pull_request: ForgeEntityId::new(label),
                        target: merge.target_ref.clone(),
                    },
                }),
                Intent::Outbox(OutboxIntent {
                    delivery_key: OutboxDeliveryKey::new(key),
                    parameters: event_root,
                }),
            ],
            mismatch_policy: MismatchPolicy::TxnAbort,
        }],
        promised_closure: sealed.closure.objects.clone(),
        atomic: true,
        durability: DurabilityProfile::CanonicalSource,
    };
    let fold = fgit_txn::IntentEvaluator::new().evaluate(
        FoldBasis {
            refs: refs.refs(),
            forge_positions: &delivery.forge_positions(),
            retention: &BTreeSet::new(),
            outbox: &delivery.outbox_bindings(),
        },
        &request,
    );
    let bodies = DecisionEvidenceBodies::derive(context, &basis, &request, &fold).unwrap();
    sealed.evidence = CommitEvidence {
        principal_snapshot_id: principal_snapshot_id(bodies.principal_snapshot()).unwrap(),
        forge_event_batch_root: event_root,
        policy_decision_root: evidence_root(bodies.policy_decision()).unwrap(),
        invariant_evidence_root: evidence_root(bodies.invariant_evidence()).unwrap(),
        outbox_effect_root: evidence_root(bodies.outbox_effect_batch()).unwrap(),
        retention_delta_root: evidence_root(bodies.retention_delta()).unwrap(),
    };
    sealed
}

#[test]
fn original_sealed_native_sync_and_async_preserve_identity_evidence_and_stale_retry() {
    for stale in [false, true] {
        let left = Fixture::new();
        let right = Fixture::new();
        let mut left_package = sealed_native_fixture(&left);
        let mut right_package = sealed_native_fixture(&right);
        let original = seal_attempt_for(&left.context, &left_package.borrowed()).unwrap();
        assert_eq!(
            original,
            seal_attempt_for(&right.context, &right_package.borrowed()).unwrap()
        );
        assert_ne!(original, left.intent.seal_attempt(&left.context).unwrap());
        if stale {
            left_package.workspace_epoch_now = WorkspaceEpoch::from_u64(10);
            right_package.workspace_epoch_now = WorkspaceEpoch::from_u64(10);
        }
        let sync = NativeDriver::Sync.sealed(&left, &left_package).unwrap();
        let asynchronous = NativeDriver::Async.sealed(&right, &right_package).unwrap();
        assert_eq!(sync, asynchronous);
        if stale {
            assert!(matches!(
                sync.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::EvidenceStale,
                    ..
                }
            ));
        } else {
            assert!(matches!(sync.outcome, DecisionOutcome::Committed { .. }));
            let head = left.head();
            let batch =
                read_decision_batch_body(&left.store.backend, head.decision_tail_id.unwrap())
                    .unwrap();
            assert_eq!(batch.committed_rcrs[0].tx_id, original.derive().unwrap().0);
            assert_eq!(
                batch.committed_rcrs[0].invariant_evidence_root,
                left_package.evidence.invariant_evidence_root
            );
        }
        assert_same_native_state(&left, &right);
        let head = left.head();
        left_package.workspace_epoch_now = WorkspaceEpoch::from_u64(11);
        right_package.workspace_epoch_now = WorkspaceEpoch::from_u64(11);
        assert_eq!(
            NativeDriver::Sync.sealed(&left, &left_package).unwrap(),
            sync
        );
        assert_eq!(
            NativeDriver::Async.sealed(&right, &right_package).unwrap(),
            asynchronous
        );
        assert_eq!(left.head(), head);
        assert_same_native_state(&left, &right);
    }
}

fn scheduled_native_race(
    schedule: &LabSchedule,
    delayed_driver: NativeDriver,
) -> (
    TerminalOutcome,
    TerminalOutcome,
    RepositoryAuthorityHeadBody,
) {
    let mut fixture = Fixture::new();
    let first = fixture.intent.merge().unwrap().clone();
    let tree = fixture
        .objects
        .0
        .values()
        .find(|object| object.object_type() == ObjectType::Tree)
        .unwrap()
        .id();
    let mut objects = Objects(fixture.objects.0.clone());
    let rival_commit = objects.commit(
        tree,
        &[first.target_tip_before, first.source_tip],
        "competing reviewed merge",
    );
    fixture.objects = Arc::new(objects);
    let intents = [
        fixture.intent.clone(),
        NativeMergeIntent::new(
            PullRequestNumber::try_new(1).unwrap(),
            ExpectedVersion::NewStream,
            NativeMerge {
                merge_commit: rival_commit,
                ..first
            },
        )
        .unwrap(),
    ];
    let mut contexts = [fixture.context.clone(), fixture.context.clone()];
    contexts[0].idempotency_key = IdempotencyKey::new(b"scheduled-native-a".to_vec()).unwrap();
    contexts[1].idempotency_key = IdempotencyKey::new(b"scheduled-native-b".to_vec()).unwrap();
    assert_ne!(
        intents[0].merge().unwrap().merge_commit,
        intents[1].merge().unwrap().merge_commit
    );
    assert_eq!(intents[0].event().aggregate, intents[1].event().aggregate);
    let participant_index = |id: &StepId| {
        schedule
            .participants()
            .iter()
            .position(|participant| participant == id)
            .unwrap()
    };
    let delayed = participant_index(&schedule.order()[0]);
    let rival = participant_index(&schedule.order()[1]);
    assert_ne!(delayed, rival);
    let fixture = Arc::new(fixture);
    let observed = Arc::new(Mutex::new(None));
    let recorded = observed.clone();
    let competitor = fixture.clone();
    let schedule_copy = schedule.clone();
    let contexts_copy = contexts.clone();
    let intents_copy = intents.clone();
    *fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
        let mut cursor = schedule_copy.cursor();
        assert_eq!(
            cursor.next_step().unwrap(),
            &schedule_copy.participants()[delayed],
            "first native driver reached its actual publication boundary"
        );
        let selected = cursor.next_step().unwrap();
        let rival = schedule_copy
            .participants()
            .iter()
            .position(|id| id == selected)
            .unwrap();
        let winner = delayed_driver
            .other()
            .run(&competitor, &contexts_copy[rival], &intents_copy[rival])
            .unwrap();
        assert!(matches!(winner.outcome, DecisionOutcome::Committed { .. }));
        assert_eq!(
            cursor.next_step().unwrap(),
            &schedule_copy.participants()[delayed],
            "resume the prepared candidate against its now-stale CAS token"
        );
        assert!(cursor.is_exhausted());
        *recorded.lock().unwrap() =
            Some((winner, cursor.position(), schedule_copy.canonical_line()));
    }));
    let loser = delayed_driver
        .run(&fixture, &contexts[delayed], &intents[delayed])
        .unwrap();
    let (winner, consumed, replay) = observed
        .lock()
        .unwrap()
        .clone()
        .expect("the scheduled publication boundary must actually fire");
    assert_eq!(consumed, schedule.len());
    assert_eq!(replay, schedule.canonical_line());
    assert!(matches!(
        loser.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::TargetRefMoved,
            ..
        }
    ));
    let publications = fixture.store.publications.lock().unwrap().clone();
    assert_eq!(
        publications.len(),
        3,
        "winner CAS, actual stale CAS, then canonical loser refusal"
    );
    assert!(matches!(publications[0].1, CasOutcome::Committed(_)));
    assert!(matches!(publications[1].1, CasOutcome::PredecessorMismatch));
    assert!(matches!(publications[2].1, CasOutcome::Committed(_)));
    assert_eq!(
        publications[0].0, publications[1].0,
        "both native candidates prepared against the exact same authority token"
    );
    assert_ne!(publications[1].0, publications[2].0);
    let head = fixture.head();
    let latest =
        read_decision_batch_body(&fixture.store.backend, head.decision_tail_id.unwrap()).unwrap();
    assert!(latest.committed_rcrs.is_empty());
    let predecessor = fgit_authority::read_authority_head_body(
        &fixture.store.backend,
        head.predecessor_head_id.unwrap(),
    )
    .unwrap();
    assert_eq!(
        (head.ref_root, head.forge_position_root, head.outbox_root),
        (
            predecessor.ref_root,
            predecessor.forge_position_root,
            predecessor.outbox_root
        )
    );
    let winning = read_decision_batch_body(
        &fixture.store.backend,
        predecessor.decision_tail_id.unwrap(),
    )
    .unwrap();
    assert_eq!(winning.committed_rcrs.len(), 1);
    let winner_tx = intents[rival]
        .seal_attempt(&contexts[rival])
        .unwrap()
        .derive()
        .unwrap()
        .0;
    let loser_tx = intents[delayed]
        .seal_attempt(&contexts[delayed])
        .unwrap()
        .derive()
        .unwrap()
        .0;
    assert_eq!(winning.committed_rcrs[0].tx_id, winner_tx);
    assert_eq!(fixture.outcome(winner_tx), OutcomeLookup::Decided(winner));
    assert_eq!(fixture.outcome(loser_tx), OutcomeLookup::Decided(loser));
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
    assert_eq!(selected.outbox.entries()[0].tx_id(), winner_tx);
    assert_eq!(
        selected.outbox.entries()[0].payload_root(),
        evidence_root(&ForgeEventBatch::of_one(intents[rival].event().clone())).unwrap()
    );
    let refs: CanonicalRefState = fixture
        .store
        .read(fixture.context.repository_id, REF_NAMESPACE, head.ref_root)
        .unwrap();
    assert_eq!(
        refs.refs().get(&name(b"refs/heads/main")),
        Some(&intents[rival].merge().unwrap().merge_commit)
    );
    assert_eq!(
        delayed_driver
            .run(&fixture, &contexts[delayed], &intents[delayed])
            .unwrap(),
        loser
    );
    assert_eq!(
        delayed_driver
            .other()
            .run(&fixture, &contexts[rival], &intents[rival])
            .unwrap(),
        winner
    );
    assert_eq!(fixture.head(), head);
    (winner, loser, head)
}

#[test]
fn lab_schedule_drives_two_distinct_native_candidates_for_one_pr_and_replays_exactly() {
    for order in [
        ["merge-a", "merge-b", "merge-a"],
        ["merge-b", "merge-a", "merge-b"],
    ] {
        let schedule = LabSchedule::explicit(
            vec![StepId::new("merge-a"), StepId::new("merge-b")],
            order.into_iter().map(StepId::new).collect(),
        )
        .unwrap();
        assert_eq!(
            schedule.canonical_line(),
            format!(
                "fgit-lab-schedule-v1|seed=none|participants=merge-a,merge-b|steps=3|order={}",
                order.join(",")
            )
        );
        let synchronous = scheduled_native_race(&schedule, NativeDriver::Sync);
        let asynchronous = scheduled_native_race(&schedule, NativeDriver::Async);
        assert_eq!(
            synchronous, asynchronous,
            "the schedule must replay the same actual native publications through both facades"
        );
    }
}

//! Reference-memory fixture with real immutable frames, RCR publication and
//! exact head-history verification. This is not a filesystem durability test.
use super::super::*;
use crate::AdmissionContext;
use crate::evidence::DecisionEvidenceBodies;
use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken,
    CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt, IdempotencyKey, ImmutableKey,
    ImmutableRead, MemoryAuthorityStore, PutOutcome, StoreInstanceId, authority_head_identity,
    collect_cumulative_outcomes, initialize_repository, outcome_index_root, publish_decisions,
};
use fgit_chronicle::{PublicationPlan, ResultingRoots};
use fgit_codec::{
    CanonicalBody, CanonicalOutboxEffectState, CanonicalOutboxState, CanonicalOutboxStateEntry,
    CryptoBodyIdentity, RepositoryAuthorityHeadBody, RepositoryCommitRecord,
};
use fgit_forge::ForgeEventBatch;
use fgit_reference::effect::{FoldOutcome, FoldReport, NetEffects};
use fgit_reference::intent::{DurabilityProfile, TransactionRequest};
use fgit_types::{
    AsciiSlug, CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm,
    HeadGeneration, RepositorySequence, SchemaFamily, SchemaId, TenantId, TxId,
};
use std::future::Future;
use std::sync::Mutex;

pub(super) struct Store {
    pub backend: MemoryAuthorityStore,
    pub reads: Mutex<Vec<ImmutableKey>>,
    pub fault: Mutex<Option<(ImmutableKey, bool)>>,
}
impl AsyncAuthorityStore for Store {
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
        std::future::ready(self.backend.put_if_absent(key, body))
    }
    fn read_immutable(
        &self,
        _: &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        self.reads.lock().unwrap().push(key.clone());
        let fault = self.fault.lock().unwrap().clone();
        let value = match fault.filter(|(target, _)| target == key) {
            Some((_, true)) => Ok(ImmutableRead::Present(vec![0])),
            Some((_, false)) => Ok(ImmutableRead::Absent),
            None => self.backend.read_immutable(key),
        };
        std::future::ready(value)
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
    fn authenticate_head_receipt(
        &self,
        _: &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::ready(self.backend.authenticate_head_receipt(receipt))
    }
}

pub(super) fn run<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("memory authority does not suspend"),
    }
}

fn digest(value: u64) -> Digest {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    Digest::new(
        DigestAlgorithmId::try_new(0xfff1).unwrap(),
        DigestBytes::try_new(&bytes).unwrap(),
    )
}
pub(super) fn actor(value: u8) -> PrincipalId {
    PrincipalId::from_bytes([value; 16])
}

pub(super) struct Fixture {
    pub store: Store,
    pub basis: PublicationBasis,
    pub forge: CanonicalForgePositionState,
    pub outbox: CanonicalOutboxState,
    pub principal_keys: Vec<ImmutableKey>,
    pub event_keys: Vec<ImmutableKey>,
    key: HeadKey,
    next: u64,
}
impl Fixture {
    pub fn new() -> Self {
        let store = Store {
            backend: MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x1b0a)),
            reads: Mutex::new(Vec::new()),
            fault: Mutex::new(None),
        };
        let mut head = fgit_codec::harness::genesis_head();
        head.repository_id = RepositoryId::from_bytes([0x57; 16]);
        head.ref_root = crate::ref_state_root(
            fgit_types::RootLayoutVersion::LegacyWholeBody,
            &crate::CanonicalRefState::default(),
        )
        .unwrap();
        head.outcome_index_root = outcome_index_root(&[]).unwrap();
        let forge = CanonicalForgePositionState::try_new(head.repository_id, Vec::new()).unwrap();
        let outbox = CanonicalOutboxState::try_new(head.repository_id, Vec::new()).unwrap();
        head.forge_position_root = stage(
            &store,
            head.repository_id,
            storage::POSITION_NAMESPACE,
            &forge,
        );
        head.outbox_root = stage(
            &store,
            head.repository_id,
            super::super::super::super::super::delivery::OUTBOX_NAMESPACE,
            &outbox,
        );
        let key = HeadKey::new(b"pr-notification-activity/head".to_vec()).unwrap();
        initialize_repository(&store.backend, &key, &head).unwrap();
        Self {
            store,
            basis: PublicationBasis::new(authority_head_identity(&head).unwrap(), head),
            forge,
            outbox,
            principal_keys: Vec::new(),
            event_keys: Vec::new(),
            key,
            next: 1,
        }
    }

    pub fn append(&mut self, events: Vec<fgit_forge::ForgeEvent>, who: u8) {
        self.append_records(vec![(events, who)]);
    }

    pub fn context(&self, who: u8) -> AdmissionContext {
        AdmissionContext {
            head_key: self.key.clone(),
            tenant_id: TenantId::from_bytes([0x58; 16]),
            repository_id: self.basis.body().repository_id,
            principal_id: actor(who),
            idempotency_key: IdempotencyKey::new(b"prepare-activity-read-prefix".to_vec()).unwrap(),
            object_format: GitHashAlgorithm::Sha1,
        }
    }

    /// One vector element is one RCR; elements share one real publication CAS.
    pub fn append_records(&mut self, records: Vec<(Vec<fgit_forge::ForgeEvent>, u8)>) {
        let HeadRead::Present(receipt) = self.store.backend.read_head(&self.key).unwrap() else {
            panic!("fixture head missing");
        };
        let repository = self.basis.body().repository_id;
        let witness = collect_cumulative_outcomes(&self.store.backend, &self.key).unwrap();
        let mut plan = PublicationPlan::open(self.basis.clone()).unwrap();
        let mut roots = ResultingRoots::carried_forward(&self.basis);
        for (events, who) in records {
            self.next += 1;
            let d = digest(self.next);
            let tx = TxId::from_digest(d.algorithm(), CANONICAL_CODEC_VERSION, *d.bytes());
            let batch = ForgeEventBatch { events };
            let event_root = stage(&self.store, repository, storage::EVENT_NAMESPACE, &batch);
            self.event_keys
                .push(storage::body_key(storage::EVENT_NAMESPACE, repository, event_root).unwrap());
            self.forge = storage::advance_positions(&self.forge, &batch, event_root).unwrap();
            roots.forge_position_root = stage(
                &self.store,
                repository,
                storage::POSITION_NAMESPACE,
                &self.forge,
            );
            let destination = AsciiSlug::from_static("forge-projection");
            let delivery = fgit_codec::derive_outbox_delivery_key(
                fgit_codec::OutboxDeliveryIdentityInput::new(
                    repository,
                    AsciiSlug::from_static("forge-event"),
                    destination,
                    event_root,
                    tx,
                    None,
                ),
            )
            .unwrap();
            let effect =
                CanonicalOutboxEffectState::committed(repository, delivery, tx, event_root);
            let effect_root = stage(
                &self.store,
                repository,
                super::super::super::super::super::delivery::EFFECT_NAMESPACE,
                &effect,
            );
            let mut entries = self.outbox.entries().to_vec();
            entries.push(CanonicalOutboxStateEntry::new(
                delivery,
                AsciiSlug::from_static("forge-event"),
                destination,
                event_root,
                tx,
                None,
                effect_root,
                None,
            ));
            self.outbox = CanonicalOutboxState::try_new(repository, entries).unwrap();
            roots.outbox_root = stage(
                &self.store,
                repository,
                super::super::super::super::super::delivery::OUTBOX_NAMESPACE,
                &self.outbox,
            );
            let context = AdmissionContext {
                head_key: self.key.clone(),
                tenant_id: TenantId::from_bytes([0x58; 16]),
                repository_id: repository,
                principal_id: actor(who),
                idempotency_key: IdempotencyKey::new(
                    format!("activity-{}", self.next).into_bytes(),
                )
                .unwrap(),
                object_format: GitHashAlgorithm::Sha1,
            };
            let request = TransactionRequest {
                tx_id: tx,
                tenant: context.tenant_id,
                repository,
                principal: actor(who),
                schema: SchemaId::new(SchemaFamily::from_static("notification-fixture"), 1, 0),
                idempotency_key: fgit_reference::intent::IdempotencyKey::new(
                    AsciiSlug::from_static("activity"),
                ),
                canonical_request_digest: d,
                statements: Vec::new(),
                promised_closure: BTreeSet::new(),
                atomic: true,
                durability: DurabilityProfile::CanonicalSource,
            };
            let fold = FoldReport {
                outcome: FoldOutcome::Folded(NetEffects::default()),
                mappings: Vec::new(),
            };
            let evidence =
                DecisionEvidenceBodies::derive(&context, &self.basis, &request, &fold).unwrap();
            let principal = evidence.principal_snapshot();
            let principal_id = principal.id().unwrap();
            let id = principal_id.as_internal_object_id();
            let key = storage::body_key(
                PRINCIPAL_NAMESPACE,
                repository,
                Digest::new(id.algorithm(), *id.digest()),
            )
            .unwrap();
            self.store
                .backend
                .put_if_absent(&key, &principal.encode().unwrap())
                .unwrap();
            self.principal_keys.push(key);
            plan.commit(RepositoryCommitRecord {
                repository_id: repository,
                repository_sequence: RepositorySequence::FIRST,
                parent_rcr_id: None,
                tx_id: tx,
                principal_snapshot_id: principal_id,
                canonical_request_digest: d,
                ref_delta_root: d,
                resulting_ref_root: roots.ref_root,
                object_closure_root: d,
                forge_event_batch_root: event_root,
                resulting_forge_position_root: roots.forge_position_root,
                policy_epoch: roots.policy_epoch,
                policy_decision_root: d,
                invariant_evidence_root: d,
                outbox_effect_root: d,
                retention_delta_root: d,
            });
        }
        let publication = plan
            .seal(&CryptoBodyIdentity, roots, &witness, receipt.token())
            .unwrap();
        publish_decisions(
            &self.store.backend,
            &self.key,
            receipt.token(),
            publication.batch(),
            publication.head(),
            TenantId::from_bytes([0x58; 16]),
        )
        .unwrap();
        self.basis = PublicationBasis::new(
            authority_head_identity(publication.head()).unwrap(),
            publication.head().clone(),
        );
    }

    pub fn source(&self, who: u8) -> Result<Vec<NotificationThread>, AdmissionError> {
        run(read_threads(
            &self.store,
            &(),
            &self.basis,
            &self.forge,
            actor(who),
            &|| false,
        ))
    }
    pub fn selected_head(
        &self,
        head: &RepositoryAuthorityHeadBody,
        who: u8,
    ) -> Result<super::super::super::NotificationSourceSnapshot, AdmissionError> {
        run(super::super::super::read_source_for_kind_at(
            &self.store,
            &(),
            &PublicationBasis::new(authority_head_identity(head).unwrap(), head.clone()),
            actor(who),
            fgit_forge::event::notification::NotificationTargetKind::PullRequest,
            &|| false,
        ))
    }
}

fn stage<B: CanonicalBody + Sync>(
    store: &Store,
    repository: RepositoryId,
    namespace: &[u8],
    body: &B,
) -> Digest {
    run(storage::stage_body(store, &(), repository, namespace, body)).unwrap()
}

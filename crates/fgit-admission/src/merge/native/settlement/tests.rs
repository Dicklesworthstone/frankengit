//! Production worker and publication logic over the reference authority store.
//! The scripted transport supplies observations, not durability evidence. These
//! tests do not establish filesystem crash behavior or a real remote service.

use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken,
    CasOutcome, DuplicateAbsenceWitness, HeadInit, HeadKey, HeadRead, HeadReadReceipt,
    ImmutableKey, ImmutableRead, MemoryAuthorityStore, PutOutcome, StoreInstanceId,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::harness::{digest_of, genesis_head, tx_id};
use fgit_codec::{
    CanonicalBody, CanonicalForgePositionState, DecodeLimits, RepositoryAuthorityHeadBody,
    decode_body,
};
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventPayload, PullRequestNumber};
use fgit_resource::twophase::EscalationReason;
use fgit_types::{GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId, TxId};

use crate::evidence::{DecisionEvidenceBodies, RefusalEvidenceBodies, principal_snapshot_id};
use crate::{
    AdmissionSnapshot, CanonicalRefState, CommitEvidence, CommitMaterialization,
    RefusalMaterialization, TransactionFoldReport, TransactionRequest, prepare_canonical_commit,
};

use super::*;

fn run<F: Future>(future: F) -> F::Output {
    match Box::pin(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("reference authority operations never suspend"),
    }
}

#[derive(Clone, Copy)]
enum StopAfter {
    Pending(u32),
    InFlight(u32),
    Terminal,
}

struct Store {
    memory: MemoryAuthorityStore,
    stopped: Arc<AtomicBool>,
    stop_after: Mutex<Option<StopAfter>>,
}

impl Store {
    fn observe_publication(&self, body: &[u8]) {
        let mut stop_after = self.stop_after.lock().expect("stop selector");
        let Some(selector) = *stop_after else {
            return;
        };
        let head = decode_body::<RepositoryAuthorityHeadBody>(body, DecodeLimits::DEFAULT)
            .expect("published head");
        let batch = fgit_authority::read_decision_batch_body(
            &self.memory,
            head.decision_tail_id.expect("published batch"),
        )
        .expect("published batch body");
        for record in &batch.committed_rcrs {
            let key = storage::body_key(
                history::OUTBOX_EFFECT_NAMESPACE,
                head.repository_id,
                record.outbox_effect_root,
            )
            .expect("evidence key");
            let ImmutableRead::Present(frame) =
                self.memory.read_immutable(&key).expect("evidence read")
            else {
                panic!("publication must stage its evidence");
            };
            if let Ok(progress) =
                decode_body::<CanonicalOutboxProgress>(&frame, DecodeLimits::DEFAULT)
            {
                let selected = match selector {
                    StopAfter::Pending(attempt) => {
                        progress.state() == ReconcileState::Pending { attempt }
                            && !progress.dispatch_in_flight()
                    }
                    StopAfter::InFlight(attempt) => {
                        progress.state() == ReconcileState::Pending { attempt }
                            && progress.dispatch_in_flight()
                    }
                    StopAfter::Terminal => progress.state().is_terminal(),
                };
                if selected {
                    *stop_after = None;
                    self.stopped.store(true, Ordering::SeqCst);
                }
            }
        }
    }
}

impl AsyncAuthorityStore for Store {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId {
        self.memory.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.memory.limits()
    }
    fn put_if_absent(
        &self,
        _: &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        std::future::ready(self.memory.put_if_absent(key, body))
    }
    fn read_immutable(
        &self,
        _: &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        std::future::ready(self.memory.read_immutable(key))
    }
    fn initialize_head(
        &self,
        _: &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        std::future::ready(self.memory.initialize_head(key, generation, body))
    }
    fn read_head(
        &self,
        _: &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        std::future::ready(self.memory.read_head(key))
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
            self.memory
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
        let result = self
            .memory
            .publish_head_with_outcomes(key, expected, generation, body, outcomes, witness);
        if matches!(result, Ok(CasOutcome::Committed(_))) {
            self.observe_publication(body);
        }
        std::future::ready(result)
    }
    fn authenticate_head_receipt(
        &self,
        _: &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::ready(self.memory.authenticate_head_receipt(receipt))
    }
}

const REF_NAMESPACE: &[u8] = b"frankengit/admission/ref-state/v1/";
const CLOSURE_NAMESPACE: &[u8] = b"frankengit/admission/object-closure/v1/";

#[derive(Clone, Copy, Default)]
enum MaterializationFault {
    #[default]
    None,
    Retention,
    RefRoot,
    Transaction,
    Refuse,
}

struct Projection {
    context: AdmissionContext,
    fault: MaterializationFault,
}

fn unavailable_projection(_: AdmissionError) -> ProjectionFailure {
    ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid)
}

async fn stage<B: CanonicalBody + Sync>(
    store: &Store,
    repo: RepositoryId,
    namespace: &[u8],
    body: &B,
) -> Result<Digest, ProjectionFailure> {
    storage::stage_body(store, &(), repo, namespace, body)
        .await
        .map_err(unavailable_projection)
}

impl AsyncAdmissionProjection<Store> for Projection {
    fn snapshot_async<'a>(
        &'a self,
        store: &'a Store,
        _: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        async move {
            if authenticated.receipt().body()
                != fgit_codec::encode_body(basis.body())
                    .map_err(|_| ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))?
            {
                return Err(ProjectionFailure::Unavailable(
                    RefusalCode::AuthorityReceiptStale,
                ));
            }
            let delivery = delivery::read_in(store, &(), basis, &|| false)
                .await
                .map_err(unavailable_projection)?;
            Ok(AdmissionSnapshot {
                forge_positions: delivery.forge_positions(),
                outbox: delivery.outbox_bindings(),
                ..AdmissionSnapshot::default()
            })
        }
    }
    fn materialize_commit_async<'a>(
        &'a self,
        store: &'a Store,
        _: &'a (),
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, ProjectionFailure>> + Send + 'a {
        async move {
            if matches!(self.fault, MaterializationFault::Refuse) {
                return Err(ProjectionFailure::Refuse(
                    RefusalCode::PublicationPolicyRefused,
                ));
            }
            let bodies = DecisionEvidenceBodies::derive(&self.context, basis, request, fold)
                .map_err(ProjectionFailure::Unavailable)?;
            let repo = self.context.repository_id;
            stage(
                store,
                repo,
                b"frankengit/admission/principal-snapshot/v1/",
                bodies.principal_snapshot(),
            )
            .await?;
            let evidence = CommitEvidence {
                principal_snapshot_id: principal_snapshot_id(bodies.principal_snapshot())
                    .map_err(ProjectionFailure::Unavailable)?,
                forge_event_batch_root: stage(
                    store,
                    repo,
                    storage::EVENT_NAMESPACE,
                    bodies.forge_event_batch(),
                )
                .await?,
                policy_decision_root: stage(
                    store,
                    repo,
                    b"frankengit/admission/policy-decision/v1/",
                    bodies.policy_decision(),
                )
                .await?,
                invariant_evidence_root: stage(
                    store,
                    repo,
                    storage::INVARIANT_NAMESPACE,
                    bodies.invariant_evidence(),
                )
                .await?,
                outbox_effect_root: stage(
                    store,
                    repo,
                    history::OUTBOX_EFFECT_NAMESPACE,
                    bodies.outbox_effect_batch(),
                )
                .await?,
                retention_delta_root: stage(
                    store,
                    repo,
                    b"frankengit/admission/retention-delta/v1/",
                    bodies.retention_delta(),
                )
                .await?,
            };
            let prepared = prepare_canonical_commit(
                basis,
                request,
                fold,
                closure,
                CanonicalRefState::default(),
                fgit_types::layout::RootLayoutVersion::LegacyWholeBody,
                evidence,
            )
            .map_err(ProjectionFailure::Unavailable)?;
            stage(store, repo, REF_NAMESPACE, prepared.next_ref_state()).await?;
            stage(store, repo, CLOSURE_NAMESPACE, prepared.object_closure()).await?;
            let mut materialization = prepared.into_materialization();
            match self.fault {
                MaterializationFault::None | MaterializationFault::Refuse => {}
                MaterializationFault::Retention => {
                    materialization.roots.retention_root = digest_of(201)
                }
                MaterializationFault::RefRoot => {
                    materialization.roots.ref_root = digest_of(202);
                    materialization.record.resulting_ref_root = digest_of(202);
                }
                MaterializationFault::Transaction => materialization.record.tx_id = tx_id(),
            }
            Ok(materialization)
        }
    }
    fn materialize_refusal_async<'a>(
        &'a self,
        store: &'a Store,
        _: &'a (),
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        async move {
            let bodies = RefusalEvidenceBodies::derive(&self.context, basis, tx_id, code)
                .map_err(ProjectionFailure::Unavailable)?;
            stage(
                store,
                self.context.repository_id,
                b"frankengit/admission/principal-snapshot/v1/",
                bodies.principal_snapshot(),
            )
            .await?;
            Ok(RefusalMaterialization {
                policy_epoch: basis.body().policy_epoch,
                detail: "scripted admission refusal with derived evidence".to_owned(),
                evidence_root: stage(
                    store,
                    self.context.repository_id,
                    b"frankengit/admission/refusal-evidence/v1/",
                    bodies.refusal_evidence(),
                )
                .await?,
            })
        }
    }
}

struct Fixture {
    store: Store,
    context: AdmissionContext,
    key: AsciiSlug,
}

impl Fixture {
    fn new() -> Self {
        let context = AdmissionContext {
            head_key: HeadKey::new(b"outbox-worker-test".to_vec()).expect("head key"),
            tenant_id: TenantId::from_bytes([1; 16]),
            repository_id: RepositoryId::from_bytes([2; 16]),
            principal_id: PrincipalId::from_bytes([3; 16]),
            idempotency_key: fgit_authority::IdempotencyKey::new(b"worker".to_vec())
                .expect("client key"),
            object_format: GitHashAlgorithm::Sha1,
        };
        let store = Store {
            memory: MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x957)),
            stopped: Arc::new(AtomicBool::new(false)),
            stop_after: Mutex::new(None),
        };
        let events = ForgeEventBatch::of_one(ForgeEvent {
            aggregate: AggregateId::PullRequest(PullRequestNumber::FIRST),
            version: AggregateVersion::FIRST,
            payload: ForgeEventPayload::PullRequestOpened {
                source_ref: b"refs/heads/topic".to_vec(),
                target_ref: b"refs/heads/main".to_vec(),
                source_tip: digest_of(4),
                target_tip: digest_of(5),
            },
        });
        let payload = storage::root(&events).expect("payload root");
        let key =
            fgit_codec::derive_outbox_delivery_key(fgit_codec::OutboxDeliveryIdentityInput::new(
                context.repository_id,
                AsciiSlug::from_static("forge-event"),
                AsciiSlug::from_static("forge-projection"),
                payload,
                tx_id(),
                None,
            ))
            .expect("canonical delivery identity");
        let effect =
            CanonicalOutboxEffectState::committed(context.repository_id, key, tx_id(), payload);
        let forge = storage::advance_positions(
            &CanonicalForgePositionState::try_new(context.repository_id, Vec::new())
                .expect("empty frontier"),
            &events,
            payload,
        )
        .expect("event frontier");
        let outbox = CanonicalOutboxState::try_new(
            context.repository_id,
            vec![fgit_codec::CanonicalOutboxStateEntry::new(
                key,
                AsciiSlug::from_static("forge-event"),
                AsciiSlug::from_static("forge-projection"),
                payload,
                tx_id(),
                None,
                storage::root(&effect).expect("effect root"),
                None,
            )],
        )
        .expect("initial obligation index");
        let delivery = delivery::DeliveryState { forge, outbox };
        run(delivery::stage_in(
            &store,
            &(),
            &delivery,
            &events,
            &effect,
            &|| false,
        ))
        .expect("stage canonical obligation and payload");
        let mut head = genesis_head();
        head.repository_id = context.repository_id;
        head.ref_root = run(stage(
            &store,
            context.repository_id,
            REF_NAMESPACE,
            &CanonicalRefState::default(),
        ))
        .expect("canonical empty refs");
        head.forge_position_root = storage::root(&delivery.forge).expect("frontier root");
        head.outbox_root = storage::root(&delivery.outbox).expect("outbox root");
        fgit_authority::initialize_repository(&store.memory, &context.head_key, &head)
            .expect("initialize the reference authority");
        Self {
            store,
            context,
            key,
        }
    }
    fn projection(&self, fault: MaterializationFault) -> Projection {
        Projection {
            context: self.context.clone(),
            fault,
        }
    }
    fn basis(&self) -> PublicationBasis {
        run(crate::read_basis_async(
            &self.store,
            &(),
            &self.context.head_key,
        ))
        .expect("authenticated basis")
        .0
    }
    fn effect(&self) -> CanonicalOutboxEffectState {
        let state = run(delivery::read_in(&self.store, &(), &self.basis(), &|| {
            false
        }))
        .expect("selected outbox");
        run(delivery::read_effect_in(
            &self.store,
            &(),
            self.context.repository_id,
            state.outbox.entry(self.key).expect("obligation"),
            &|| false,
        ))
        .expect("selected lifecycle")
    }
    fn progress(&self) -> CanonicalOutboxProgress {
        run(history::latest_progress(
            &self.store,
            &(),
            &self.basis(),
            self.key,
            &|| false,
        ))
        .expect("authenticated history")
        .expect("persisted progress")
    }
    fn deliver(
        &self,
        transport: &mut Transport,
        attempts: u32,
        fault: MaterializationFault,
    ) -> Result<CanonicalOutboxEffectState, AdmissionError> {
        run(deliver_outbox_async(
            &self.store,
            &(),
            &self.context,
            self.key,
            &self.projection(fault),
            transport,
            ReconcilePolicy::new(NonZeroU32::new(attempts).expect("positive policy")),
            AdmissionLimits::default(),
            &|| {
                if self.store.stopped.load(Ordering::SeqCst) {
                    Err(RefusalCode::CancellationInProgress)
                } else {
                    Ok(())
                }
            },
        ))
    }
    fn stop_after(&self, selected: StopAfter) {
        *self.store.stop_after.lock().expect("stop selector") = Some(selected);
    }
    fn resume(&self) {
        self.store.stopped.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Probe,
    Deliver(u32),
}

struct Transport {
    key: AsciiSlug,
    destination: AsciiSlug,
    idempotency: DownstreamIdempotency,
    observations: VecDeque<Observation>,
    calls: Vec<Call>,
    stop_after_delivery: Option<Arc<AtomicBool>>,
}

impl Transport {
    fn new(key: AsciiSlug, observations: impl IntoIterator<Item = Observation>) -> Self {
        Self {
            key,
            destination: AsciiSlug::from_static("forge-projection"),
            idempotency: DownstreamIdempotency::Strong,
            observations: observations.into_iter().collect(),
            calls: Vec::new(),
            stop_after_delivery: None,
        }
    }
    fn check(&self, request: &DeliveryRequest<'_>) {
        assert_eq!(request.key, self.key);
        assert_eq!(request.destination, self.destination);
        assert_eq!(
            storage::root(request.events).expect("transport payload root"),
            request.payload_root
        );
    }
}

impl OutboxDestination<()> for Transport {
    fn destination(&self) -> AsciiSlug {
        self.destination
    }
    fn idempotency(&self) -> DownstreamIdempotency {
        self.idempotency
    }
    fn probe<'a>(
        &'a mut self,
        _: &'a (),
        request: &'a DeliveryRequest<'_>,
    ) -> impl Future<Output = Result<(ProbeVerdict, Vec<u8>), RefusalCode>> + Send + 'a {
        self.check(request);
        self.calls.push(Call::Probe);
        let Some(Observation::Probe(verdict)) = self.observations.pop_front() else {
            panic!("unexpected probe");
        };
        std::future::ready(Ok((verdict, b"scripted probe evidence".to_vec())))
    }
    fn deliver<'a>(
        &'a mut self,
        _: &'a (),
        request: &'a DeliveryRequest<'_>,
        attempt: u32,
    ) -> impl Future<Output = Result<(DeliveryVerdict, Vec<u8>), RefusalCode>> + Send + 'a {
        self.check(request);
        self.calls.push(Call::Deliver(attempt));
        let Some(Observation::Delivery(verdict)) = self.observations.pop_front() else {
            panic!("unexpected dispatch");
        };
        if let Some(stopped) = self.stop_after_delivery.take() {
            stopped.store(true, Ordering::SeqCst);
        }
        std::future::ready(Ok((verdict, b"scripted delivery evidence".to_vec())))
    }
}

fn success(key: AsciiSlug) -> Transport {
    Transport::new(
        key,
        [
            Observation::Probe(ProbeVerdict::NotDelivered),
            Observation::Delivery(DeliveryVerdict::Accepted),
        ],
    )
}

#[test]
fn delivered_obligation_and_terminal_retry_are_read_from_canonical_roots() {
    let fixture = Fixture::new();
    let before = fixture.basis();
    let mut transport = success(fixture.key);
    let acknowledged = fixture
        .deliver(&mut transport, 3, MaterializationFault::None)
        .expect("worker acknowledges");
    assert_eq!(acknowledged.state(), ObligationState::Acknowledged);
    assert_eq!(fixture.effect(), acknowledged);
    assert_eq!(transport.calls, [Call::Probe, Call::Deliver(2)]);
    assert!(transport.observations.is_empty());
    assert_eq!(
        fixture.progress().state(),
        ReconcileState::Delivered { attempt: 2 }
    );
    let after = fixture.basis();
    assert_eq!(before.body().ref_root, after.body().ref_root);
    assert_eq!(
        before.body().forge_position_root,
        after.body().forge_position_root
    );
    assert_ne!(before.body().outbox_root, after.body().outbox_root);
    let mut retry = Transport::new(fixture.key, []);
    assert_eq!(
        fixture
            .deliver(&mut retry, 3, MaterializationFault::None)
            .expect("terminal retry"),
        acknowledged
    );
    assert!(retry.calls.is_empty());
    assert_eq!(fixture.basis(), after);
}

#[test]
fn terminal_progress_survives_interruption_before_lifecycle_settlement() {
    let fixture = Fixture::new();
    fixture.stop_after(StopAfter::Terminal);
    let mut transport = success(fixture.key);
    assert!(
        fixture
            .deliver(&mut transport, 3, MaterializationFault::None)
            .is_err()
    );
    assert_eq!(
        fixture.effect().state(),
        ObligationState::DeferredExternally
    );
    let progress = fixture.progress();
    assert_eq!(progress.state(), ReconcileState::Delivered { attempt: 2 });
    assert_eq!(progress.evidence(), b"scripted delivery evidence");
    fixture.resume();
    let mut retry = Transport::new(fixture.key, []);
    assert_eq!(
        fixture
            .deliver(&mut retry, 3, MaterializationFault::None)
            .expect("settlement from recorded evidence")
            .state(),
        ObligationState::Acknowledged
    );
    assert!(retry.calls.is_empty());
}

#[test]
fn persisted_budget_cannot_be_reset_by_another_invocation_or_changed_policy() {
    let fixture = Fixture::new();
    fixture.stop_after(StopAfter::Pending(3));
    let mut first = Transport::new(
        fixture.key,
        [
            Observation::Probe(ProbeVerdict::NotDelivered),
            Observation::Delivery(DeliveryVerdict::TransientFailure),
        ],
    );
    assert!(
        fixture
            .deliver(&mut first, 3, MaterializationFault::None)
            .is_err()
    );
    assert_eq!(first.calls, [Call::Probe, Call::Deliver(2)]);
    assert_eq!(
        fixture.progress().state(),
        ReconcileState::Pending { attempt: 3 }
    );
    fixture.resume();
    let head = fixture.basis();
    let mut changed_policy = Transport::new(fixture.key, []);
    assert!(
        fixture
            .deliver(&mut changed_policy, 4, MaterializationFault::None)
            .is_err()
    );
    assert!(changed_policy.calls.is_empty());
    assert_eq!(fixture.basis(), head);
    let mut retry = Transport::new(
        fixture.key,
        [Observation::Delivery(DeliveryVerdict::TransientFailure)],
    );
    assert_eq!(
        fixture
            .deliver(&mut retry, 3, MaterializationFault::None)
            .expect("retry budget settles to escalation")
            .state(),
        ObligationState::Escalated
    );
    assert_eq!(retry.calls, [Call::Deliver(3)]);
    assert_eq!(
        fixture.progress().state(),
        ReconcileState::Indeterminate {
            reason: EscalationReason::RetryBudgetExhausted
        }
    );
    assert_eq!(fixture.progress().attempt(), 3);
}

#[test]
fn cancellation_after_dispatch_marker_requires_probe_before_a_later_attempt() {
    let fixture = Fixture::new();
    fixture.stop_after(StopAfter::InFlight(2));
    let mut first = Transport::new(
        fixture.key,
        [Observation::Probe(ProbeVerdict::NotDelivered)],
    );
    assert!(
        fixture
            .deliver(&mut first, 3, MaterializationFault::None)
            .is_err()
    );
    assert_eq!(first.calls, [Call::Probe]);
    assert!(fixture.progress().dispatch_in_flight());
    assert_eq!(fixture.progress().attempt(), 2);
    fixture.resume();
    let mut retry = success(fixture.key);
    assert_eq!(
        fixture
            .deliver(&mut retry, 3, MaterializationFault::None)
            .expect("recovered dispatch")
            .state(),
        ObligationState::Acknowledged
    );
    assert_eq!(retry.calls, [Call::Probe, Call::Deliver(3)]);
}

#[test]
fn cancellation_after_external_acceptance_reconciles_without_redelivery() {
    let fixture = Fixture::new();
    let mut first = success(fixture.key);
    first.stop_after_delivery = Some(fixture.store.stopped.clone());
    assert!(
        fixture
            .deliver(&mut first, 3, MaterializationFault::None)
            .is_err()
    );
    assert_eq!(first.calls, [Call::Probe, Call::Deliver(2)]);
    assert_eq!(
        fixture.effect().state(),
        ObligationState::DeferredExternally
    );
    assert!(fixture.progress().dispatch_in_flight());
    fixture.resume();
    let mut retry = Transport::new(fixture.key, [Observation::Probe(ProbeVerdict::Delivered)]);
    assert_eq!(
        fixture
            .deliver(&mut retry, 3, MaterializationFault::None)
            .expect("probe settles accepted call")
            .state(),
        ObligationState::Acknowledged
    );
    assert_eq!(retry.calls, [Call::Probe]);
    assert_eq!(fixture.progress().attempt(), 2);
}

#[test]
fn an_authoritative_refusal_for_the_deferral_seal_never_authorizes_transport() {
    let fixture = Fixture::new();
    let next = fixture
        .effect()
        .transition(LifecycleEvent::Defer, None)
        .expect("candidate defer");
    let next_root = storage::root(&next).expect("successor root");
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
                next_root.bytes().as_bytes(),
            )
            .expect("semantic binding"),
        ],
    )
    .expect("deferral request");
    let attempt = SealAttempt {
        tenant_id: fixture.context.tenant_id,
        repository_id: fixture.context.repository_id,
        authenticated_principal_id: fixture.context.principal_id,
        idempotency_key: fgit_authority::IdempotencyKey::new(
            format!(
                "outbox/{}",
                fgit_crypto::lowercase_hex(next_root.bytes().as_bytes())
            )
            .into_bytes(),
        )
        .expect("same stable mutation key"),
        request: semantic,
    };
    let sealed = run(fgit_authority::seal_request_async(
        &fixture.store,
        &(),
        &attempt,
    ))
    .expect("same deferral seal");
    let (basis, receipt, _) = run(crate::read_basis_async(
        &fixture.store,
        &(),
        &fixture.context.head_key,
    ))
    .expect("basis");
    let cumulative = run(fgit_authority::collect_cumulative_outcomes_async(
        &fixture.store,
        &(),
        &fixture.context.head_key,
    ))
    .expect("outcome witness");
    let terminal = run(crate::publish_refusal_async(
        &fixture.store,
        &(),
        &fixture.context,
        &basis,
        receipt.token(),
        sealed.seal_id(),
        sealed.tx_id(),
        RefusalCode::PublicationPolicyRefused,
        &fixture.projection(MaterializationFault::None),
        &cumulative,
    ))
    .expect("refusal publication")
    .expect("authoritative decision");
    assert!(matches!(
        terminal.outcome,
        fgit_types::DecisionOutcome::Refused {
            code: RefusalCode::PublicationPolicyRefused,
            ..
        }
    ));
    let after_refusal = fixture.basis();
    let mut transport = Transport::new(fixture.key, []);
    assert!(
        fixture
            .deliver(&mut transport, 3, MaterializationFault::None)
            .is_err()
    );
    assert!(transport.calls.is_empty());
    assert_eq!(fixture.effect().state(), ObligationState::Committed);
    assert_eq!(fixture.basis(), after_refusal);
}

#[test]
fn malformed_or_refused_materialization_cannot_publish_deferral_or_call_transport() {
    for fault in [
        MaterializationFault::Retention,
        MaterializationFault::RefRoot,
        MaterializationFault::Transaction,
        MaterializationFault::Refuse,
    ] {
        let fixture = Fixture::new();
        let before = fixture.basis();
        let mut transport = Transport::new(fixture.key, []);
        assert!(fixture.deliver(&mut transport, 3, fault).is_err());
        assert!(transport.calls.is_empty());
        assert_eq!(fixture.basis(), before);
        assert_eq!(fixture.effect().state(), ObligationState::Committed);
    }
}

#[test]
fn weak_or_misdirected_transport_and_precancelled_request_have_no_canonical_effect() {
    let fixture = Fixture::new();
    let before = fixture.basis();
    let mut weak = Transport::new(fixture.key, []);
    weak.idempotency = DownstreamIdempotency::Weak;
    assert!(
        fixture
            .deliver(&mut weak, 3, MaterializationFault::None)
            .is_err()
    );
    let mut wrong = Transport::new(fixture.key, []);
    wrong.destination = AsciiSlug::from_static("other-destination");
    assert!(
        fixture
            .deliver(&mut wrong, 3, MaterializationFault::None)
            .is_err()
    );
    fixture.store.stopped.store(true, Ordering::SeqCst);
    let mut cancelled = Transport::new(fixture.key, []);
    assert!(
        fixture
            .deliver(&mut cancelled, 3, MaterializationFault::None)
            .is_err()
    );
    assert!(weak.calls.is_empty() && wrong.calls.is_empty() && cancelled.calls.is_empty());
    assert_eq!(fixture.basis(), before);
}

//! Canonical ref-submission responsibility through real authority and journal codecs.
//! The reference authority publishes decision fixtures; these tests do not stand
//! in for the native node's object validation or ref-state admission tests.

mod cumulative;
mod retained_resume;

use super::*;

mod recovered_abort;
mod recovery;

use std::cell::RefCell;
use std::future::{Future, ready};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::effect_journal::{
    EffectJournalCodecRefusal, EffectJournalEncoder, EffectJournalPersistenceRefusal,
    EffectJournalPosition, EffectJournalSink, RecoveredEffectJournal,
};
use crate::{
    AgentInstanceId, AttenuationRequest, AuthorityReadReceipt, Capability,
    CapabilityEffectAuthorizationRefusal, CapabilityId, ClassSet, EffectJournalEntry,
    EffectJournalEvent, EffectTerminalOutcome, RunId, RunReconciliationReadiness,
    read_current_authority_capability_revocations,
};
use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken,
    CapabilityRevocationGenerationBody, CasOutcome, DuplicateAbsenceWitness, ExpectedOld, HeadInit,
    HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead, MemoryAuthorityStore, ProposedNew,
    PublicationOutcome, PutOutcome, RefCommand, SealAttempt, SemanticRequest, StoreInstanceId,
    authority_head_identity, body_key, canonical_body_id, decision_batch_identity,
    initialize_repository, publish_decisions, seal_request, stage_capability_revocation_generation,
    stage_revocation_aware_repository_incarnation_configuration,
};
use fgit_codec::{
    RepositoryAuthorityHeadBody, RepositoryCommitRecord, RepositoryDecision,
    RepositoryDecisionBatchBody, RepositoryIncarnationConfigurationBodyV2_2,
};
use fgit_crypto::IdentityDomain;
use fgit_resource::{LifecycleEvent, ObligationClass, ObligationState, RegionId, algebra::Grade};
use fgit_types::{
    DecisionOutcome, DecisionSequence, DigestBytes, GitHashAlgorithm as GitFormat, GitOid,
    HeadGeneration, PolicyEpoch, PrincipalSnapshotId, RefName, RefusalCode, RefusalRecordId,
    RegistryEpoch, RepositoryCommitId, RepositoryId, RepositoryIncarnationId, RepositorySequence,
    RootLayoutVersion, SchemaFamily, SchemaId,
};

const ISSUER_KEY: &[u8] = b"canonical-ref-submission-tests";
const TENANT: TenantId = TenantId::from_bytes([0x11; 16]);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x22; 16]);
const INCARNATION: RepositoryIncarnationId = RepositoryIncarnationId::from_bytes([0x33; 16]);
const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0x44; 16]);

fn digest(marker: u8) -> Digest {
    let empty = outcome_index_root(&[]).unwrap();
    Digest::new(
        empty.algorithm(),
        DigestBytes::try_new(&[marker; 32]).unwrap(),
    )
}

fn resources(bytes: u64, objects: u64) -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::Bytes, bytes), (Grade::Objects, objects)])
}

fn cost() -> ResourceVector {
    resources(256, 1)
}

fn stage_configuration(store: &MemoryAuthorityStore, revoked: &[CapabilityId]) -> Digest {
    let generation = CapabilityRevocationGenerationBody::try_new(
        TENANT,
        REPOSITORY,
        INCARNATION,
        PolicyEpoch::FIRST,
        None,
        revoked.iter().map(|id| id.value().to_be_bytes()).collect(),
        digest(0x90),
    )
    .unwrap();
    let staged = stage_capability_revocation_generation(store, &generation).unwrap();
    stage_revocation_aware_repository_incarnation_configuration(
        store,
        &RepositoryIncarnationConfigurationBodyV2_2 {
            root_layout: RootLayoutVersion::RefStateMerkleV1,
            object_format: GitFormat::Sha256,
            repository_incarnation_id: INCARNATION,
            policy_root: None,
            capability_revocation_root: Some(staged.generation_root()),
        },
    )
    .unwrap()
}

struct Fixture {
    store: MemoryAuthorityStore,
    head_key: HeadKey,
    genesis: RepositoryAuthorityHeadBody,
    run: IntentRun,
}

impl Fixture {
    fn new(id: u64) -> Self {
        let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(id));
        let root = outcome_index_root(&[]).unwrap();
        let genesis = RepositoryAuthorityHeadBody {
            repository_id: REPOSITORY,
            generation: HeadGeneration::FIRST,
            predecessor_head_id: None,
            decision_tail_id: None,
            latest_decision_sequence: None,
            latest_committed_rcr_id: None,
            latest_repository_sequence: None,
            ref_root: digest(0x41),
            forge_position_root: root,
            outcome_index_root: root,
            retention_root: root,
            outbox_root: root,
            configuration_root: stage_configuration(&store, &[]),
            policy_epoch: PolicyEpoch::FIRST,
            format_registry_epoch: RegistryEpoch::FIRST,
            last_checkpoint_id: None,
        };
        let head_key = HeadKey::new(format!("ref-submission-{id}").into_bytes()).unwrap();
        let HeadInit::Created(receipt) =
            initialize_repository(&store, &head_key, &genesis).unwrap()
        else {
            panic!("fresh reference authority initializes once");
        };
        let authenticated = store.authenticate_head_receipt(&receipt).unwrap();
        let authority = AuthorityReadReceipt::from_authenticated_head(
            &authenticated,
            LogicalTime::new(10),
            [0x51; 32],
        )
        .unwrap();
        let run = IntentRun::new_authenticated(
            RunId::new(7),
            authority,
            ClassSet::from_classes(&[
                OperationClass::ReadCanonicalObject,
                OperationClass::PublishRefTransaction,
            ]),
            resources(16_384, 64),
            LogicalTime::new(100),
        )
        .unwrap();
        Self {
            store,
            head_key,
            genesis,
            run,
        }
    }

    fn current_head(&self) -> (HeadReadReceipt, RepositoryAuthorityHeadBody) {
        let HeadRead::Present(receipt) = self.store.read_head(&self.head_key).unwrap() else {
            panic!("fixture head remains present");
        };
        let body = self
            .store
            .authenticate_head_receipt(&receipt)
            .unwrap()
            .body()
            .unwrap();
        (receipt, body)
    }

    fn revocations(&self, now: u64) -> CurrentAuthorityCapabilityRevocationReceipt {
        read_current_authority_capability_revocations(
            &self.store,
            TENANT,
            &self.head_key,
            &self.run,
            LogicalTime::new(now),
            1_000,
            32,
            32,
        )
        .unwrap()
    }

    fn revoke(&self, ids: &[CapabilityId]) {
        let (receipt, previous) = self.current_head();
        let next = RepositoryAuthorityHeadBody {
            generation: previous.generation.next().unwrap(),
            predecessor_head_id: Some(authority_head_identity(&previous).unwrap()),
            configuration_root: stage_configuration(&self.store, ids),
            ..previous
        };
        let bytes = encode_body(&next).unwrap();
        let key = body_key(IdentityDomain::RepositoryAuthorityHead, &next).unwrap();
        self.store.put_if_absent(&key, &bytes).unwrap();
        assert!(matches!(
            self.store
                .compare_exchange_head(&self.head_key, receipt.token(), next.generation, &bytes,)
                .unwrap(),
            CasOutcome::Committed(_)
        ));
    }

    /// Publish one real canonical terminal decision. Committed decisions carry
    /// their canonically identified RCR bodies; refusal-record identities are
    /// corpus values. This tests stream observation, not native ref admission.
    fn decide(&self, tx_id: TxId, commit: bool) -> TerminalOutcome {
        let (receipt, previous) = self.current_head();
        assert!(
            previous.latest_decision_sequence.is_none(),
            "one decision per fixture"
        );
        let committed_record = commit.then(|| {
            let seal = fgit_authority::read_seal(&self.store, TENANT, REPOSITORY, tx_id)
                .unwrap()
                .expect("a committed fixture has its ordinary seal");
            RepositoryCommitRecord {
                repository_id: REPOSITORY,
                repository_sequence: RepositorySequence::FIRST,
                parent_rcr_id: None,
                tx_id,
                principal_snapshot_id: PrincipalSnapshotId::from_digest(
                    IdentityDomain::PrincipalSnapshot.algorithm().id(),
                    fgit_types::CANONICAL_CODEC_VERSION,
                    DigestBytes::try_new(&[0x61; 32]).unwrap(),
                ),
                canonical_request_digest: seal.canonical_request_digest,
                ref_delta_root: digest(0x64),
                resulting_ref_root: previous.ref_root,
                object_closure_root: digest(0x65),
                forge_event_batch_root: digest(0x66),
                resulting_forge_position_root: previous.forge_position_root,
                policy_epoch: previous.policy_epoch,
                policy_decision_root: digest(0x67),
                invariant_evidence_root: digest(0x68),
                outbox_effect_root: previous.outbox_root,
                retention_delta_root: digest(0x69),
            }
        });
        let rcr = committed_record.as_ref().map(|record| {
            let id = RepositoryCommitId::from_internal_object_id(
                canonical_body_id(
                    IdentityDomain::RepositoryCommitRecord,
                    fgit_types::CANONICAL_CODEC_VERSION,
                    record,
                )
                .unwrap(),
            )
            .unwrap();
            self.store
                .put_if_absent(
                    &body_key(IdentityDomain::RepositoryCommitRecord, record).unwrap(),
                    &encode_body(record).unwrap(),
                )
                .unwrap();
            id
        });
        let outcome = if let Some(repository_commit_id) = rcr {
            DecisionOutcome::Committed {
                repository_commit_id,
            }
        } else {
            DecisionOutcome::Refused {
                code: RefusalCode::QuotaExceeded,
                refusal_record_id: RefusalRecordId::from_digest(
                    IdentityDomain::RefusalRecord.algorithm().id(),
                    fgit_types::CANONICAL_CODEC_VERSION,
                    DigestBytes::try_new(&[0x62; 32]).unwrap(),
                ),
            }
        };
        let terminal = TerminalOutcome {
            decision_sequence: DecisionSequence::FIRST,
            outcome,
        };
        let outcome_root = outcome_index_root(&[(tx_id, terminal.clone())]).unwrap();
        let batch = RepositoryDecisionBatchBody {
            repository_id: REPOSITORY,
            predecessor_head_id: authority_head_identity(&previous).unwrap(),
            predecessor_head_generation: previous.generation,
            first_decision_sequence: DecisionSequence::FIRST,
            decisions: vec![RepositoryDecision {
                tx_id,
                decision_sequence: DecisionSequence::FIRST,
                outcome: terminal.outcome.clone(),
            }],
            committed_rcrs: committed_record.into_iter().collect(),
            resulting_ref_root: previous.ref_root,
            resulting_forge_position_root: previous.forge_position_root,
            resulting_outcome_index_root: outcome_root,
            resulting_retention_root: previous.retention_root,
            resulting_outbox_root: previous.outbox_root,
            resulting_policy_epoch: previous.policy_epoch,
            batch_evidence_root: digest(0x63),
            compaction_generation_link: None,
        };
        let head = RepositoryAuthorityHeadBody {
            generation: previous.generation.next().unwrap(),
            predecessor_head_id: Some(authority_head_identity(&previous).unwrap()),
            decision_tail_id: Some(decision_batch_identity(&batch).unwrap()),
            latest_decision_sequence: Some(DecisionSequence::FIRST),
            latest_committed_rcr_id: rcr,
            latest_repository_sequence: commit.then_some(RepositorySequence::FIRST),
            outcome_index_root: outcome_root,
            ..previous
        };
        assert!(matches!(
            publish_decisions(
                &self.store,
                &self.head_key,
                receipt.token(),
                &batch,
                &head,
                TENANT,
            )
            .unwrap(),
            PublicationOutcome::Published(_)
        ));
        terminal
    }
}

fn seal_attempt(key: &[u8]) -> SealAttempt {
    SealAttempt {
        tenant_id: TENANT,
        repository_id: REPOSITORY,
        authenticated_principal_id: PRINCIPAL,
        idempotency_key: IdempotencyKey::new(key.to_vec()).unwrap(),
        request: SemanticRequest::build(
            SchemaId::new(SchemaFamily::from_static("receive-pack"), 1, 0),
            GitFormat::Sha256,
            true,
            vec![RefCommand {
                name: RefName::try_new(b"refs/heads/main").unwrap(),
                expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(
                    GitOid::from_hex(GitFormat::Sha256, &"72".repeat(32)).unwrap(),
                ),
                force: false,
            }],
            Vec::new(),
            Vec::new(),
        )
        .unwrap(),
    }
}

fn submission_binding(run: &IntentRun, attempt: &SealAttempt) -> RefTransactionBinding {
    RefTransactionBinding::from_parts(
        run.commitment().unwrap(),
        attempt.derive().unwrap().1,
        [0x81; 32],
    )
    .unwrap()
}

fn chain(operation: OperationClass) -> VerifiedCapabilityChain {
    let root = Capability::issue(
        CapabilityId::new(1),
        ClassSet::from_classes(&[operation]),
        resources(8_192, 32),
        LogicalTime::new(0),
        LogicalTime::new(100),
    )
    .unwrap();
    let sealed_root = root.seal(ISSUER_KEY, None).unwrap();
    let leaf = root
        .attenuate(&AttenuationRequest {
            id: CapabilityId::new(2),
            operations: ClassSet::from_classes(&[operation]),
            quota: resources(4_096, 16),
            not_before: LogicalTime::new(5),
            expires_at: LogicalTime::new(90),
        })
        .unwrap();
    let sealed_leaf = leaf.seal(ISSUER_KEY, Some(sealed_root.tag())).unwrap();
    VerifiedCapabilityChain::verify(&[sealed_root, sealed_leaf], ISSUER_KEY).unwrap()
}

/// Test-only adapter over the actual reference authority. Ready futures own
/// their already-computed answers; no executor or production blocking adapter.
type ImmutableReadHook<'a> = Box<dyn Fn(&ImmutableKey) + Send + Sync + 'a>;

struct AsyncView<'a> {
    inner: &'a MemoryAuthorityStore,
    writes: AtomicUsize,
    immutable_override: Option<(ImmutableKey, ImmutableRead)>,
    overridden_reads: AtomicUsize,
    after_read: Option<ImmutableReadHook<'a>>,
    absent_head: bool,
}

impl<'a> AsyncView<'a> {
    fn new(inner: &'a MemoryAuthorityStore) -> Self {
        Self {
            inner,
            writes: AtomicUsize::new(0),
            immutable_override: None,
            overridden_reads: AtomicUsize::new(0),
            after_read: None,
            absent_head: false,
        }
    }

    fn with_immutable_override(mut self, key: ImmutableKey, value: ImmutableRead) -> Self {
        self.immutable_override = Some((key, value));
        self
    }

    fn assert_read_only(&self) {
        assert_eq!(
            self.writes.load(Ordering::SeqCst),
            0,
            "observation must not submit"
        );
    }
}

impl AsyncAuthorityStore for AsyncView<'_> {
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
        self.writes.fetch_add(1, Ordering::SeqCst);
        ready(self.inner.put_if_absent(key, body))
    }

    fn read_immutable(
        &self,
        _: &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        let result = match &self.immutable_override {
            Some((selected, value)) if selected == key => {
                self.overridden_reads.fetch_add(1, Ordering::SeqCst);
                Ok(value.clone())
            }
            _ => self.inner.read_immutable(key),
        };
        if let Some(after_read) = &self.after_read {
            after_read(key);
        }
        ready(result)
    }

    fn initialize_head(
        &self,
        _: &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        self.writes.fetch_add(1, Ordering::SeqCst);
        ready(self.inner.initialize_head(key, generation, body))
    }

    fn read_head(
        &self,
        _: &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        ready(if self.absent_head {
            Ok(HeadRead::Absent)
        } else {
            self.inner.read_head(key)
        })
    }

    fn compare_exchange_head(
        &self,
        _: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        self.writes.fetch_add(1, Ordering::SeqCst);
        ready(
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
        self.writes.fetch_add(1, Ordering::SeqCst);
        ready(
            self.inner
                .publish_head_with_outcomes(key, expected, generation, body, outcomes, witness),
        )
    }

    fn authenticate_head_receipt(
        &self,
        _: &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        ready(self.inner.authenticate_head_receipt(receipt))
    }
}

fn poll_ready<F: Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut context = Context::from_waker(Waker::noop());
    match Box::pin(future).as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("reference authority futures must be ready"),
    }
}

#[derive(Clone, Copy, Debug)]
enum FailurePoint {
    Accepted,
    Binding,
    Bound,
    Commit,
    Defer,
    Acknowledge,
}

impl FailurePoint {
    fn matches(self, event: &EffectJournalEvent) -> bool {
        matches!(
            (self, event),
            (Self::Accepted, EffectJournalEvent::Accepted(_))
                | (
                    Self::Binding,
                    EffectJournalEvent::RefTransactionBound { .. }
                )
                | (Self::Bound, EffectJournalEvent::BoundObligation { .. })
                | (
                    Self::Commit,
                    EffectJournalEvent::Lifecycle {
                        event: LifecycleEvent::Commit,
                        ..
                    }
                )
                | (
                    Self::Defer,
                    EffectJournalEvent::Lifecycle {
                        event: LifecycleEvent::Defer,
                        ..
                    }
                )
                | (
                    Self::Acknowledge,
                    EffectJournalEvent::Lifecycle {
                        event: LifecycleEvent::Acknowledge,
                        ..
                    }
                )
        )
    }
}

#[derive(Debug)]
struct JournalState {
    encoder: EffectJournalEncoder,
    bytes: Vec<u8>,
    acknowledged: EffectJournalPosition,
    failure: Option<(FailurePoint, bool)>,
}

#[derive(Clone, Debug)]
struct Capture(Rc<RefCell<JournalState>>);

#[derive(Debug)]
struct Sink(Capture);

impl EffectJournalSink for Sink {
    fn run_commitment(&self) -> IntentRunCommitment {
        self.0.0.borrow().encoder.run_commitment()
    }
    fn position(&self) -> EffectJournalPosition {
        self.0.0.borrow().acknowledged
    }

    fn append(
        &mut self,
        entry: &EffectJournalEntry,
    ) -> Result<(), EffectJournalPersistenceRefusal> {
        let mut state = self.0.0.borrow_mut();
        let failure = state
            .failure
            .filter(|(point, _)| point.matches(&entry.event));
        if matches!(failure, Some((_, false))) {
            return Err(EffectJournalPersistenceRefusal::OutcomeUnknown);
        }
        let frame = state
            .encoder
            .encode(entry)
            .map_err(|_| EffectJournalPersistenceRefusal::Binding)?;
        state.bytes.extend(frame);
        if matches!(failure, Some((_, true))) {
            return Err(EffectJournalPersistenceRefusal::OutcomeUnknown);
        }
        state.acknowledged = state.encoder.position();
        Ok(())
    }
}

impl Capture {
    fn fail(&self, point: FailurePoint, after_write: bool) {
        self.0.borrow_mut().failure = Some((point, after_write));
    }

    fn decode(&self, run: &IntentRun) -> Result<RecoveredEffectJournal, EffectJournalCodecRefusal> {
        let state = self.0.borrow();
        RecoveredEffectJournal::decode(run, &state.bytes, Some(state.acknowledged))
    }
}

fn broker(run: &IntentRun) -> (CurrentAuthorityRevocationCheckedEffectBroker, Capture) {
    let (encoder, bytes) = EffectJournalEncoder::new(run).unwrap();
    let acknowledged = encoder.position();
    let capture = Capture(Rc::new(RefCell::new(JournalState {
        encoder,
        bytes,
        acknowledged,
        failure: None,
    })));
    let broker = CurrentAuthorityRevocationCheckedEffectBroker::open_with_journal(
        run.clone(),
        RegionId::new(7),
        AgentInstanceId::new(7),
        Box::new(Sink(capture.clone())),
    )
    .unwrap();
    (broker, capture)
}

fn reserve(
    fixture: &Fixture,
    owner: &mut CurrentAuthorityRevocationCheckedEffectBroker,
    binding: &RefTransactionBinding,
) -> ReservedRefTransactionSubmission {
    owner
        .reserve_ref_transaction(
            binding,
            &chain(OperationClass::PublishRefTransaction),
            &fixture.revocations(20),
            LogicalTime::new(21),
            cost(),
        )
        .unwrap()
}

fn start(
    fixture: &Fixture,
    owner: &mut CurrentAuthorityRevocationCheckedEffectBroker,
    reserved: ReservedRefTransactionSubmission,
) -> PendingRefTransactionSubmission {
    owner
        .start_ref_transaction(
            reserved,
            &chain(OperationClass::PublishRefTransaction),
            &fixture.revocations(20),
            LogicalTime::new(22),
        )
        .unwrap()
}

fn before_start(refusal: RefTransactionStartRefused) -> ReservedRefTransactionSubmission {
    let RefTransactionStartRefused::BeforeStart { reservation, .. } = refusal else {
        panic!("pre-start refusal must retain an abortable reservation");
    };
    *reservation
}

#[test]
fn committed_and_refused_decisions_settle_only_after_authenticated_observation() {
    for committed in [false, true] {
        let fixture = Fixture::new(701 + u64::from(committed));
        let attempt = seal_attempt(b"canonical-outcome");
        let binding = submission_binding(&fixture.run, &attempt);
        let (mut owner, capture) = broker(&fixture.run);
        let reserved = reserve(&fixture, &mut owner, &binding);
        let initial = reserved.initial_authorization();
        let pending = start(&fixture, &mut owner, reserved);
        let started = pending.start_authorization();
        assert_eq!(owner.dispatch_authorizations().len(), 1);
        assert_eq!(owner.generic_dispatch_authorizations().len(), 1);
        assert_eq!(
            owner.records()[0].obligation_state,
            ObligationState::DeferredExternally
        );
        assert_eq!(owner.records()[0].budget_consumed, cost());
        assert_eq!(owner.records()[0].terminal_outcome, None);

        let original_head = fixture.store.read_head(&fixture.head_key).unwrap();
        let view = AsyncView::new(&fixture.store);
        let RefTransactionResolution::Pending(pending) =
            poll_ready(pending.reconcile_async(&view, &(), &fixture.head_key)).unwrap()
        else {
            panic!("starting submission responsibility cannot invent a terminal");
        };
        assert!(
            poll_ready(read_seal_async(
                &view,
                &(),
                TENANT,
                REPOSITORY,
                binding.tx_id(),
            ))
            .unwrap()
            .is_none()
        );
        assert_eq!(
            fixture.store.read_head(&fixture.head_key).unwrap(),
            original_head
        );
        view.assert_read_only();

        let sealed = seal_request(&fixture.store, &attempt).unwrap();
        assert_eq!(sealed.tx_id(), binding.tx_id());
        let terminal = fixture.decide(binding.tx_id(), committed);
        let after = fixture.store.read_head(&fixture.head_key).unwrap();
        let RefTransactionResolution::Decided(settled) =
            poll_ready(pending.reconcile_async(&view, &(), &fixture.head_key)).unwrap()
        else {
            panic!("the authenticated canonical terminal must settle responsibility");
        };
        assert_eq!(settled.observation().terminal(), &terminal);
        assert_eq!(settled.observation().binding(), &binding);
        assert_eq!(settled.initial_authorization(), initial);
        assert_eq!(settled.start_authorization(), started);
        assert_eq!(settled.settled().state(), ObligationState::Acknowledged);
        assert_eq!(
            owner.records()[0].terminal_outcome,
            Some(EffectTerminalOutcome::Acknowledged)
        );
        assert_eq!(owner.records()[0].budget_consumed, cost());
        assert_eq!(owner.records()[0].output_commitments.len(), 1);
        assert_eq!(
            owner.records()[0].output_commitments[0].as_slice(),
            settled.observation().commitment().bytes().as_bytes(),
        );
        // Acknowledgement records a terminal observation, including refusal.
        assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }) == committed);
        assert_eq!(fixture.store.read_head(&fixture.head_key).unwrap(), after);
        view.assert_read_only();
        let recovered = capture.decode(&fixture.run).unwrap();
        assert_eq!(recovered.records(), owner.records());
        assert_eq!(
            recovered.ref_transactions().get(&binding.effect_id()),
            Some(&binding)
        );
        let report = recovered
            .reconciliation_report(&fixture.run, LogicalTime::new(40))
            .unwrap();
        assert_eq!(report.readiness(), RunReconciliationReadiness::Ready);
        assert!(!report.has_unsettled_effects());
        assert!(owner.close().is_quiescent());
    }
}

#[test]
fn observation_uses_the_full_seal_exact_transaction_store_slot_and_run() {
    let fixture = Fixture::new(710);
    let attempt = seal_attempt(b"the-decided-transaction");
    let binding = submission_binding(&fixture.run, &attempt);
    seal_request(&fixture.store, &attempt).unwrap();
    let terminal = fixture.decide(binding.tx_id(), true);
    let view = AsyncView::new(&fixture.store);

    let other = submission_binding(&fixture.run, &seal_attempt(b"another-idempotency-key"));
    assert_ne!(binding.tx_id(), other.tx_id());
    assert!(
        poll_ready(observe_ref_transaction_async(
            &view,
            &(),
            &fixture.head_key,
            &fixture.run,
            &other,
        ))
        .unwrap()
        .is_none(),
        "another transaction's terminal is not this one's outcome"
    );

    let mut changed_seal = binding.seal().clone();
    changed_seal.authenticated_principal_id = PrincipalId::from_bytes([0x45; 16]);
    let wrong_seal = RefTransactionBinding::from_parts(
        fixture.run.commitment().unwrap(),
        changed_seal,
        *binding.publication_binding(),
    )
    .unwrap();
    assert_eq!(wrong_seal.tx_id(), binding.tx_id());
    assert!(
        matches!(
            poll_ready(observe_ref_transaction_async(
                &view,
                &(),
                &fixture.head_key,
                &fixture.run,
                &wrong_seal,
            )),
            Err(RefTransactionObservationRefusal::Binding)
        ),
        "a matching TxId is insufficient when the complete stored seal differs"
    );

    let changed_run = IntentRun::new_authenticated(
        fixture.run.run_id(),
        fixture.run.authority_read_receipt().unwrap().clone(),
        fixture.run.allowed_operation_classes(),
        fixture.run.resource_budget(),
        LogicalTime::new(101),
    )
    .unwrap();
    assert!(matches!(
        poll_ready(observe_ref_transaction_async(
            &view,
            &(),
            &fixture.head_key,
            &changed_run,
            &binding,
        )),
        Err(RefTransactionObservationRefusal::Binding)
    ));

    let wrong_slot = HeadKey::new(b"same-body-other-slot".to_vec()).unwrap();
    initialize_repository(&fixture.store, &wrong_slot, &fixture.genesis).unwrap();
    assert!(matches!(
        poll_ready(observe_ref_transaction_async(
            &view,
            &(),
            &wrong_slot,
            &fixture.run,
            &binding,
        )),
        Err(RefTransactionObservationRefusal::Historical(_))
    ));
    let unrelated = Fixture::new(711);
    let wrong_store = AsyncView::new(&unrelated.store);
    assert!(matches!(
        poll_ready(observe_ref_transaction_async(
            &wrong_store,
            &(),
            &unrelated.head_key,
            &fixture.run,
            &binding,
        )),
        Err(RefTransactionObservationRefusal::Historical(_))
    ));
    let observed = poll_ready(observe_ref_transaction_async(
        &view,
        &(),
        &fixture.head_key,
        &fixture.run,
        &binding,
    ))
    .unwrap()
    .unwrap();
    assert_eq!(observed.terminal(), &terminal);
    view.assert_read_only();
    wrong_store.assert_read_only();

    let unsealed = Fixture::new(712);
    let unsealed_binding = submission_binding(&unsealed.run, &seal_attempt(b"missing-seal"));
    unsealed.decide(unsealed_binding.tx_id(), false);
    assert!(
        matches!(
            poll_ready(observe_ref_transaction_async(
                &AsyncView::new(&unsealed.store),
                &(),
                &unsealed.head_key,
                &unsealed.run,
                &unsealed_binding,
            )),
            Err(RefTransactionObservationRefusal::Binding)
        ),
        "even a canonical terminal cannot substitute for the exact ordinary seal"
    );
}

#[test]
fn sibling_brokers_and_changed_complete_runs_cannot_take_submission_custody() {
    let fixture = Fixture::new(720);
    let binding = submission_binding(&fixture.run, &seal_attempt(b"owner-custody"));
    let (mut owner, _) = broker(&fixture.run);
    let (mut sibling, _) = broker(&fixture.run);
    let reserved = reserve(&fixture, &mut owner, &binding);
    let before = owner.records();
    let history = owner.journal();
    let refusal = sibling
        .start_ref_transaction(
            reserved,
            &chain(OperationClass::PublishRefTransaction),
            &fixture.revocations(20),
            LogicalTime::new(22),
        )
        .unwrap_err();
    assert!(matches!(
        &refusal,
        RefTransactionStartRefused::BeforeStart {
            reason: RefTransactionEffectRefusal::Binding,
            ..
        }
    ));
    assert_eq!(owner.records(), before);
    assert_eq!(owner.journal(), history);
    assert!(sibling.records().is_empty());
    let reserved = before_start(refusal);

    let changed_run = IntentRun::new_authenticated(
        fixture.run.run_id(),
        fixture.run.authority_read_receipt().unwrap().clone(),
        fixture.run.allowed_operation_classes(),
        fixture.run.resource_budget(),
        LogicalTime::new(150),
    )
    .unwrap();
    let (mut other_run, _) = broker(&changed_run);
    assert_eq!(other_run.run_id(), owner.run_id());
    assert_ne!(other_run.run_commitment(), owner.run_commitment());
    let refusal = other_run
        .start_ref_transaction(
            reserved,
            &chain(OperationClass::PublishRefTransaction),
            &fixture.revocations(20),
            LogicalTime::new(22),
        )
        .unwrap_err();
    assert!(matches!(
        &refusal,
        RefTransactionStartRefused::BeforeStart {
            reason: RefTransactionEffectRefusal::Binding,
            ..
        }
    ));
    assert!(other_run.records().is_empty());
    let pending = start(&fixture, &mut owner, before_start(refusal));
    let attempt = seal_attempt(b"owner-custody");
    seal_request(&fixture.store, &attempt).unwrap();
    fixture.decide(binding.tx_id(), true);
    assert!(matches!(
        poll_ready(pending.reconcile_async(
            &AsyncView::new(&fixture.store),
            &(),
            &fixture.head_key,
        ))
        .unwrap(),
        RefTransactionResolution::Decided(_)
    ));
    assert!(owner.close().is_quiescent());
    assert!(sibling.close().is_quiescent());
    assert!(other_run.close().is_quiescent());
}

#[test]
fn durable_custody_and_publication_capability_are_required_before_reserving() {
    let fixture = Fixture::new(730);
    let binding = submission_binding(&fixture.run, &seal_attempt(b"publication-capability"));
    let mut volatile = CurrentAuthorityRevocationCheckedEffectBroker::open(
        fixture.run.clone(),
        RegionId::new(7),
        AgentInstanceId::new(7),
    )
    .unwrap();
    assert!(matches!(
        volatile.reserve_ref_transaction(
            &binding,
            &chain(OperationClass::PublishRefTransaction),
            &fixture.revocations(20),
            LogicalTime::new(21),
            cost(),
        ),
        Err(RefTransactionEffectRefusal::DurableJournalRequired)
    ));
    assert!(volatile.records().is_empty());
    assert!(volatile.close().is_quiescent());

    let (mut owner, _) = broker(&fixture.run);
    assert!(matches!(
        owner.reserve_ref_transaction(
            &binding,
            &chain(OperationClass::PreparePublication),
            &fixture.revocations(20),
            LogicalTime::new(21),
            cost(),
        ),
        Err(RefTransactionEffectRefusal::Authorization(_))
    ));
    assert!(owner.records().is_empty());
    let reserved = reserve(&fixture, &mut owner, &binding);
    let settled = reserved.abort(NoCandidateReason::Cancelled).unwrap();
    assert_eq!(settled.state(), ObligationState::Aborted);
    assert_eq!(owner.records()[0].budget_consumed, ResourceVector::ZERO);
    assert!(owner.close().is_quiescent());
}

#[test]
fn fresh_revocation_and_expiry_refusals_return_the_live_prestart_reservation() {
    for case in 0..3 {
        let fixture = Fixture::new(740 + case);
        let binding = submission_binding(&fixture.run, &seal_attempt(b"fresh-before-start"));
        let (mut owner, capture) = broker(&fixture.run);
        let reserved = reserve(&fixture, &mut owner, &binding);
        let initial = reserved.initial_authorization();
        let history = owner.journal();
        let (revocations, now) = match case {
            0 => {
                fixture.revoke(&[CapabilityId::new(1)]);
                (fixture.revocations(30), 31)
            }
            1 => (fixture.revocations(20), 90),
            _ => (fixture.revocations(20), 100),
        };
        let refusal = owner
            .start_ref_transaction(
                reserved,
                &chain(OperationClass::PublishRefTransaction),
                &revocations,
                LogicalTime::new(now),
            )
            .unwrap_err();
        let RefTransactionStartRefused::BeforeStart {
            reservation,
            reason,
        } = refusal
        else {
            panic!("revoked or expired authority cannot commit submission responsibility");
        };
        let RefTransactionEffectRefusal::FreshAuthorization(reason) = reason else {
            panic!("the new authorization must produce the refusal");
        };
        // Revocation receipts are clipped to run expiry; at that deadline
        // the existing freshness gate refuses before the run-lifetime gate.
        assert!(match (case, &*reason) {
            (0, CapabilityEffectAuthorizationRefusal::CapabilityRevoked { chain_index: 0, .. })
            | (1, CapabilityEffectAuthorizationRefusal::CapabilityNotValid { .. })
            | (2, CapabilityEffectAuthorizationRefusal::RevocationReadStale { .. }) => true,
            _ => false,
        });
        assert_eq!(reservation.initial_authorization(), initial);
        assert_eq!(owner.journal(), history);
        assert!(owner.dispatch_authorizations().is_empty());
        assert!(owner.generic_dispatch_authorizations().is_empty());
        assert_eq!(
            owner.records()[0].obligation_state,
            ObligationState::Reserved
        );
        let _settled = reservation.abort(NoCandidateReason::Cancelled).unwrap();
        assert_eq!(
            owner.records()[0].obligation_state,
            ObligationState::Aborted
        );
        assert_eq!(owner.records()[0].budget_consumed, ResourceVector::ZERO);
        let report = capture
            .decode(&fixture.run)
            .unwrap()
            .reconciliation_report(&fixture.run, LogicalTime::new(101))
            .unwrap();
        assert_eq!(report.readiness(), RunReconciliationReadiness::Ready);
        assert!(owner.close().is_quiescent());
    }
}

#[test]
fn observation_failure_retains_pending_debt_and_later_revocation_does_not_block_cleanup() {
    let fixture = Fixture::new(750);
    let attempt = seal_attempt(b"pending-observation");
    let binding = submission_binding(&fixture.run, &attempt);
    let (mut owner, capture) = broker(&fixture.run);
    let reserved = reserve(&fixture, &mut owner, &binding);
    let pending = start(&fixture, &mut owner, reserved);
    let wrong = Fixture::new(751);
    let refused =
        poll_ready(pending.reconcile_async(&AsyncView::new(&wrong.store), &(), &wrong.head_key))
            .unwrap_err();
    let RefTransactionReconciliationRefused::Pending { pending, reason } = refused else {
        panic!("a failed authority read cannot settle responsibility");
    };
    assert!(matches!(
        reason,
        RefTransactionObservationRefusal::Historical(_)
    ));
    assert_eq!(pending.binding(), &binding);
    assert_eq!(
        owner.records()[0].obligation_state,
        ObligationState::DeferredExternally
    );
    let report = capture
        .decode(&fixture.run)
        .unwrap()
        .reconciliation_report(&fixture.run, LogicalTime::new(30))
        .unwrap();
    assert_eq!(
        report.readiness(),
        RunReconciliationReadiness::EffectReconciliationRequired
    );
    assert!(report.has_unsettled_effects());
    assert!(owner.journal().iter().all(|entry| !matches!(
        entry.event,
        EffectJournalEvent::Lifecycle {
            event: LifecycleEvent::Abort,
            ..
        }
    )));

    fixture.revoke(&[CapabilityId::new(1)]);
    seal_request(&fixture.store, &attempt).unwrap();
    let terminal = fixture.decide(binding.tx_id(), false);
    assert!(!fixture.run.is_open_at(LogicalTime::new(101)));
    let view = AsyncView::new(&fixture.store);
    let RefTransactionResolution::Decided(settled) =
        poll_ready((*pending).reconcile_async(&view, &(), &fixture.head_key)).unwrap()
    else {
        panic!("historical cleanup is permitted after authority expires or is revoked");
    };
    assert_eq!(settled.observation().terminal(), &terminal);
    view.assert_read_only();
    assert!(owner.close().is_quiescent());
}

#[test]
fn new_binding_events_roundtrip_with_existing_journal_events_and_exact_tail_anchors() {
    let fixture = Fixture::new(760);
    let (mut owner, capture) = broker(&fixture.run);
    let low_risk = Capability::issue(
        CapabilityId::new(3),
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        resources(256, 1),
        LogicalTime::new(0),
        LogicalTime::new(100),
    )
    .unwrap();
    let grant = owner
        .request_low_risk(
            &low_risk,
            LogicalTime::new(20),
            &EffectRequest {
                effect_id: EffectId::new(99),
                parent_effect_id: None,
                operation: OperationClass::ReadCanonicalObject,
                cost: resources(16, 1),
                input_commitment: [0x91; 32],
            },
        )
        .unwrap();
    let _released = owner.abort_low_risk(grant).unwrap();
    let legacy_tail = capture.0.borrow().acknowledged;

    let binding = submission_binding(&fixture.run, &seal_attempt(b"journal-roundtrip"));
    let reserved = reserve(&fixture, &mut owner, &binding);
    let pending = start(&fixture, &mut owner, reserved);
    let recovered = capture.decode(&fixture.run).unwrap();
    assert_eq!(recovered.entries(), owner.journal());
    assert_eq!(recovered.records(), owner.records());
    assert_eq!(recovered.ref_transactions().len(), 1);
    assert_eq!(recovered.ref_transactions()[&binding.effect_id()], binding);
    assert_eq!(
        recovered.records()[0].operation,
        OperationClass::ReadCanonicalObject
    );
    assert_eq!(
        recovered.records()[1].obligation_class,
        Some(ObligationClass::RefTransactionSubmission)
    );
    let report = recovered
        .reconciliation_report(&fixture.run, LogicalTime::new(30))
        .unwrap();
    assert_eq!(report.counts().aborted(), 1);
    assert_eq!(report.counts().committed_or_deferred(), 1);

    let state = capture.0.borrow();
    assert!(matches!(
        RecoveredEffectJournal::decode(&fixture.run, &state.bytes, Some(legacy_tail)),
        Err(EffectJournalCodecRefusal::AnchorMismatch)
    ));
    let unanchored = RecoveredEffectJournal::decode(&fixture.run, &state.bytes, None).unwrap();
    assert!(matches!(
        unanchored.reconciliation_report(&fixture.run, LogicalTime::new(30)),
        Err(EffectJournalCodecRefusal::AnchorRequired)
    ));
    let mut changed = state.bytes.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(
        RecoveredEffectJournal::decode(&fixture.run, &changed, Some(state.acknowledged),).is_err()
    );
    assert!(
        RecoveredEffectJournal::decode(
            &fixture.run,
            &state.bytes[..state.bytes.len() - 1],
            Some(state.acknowledged),
        )
        .is_err()
    );
    drop(state);

    let attempt = seal_attempt(b"journal-roundtrip");
    seal_request(&fixture.store, &attempt).unwrap();
    fixture.decide(binding.tx_id(), true);
    assert!(matches!(
        poll_ready(pending.reconcile_async(
            &AsyncView::new(&fixture.store),
            &(),
            &fixture.head_key,
        ))
        .unwrap(),
        RefTransactionResolution::Decided(_)
    ));
    assert!(owner.close().is_quiescent());
}

#[test]
fn failed_reservation_journals_release_unstarted_resources_and_poison_new_issuance() {
    for (index, point) in [
        FailurePoint::Accepted,
        FailurePoint::Binding,
        FailurePoint::Bound,
    ]
    .into_iter()
    .enumerate()
    {
        for after_write in [false, true] {
            let fixture = Fixture::new(770 + index as u64 * 2 + u64::from(after_write));
            let binding =
                submission_binding(&fixture.run, &seal_attempt(b"reservation-journal-failure"));
            let (mut owner, capture) = broker(&fixture.run);
            capture.fail(point, after_write);
            let before = fixture.store.read_head(&fixture.head_key).unwrap();
            assert!(
                owner
                    .reserve_ref_transaction(
                        &binding,
                        &chain(OperationClass::PublishRefTransaction),
                        &fixture.revocations(20),
                        LogicalTime::new(21),
                        cost(),
                    )
                    .is_err()
            );
            assert!(owner.durable_position().is_err());
            assert!(
                owner
                    .records()
                    .iter()
                    .all(|record| record.budget_consumed.is_zero())
            );
            // An ambiguous first acceptance retains its nonterminal inspection
            // record, but its unexposed budget grant is released. Later bind
            // failures can explicitly abort the already-accepted record.
            for record in owner.records() {
                if matches!(point, FailurePoint::Accepted) {
                    assert_eq!(record.obligation_state, ObligationState::Reserved);
                    assert_eq!(record.terminal_outcome, None);
                } else {
                    assert_eq!(record.obligation_state, ObligationState::Aborted);
                    assert_eq!(
                        record.terminal_outcome,
                        Some(EffectTerminalOutcome::Aborted)
                    );
                }
            }
            assert!(
                owner
                    .reserve_ref_transaction(
                        &binding,
                        &chain(OperationClass::PublishRefTransaction),
                        &fixture.revocations(20),
                        LogicalTime::new(21),
                        cost(),
                    )
                    .is_err()
            );
            assert_eq!(fixture.store.read_head(&fixture.head_key).unwrap(), before);
            assert!(
                owner.close().is_quiescent(),
                "no pre-start failure may leak a live grant"
            );
        }
    }
}

#[test]
fn journal_failures_after_start_retain_debt_and_never_dispatch_or_abort() {
    for (index, point) in [FailurePoint::Commit, FailurePoint::Defer]
        .into_iter()
        .enumerate()
    {
        for after_write in [false, true] {
            let fixture = Fixture::new(780 + index as u64 * 2 + u64::from(after_write));
            let binding = submission_binding(&fixture.run, &seal_attempt(b"start-journal-failure"));
            let (mut owner, capture) = broker(&fixture.run);
            let reserved = reserve(&fixture, &mut owner, &binding);
            capture.fail(point, after_write);
            let original_head = fixture.store.read_head(&fixture.head_key).unwrap();
            let refused = owner
                .start_ref_transaction(
                    reserved,
                    &chain(OperationClass::PublishRefTransaction),
                    &fixture.revocations(20),
                    LogicalTime::new(22),
                )
                .unwrap_err();
            let RefTransactionStartRefused::AfterStart { pending, .. } = refused else {
                panic!("a committed resource obligation must return pending responsibility");
            };
            assert_eq!(owner.dispatch_authorizations().len(), 1);
            assert_eq!(owner.generic_dispatch_authorizations().len(), 1);
            assert_eq!(
                owner.records()[0].obligation_state,
                ObligationState::DeferredExternally
            );
            assert_eq!(owner.records()[0].budget_consumed, cost());
            assert!(owner.durable_position().is_err());
            let view = AsyncView::new(&fixture.store);
            let RefTransactionResolution::Pending(pending) =
                poll_ready((*pending).reconcile_async(&view, &(), &fixture.head_key)).unwrap()
            else {
                panic!("journal failure cannot manufacture an authority outcome");
            };
            assert!(
                poll_ready(read_seal_async(
                    &view,
                    &(),
                    TENANT,
                    REPOSITORY,
                    binding.tx_id(),
                ))
                .unwrap()
                .is_none(),
                "the broker must not submit after its start mirror failed"
            );
            view.assert_read_only();
            assert_eq!(
                fixture.store.read_head(&fixture.head_key).unwrap(),
                original_head
            );
            assert!(owner.journal().iter().all(|entry| !matches!(
                entry.event,
                EffectJournalEvent::Lifecycle {
                    event: LifecycleEvent::Abort,
                    ..
                }
            )));
            if after_write {
                assert!(matches!(
                    capture.decode(&fixture.run),
                    Err(EffectJournalCodecRefusal::AnchorMismatch)
                ));
            }
            // Dropping responsibility is deliberately classified as a leak;
            // no API silently turns a post-start unknown outcome into an abort.
            drop(pending);
            assert!(!owner.close().is_quiescent());
        }
    }
}

#[test]
fn acknowledgement_mirror_failure_retains_the_authoritative_terminal_and_settlement() {
    for after_write in [false, true] {
        let fixture = Fixture::new(790 + u64::from(after_write));
        let attempt = seal_attempt(b"acknowledgement-journal-failure");
        let binding = submission_binding(&fixture.run, &attempt);
        let (mut owner, capture) = broker(&fixture.run);
        let reserved = reserve(&fixture, &mut owner, &binding);
        let pending = start(&fixture, &mut owner, reserved);
        seal_request(&fixture.store, &attempt).unwrap();
        let terminal = fixture.decide(binding.tx_id(), false);
        capture.fail(FailurePoint::Acknowledge, after_write);
        let view = AsyncView::new(&fixture.store);
        let refusal =
            poll_ready(pending.reconcile_async(&view, &(), &fixture.head_key)).unwrap_err();
        let RefTransactionReconciliationRefused::JournalAfterSettlement { settled, .. } = refusal
        else {
            panic!("post-settlement persistence failure must preserve terminal evidence");
        };
        assert_eq!(settled.observation().terminal(), &terminal);
        assert_eq!(settled.observation().binding(), &binding);
        assert_eq!(settled.settled().state(), ObligationState::Acknowledged);
        assert_eq!(
            owner.records()[0].obligation_state,
            ObligationState::Acknowledged
        );
        assert!(owner.durable_position().is_err());
        view.assert_read_only();
        if after_write {
            assert!(matches!(
                capture.decode(&fixture.run),
                Err(EffectJournalCodecRefusal::AnchorMismatch)
            ));
        } else {
            let recovered = capture.decode(&fixture.run).unwrap();
            assert_eq!(
                recovered.records()[0].obligation_state,
                ObligationState::DeferredExternally
            );
            assert_eq!(
                recovered
                    .reconciliation_report(&fixture.run, LogicalTime::new(40))
                    .unwrap()
                    .readiness(),
                RunReconciliationReadiness::EffectReconciliationRequired
            );
            let reread = poll_ready(observe_ref_transaction_async(
                &view,
                &(),
                &fixture.head_key,
                &fixture.run,
                &recovered.ref_transactions()[&binding.effect_id()],
            ))
            .unwrap()
            .unwrap();
            assert_eq!(reread.terminal(), &terminal);
        }
        assert!(
            owner.close().is_quiescent(),
            "resource settlement survives its failed mirror"
        );
    }
}

#[test]
fn custody_pins_survive_recovery_and_cannot_acknowledge_another_bundle() {
    use crate::broker::ref_publication::AcknowledgementFailure;

    let fixture = Fixture::new(800);
    let attempt = seal_attempt(b"custody-pin");
    let unpinned = submission_binding(&fixture.run, &attempt);
    let binding = unpinned
        .clone()
        .with_custody_commitment([0xa1; 32])
        .unwrap();
    let substituted = unpinned
        .clone()
        .with_custody_commitment([0xa2; 32])
        .unwrap();
    assert_eq!(unpinned.custody_commitment(), None);
    assert_eq!(binding.custody_commitment(), Some([0xa1; 32]));
    assert_eq!(binding.tx_id(), unpinned.tx_id());
    assert_eq!(binding.seal(), substituted.seal());
    assert_ne!(binding.effect_id(), unpinned.effect_id());
    assert_ne!(binding.effect_id(), substituted.effect_id());
    assert_ne!(binding.input_commitment(), substituted.input_commitment());

    let (mut owner, capture) = broker(&fixture.run);
    let reserved = reserve(&fixture, &mut owner, &binding);
    let pending = start(&fixture, &mut owner, reserved);
    let recovered = capture.decode(&fixture.run).unwrap();
    assert_eq!(recovered.ref_transactions()[&binding.effect_id()], binding);
    assert_eq!(
        recovered.ref_transactions()[&binding.effect_id()].custody_commitment(),
        Some([0xa1; 32]),
    );
    seal_request(&fixture.store, &attempt).unwrap();
    let terminal = fixture.decide(binding.tx_id(), true);
    let view = AsyncView::new(&fixture.store);
    let wrong_observation = poll_ready(observe_ref_transaction_async(
        &view,
        &(),
        &fixture.head_key,
        &fixture.run,
        &substituted,
    ))
    .unwrap()
    .unwrap();
    assert_eq!(wrong_observation.terminal(), &terminal);
    let before = owner.journal();
    let PendingRefTransactionSubmission {
        run,
        initial,
        started,
        raw,
    } = pending;
    let refused = raw.acknowledge(&wrong_observation);
    let Err(AcknowledgementFailure::Before {
        pending: raw,
        reason,
    }) = refused
    else {
        panic!("a real terminal for the same TxId cannot settle another custody binding");
    };
    assert!(matches!(
        reason,
        EffectJournalRefusal::RefTransactionBinding { .. }
    ));
    assert_eq!(owner.journal(), before);
    assert_eq!(
        owner.records()[0].obligation_state,
        ObligationState::DeferredExternally
    );
    let pending = PendingRefTransactionSubmission {
        run,
        initial,
        started,
        raw,
    };
    let RefTransactionResolution::Decided(settled) =
        poll_ready(pending.reconcile_async(&view, &(), &fixture.head_key)).unwrap()
    else {
        panic!("the original complete binding must still settle");
    };
    assert_eq!(settled.observation().binding(), &binding);
    assert_eq!(settled.observation().terminal(), &terminal);
    assert_eq!(
        capture.decode(&fixture.run).unwrap().ref_transactions()[&binding.effect_id()],
        binding,
    );
    view.assert_read_only();
    assert!(owner.close().is_quiescent());
}

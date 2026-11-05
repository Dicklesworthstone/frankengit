#![forbid(unsafe_code)]
//! Actual-file cleanup tests over the production file owner. Public TreeFS/ECC
//! preparation, ordinary seals and the reference authority produce the original
//! binding and authenticated terminal. ECC assertions are test inputs, not
//! executed verifier evidence. These are component tests, not a native-node gate.

// Reuse the real export/public preparation builders. Their alternative authority
// fixture is unnecessary here because this fixture publishes its base RCR too.
#[allow(dead_code)]
#[path = "../../../fgit-agent/tests/publication/fixture.rs"]
mod publication_fixture;

use std::{
    cell::{Cell, RefCell},
    fs::{self, File, OpenOptions},
    future::{Future, ready},
    io::Write,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use fgit_agent::{
    AgentInstanceId, AttenuationRequest, AuthorityReadReceipt, Capability, CapabilityId, ClassSet,
    CurrentAuthorityRevocationCheckedEffectBroker, EffectJournalEntry, EffectTerminalOutcome,
    IntentRun, IntentRunCommitment, LogicalTime, OperationClass, RunId, RunReconciliationReadiness,
    VerifiedCapabilityChain, WorkspaceBinding,
    effect_journal::{
        EffectJournalEncoder, EffectJournalPersistenceRefusal, EffectJournalPosition,
        EffectJournalSink, RecoveredEffectJournal,
    },
    read_current_authority_capability_revocations,
    ref_publication::{
        ObservedRefTransaction, PreparedRefTransactionAcknowledgement, RefTransactionBinding,
        RefTransactionResolution, observe_ref_transaction_async,
        prepare_recovered_ref_transaction_acknowledgement,
    },
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore,
    AuthorityVersionToken, CapabilityRevocationGenerationBody, CasOutcome, DuplicateAbsenceWitness,
    ExpectedOld, HeadInit, HeadKey, HeadRead, HeadReadReceipt, IdempotencyKey, ImmutableKey,
    ImmutableRead, MemoryAuthorityStore, ProposedNew, PublicationOutcome, PutOutcome, RefCommand,
    SealAttempt, SemanticRequest, StoreInstanceId, TerminalOutcome, authority_head_identity,
    body_key, canonical_body_id, decision_batch_identity, initialize_repository,
    outcome_index_root, publish_decisions, seal_request, stage_capability_revocation_generation,
    stage_revocation_aware_repository_incarnation_configuration,
};
use fgit_codec::{
    RepositoryAuthorityHeadBody, RepositoryCommitRecord, RepositoryDecision,
    RepositoryDecisionBatchBody, RepositoryIncarnationConfigurationBodyV2_2, wire::encode_body,
};
use fgit_crypto::{IdentityDomain, Sha256};
use fgit_resource::{Grade, ObligationState, RegionId, ResourceVector, kinds::NoCandidateReason};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionOutcome, DecisionSequence, Digest, DigestBytes,
    GitHashAlgorithm as GitFormat, GitOid, HeadGeneration, PolicyEpoch, PrincipalId,
    PrincipalSnapshotId, RefName, RegistryEpoch, RepositoryCommitId, RepositoryId,
    RepositoryIncarnationId, RepositorySequence, RootLayoutVersion, SchemaFamily, SchemaId,
    TenantId, TxId,
};

use super::{
    file::{AgentJournalHostRefusal, journal_path, recover},
    settlement::FileRefTransactionSettlement,
};
use publication_fixture::{Evidence, digest};

const TENANT: TenantId = TenantId::from_bytes([0x11; 16]);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x27; 16]);
const INCARNATION: RepositoryIncarnationId = RepositoryIncarnationId::from_bytes([0x33; 16]);
const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0x44; 16]);
const ISSUER_KEY: &[u8] = b"file-ref-transaction-settlement-tests";
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-ref-settlement-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn resources(bytes: u64, objects: u64) -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::Bytes, bytes), (Grade::Objects, objects)])
}

fn cost() -> ResourceVector {
    resources(256, 1)
}

fn capability() -> VerifiedCapabilityChain {
    let root = Capability::issue(
        CapabilityId::new(1),
        ClassSet::from_classes(&[OperationClass::PublishRefTransaction]),
        resources(8_192, 32),
        LogicalTime::new(0),
        LogicalTime::new(100),
    )
    .unwrap();
    let root_seal = root.seal(ISSUER_KEY, None).unwrap();
    let leaf = root
        .attenuate(&AttenuationRequest {
            id: CapabilityId::new(2),
            operations: root.operations(),
            quota: resources(4_096, 16),
            not_before: LogicalTime::new(5),
            expires_at: LogicalTime::new(90),
        })
        .unwrap();
    let leaf_seal = leaf.seal(ISSUER_KEY, Some(root_seal.tag())).unwrap();
    VerifiedCapabilityChain::verify(&[root_seal, leaf_seal], ISSUER_KEY).unwrap()
}

fn configuration(store: &MemoryAuthorityStore) -> Digest {
    let generation = CapabilityRevocationGenerationBody::try_new(
        TENANT,
        REPOSITORY,
        INCARNATION,
        PolicyEpoch::FIRST,
        None,
        vec![],
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

fn current_head(
    store: &MemoryAuthorityStore,
    key: &HeadKey,
) -> (HeadReadReceipt, RepositoryAuthorityHeadBody) {
    let HeadRead::Present(receipt) = store.read_head(key).unwrap() else {
        panic!("the reference repository remains present");
    };
    let head = store
        .authenticate_head_receipt(&receipt)
        .unwrap()
        .body()
        .unwrap();
    (receipt, head)
}

/// Stage and publish an ordinary RCR and decision through the reference engine.
/// Object/ref validation is outside these filesystem component tests.
fn decide(
    store: &MemoryAuthorityStore,
    key: &HeadKey,
    tx_id: TxId,
    outcomes: &mut Vec<(TxId, TerminalOutcome)>,
) -> TerminalOutcome {
    let (receipt, previous) = current_head(store, key);
    let sequence = previous
        .latest_decision_sequence
        .map_or(DecisionSequence::FIRST, |value| value.next().unwrap());
    let repository_sequence = previous
        .latest_repository_sequence
        .map_or(RepositorySequence::FIRST, |value| value.next().unwrap());
    let seal = fgit_authority::read_seal(store, TENANT, REPOSITORY, tx_id)
        .unwrap()
        .unwrap();
    let record = RepositoryCommitRecord {
        repository_id: REPOSITORY,
        repository_sequence,
        parent_rcr_id: previous.latest_committed_rcr_id,
        tx_id,
        principal_snapshot_id: PrincipalSnapshotId::from_digest(
            IdentityDomain::PrincipalSnapshot.algorithm().id(),
            CANONICAL_CODEC_VERSION,
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
    };
    let rcr = RepositoryCommitId::from_internal_object_id(
        canonical_body_id(
            IdentityDomain::RepositoryCommitRecord,
            CANONICAL_CODEC_VERSION,
            &record,
        )
        .unwrap(),
    )
    .unwrap();
    store
        .put_if_absent(
            &body_key(IdentityDomain::RepositoryCommitRecord, &record).unwrap(),
            &encode_body(&record).unwrap(),
        )
        .unwrap();
    let terminal = TerminalOutcome {
        decision_sequence: sequence,
        outcome: DecisionOutcome::Committed {
            repository_commit_id: rcr,
        },
    };
    outcomes.push((tx_id, terminal.clone()));
    let outcome_root = outcome_index_root(outcomes).unwrap();
    let batch = RepositoryDecisionBatchBody {
        repository_id: REPOSITORY,
        predecessor_head_id: authority_head_identity(&previous).unwrap(),
        predecessor_head_generation: previous.generation,
        first_decision_sequence: sequence,
        decisions: vec![RepositoryDecision {
            tx_id,
            decision_sequence: sequence,
            outcome: terminal.outcome.clone(),
        }],
        committed_rcrs: vec![record],
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
        latest_decision_sequence: Some(sequence),
        latest_committed_rcr_id: Some(rcr),
        latest_repository_sequence: Some(repository_sequence),
        outcome_index_root: outcome_root,
        ..previous
    };
    assert!(matches!(
        publish_decisions(store, key, receipt.token(), &batch, &head, TENANT).unwrap(),
        PublicationOutcome::Published(_)
    ));
    terminal
}

#[derive(Debug)]
struct Capture {
    encoder: EffectJournalEncoder,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct CaptureSink(Rc<RefCell<Capture>>);

impl EffectJournalSink for CaptureSink {
    fn run_commitment(&self) -> IntentRunCommitment {
        self.0.borrow().encoder.run_commitment()
    }

    fn position(&self) -> EffectJournalPosition {
        self.0.borrow().encoder.position()
    }

    fn append(
        &mut self,
        entry: &EffectJournalEntry,
    ) -> Result<(), EffectJournalPersistenceRefusal> {
        let mut capture = self.0.borrow_mut();
        let frame = capture
            .encoder
            .encode(entry)
            .map_err(|_| EffectJournalPersistenceRefusal::Binding)?;
        capture.bytes.extend(frame);
        Ok(())
    }
}

struct Fixture {
    run: IntentRun,
    bytes: Vec<u8>,
    tail: EffectJournalPosition,
    observation: ObservedRefTransaction,
}

impl Fixture {
    fn new() -> Self {
        let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x6a31));
        let key = HeadKey::new(b"file-settlement-reference-head".to_vec()).unwrap();
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
            configuration_root: configuration(&store),
            policy_epoch: PolicyEpoch::FIRST,
            format_registry_epoch: RegistryEpoch::FIRST,
            last_checkpoint_id: None,
        };
        assert!(matches!(
            initialize_repository(&store, &key, &genesis).unwrap(),
            HeadInit::Created(_)
        ));
        let bootstrap = SealAttempt {
            tenant_id: TENANT,
            repository_id: REPOSITORY,
            authenticated_principal_id: PRINCIPAL,
            idempotency_key: IdempotencyKey::new(b"initial-base".to_vec()).unwrap(),
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
                vec![],
                vec![],
            )
            .unwrap(),
        };
        let bootstrap_id = seal_request(&store, &bootstrap).unwrap().tx_id();
        let mut outcomes = vec![];
        decide(&store, &key, bootstrap_id, &mut outcomes);
        let (head, _) = current_head(&store, &key);
        let authenticated = store.authenticate_head_receipt(&head).unwrap();
        let receipt = AuthorityReadReceipt::from_authenticated_head(
            &authenticated,
            LogicalTime::new(10),
            [0x51; 32],
        )
        .unwrap();
        let run = IntentRun::new_authenticated(
            RunId::new(305),
            receipt.clone(),
            ClassSet::from_classes(&[
                OperationClass::ReadCanonicalObject,
                OperationClass::TreeFsWorkspace,
                OperationClass::PreparePublication,
                OperationClass::PublishRefTransaction,
            ]),
            resources(16_384, 64),
            LogicalTime::new(100),
        )
        .unwrap();
        let mut change =
            publication_fixture::change::<Sha256>(&receipt, b"fn recovered_publication() {}\n");
        change.workspace =
            WorkspaceBinding::bind(run.clone(), change.workspace.snapshot().clone()).unwrap();
        let evidence = Evidence::new(
            &change.workspace,
            &change.proposal,
            &change.contexts,
            &change.overlay,
            &change.export,
        );
        let transaction = change
            .workspace
            .prepare_ref_transaction(
                change.proposal.clone(),
                &change.contexts,
                evidence.input(&change.overlay, &change.export),
            )
            .unwrap();
        let idempotency = IdempotencyKey::new(b"file-settlement-original".to_vec()).unwrap();
        let binding =
            RefTransactionBinding::derive(&transaction, TENANT, PRINCIPAL, idempotency.clone())
                .unwrap()
                .with_custody_commitment([0xa1; 32])
                .unwrap();
        let other_binding = RefTransactionBinding::derive(
            &transaction,
            TENANT,
            PRINCIPAL,
            IdempotencyKey::new(b"other-unstarted-effect".to_vec()).unwrap(),
        )
        .unwrap();
        let revocations = read_current_authority_capability_revocations(
            &store,
            TENANT,
            &key,
            &run,
            LogicalTime::new(20),
            1_000,
            32,
            32,
        )
        .unwrap();
        let (encoder, header) = EffectJournalEncoder::new(&run).unwrap();
        let capture = Rc::new(RefCell::new(Capture {
            encoder,
            bytes: header,
        }));
        let mut broker = CurrentAuthorityRevocationCheckedEffectBroker::open_with_journal(
            run.clone(),
            RegionId::new(7),
            AgentInstanceId::new(7),
            Box::new(CaptureSink(capture.clone())),
        )
        .unwrap();
        let chain = capability();
        let reserved = broker
            .reserve_ref_transaction(&binding, &chain, &revocations, LogicalTime::new(21), cost())
            .unwrap();
        let pending = broker
            .start_ref_transaction(reserved, &chain, &revocations, LogicalTime::new(22))
            .unwrap();
        let other = broker
            .reserve_ref_transaction(
                &other_binding,
                &chain,
                &revocations,
                LogicalTime::new(23),
                cost(),
            )
            .unwrap();
        // Snapshot the actual checked lifecycle at the crash boundary. Every
        // test below writes and fsyncs these independently encoded bytes itself.
        let (bytes, tail) = {
            let capture = capture.borrow();
            (capture.bytes.clone(), capture.encoder.position())
        };
        let attempt = transaction.seal_attempt(TENANT, PRINCIPAL, idempotency);
        assert_eq!(
            seal_request(&store, &attempt).unwrap().tx_id(),
            binding.tx_id()
        );
        let terminal = decide(&store, &key, binding.tx_id(), &mut outcomes);
        let view = AsyncView::new(&store);
        let head_before = store.read_head(&key).unwrap();
        let observation = poll_ready(observe_ref_transaction_async(
            &view,
            &(),
            &key,
            &run,
            &binding,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(observation.terminal(), &terminal);
        assert_eq!(store.read_head(&key).unwrap(), head_before);
        assert_eq!(view.writes.load(Ordering::SeqCst), 0);
        // Explicitly settle live fixture handles without changing the saved
        // crash prefix. File recovery never obtains these handles or a broker.
        assert!(matches!(
            poll_ready(pending.reconcile_async(&view, &(), &key)).unwrap(),
            RefTransactionResolution::Decided(_)
        ));
        let _aborted = other.abort(NoCandidateReason::Cancelled).unwrap();
        assert!(broker.close().is_quiescent());
        assert_eq!(view.writes.load(Ordering::SeqCst), 0);
        Self {
            run,
            bytes,
            tail,
            observation,
        }
    }

    fn prefix(&self) -> RecoveredEffectJournal {
        RecoveredEffectJournal::decode(&self.run, &self.bytes, Some(self.tail)).unwrap()
    }

    fn prepare(&self, prefix: &RecoveredEffectJournal) -> PreparedRefTransactionAcknowledgement {
        prepare_recovered_ref_transaction_acknowledgement(
            &self.run,
            prefix,
            &self.observation,
            LogicalTime::new(101),
        )
        .unwrap()
    }

    fn file(&self, suffix: &[u8]) -> Scratch {
        let directory = Scratch::new();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(journal_path(&directory.0, &self.run))
            .unwrap();
        file.write_all(&self.bytes).unwrap();
        file.write_all(suffix).unwrap();
        file.sync_all().unwrap();
        File::open(&directory.0).unwrap().sync_all().unwrap();
        directory
    }

    fn open(&self, directory: &Scratch) -> (FileRefTransactionSettlement, RecoveredEffectJournal) {
        FileRefTransactionSettlement::open(&directory.0, &self.run, self.tail, Box::new(|| Ok(())))
            .unwrap()
    }

    fn expected(&self) -> Vec<u8> {
        let mut bytes = self.bytes.clone();
        bytes.extend_from_slice(self.prepare(&self.prefix()).frame());
        bytes
    }

    fn assert_settled(&self, journal: &RecoveredEffectJournal) {
        let before = self.prefix();
        assert_eq!(journal.records().len(), 2);
        assert_eq!(journal.records()[1], before.records()[1]);
        assert_eq!(journal.ref_transactions(), before.ref_transactions());
        let record = &journal.records()[0];
        assert_eq!(record.obligation_state, ObligationState::Acknowledged);
        assert_eq!(
            record.terminal_outcome,
            Some(EffectTerminalOutcome::Acknowledged)
        );
        assert_eq!(record.budget_consumed, before.records()[0].budget_consumed);
        assert_eq!(record.budget_reserved, before.records()[0].budget_reserved);
        assert_eq!(
            record.output_commitments[0].as_slice(),
            self.observation.commitment().bytes().as_bytes()
        );
        let report = journal
            .reconciliation_report(&self.run, LogicalTime::new(101))
            .unwrap();
        assert_eq!(
            report.readiness(),
            RunReconciliationReadiness::ReservationAbortRequired
        );
        assert_eq!(report.counts().acknowledged(), 1);
        assert_eq!(report.counts().reserved(), 1);
        assert_eq!(report.cumulative_budget_consumed(), cost());
    }
}

/// Ready futures over the real reference authority; no alternate async runtime.
struct AsyncView<'a> {
    inner: &'a MemoryAuthorityStore,
    writes: AtomicUsize,
}

impl<'a> AsyncView<'a> {
    fn new(inner: &'a MemoryAuthorityStore) -> Self {
        Self {
            inner,
            writes: AtomicUsize::new(0),
        }
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
        ready(self.inner.read_immutable(key))
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
        ready(self.inner.read_head(key))
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
    match Box::pin(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("reference authority futures are ready"),
    }
}

#[test]
fn empty_partial_and_full_ack_suffixes_finish_once_and_preserve_other_debt() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare(&fixture.prefix());
    let frame = prepared.frame();
    for length in [0, 1, 4, frame.len() / 2, frame.len() - 1, frame.len()] {
        let directory = fixture.file(&frame[..length]);
        let path = journal_path(&directory.0, &fixture.run);
        let (mut owner, prefix) = fixture.open(&directory);
        assert_eq!(prefix.entries(), fixture.prefix().entries());
        let settled = fixture.prepare(&prefix).persist(&mut owner).unwrap();
        fixture.assert_settled(settled.journal());
        assert_eq!(fs::read(&path).unwrap(), fixture.expected());
        assert_eq!(settled.after_position().entries, fixture.tail.entries + 1);
        let new_tail = settled.after_position();
        drop(owner);

        // A lost response may leave the caller with its original anchor. The
        // exact already-written ACK is synchronized, never appended twice.
        let (mut owner, original_prefix) = fixture.open(&directory);
        let replayed = fixture
            .prepare(&original_prefix)
            .persist(&mut owner)
            .unwrap();
        assert_eq!(replayed.after_position(), new_tail);
        assert_eq!(fs::read(&path).unwrap(), fixture.expected());
        drop(owner);
        let recovered = recover(&directory.0, &fixture.run, Some(new_tail), &|| Ok(())).unwrap();
        fixture.assert_settled(&recovered);
        assert!(recover(&directory.0, &fixture.run, Some(fixture.tail), &|| Ok(())).is_err());
    }
}

#[test]
fn wrong_or_extra_suffix_is_never_truncated_or_acknowledged() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare(&fixture.prefix());
    let frame = prepared.frame();
    let mut wrong = frame[..frame.len() / 2].to_vec();
    wrong[0] ^= 1;
    let mut extra = frame.to_vec();
    extra.push(0);
    let mut duplicate = frame.to_vec();
    duplicate.extend_from_slice(frame);
    for suffix in [wrong, extra, duplicate] {
        let directory = fixture.file(&suffix);
        let path = journal_path(&directory.0, &fixture.run);
        let original = fs::read(&path).unwrap();
        let (mut owner, prefix) = fixture.open(&directory);
        let refused = fixture.prepare(&prefix).persist(&mut owner).unwrap_err();
        assert_eq!(refused.reason(), EffectJournalPersistenceRefusal::Binding);
        assert_eq!(refused.prepared().before_position(), fixture.tail);
        assert_eq!(refused.prepared().observation(), &fixture.observation);
        assert_eq!(fs::read(&path).unwrap(), original);
        let refused_again = refused.into_prepared().persist(&mut owner).unwrap_err();
        assert_eq!(
            refused_again.reason(),
            EffectJournalPersistenceRefusal::Unavailable
        );
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[test]
fn cleanup_retains_exclusive_file_custody_until_the_owner_is_dropped() {
    let fixture = Fixture::new();
    let directory = fixture.file(&[]);
    let (owner, _) = fixture.open(&directory);
    assert!(matches!(
        FileRefTransactionSettlement::open(
            &directory.0,
            &fixture.run,
            fixture.tail,
            Box::new(|| Ok(()))
        ),
        Err(AgentJournalHostRefusal::Busy)
    ));
    assert!(matches!(
        recover(&directory.0, &fixture.run, Some(fixture.tail), &|| Ok(())),
        Err(AgentJournalHostRefusal::Busy)
    ));
    drop(owner);
    let (mut owner, prefix) = fixture.open(&directory);
    fixture.assert_settled(
        fixture
            .prepare(&prefix)
            .persist(&mut owner)
            .unwrap()
            .journal(),
    );
}

#[test]
fn cancellation_before_append_keeps_the_original_prefix_and_a_retryable_candidate() {
    let fixture = Fixture::new();
    let directory = fixture.file(&[]);
    let path = journal_path(&directory.0, &fixture.run);
    let cancelled = Rc::new(Cell::new(false));
    let check = cancelled.clone();
    let (mut owner, prefix) = FileRefTransactionSettlement::open(
        &directory.0,
        &fixture.run,
        fixture.tail,
        Box::new(move || {
            if check.get() {
                Err(EffectJournalPersistenceRefusal::Cancelled)
            } else {
                Ok(())
            }
        }),
    )
    .unwrap();
    cancelled.set(true);
    let refused = fixture.prepare(&prefix).persist(&mut owner).unwrap_err();
    assert_eq!(refused.reason(), EffectJournalPersistenceRefusal::Cancelled);
    assert_eq!(fs::read(&path).unwrap(), fixture.bytes);
    assert_eq!(
        prefix.records()[0].obligation_state,
        ObligationState::DeferredExternally
    );
    drop(owner);
    let (mut retry, _) = fixture.open(&directory);
    let settled = refused.into_prepared().persist(&mut retry).unwrap();
    fixture.assert_settled(settled.journal());
    assert_eq!(fs::read(&path).unwrap(), fixture.expected());
}

#[test]
fn cancellation_after_append_retains_debt_and_retry_does_not_duplicate_the_ack() {
    let fixture = Fixture::new();
    let directory = fixture.file(&[]);
    let path = journal_path(&directory.0, &fixture.run);
    let check_path = path.clone();
    let old_length = fixture.tail.bytes;
    let (mut owner, prefix) = FileRefTransactionSettlement::open(
        &directory.0,
        &fixture.run,
        fixture.tail,
        Box::new(move || {
            if fs::metadata(&check_path).unwrap().len() > old_length {
                Err(EffectJournalPersistenceRefusal::Cancelled)
            } else {
                Ok(())
            }
        }),
    )
    .unwrap();
    let refused = fixture.prepare(&prefix).persist(&mut owner).unwrap_err();
    assert_eq!(refused.reason(), EffectJournalPersistenceRefusal::Cancelled);
    assert_eq!(refused.prepared().observation(), &fixture.observation);
    assert_eq!(refused.prepared().before_position(), fixture.tail);
    assert_eq!(fs::read(&path).unwrap(), fixture.expected());
    assert_eq!(
        prefix.records()[0].obligation_state,
        ObligationState::DeferredExternally
    );
    drop(owner);
    let (mut retry, _) = fixture.open(&directory);
    let settled = refused.into_prepared().persist(&mut retry).unwrap();
    fixture.assert_settled(settled.journal());
    assert_eq!(settled.after_position().entries, fixture.tail.entries + 1);
    assert_eq!(fs::read(&path).unwrap(), fixture.expected());
}

#[test]
fn an_already_acknowledged_new_tail_still_checks_cancellation_without_appending() {
    let fixture = Fixture::new();
    let directory = fixture.file(&[]);
    let path = journal_path(&directory.0, &fixture.run);
    let (mut owner, prefix) = fixture.open(&directory);
    let settled = fixture.prepare(&prefix).persist(&mut owner).unwrap();
    let new_tail = settled.after_position();
    drop(owner);
    let cancelled = Rc::new(Cell::new(false));
    let check = cancelled.clone();
    let (mut owner, acknowledged) = FileRefTransactionSettlement::open(
        &directory.0,
        &fixture.run,
        new_tail,
        Box::new(move || {
            if check.get() {
                Err(EffectJournalPersistenceRefusal::Cancelled)
            } else {
                Ok(())
            }
        }),
    )
    .unwrap();
    let prepared = fixture.prepare(&acknowledged);
    assert!(prepared.already_acknowledged());
    assert!(prepared.frame().is_empty());
    assert_eq!(prepared.before_position(), new_tail);
    assert_eq!(prepared.after_position(), new_tail);
    cancelled.set(true);
    let refused = prepared.persist(&mut owner).unwrap_err();
    assert_eq!(refused.reason(), EffectJournalPersistenceRefusal::Cancelled);
    assert_eq!(fs::read(&path).unwrap(), fixture.expected());
    drop(owner);
    let checks = Rc::new(Cell::new(0usize));
    let counter = checks.clone();
    let (mut retry, _) = FileRefTransactionSettlement::open(
        &directory.0,
        &fixture.run,
        new_tail,
        Box::new(move || {
            counter.set(counter.get() + 1);
            Ok(())
        }),
    )
    .unwrap();
    let checks_before = checks.get();
    let settled = refused.into_prepared().persist(&mut retry).unwrap();
    assert!(checks.get() > checks_before);
    assert!(settled.already_acknowledged());
    assert_eq!(settled.after_position(), new_tail);
    fixture.assert_settled(settled.journal());
    assert_eq!(fs::read(&path).unwrap(), fixture.expected());
}

#[test]
fn same_length_file_change_during_observation_refuses_without_writing() {
    let fixture = Fixture::new();
    let directory = fixture.file(&[]);
    let path = journal_path(&directory.0, &fixture.run);
    let (mut owner, prefix) = fixture.open(&directory);
    let mut changed = fixture.bytes.clone();
    *changed.last_mut().unwrap() ^= 1;
    // Model a writer violating the advisory lock. Exact snapshot revalidation
    // must reject it even when metadata length still matches the held prefix.
    let mut interfering = OpenOptions::new().write(true).open(&path).unwrap();
    interfering.write_all(&changed).unwrap();
    interfering.sync_all().unwrap();
    let refused = fixture.prepare(&prefix).persist(&mut owner).unwrap_err();
    assert_eq!(refused.reason(), EffectJournalPersistenceRefusal::Binding);
    assert_eq!(fs::read(&path).unwrap(), changed);
}

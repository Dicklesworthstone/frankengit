#![forbid(unsafe_code)]
//! Actual-file responsibility-log tests. The authority source below is the
//! repository's reference authority engine; it is not a durable-node claim.
//! The file host is the exact production module, not a mock transport.

use std::{
    cell::{Cell, RefCell},
    fs,
    io::Write,
    num::NonZeroU32,
    path::PathBuf,
    process::{Command, Stdio},
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

use fgit_agent::{
    AgentInstanceId, AuthorityReadReceipt, BrokerRefusal, Capability, CapabilityId, ClassSet,
    CurrentAuthorityRevocationCheckedEffectBroker, EffectBroker, EffectId, EffectJournalEntry,
    EffectJournalEvent, EffectJournalRefusal, EffectRequest, ExternalEffectOutcome, IntentRun,
    IntentRunCommitment, LogicalTime, OperationClass, ReconciliationRefused, RunId,
    RunReconciliationReadiness,
    effect_journal::{
        EffectJournalCodecRefusal, EffectJournalEncoder, EffectJournalPersistenceRefusal,
        EffectJournalPosition, EffectJournalSink, RecoveredEffectJournal,
    },
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::DigestAlgorithm;
use fgit_resource::{
    DownstreamChannel, DownstreamIdempotency, IdempotencyKey, LifecycleEvent, ObligationState,
    OpaqueHandle, ReconcilePlan, ReconcilePolicy, RegionId, ResourceVector,
    algebra::Grade,
    kinds::{DownstreamAck, OutboxDispatch},
    settlement::{DeliveryVerdict, ProbeVerdict},
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, PrincipalId,
    RegistryEpoch, RepositoryCommitId, RepositoryId,
};

#[path = "../../fgit-node/src/agent_journal/file.rs"]
mod native_file;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-agent-journal-{}-{}",
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

fn amount(n: u64) -> ResourceVector {
    ResourceVector::single(Grade::EgressBytes, n)
}
fn run() -> IntentRun {
    let root = outcome_index_root(&[]).unwrap();
    let head = RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([27; 16]),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: root,
        forge_position_root: root,
        outcome_index_root: root,
        retention_root: root,
        outbox_root: root,
        configuration_root: root,
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x9911));
    let key = HeadKey::new(b"agent-journal-reference-authority".to_vec()).unwrap();
    let HeadInit::Created(read) = initialize_repository(&store, &key, &head).unwrap() else {
        panic!("fresh reference authority");
    };
    let authenticated = store.authenticate_head_receipt(&read).unwrap();
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(1),
        [77; 32],
    )
    .unwrap();
    IntentRun::new_authenticated(
        RunId::new(0x41),
        receipt,
        ClassSet::from_classes(&[
            OperationClass::ReadCanonicalObject,
            OperationClass::ExternalIntegration,
        ]),
        amount(1000),
        LogicalTime::new(100),
    )
    .unwrap()
}
fn changed_run(run: &IntentRun) -> IntentRun {
    IntentRun::new_authenticated(
        run.run_id(),
        run.authority_read_receipt().unwrap().clone(),
        run.allowed_operation_classes(),
        amount(2000),
        run.expiry(),
    )
    .unwrap()
}
fn capability() -> Capability {
    Capability::issue(
        CapabilityId::new(11),
        run().allowed_operation_classes(),
        amount(1000),
        LogicalTime::new(1),
        LogicalTime::new(100),
    )
    .unwrap()
}
fn request(id: u128, operation: OperationClass) -> EffectRequest {
    EffectRequest {
        effect_id: EffectId::new(id),
        parent_effect_id: None,
        operation,
        cost: amount(250),
        input_commitment: [55; 32],
    }
}
fn digest(value: u8) -> Digest {
    Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&[value; 32]).unwrap(),
    )
}
fn dispatch() -> OutboxDispatch {
    OutboxDispatch {
        idempotency: IdempotencyKey::new(digest(71)),
        precondition_rcr: RepositoryCommitId::from_digest(
            DigestAlgorithm::Sha256.id(),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[72; 32]).unwrap(),
        ),
        endpoint: OpaqueHandle::new(&[73; 16]).unwrap(),
        idempotency_strength: DownstreamIdempotency::Strong,
    }
}
const fn plan(dispatch: &OutboxDispatch) -> ReconcilePlan {
    ReconcilePlan::new(
        dispatch.idempotency,
        dispatch.idempotency_strength,
        ReconcilePolicy::new(NonZeroU32::new(2).unwrap()),
    )
}
fn ack(attempt: u32) -> DownstreamAck {
    DownstreamAck {
        receipt: OpaqueHandle::new(&[81; 16]).unwrap(),
        attempt,
    }
}
const fn owner() -> PrincipalId {
    PrincipalId::from_bytes([82; 16])
}

#[derive(Default)]
struct Channel {
    calls: usize,
    ambiguous: bool,
}
impl DownstreamChannel for Channel {
    fn deliver(&mut self, _: &IdempotencyKey, _: u32) -> DeliveryVerdict {
        self.calls += 1;
        if self.ambiguous {
            DeliveryVerdict::AmbiguousTimeout
        } else {
            DeliveryVerdict::Accepted
        }
    }
    fn probe(&mut self, _: &IdempotencyKey) -> ProbeVerdict {
        self.calls += 1;
        ProbeVerdict::Delivered
    }
}

fn broker_at(path: &std::path::Path, run: &IntentRun) -> EffectBroker {
    let sink = native_file::FileEffectJournal::create(path, run, Box::new(|| Ok(()))).unwrap();
    EffectBroker::open_with_journal(
        run.clone(),
        RegionId::new(1),
        AgentInstanceId::new(1),
        Box::new(sink),
    )
    .unwrap()
}

#[test]
fn real_file_reopen_recovers_every_record_and_exact_consumed_budget() {
    let scratch = Scratch::new();
    let run = run();
    let mut broker = broker_at(&scratch.0, &run);
    let grant = broker
        .request(
            &capability(),
            LogicalTime::new(10),
            &request(1, OperationClass::ExternalIntegration),
        )
        .unwrap();
    let outbox = dispatch();
    let deferred = broker
        .reserve_outbox(grant, outbox)
        .unwrap()
        .dispatch(1, &amount(200))
        .unwrap();
    let mut channel = Channel {
        calls: 0,
        ambiguous: true,
    };
    assert!(matches!(
        deferred
            .reconcile(
                &mut plan(&outbox),
                &mut channel,
                owner(),
                ack,
                vec![[88; 32]]
            )
            .unwrap(),
        ExternalEffectOutcome::Acknowledged(_)
    ));
    assert_eq!(channel.calls, 2);
    let expected = broker.records();
    let position = broker.durable_position().unwrap().unwrap();
    assert!(broker.close().is_quiescent());
    let recovered = native_file::recover(&scratch.0, &run, Some(position), &|| Ok(())).unwrap();
    assert_eq!(recovered.records(), expected);
    let report = recovered
        .reconciliation_report(&run, LogicalTime::new(200))
        .unwrap();
    assert_eq!(report.readiness(), RunReconciliationReadiness::Ready);
    assert_eq!(report.cumulative_budget_consumed(), amount(200));
    assert_eq!(recovered.position(), position);
}

#[test]
fn checked_broker_uses_the_same_writer_and_preserves_single_owner_custody() {
    let scratch = Scratch::new();
    let run = run();
    let sink =
        native_file::FileEffectJournal::create(&scratch.0, &run, Box::new(|| Ok(()))).unwrap();
    let mut broker = CurrentAuthorityRevocationCheckedEffectBroker::open_with_journal(
        run.clone(),
        RegionId::new(1),
        AgentInstanceId::new(1),
        Box::new(sink),
    )
    .unwrap();
    assert!(matches!(
        native_file::recover(&scratch.0, &run, None, &|| Ok(())),
        Err(native_file::AgentJournalHostRefusal::Busy)
    ));
    let grant = broker
        .request_low_risk(
            &capability(),
            LogicalTime::new(10),
            &request(2, OperationClass::ReadCanonicalObject),
        )
        .unwrap();
    assert_eq!(broker.durable_position().unwrap().unwrap().entries, 1);
    assert_eq!(broker.abort_low_risk(grant).unwrap().amount(), amount(250));
    let tail = broker.durable_position().unwrap().unwrap();
    assert!(broker.close().is_quiescent());
    let restored = native_file::recover(&scratch.0, &run, Some(tail), &|| Ok(())).unwrap();
    assert_eq!(
        restored.records()[0].obligation_state,
        ObligationState::Aborted
    );
    // Neither normal restart nor a same-ID wider body gets a fresh budget.
    for retry in [run.clone(), changed_run(&run)] {
        assert!(matches!(
            native_file::FileEffectJournal::create(&scratch.0, &retry, Box::new(|| Ok(()))),
            Err(native_file::AgentJournalHostRefusal::Exists)
        ));
    }
    assert!(matches!(
        native_file::recover(&scratch.0, &changed_run(&run), Some(tail), &|| Ok(())),
        Err(native_file::AgentJournalHostRefusal::Codec(
            EffectJournalCodecRefusal::RunMismatch
        ))
    ));
}

#[test]
fn unanchored_inspection_cannot_become_a_complete_inventory_or_another_run() {
    let run = run();
    let (encoder, header) = EffectJournalEncoder::new(&run).unwrap();
    let inspection = RecoveredEffectJournal::decode(&run, &header, None).unwrap();
    assert!(!inspection.is_anchored());
    assert!(matches!(
        inspection.reconciliation_report(&run, LogicalTime::new(20)),
        Err(EffectJournalCodecRefusal::AnchorRequired)
    ));
    let anchored = RecoveredEffectJournal::decode(&run, &header, Some(encoder.position())).unwrap();
    assert!(matches!(
        anchored.reconciliation_report(&changed_run(&run), LogicalTime::new(20)),
        Err(EffectJournalCodecRefusal::RunMismatch)
    ));
}

#[test]
fn a_well_hashed_replay_cannot_reduce_spend_at_a_later_lifecycle_event() {
    let run = run();
    let mut broker = EffectBroker::open(run.clone(), RegionId::new(1), AgentInstanceId::new(1));
    let grant = broker
        .request(
            &capability(),
            LogicalTime::new(10),
            &request(18, OperationClass::ExternalIntegration),
        )
        .unwrap();
    let outbox = dispatch();
    let deferred = broker
        .reserve_outbox(grant, outbox)
        .unwrap()
        .dispatch(1, &amount(200))
        .unwrap();
    let ExternalEffectOutcome::Acknowledged(settled) = deferred
        .reconcile(
            &mut plan(&outbox),
            &mut Channel::default(),
            owner(),
            ack,
            Vec::new(),
        )
        .unwrap()
    else {
        panic!("successful downstream observation must acknowledge the effect");
    };
    assert_eq!(settled.state(), ObligationState::Acknowledged);
    let mut entries = broker.journal();
    assert!(broker.close().is_quiescent());
    let EffectJournalEvent::Lifecycle {
        budget_consumed, ..
    } = &mut entries.last_mut().unwrap().event
    else {
        panic!("terminal lifecycle");
    };
    *budget_consumed = amount(100);
    let (mut encoder, mut forged) = EffectJournalEncoder::new(&run).unwrap();
    for entry in &entries {
        forged.extend_from_slice(&encoder.encode(entry).unwrap());
    }
    assert!(matches!(
        RecoveredEffectJournal::decode(&run, &forged, Some(encoder.position())),
        Err(EffectJournalCodecRefusal::Replay)
    ));
}

#[test]
fn truncation_corruption_reordering_and_valid_prefix_rollback_refuse() {
    let scratch = Scratch::new();
    let run = run();
    let mut broker = broker_at(&scratch.0, &run);
    let grant = broker
        .request(
            &capability(),
            LogicalTime::new(10),
            &request(3, OperationClass::ReadCanonicalObject),
        )
        .unwrap();
    let prefix = broker.durable_position().unwrap().unwrap();
    assert_eq!(broker.abort(grant).unwrap().amount(), amount(250));
    let tail = broker.durable_position().unwrap().unwrap();
    assert!(broker.close().is_quiescent());
    let bytes = fs::read(native_file::journal_path(&scratch.0, &run).unwrap()).unwrap();
    assert!(RecoveredEffectJournal::decode(&run, &bytes, Some(tail)).is_ok());
    let header_len = EffectJournalEncoder::new(&run).unwrap().1.len();
    for cut in [
        0,
        header_len - 1,
        header_len,
        prefix.bytes as usize,
        bytes.len() - 1,
    ] {
        assert!(
            RecoveredEffectJournal::decode(&run, &bytes[..cut], Some(tail)).is_err(),
            "cut {cut}"
        );
    }
    assert!(matches!(
        RecoveredEffectJournal::decode(&run, &bytes[..prefix.bytes as usize], Some(tail)),
        Err(EffectJournalCodecRefusal::AnchorMismatch)
    ));
    let mut corrupted = bytes.clone();
    corrupted[header_len + 50] ^= 1;
    assert!(matches!(
        RecoveredEffectJournal::decode(&run, &corrupted, Some(tail)),
        Err(EffectJournalCodecRefusal::IncompleteTail(_))
    ));
    let mut reordered = bytes[..header_len].to_vec();
    reordered.extend_from_slice(&bytes[prefix.bytes as usize..]);
    reordered.extend_from_slice(&bytes[header_len..prefix.bytes as usize]);
    assert!(matches!(
        RecoveredEffectJournal::decode(&run, &reordered, Some(tail)),
        Err(EffectJournalCodecRefusal::Chain)
    ));
}

#[derive(Debug)]
struct FailingSink {
    encoder: EffectJournalEncoder,
    acknowledged: EffectJournalPosition,
    bytes: Rc<RefCell<Vec<u8>>>,
    fail_at: u64,
}
impl FailingSink {
    fn new(run: &IntentRun, fail_at: u64) -> (Self, Rc<RefCell<Vec<u8>>>) {
        let (encoder, header) = EffectJournalEncoder::new(run).unwrap();
        let bytes = Rc::new(RefCell::new(header));
        (
            Self {
                acknowledged: encoder.position(),
                encoder,
                bytes: bytes.clone(),
                fail_at,
            },
            bytes,
        )
    }
}
impl EffectJournalSink for FailingSink {
    fn run_commitment(&self) -> IntentRunCommitment {
        self.encoder.run_commitment()
    }
    fn position(&self) -> EffectJournalPosition {
        self.acknowledged
    }
    fn append(
        &mut self,
        entry: &EffectJournalEntry,
    ) -> Result<(), EffectJournalPersistenceRefusal> {
        let frame = self.encoder.encode(entry).unwrap();
        self.bytes.borrow_mut().extend_from_slice(&frame);
        if entry.sequence == self.fail_at {
            return Err(EffectJournalPersistenceRefusal::OutcomeUnknown);
        }
        self.acknowledged = self.encoder.position();
        Ok(())
    }
}

#[test]
fn ambiguous_acceptance_exposes_no_grant_and_poison_stops_new_issuance() {
    let run = run();
    let (sink, bytes) = FailingSink::new(&run, 0);
    let mut broker = EffectBroker::open_with_journal(
        run.clone(),
        RegionId::new(1),
        AgentInstanceId::new(1),
        Box::new(sink),
    )
    .unwrap();
    assert!(matches!(
        broker.request(
            &capability(),
            LogicalTime::new(10),
            &request(4, OperationClass::ReadCanonicalObject)
        ),
        Err(BrokerRefusal::Journal {
            source: EffectJournalRefusal::Persistence(
                EffectJournalPersistenceRefusal::OutcomeUnknown
            )
        })
    ));
    assert!(matches!(
        broker.request(
            &capability(),
            LogicalTime::new(10),
            &request(5, OperationClass::ReadCanonicalObject)
        ),
        Err(BrokerRefusal::Journal {
            source: EffectJournalRefusal::PersistencePoisoned
        })
    ));
    assert!(broker.durable_position().is_err());
    assert_eq!(
        broker.records().len(),
        1,
        "uncertain responsibility must remain visible"
    );
    assert_eq!(
        RecoveredEffectJournal::decode(&run, &bytes.borrow(), None)
            .unwrap()
            .records(),
        broker.records()
    );
    assert!(
        broker.close().is_quiescent(),
        "a grant that never escaped was explicitly released"
    );
}

#[test]
fn failed_commit_append_keeps_debt_and_never_calls_a_downstream() {
    let run = run();
    let (sink, _) = FailingSink::new(&run, 2);
    let mut broker = EffectBroker::open_with_journal(
        run,
        RegionId::new(1),
        AgentInstanceId::new(1),
        Box::new(sink),
    )
    .unwrap();
    let grant = broker
        .request(
            &capability(),
            LogicalTime::new(10),
            &request(6, OperationClass::ExternalIntegration),
        )
        .unwrap();
    let outbox = dispatch();
    let failure = broker
        .reserve_outbox(grant, outbox)
        .unwrap()
        .dispatch(1, &amount(200))
        .unwrap_err();
    let deferred = failure
        .into_deferred()
        .expect("post-commit failure must retain the typed obligation");
    let mut channel = Channel::default();
    let refused = deferred
        .reconcile(&mut plan(&outbox), &mut channel, owner(), ack, Vec::new())
        .unwrap_err();
    assert!(matches!(
        refused,
        ReconciliationRefused::BeforeSettlement { .. }
    ));
    assert_eq!(channel.calls, 0);
    let _still_owned = refused.into_effect().unwrap();
    assert!(broker.durable_position().is_err());
    assert_eq!(
        broker.records()[0].obligation_state,
        ObligationState::Committed
    );
    assert!(
        !broker.close().is_quiescent(),
        "an unresolved committed obligation cannot disappear"
    );
}

#[test]
fn an_already_poisoned_journal_keeps_older_reservations_abortable() {
    let run = run();
    let (sink, _) = FailingSink::new(&run, 2);
    let mut broker = EffectBroker::open_with_journal(
        run,
        RegionId::new(1),
        AgentInstanceId::new(1),
        Box::new(sink),
    )
    .unwrap();
    let grant = broker
        .request(
            &capability(),
            LogicalTime::new(10),
            &request(16, OperationClass::ExternalIntegration),
        )
        .unwrap();
    let held = broker.reserve_outbox(grant, dispatch()).unwrap();
    assert!(
        broker
            .request(
                &capability(),
                LogicalTime::new(10),
                &request(26, OperationClass::ReadCanonicalObject)
            )
            .is_err()
    );
    let refused = held.dispatch(1, &amount(200)).unwrap_err();
    assert!(matches!(
        *refused,
        fgit_agent::OutboxCommitRefused::JournalBeforeCommit { .. }
    ));
    let held = refused
        .into_reserved()
        .expect("known persistence failure must not commit an older reservation");
    assert_eq!(
        broker.records()[0].obligation_state,
        ObligationState::Reserved
    );
    assert!(
        held.abort_unused(fgit_resource::kinds::DispatchAbortReason::Cancelled)
            .is_err()
    );
    assert_eq!(
        broker.records()[0].obligation_state,
        ObligationState::Aborted
    );
    assert!(broker.close().is_quiescent());
}

#[test]
fn acknowledgement_append_failure_retains_observed_terminal_fact_and_old_durable_debt() {
    let run = run();
    let (sink, bytes) = FailingSink::new(&run, 4);
    let mut broker = EffectBroker::open_with_journal(
        run.clone(),
        RegionId::new(1),
        AgentInstanceId::new(1),
        Box::new(sink),
    )
    .unwrap();
    let grant = broker
        .request(
            &capability(),
            LogicalTime::new(10),
            &request(7, OperationClass::ExternalIntegration),
        )
        .unwrap();
    let outbox = dispatch();
    let deferred = broker
        .reserve_outbox(grant, outbox)
        .unwrap()
        .dispatch(1, &amount(200))
        .unwrap();
    let mut channel = Channel::default();
    assert!(matches!(
        deferred.reconcile(&mut plan(&outbox), &mut channel, owner(), ack, Vec::new()),
        Err(ReconciliationRefused::AfterSettlement(
            EffectJournalRefusal::Persistence(_)
        ))
    ));
    assert_eq!(channel.calls, 1);
    assert_eq!(
        broker.records()[0].obligation_state,
        ObligationState::Acknowledged
    );
    assert_eq!(broker.records()[0].budget_consumed, amount(200));
    assert_eq!(
        RecoveredEffectJournal::decode(&run, &bytes.borrow(), None)
            .unwrap()
            .records(),
        broker.records()
    );
    assert!(broker.durable_position().is_err());
    assert!(broker.close().is_quiescent());
}

#[test]
fn failed_escalation_append_returns_live_named_owner_debt_for_cleanup() {
    struct Unknown;
    impl DownstreamChannel for Unknown {
        fn deliver(&mut self, _: &IdempotencyKey, _: u32) -> DeliveryVerdict {
            DeliveryVerdict::AmbiguousTimeout
        }
        fn probe(&mut self, _: &IdempotencyKey) -> ProbeVerdict {
            ProbeVerdict::Unknown
        }
    }
    let run = run();
    let (sink, _) = FailingSink::new(&run, 4);
    let mut broker = EffectBroker::open_with_journal(
        run,
        RegionId::new(1),
        AgentInstanceId::new(1),
        Box::new(sink),
    )
    .unwrap();
    let grant = broker
        .request(
            &capability(),
            LogicalTime::new(10),
            &request(17, OperationClass::ExternalIntegration),
        )
        .unwrap();
    let mut outbox = dispatch();
    outbox.idempotency_strength = DownstreamIdempotency::Weak;
    let deferred = broker
        .reserve_outbox(grant, outbox)
        .unwrap()
        .dispatch(1, &amount(200))
        .unwrap();
    let failure = deferred
        .reconcile(&mut plan(&outbox), &mut Unknown, owner(), ack, Vec::new())
        .unwrap_err();
    assert!(matches!(
        failure,
        ReconciliationRefused::AfterEscalation { .. }
    ));
    let live = failure
        .into_escalated()
        .expect("escalation is not a terminal settlement");
    assert_eq!(
        broker.records()[0].obligation_state,
        ObligationState::Escalated
    );
    assert_eq!(broker.records()[0].budget_consumed, amount(200));
    // Cleanup is still allowed after the persistence failure. Its observed
    // terminal state remains in memory, alongside the persistence debt.
    assert!(
        live.resolve_failed(
            fgit_resource::TerminalFailureReason::OperatorDecision,
            Vec::new()
        )
        .is_err()
    );
    assert_eq!(
        broker.records()[0].obligation_state,
        ObligationState::TerminallyFailed
    );
    assert!(broker.close().is_quiescent());
}

#[test]
fn encoder_bounds_precede_work_and_cancelled_file_host_never_accepts_a_request() {
    let run = run();
    let (mut encoder, _) = EffectJournalEncoder::new(&run).unwrap();
    let initial = encoder.position();
    let oversized = EffectJournalEntry {
        sequence: 0,
        event: EffectJournalEvent::Lifecycle {
            effect_id: EffectId::new(1),
            event: LifecycleEvent::Acknowledge,
            budget_consumed: ResourceVector::ZERO,
            output_commitments: vec![[1; 32]; 1025],
            reconciliation_evidence: None,
            terminal_outcome: None,
        },
    };
    assert!(matches!(
        encoder.encode(&oversized),
        Err(EffectJournalCodecRefusal::Limit)
    ));
    assert_eq!(encoder.position(), initial);
    let scratch = Scratch::new();
    let cancelled = Rc::new(Cell::new(false));
    let observed = cancelled.clone();
    let sink = native_file::FileEffectJournal::create(
        &scratch.0,
        &run,
        Box::new(move || {
            if observed.get() {
                Err(EffectJournalPersistenceRefusal::Cancelled)
            } else {
                Ok(())
            }
        }),
    )
    .unwrap();
    let mut broker = EffectBroker::open_with_journal(
        run,
        RegionId::new(1),
        AgentInstanceId::new(1),
        Box::new(sink),
    )
    .unwrap();
    cancelled.set(true);
    assert!(
        broker
            .request(
                &capability(),
                LogicalTime::new(10),
                &request(8, OperationClass::ReadCanonicalObject)
            )
            .is_err()
    );
    assert!(broker.durable_position().is_err());
    assert!(broker.close().is_quiescent());
}

// The child is deliberately terminated without Rust destructors. Its exact
// acknowledged tail crosses the process boundary separately from journal bytes.
#[test]
fn native_process_child() {
    let Some(directory) = std::env::var_os("FGIT_AGENT_JOURNAL_CHILD") else {
        return;
    };
    let run = run();
    let mut broker = broker_at(&PathBuf::from(directory), &run);
    let grant = broker
        .request(
            &capability(),
            LogicalTime::new(10),
            &request(9, OperationClass::ExternalIntegration),
        )
        .unwrap();
    let _deferred = broker
        .reserve_outbox(grant, dispatch())
        .unwrap()
        .dispatch(1, &amount(200))
        .unwrap();
    let tail = broker.durable_position().unwrap().unwrap();
    let digest: String = tail
        .digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!("ANCHOR={},{},{}", tail.entries, tail.bytes, digest);
    std::io::stdout().flush().unwrap();
    std::process::exit(42);
}

#[test]
fn a_fresh_process_recovers_post_commit_debt_after_owner_death_without_dispatching() {
    let scratch = Scratch::new();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_process_child", "--nocapture"])
        .env("FGIT_AGENT_JOURNAL_CHILD", &scratch.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let anchor = text
        .split("ANCHOR=")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap();
    let parts: Vec<_> = anchor.split(',').collect();
    let mut digest = [0; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&parts[2][i * 2..i * 2 + 2], 16).unwrap();
    }
    let tail = EffectJournalPosition {
        entries: parts[0].parse().unwrap(),
        bytes: parts[1].parse().unwrap(),
        digest,
    };
    let run = run();
    let recovered = native_file::recover(&scratch.0, &run, Some(tail), &|| Ok(())).unwrap();
    let report = recovered
        .reconciliation_report(&run, LogicalTime::new(200))
        .unwrap();
    assert_eq!(
        report.readiness(),
        RunReconciliationReadiness::EffectReconciliationRequired
    );
    assert_eq!(report.effects().len(), 1);
    assert_eq!(
        recovered.records()[0].external_idempotency_key,
        Some(dispatch().idempotency)
    );
    assert_eq!(report.cumulative_budget_consumed(), amount(200));
    // Recovery exposes evidence only; no live broker or downstream is created.
    assert!(matches!(
        native_file::FileEffectJournal::create(&scratch.0, &run, Box::new(|| Ok(()))),
        Err(native_file::AgentJournalHostRefusal::Exists)
    ));
}

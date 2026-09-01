#![forbid(unsafe_code)]
//! Public-path tests for pre-situation task projection collection.

use fgit_agent::{
    AgentSituationReceipt, AuthorityReadReceipt, ClassSet, IntentRun, LogicalTime,
    OperationClass, RunId, SituationComponent, SituationComponentKind,
    SituationOmissionReason, TaskProjectionCollectionAdapterRefusal,
    TaskProjectionCollectionExecutionRefusal, TaskProjectionCollectionObservation,
    TaskProjectionCollectionRefusal, TaskProjectionCollectionRequest,
    TaskProjectionCollectionRequestId, TaskProjectionCollector, TaskProjectionGeneration,
    TaskProjectionRow, TaskPhase, WorkConflict, WorkFrontier, WorkRankingInputs, WorkTaskId,
    collect_task_projection,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::{IdentityDomain, NativeObjectIdentity};
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositoryId, RepositorySequence,
};

const GENERATION: [u8; 32] = [0x44; 32];

fn digest(byte: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width digest"),
    )
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x5a; 32]).expect("fixed-width RCR digest"),
    )
}

fn authority_receipt(store_id: u64) -> AuthorityReadReceipt {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    let body = RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([0x27; 16]),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: Some(rcr_id()),
        latest_repository_sequence: Some(RepositorySequence::FIRST),
        ref_root: root,
        forge_position_root: digest(0x31),
        outcome_index_root: digest(0x32),
        retention_root: digest(0x33),
        outbox_root: digest(0x34),
        configuration_root: digest(0x35),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let key = HeadKey::new(format!("task-collection-test-{store_id}").into_bytes())
        .expect("bounded head key");
    let read = match initialize_repository(&store, &key, &body).expect("initialize head") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("issuing store authenticates its receipt");
    AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x71; 32],
    )
    .expect("authenticated agent receipt")
}

fn run(receipt: &AuthorityReadReceipt) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(7),
        receipt.clone(),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        ResourceVector::single(Grade::Bytes, 16_384),
        LogicalTime::new(100),
    )
    .expect("authenticated run opens")
}

fn row(task_byte: u8) -> TaskProjectionRow {
    TaskProjectionRow::unclaimed(
        WorkTaskId::from_bytes([task_byte; 32]),
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        0,
        None,
        true,
        WorkConflict::Clear,
    )
    .expect("valid task row")
}

struct Collector {
    identity: [u8; 32],
    generation: TaskProjectionGeneration,
    observed_at: LogicalTime,
    rows: Vec<TaskProjectionRow>,
    override_request: Option<TaskProjectionCollectionRequestId>,
    refusal: Option<TaskProjectionCollectionAdapterRefusal>,
    calls: usize,
}

impl Collector {
    fn healthy(rows: Vec<TaskProjectionRow>) -> Self {
        Self {
            identity: [0x81; 32],
            generation: TaskProjectionGeneration::try_from_bytes(GENERATION)
                .expect("nonzero generation"),
            observed_at: LogicalTime::new(21),
            rows,
            override_request: None,
            refusal: None,
            calls: 0,
        }
    }
}

impl TaskProjectionCollector for Collector {
    fn adapter_identity(&self) -> [u8; 32] {
        self.identity
    }

    fn collect(
        &mut self,
        request: &TaskProjectionCollectionRequest,
    ) -> Result<TaskProjectionCollectionObservation, TaskProjectionCollectionAdapterRefusal> {
        self.calls += 1;
        if let Some(refusal) = self.refusal.clone() {
            return Err(refusal);
        }
        Ok(TaskProjectionCollectionObservation::new(
            self.override_request.unwrap_or_else(|| request.request_id()),
            self.generation,
            self.observed_at,
            self.rows.clone(),
            self.identity,
            digest(0x91),
        ))
    }
}

#[test]
fn current_generation_collection_builds_situation_and_frontier_without_cycle() {
    let receipt = authority_receipt(931);
    let run = run(&receipt);
    let mut collector = Collector::healthy(vec![row(0x41), row(0x42)]);

    let collection = collect_task_projection(
        &mut collector,
        &receipt,
        &run,
        LogicalTime::new(20),
    )
    .expect("current generation is collected");
    assert_eq!(collection.snapshot().rows().len(), 2);
    assert_eq!(collection.snapshot().generation().as_bytes(), &GENERATION);
    assert_eq!(collection.adapter_identity(), [0x81; 32]);
    assert_ne!(collection.receipt_id().as_bytes(), &[0; 32]);

    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            collection.situation_component(&receipt)
        } else {
            SituationComponent::omitted(
                kind,
                SituationOmissionReason::NotAvailable,
                [u8::try_from(index + 1).expect("component index fits u8"); 32],
            )
        }
    });
    let situation = AgentSituationReceipt::build(
        receipt,
        Some(&run),
        None,
        LogicalTime::new(21),
        components,
    )
    .expect("collection supplies the previously unknown task generation");
    let frontier = WorkFrontier::build_action_scoped(
        &situation,
        collection.snapshot().work_items(),
    )
    .expect("complete task rows feed the frontier");
    assert_eq!(frontier.candidates().len(), 2);
    assert_eq!(collector.calls, 1);
}

#[test]
fn collector_is_invoked_once_and_backend_refusal_remains_typed() {
    let receipt = authority_receipt(932);
    let run = run(&receipt);
    let request = TaskProjectionCollectionRequest::new(
        &receipt,
        &run,
        LogicalTime::new(20),
    )
    .expect("valid request");
    let refusal = TaskProjectionCollectionAdapterRefusal::Unavailable {
        request_id: request.request_id(),
    };
    let mut collector = Collector::healthy(Vec::new());
    collector.refusal = Some(refusal.clone());

    assert_eq!(
        collect_task_projection(
            &mut collector,
            &receipt,
            &run,
            LogicalTime::new(20),
        )
        .expect_err("unavailable backend remains a read-only refusal"),
        TaskProjectionCollectionExecutionRefusal::Adapter(refusal)
    );
    assert_eq!(collector.calls, 1);
}

#[test]
fn substituted_request_identity_is_refused() {
    let receipt = authority_receipt(933);
    let run = run(&receipt);
    let alternate = TaskProjectionCollectionRequest::new(
        &receipt,
        &run,
        LogicalTime::new(21),
    )
    .expect("alternate request");
    let mut collector = Collector::healthy(vec![row(0x41)]);
    collector.override_request = Some(alternate.request_id());
    collector.observed_at = LogicalTime::new(22);

    let refusal = collect_task_projection(
        &mut collector,
        &receipt,
        &run,
        LogicalTime::new(20),
    )
    .expect_err("collector cannot substitute another request");
    assert!(matches!(
        refusal,
        TaskProjectionCollectionExecutionRefusal::Collection(
            TaskProjectionCollectionRefusal::ObservationRequestMismatch { .. }
        )
    ));
}

#[test]
fn observation_rollback_is_refused() {
    let receipt = authority_receipt(934);
    let run = run(&receipt);
    let mut collector = Collector::healthy(vec![row(0x41)]);
    collector.observed_at = LogicalTime::new(19);

    assert_eq!(
        collect_task_projection(
            &mut collector,
            &receipt,
            &run,
            LogicalTime::new(20),
        )
        .expect_err("backend observation cannot predate its request"),
        TaskProjectionCollectionExecutionRefusal::Collection(
            TaskProjectionCollectionRefusal::ObservationRollback {
                requested_at: LogicalTime::new(20),
                observed_at: LogicalTime::new(19),
            },
        )
    );
}

#[test]
fn duplicate_task_rows_are_refused_by_canonical_snapshot_validation() {
    let receipt = authority_receipt(935);
    let run = run(&receipt);
    let duplicate = row(0x41);
    let mut collector = Collector::healthy(vec![duplicate.clone(), duplicate]);

    assert!(matches!(
        collect_task_projection(
            &mut collector,
            &receipt,
            &run,
            LogicalTime::new(20),
        ),
        Err(TaskProjectionCollectionExecutionRefusal::Collection(
            TaskProjectionCollectionRefusal::Projection(
                fgit_agent::TaskProjectionRefusal::DuplicateTask { .. }
            )
        ))
    ));
}

#[test]
fn zero_collector_identity_refuses_before_io() {
    let receipt = authority_receipt(936);
    let run = run(&receipt);
    let mut collector = Collector::healthy(vec![row(0x41)]);
    collector.identity = [0; 32];

    assert_eq!(
        collect_task_projection(
            &mut collector,
            &receipt,
            &run,
            LogicalTime::new(20),
        )
        .expect_err("zero profile is reserved"),
        TaskProjectionCollectionExecutionRefusal::Collection(
            TaskProjectionCollectionRefusal::ZeroAdapterIdentity,
        )
    );
    assert_eq!(collector.calls, 0);
}

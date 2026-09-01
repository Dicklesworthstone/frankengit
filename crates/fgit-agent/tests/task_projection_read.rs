#![forbid(unsafe_code)]
//! Public-path tests for evidenced exact-generation task projection reads.

use fgit_agent::{
    AgentSituationReceipt, AuthorityReadReceipt, ClassSet, IntentRun, LogicalTime,
    OperationClass, RunId, SituationComponent, SituationComponentKind,
    SituationOmissionReason, TaskProjectionGeneration, TaskProjectionReadAdapterRefusal,
    TaskProjectionReadExecutionRefusal, TaskProjectionReadObservation, TaskProjectionReadRequest,
    TaskProjectionReader, TaskProjectionRow, TaskPhase, WorkConflict, WorkRankingInputs,
    WorkTaskId, read_task_projection,
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

fn authority_receipt() -> AuthorityReadReceipt {
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(341));
    let key = HeadKey::new(b"task-projection-read-test".to_vec()).expect("bounded head key");
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

fn situation(receipt: &AuthorityReadReceipt, run: &IntentRun) -> AgentSituationReceipt {
    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            SituationComponent::observed(kind, receipt.authority_head_id(), GENERATION)
        } else {
            SituationComponent::omitted(
                kind,
                SituationOmissionReason::NotAvailable,
                [u8::try_from(index + 1).expect("component index fits u8"); 32],
            )
        }
    });
    AgentSituationReceipt::build(
        receipt.clone(),
        Some(run),
        None,
        LogicalTime::new(20),
        components,
    )
    .expect("complete situation")
}

fn row() -> TaskProjectionRow {
    TaskProjectionRow::unclaimed(
        WorkTaskId::from_bytes([0x51; 32]),
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        0,
        None,
        true,
        WorkConflict::Clear,
    )
    .expect("valid projected task row")
}

struct Reader {
    identity: [u8; 32],
    generation: TaskProjectionGeneration,
    rows: Vec<TaskProjectionRow>,
    calls: usize,
}

impl TaskProjectionReader for Reader {
    fn adapter_identity(&self) -> [u8; 32] {
        self.identity
    }

    fn read(
        &mut self,
        request: &TaskProjectionReadRequest,
    ) -> Result<TaskProjectionReadObservation, TaskProjectionReadAdapterRefusal> {
        self.calls += 1;
        Ok(TaskProjectionReadObservation::new(
            request.request_id(),
            self.generation,
            LogicalTime::new(request.requested_at().value() + 1),
            self.rows.clone(),
            self.identity,
            digest(0x91),
        ))
    }
}

struct UnavailableReader {
    calls: usize,
}

impl TaskProjectionReader for UnavailableReader {
    fn adapter_identity(&self) -> [u8; 32] {
        [0xa1; 32]
    }

    fn read(
        &mut self,
        request: &TaskProjectionReadRequest,
    ) -> Result<TaskProjectionReadObservation, TaskProjectionReadAdapterRefusal> {
        self.calls += 1;
        Err(TaskProjectionReadAdapterRefusal::GenerationUnavailable {
            generation: request.expected_generation(),
        })
    }
}

#[test]
fn exact_generation_read_is_evidenced_and_deterministic() {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let situation = situation(&receipt, &run);
    let generation = TaskProjectionGeneration::try_from_bytes(GENERATION)
        .expect("nonzero generation");
    let mut first_reader = Reader {
        identity: [0x81; 32],
        generation,
        rows: vec![row()],
        calls: 0,
    };
    let mut second_reader = Reader {
        identity: [0x81; 32],
        generation,
        rows: vec![row()],
        calls: 0,
    };

    let first = read_task_projection(&mut first_reader, &situation, &run)
        .expect("exact generation is collected");
    let second = read_task_projection(&mut second_reader, &situation, &run)
        .expect("same read evidence is deterministic");

    assert_eq!(first.receipt_id(), second.receipt_id());
    assert_eq!(first.snapshot().generation(), generation);
    assert_eq!(first.work_items().len(), 1);
    assert_eq!(first.work_items()[0].task_id(), WorkTaskId::from_bytes([0x51; 32]));
    assert_eq!(first_reader.calls, 1);
    assert_eq!(second_reader.calls, 1);
    assert_ne!(first.receipt_id().as_bytes(), &[0; 32]);
}

#[test]
fn substituted_generation_is_refused_after_one_read() {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let situation = situation(&receipt, &run);
    let observed = TaskProjectionGeneration::try_from_bytes([0x45; 32])
        .expect("nonzero substituted generation");
    let mut reader = Reader {
        identity: [0x81; 32],
        generation: observed,
        rows: vec![row()],
        calls: 0,
    };

    assert_eq!(
        read_task_projection(&mut reader, &situation, &run)
            .expect_err("reader cannot substitute its current generation"),
        TaskProjectionReadExecutionRefusal::Read(
            fgit_agent::TaskProjectionReadRefusal::GenerationMismatch {
                expected: TaskProjectionGeneration::try_from_bytes(GENERATION)
                    .expect("nonzero expected generation"),
                observed,
            },
        )
    );
    assert_eq!(reader.calls, 1);
}

#[test]
fn unavailable_exact_generation_remains_a_typed_backend_result() {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let situation = situation(&receipt, &run);
    let mut reader = UnavailableReader { calls: 0 };

    assert_eq!(
        read_task_projection(&mut reader, &situation, &run)
            .expect_err("backend no longer retains the exact generation"),
        TaskProjectionReadExecutionRefusal::Adapter(
            TaskProjectionReadAdapterRefusal::GenerationUnavailable {
                generation: TaskProjectionGeneration::try_from_bytes(GENERATION)
                    .expect("nonzero expected generation"),
            },
        )
    );
    assert_eq!(reader.calls, 1);
}

#![forbid(unsafe_code)]
//! Public-path tests for collection-to-claim-basis conversion.

use fgit_agent::{
    AuthorityReadReceipt, ClassSet, IntentRun, LogicalTime, OperationClass, RunId,
    TaskCollectionBridgeRefusal, TaskProjectionCollectionObservation,
    TaskProjectionCollectionRequest, TaskProjectionCollector, TaskProjectionGeneration,
    TaskProjectionRow, TaskPhase, WorkConflict, WorkRankingInputs, WorkTaskId,
    collect_task_projection, collected_unclaimed_task,
};
use fgit_authority::{
    AuthenticatedHead, AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore,
    StoreInstanceId, initialize_repository, outcome_index_root,
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

fn authenticated_head() -> AuthenticatedHead {
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(951));
    let key = HeadKey::new(b"task-collection-bridge-test".to_vec()).expect("bounded head key");
    let read = match initialize_repository(&store, &key, &body).expect("initialize head") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    store
        .authenticate_head_receipt(&read)
        .expect("issuing store authenticates its receipt")
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

struct Collector {
    row: TaskProjectionRow,
}

impl TaskProjectionCollector for Collector {
    fn adapter_identity(&self) -> [u8; 32] {
        [0x81; 32]
    }

    fn collect(
        &mut self,
        request: &TaskProjectionCollectionRequest,
    ) -> Result<
        TaskProjectionCollectionObservation,
        fgit_agent::TaskProjectionCollectionAdapterRefusal,
    > {
        Ok(TaskProjectionCollectionObservation::new(
            request.request_id(),
            TaskProjectionGeneration::try_from_bytes(GENERATION)
                .expect("nonzero generation"),
            LogicalTime::new(21),
            vec![self.row.clone()],
            [0x81; 32],
            digest(0x91),
        ))
    }
}

#[test]
fn collected_unassigned_row_becomes_exact_claim_basis() {
    let authenticated = authenticated_head();
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x71; 32],
    )
    .expect("first exact read");
    let run = run(&receipt);
    let task_id = WorkTaskId::from_bytes([0x41; 32]);
    let row = TaskProjectionRow::unclaimed(
        task_id,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        0,
        None,
        true,
        WorkConflict::Clear,
    )
    .expect("unassigned row");
    let mut collector = Collector { row };
    let collection = collect_task_projection(
        &mut collector,
        &receipt,
        &run,
        LogicalTime::new(20),
    )
    .expect("current task collection");

    let claim_basis = collected_unclaimed_task(&collection, &receipt, task_id)
        .expect("exact read and unclaimed row make a claim basis");
    assert_eq!(claim_basis.repository_id(), receipt.repository_id());
    assert_eq!(claim_basis.task_id(), task_id);
    assert_eq!(claim_basis.generation(), &GENERATION);
    assert_eq!(
        claim_basis.assignment(),
        fgit_agent::TaskProjectionAssignment::Unassigned
    );
    assert_eq!(claim_basis.observed_at(), LogicalTime::new(21));
}

#[test]
fn same_head_later_read_is_not_interchangeable_for_mutation() {
    let authenticated = authenticated_head();
    let first = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x71; 32],
    )
    .expect("first exact read");
    let later = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(11),
        [0x71; 32],
    )
    .expect("later exact read of same head");
    let run = run(&first);
    let task_id = WorkTaskId::from_bytes([0x41; 32]);
    let row = TaskProjectionRow::unclaimed(
        task_id,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        0,
        None,
        true,
        WorkConflict::Clear,
    )
    .expect("unassigned row");
    let mut collector = Collector { row };
    let collection = collect_task_projection(
        &mut collector,
        &first,
        &run,
        LogicalTime::new(20),
    )
    .expect("current task collection");

    assert_eq!(
        collected_unclaimed_task(&collection, &later, task_id)
            .expect_err("another exact read event cannot become the mutation basis"),
        TaskCollectionBridgeRefusal::AuthorityMismatch
    );
}

#[test]
fn missing_task_fails_without_inventing_state() {
    let authenticated = authenticated_head();
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x71; 32],
    )
    .expect("exact read");
    let run = run(&receipt);
    let present = WorkTaskId::from_bytes([0x41; 32]);
    let missing = WorkTaskId::from_bytes([0x42; 32]);
    let row = TaskProjectionRow::unclaimed(
        present,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        0,
        None,
        true,
        WorkConflict::Clear,
    )
    .expect("unassigned row");
    let mut collector = Collector { row };
    let collection = collect_task_projection(
        &mut collector,
        &receipt,
        &run,
        LogicalTime::new(20),
    )
    .expect("current task collection");

    assert_eq!(
        collected_unclaimed_task(&collection, &receipt, missing)
            .expect_err("missing task cannot become a single-task snapshot"),
        TaskCollectionBridgeRefusal::TaskMissing { task_id: missing }
    );
}

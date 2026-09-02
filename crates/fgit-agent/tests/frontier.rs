#![forbid(unsafe_code)]
//! Public-path tests for authority-bound work-frontier construction.

use fgit_agent::{
    AgentSituationReceipt, AuthorityReadReceipt, ClassSet, FrontierRefusal, IntentRun, LogicalTime,
    OperationClass, RunId, SITUATION_COMPONENT_COUNT, SituationComponent, SituationComponentKind,
    SituationOmissionReason, TaskPhase, WorkAction, WorkConflict, WorkEligibilityInputs,
    WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    authority_head_identity, initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::IdentityDomain;
use fgit_resource::{ResourceVector, algebra::Grade};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositoryId, RepositorySequence,
};

const TASK_GENERATION: [u8; 32] = [0x44; 32];

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x5a; 32]).expect("fixed-width RCR identity digest"),
    )
}

fn authority_receipt() -> AuthorityReadReceipt {
    let repository_id = RepositoryId::from_bytes([0x22; 16]);
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    let configuration_root = Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[0x41; 32]).expect("fixed-width configuration root"),
    );
    let head = RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: Some(rcr_id()),
        latest_repository_sequence: Some(RepositorySequence::FIRST),
        ref_root: root,
        forge_position_root: root,
        outcome_index_root: root,
        retention_root: root,
        outbox_root: root,
        configuration_root,
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let expected_head_id = authority_head_identity(&head)
        .expect("a complete canonical authority head re-identifies itself");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(91));
    let head_key =
        HeadKey::new(b"agent-frontier-test-head".to_vec()).expect("bounded nonempty head key");
    let initialized = initialize_repository(&store, &head_key, &head)
        .expect("the reference store initializes one complete authority head");
    let head_read = match initialized {
        HeadInit::Created(receipt) => receipt,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => {
            panic!("fresh reference store must create the head")
        }
    };
    let authenticated = store
        .authenticate_head_receipt(&head_read)
        .expect("the issuing store authenticates its own head receipt");
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x51; 32],
    )
    .expect("authenticated head makes a complete agent receipt");
    assert_eq!(receipt.authority_head_id(), expected_head_id);
    receipt
}

fn authenticated_run(receipt: &AuthorityReadReceipt) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(7),
        receipt.clone(),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        ResourceVector::single(Grade::Bytes, 4_096),
        LogicalTime::new(1_000),
    )
    .expect("authenticated run opens")
}

fn situation_components(
    receipt: &AuthorityReadReceipt,
    task_observed: bool,
) -> [SituationComponent; SITUATION_COMPONENT_COUNT] {
    std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection && task_observed {
            SituationComponent::observed(kind, receipt.authority_head_id(), TASK_GENERATION)
        } else {
            let detail_byte = u8::try_from(index + 1).expect("ten component indexes fit u8");
            SituationComponent::omitted(
                kind,
                SituationOmissionReason::NotAvailable,
                [detail_byte; 32],
            )
        }
    })
}

const fn ready_item() -> WorkItem {
    WorkItem::new(
        WorkTaskId::from_bytes([0x61; 32]),
        TASK_GENERATION,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 3, 5),
        WorkEligibilityInputs::new(0, Some(RunId::new(7)), None, true, WorkConflict::Clear),
    )
}

#[test]
fn public_frontier_path_binds_observed_projection_and_active_run() {
    let receipt = authority_receipt();
    let run = authenticated_run(&receipt);
    let situation = AgentSituationReceipt::build(
        receipt.clone(),
        Some(&run),
        None,
        LogicalTime::new(20),
        situation_components(&receipt, true),
    )
    .expect("authority-bound situation");

    let frontier = WorkFrontier::build(&situation, vec![ready_item()])
        .expect("observed projection and matching run make one candidate");
    assert_eq!(frontier.situation_id(), situation.situation_id().as_bytes());
    assert_eq!(frontier.task_projection_generation(), &TASK_GENERATION);
    assert_eq!(frontier.active_run(), Some(run.run_id()));
    assert_eq!(frontier.candidates().len(), 1);
    assert_eq!(frontier.candidates()[0].action(), WorkAction::Implement);
    assert!(frontier.excluded().is_empty());
}

#[test]
fn omitted_task_projection_is_a_refusal_not_an_empty_frontier() {
    let receipt = authority_receipt();
    let run = authenticated_run(&receipt);
    let components = situation_components(&receipt, false);
    let expected_detail = components[0]
        .omission_detail_commitment()
        .expect("task projection is explicitly omitted");
    let situation =
        AgentSituationReceipt::build(receipt, Some(&run), None, LogicalTime::new(20), components)
            .expect("omitted components are a complete situation");

    assert_eq!(
        WorkFrontier::build(&situation, vec![ready_item()])
            .expect_err("omitted task projection must fail closed"),
        FrontierRefusal::TaskProjectionUnavailable {
            reason: SituationOmissionReason::NotAvailable,
            detail_commitment: expected_detail,
        }
    );
}

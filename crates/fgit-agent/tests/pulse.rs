#![forbid(unsafe_code)]
//! Public contract tests for the compact Agent Control Plane pulse.

use fgit_agent::{
    AgentControlPulse, AgentSituationReceipt, AuthorityReadReceipt, ClassSet, IntentRun,
    LogicalTime, OperationClass, PulseRefusal, PulseState, RunId, SITUATION_COMPONENT_COUNT,
    SituationComponent, SituationComponentKind, SituationOmissionReason, TaskPhase, WorkAction,
    WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    authority_head_identity, initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::{IdentityDomain, NativeObjectIdentity};
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositorySequence,
};

const TASK_GENERATION: [u8; 32] = [0x44; 32];

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x5a; 32]).expect("fixed-width RCR identity digest"),
    )
}

fn receipt() -> AuthorityReadReceipt {
    let repository_id = fgit_types::RepositoryId::from_bytes([0x22; 16]);
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
    let expected = authority_head_identity(&head).expect("head identity");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(93));
    let key = HeadKey::new(b"agent-pulse-test-head".to_vec()).expect("head key");
    let read = match initialize_repository(&store, &key, &head).expect("initialize") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("store authenticates its receipt");
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x51; 32],
    )
    .expect("complete receipt");
    assert_eq!(receipt.authority_head_id(), expected);
    receipt
}

fn run(receipt: &AuthorityReadReceipt, id: u128, expiry: u64) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(id),
        receipt.clone(),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        ResourceVector::single(Grade::Bytes, 4_096),
        LogicalTime::new(expiry),
    )
    .expect("run opens")
}

fn situation(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    observed_at: u64,
    extra_generation: u8,
) -> AgentSituationReceipt {
    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            SituationComponent::observed(kind, receipt.authority_head_id(), TASK_GENERATION)
        } else if kind == SituationComponentKind::Search {
            SituationComponent::observed(
                kind,
                receipt.authority_head_id(),
                [extra_generation; 32],
            )
        } else {
            SituationComponent::omitted(
                kind,
                SituationOmissionReason::NotAvailable,
                [u8::try_from(index + 1).expect("component index"); 32],
            )
        }
    });
    AgentSituationReceipt::build(
        receipt.clone(),
        Some(run),
        None,
        LogicalTime::new(observed_at),
        components,
    )
    .expect("complete situation")
}

fn item(id: u8, blockers: u32, owner: RunId) -> WorkItem {
    WorkItem::new(
        WorkTaskId::from_bytes([id; 32]),
        TASK_GENERATION,
        TaskPhase::Open,
        WorkRankingInputs::new(1, u32::from(id), u64::from(id)),
        WorkEligibilityInputs::new(
            blockers,
            Some(owner),
            None,
            true,
            WorkConflict::Clear,
        ),
    )
}

#[test]
fn pulse_is_deterministic_and_keeps_exclusion_counts_visible() {
    let receipt = receipt();
    let run = run(&receipt, 7, 100);
    let situation = situation(&receipt, &run, 20, 0x71);
    let frontier = WorkFrontier::build_action_scoped(
        &situation,
        vec![item(1, 0, run.run_id()), item(2, 3, run.run_id())],
    )
    .expect("frontier");

    let pulse = AgentControlPulse::build(&situation, &frontier, Some(&run)).expect("pulse");
    let identical = AgentControlPulse::build(&situation, &frontier, Some(&run)).expect("pulse");

    assert_eq!(pulse.pulse_id(), identical.pulse_id());
    assert_eq!(pulse.state(), PulseState::Actionable);
    assert_eq!(pulse.candidate_count(), 1);
    assert_eq!(pulse.excluded_count(), 1);
    assert_eq!(pulse.exclusions().blocked_tasks(), 1);
    assert_eq!(pulse.exclusions().declared_blockers(), 3);
    let selected = pulse.selected().expect("selected work");
    assert_eq!(selected.task_id(), WorkTaskId::from_bytes([1; 32]));
    assert_eq!(selected.action(), WorkAction::Implement);
}

#[test]
fn pulse_refuses_an_expired_or_substituted_run() {
    let receipt = receipt();
    let expired = run(&receipt, 7, 20);
    let situation = situation(&receipt, &expired, 20, 0x71);
    let frontier = WorkFrontier::build_action_scoped(
        &situation,
        vec![item(1, 0, expired.run_id())],
    )
    .expect("frontier remains an inert observation");
    assert_eq!(
        AgentControlPulse::build(&situation, &frontier, Some(&expired))
            .expect_err("expiry is exclusive"),
        PulseRefusal::ActiveRunExpired {
            run_id: expired.run_id(),
            expiry: LogicalTime::new(20),
            observed: LogicalTime::new(20),
        }
    );

    let live = run(&receipt, 8, 100);
    assert_eq!(
        AgentControlPulse::build(&situation, &frontier, Some(&live))
            .expect_err("run identity cannot be substituted"),
        PulseRefusal::ActiveRunIdMismatch {
            expected: expired.run_id(),
            observed: live.run_id(),
        }
    );
}

#[test]
fn frontier_from_another_situation_cannot_be_relabelled_current() {
    let receipt = receipt();
    let run = run(&receipt, 7, 100);
    let first = situation(&receipt, &run, 20, 0x71);
    let second = situation(&receipt, &run, 20, 0x72);
    let frontier = WorkFrontier::build_action_scoped(&first, vec![item(1, 0, run.run_id())])
        .expect("frontier");

    assert!(matches!(
        AgentControlPulse::build(&second, &frontier, Some(&run)),
        Err(PulseRefusal::FrontierSituationMismatch { .. })
    ));
}

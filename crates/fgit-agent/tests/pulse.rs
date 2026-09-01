#![forbid(unsafe_code)]
//! Public-path tests for the compact Agent Control Plane pulse.

use fgit_agent::{
    AgentControlPulse, AgentSituationReceipt, AuthorityReadReceipt, ClassSet,
    FrontierExclusionReason, IntentRun, LogicalTime, OperationClass, PulseRefusal, PulseState,
    RunId, SITUATION_COMPONENT_COUNT, SituationComponent, SituationComponentKind,
    SituationOmissionReason, TaskPhase, WorkAction, WorkConflict, WorkEligibilityInputs,
    WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
};
use fgit_authority::{
    HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId, authority_head_identity,
    initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::{IdentityDomain, NativeObjectIdentity};
use fgit_resource::{ResourceVector, algebra::Grade};
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

fn authority_receipt() -> AuthorityReadReceipt {
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
    let expected_head_id = authority_head_identity(&head)
        .expect("a complete canonical authority head re-identifies itself");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(93));
    let head_key =
        HeadKey::new(b"agent-pulse-test-head".to_vec()).expect("bounded nonempty head key");
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

fn run(receipt: &AuthorityReadReceipt, run_id: u128, expiry: u64) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(run_id),
        receipt.clone(),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        ResourceVector::single(Grade::Bytes, 4_096),
        LogicalTime::new(expiry),
    )
    .expect("authenticated run opens")
}

fn components(
    receipt: &AuthorityReadReceipt,
    search_generation: u8,
) -> [SituationComponent; SITUATION_COMPONENT_COUNT] {
    std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            SituationComponent::observed(kind, receipt.authority_head_id(), TASK_GENERATION)
        } else if kind == SituationComponentKind::Search {
            SituationComponent::observed(
                kind,
                receipt.authority_head_id(),
                [search_generation; 32],
            )
        } else {
            let byte = u8::try_from(index + 1).expect("component index fits u8");
            SituationComponent::omitted(
                kind,
                SituationOmissionReason::NotAvailable,
                [byte; 32],
            )
        }
    })
}

fn situation(
    receipt: &AuthorityReadReceipt,
    active_run: Option<&IntentRun>,
    observed_at: u64,
    search_generation: u8,
) -> AgentSituationReceipt {
    AgentSituationReceipt::build(
        receipt.clone(),
        active_run,
        None,
        LogicalTime::new(observed_at),
        components(receipt, search_generation),
    )
    .expect("complete authority-bound situation")
}

fn item(
    id: u8,
    phase: TaskPhase,
    eligibility: WorkEligibilityInputs,
    priority: u16,
) -> WorkItem {
    WorkItem::new(
        WorkTaskId::from_bytes([id; 32]),
        TASK_GENERATION,
        phase,
        WorkRankingInputs::new(priority, u32::from(id), u64::from(id)),
        eligibility,
    )
}

#[test]
fn pulse_binds_the_exact_turn_and_preserves_compact_exclusion_accounting() {
    let receipt = authority_receipt();
    let active_run = run(&receipt, 7, 100);
    let situation = situation(&receipt, Some(&active_run), 20, 0x71);
    let items = vec![
        item(
            1,
            TaskPhase::Open,
            WorkEligibilityInputs::new(
                0,
                Some(active_run.run_id()),
                None,
                true,
                WorkConflict::Clear,
            ),
            2,
        ),
        item(
            2,
            TaskPhase::Open,
            WorkEligibilityInputs::new(
                3,
                Some(active_run.run_id()),
                None,
                true,
                WorkConflict::Clear,
            ),
            1,
        ),
        item(
            3,
            TaskPhase::Open,
            WorkEligibilityInputs::new(
                0,
                Some(active_run.run_id()),
                None,
                true,
                WorkConflict::ReservedBy(RunId::new(99)),
            ),
            1,
        ),
    ];
    let frontier = WorkFrontier::build(&situation, items).expect("deterministic frontier");

    let pulse = AgentControlPulse::build(&situation, &frontier, Some(&active_run))
        .expect("live exact run makes an actionable pulse");
    let identical = AgentControlPulse::build(&situation, &frontier, Some(&active_run))
        .expect("same inputs make the same pulse");

    assert_eq!(pulse.pulse_id(), identical.pulse_id());
    assert_eq!(pulse.state(), PulseState::Actionable);
    assert_eq!(pulse.candidate_count(), 1);
    assert_eq!(pulse.excluded_count(), 2);
    assert_eq!(pulse.exclusions().blocked_tasks(), 1);
    assert_eq!(pulse.exclusions().declared_blockers(), 3);
    assert_eq!(pulse.exclusions().reserved_by_other(), 1);
    assert_eq!(pulse.exclusions().total(), 2);
    let selected = pulse.selected().expect("one candidate is selected");
    assert_eq!(selected.task_id(), WorkTaskId::from_bytes([1; 32]));
    assert_eq!(selected.action(), WorkAction::Implement);
    assert_eq!(selected.rank(), 0);
    assert_ne!(pulse.pulse_id().as_bytes(), &[0; 32]);
}

#[test]
fn action_scoped_frontier_allows_implementation_but_not_self_verification() {
    let receipt = authority_receipt();
    let active_run = run(&receipt, 7, 100);
    let situation = situation(&receipt, Some(&active_run), 20, 0x71);
    let frontier = WorkFrontier::build_action_scoped(
        &situation,
        vec![
            item(
                1,
                TaskPhase::Open,
                WorkEligibilityInputs::new(
                    0,
                    Some(active_run.run_id()),
                    Some(active_run.run_id()),
                    true,
                    WorkConflict::Clear,
                ),
                2,
            ),
            item(
                2,
                TaskPhase::VerificationPending,
                WorkEligibilityInputs::new(
                    0,
                    Some(active_run.run_id()),
                    Some(active_run.run_id()),
                    true,
                    WorkConflict::Clear,
                ),
                1,
            ),
        ],
    )
    .expect("action-scoped frontier");

    assert_eq!(frontier.candidates().len(), 1);
    assert_eq!(
        frontier.selected().expect("implementation remains eligible").item().task_id(),
        WorkTaskId::from_bytes([1; 32])
    );
    assert_eq!(frontier.excluded().len(), 1);
    assert_eq!(
        frontier.excluded()[0].reason(),
        FrontierExclusionReason::IndependenceRequired {
            implementation_run: active_run.run_id(),
        }
    );
}

#[test]
fn expired_run_is_observable_but_not_actionable() {
    let receipt = authority_receipt();
    let expired = run(&receipt, 7, 20);
    let situation = situation(&receipt, Some(&expired), 20, 0x71);
    let frontier = WorkFrontier::build(
        &situation,
        vec![item(
            1,
            TaskPhase::Open,
            WorkEligibilityInputs::new(
                0,
                Some(expired.run_id()),
                None,
                true,
                WorkConflict::Clear,
            ),
            1,
        )],
    )
    .expect("frontier is an inert description of the situation");

    assert_eq!(
        AgentControlPulse::build(&situation, &frontier, Some(&expired))
            .expect_err("expiry is exclusive and must fail closed"),
        PulseRefusal::ActiveRunExpired {
            run_id: expired.run_id(),
            expiry: LogicalTime::new(20),
            observed: LogicalTime::new(20),
        }
    );
}

#[test]
fn a_frontier_from_another_situation_cannot_be_relabelled_as_current() {
    let receipt = authority_receipt();
    let active_run = run(&receipt, 7, 100);
    let first = situation(&receipt, Some(&active_run), 20, 0x71);
    let second = situation(&receipt, Some(&active_run), 20, 0x72);
    let frontier = WorkFrontier::build(
        &first,
        vec![item(
            1,
            TaskPhase::Open,
            WorkEligibilityInputs::new(
                0,
                Some(active_run.run_id()),
                None,
                true,
                WorkConflict::Clear,
            ),
            1,
        )],
    )
    .expect("frontier for first situation");

    assert!(matches!(
        AgentControlPulse::build(&second, &frontier, Some(&active_run)),
        Err(PulseRefusal::FrontierSituationMismatch { .. })
    ));
}

#[test]
fn a_complete_but_different_run_object_is_refused() {
    let receipt = authority_receipt();
    let expected = run(&receipt, 7, 100);
    let other = run(&receipt, 8, 100);
    let situation = situation(&receipt, Some(&expected), 20, 0x71);
    let frontier = WorkFrontier::build(&situation, Vec::new())
        .expect("empty bounded task projection makes an empty frontier");

    assert_eq!(
        AgentControlPulse::build(&situation, &frontier, Some(&other))
            .expect_err("run identity cannot be substituted"),
        PulseRefusal::ActiveRunIdMismatch {
            expected: expected.run_id(),
            observed: other.run_id(),
        }
    );
}

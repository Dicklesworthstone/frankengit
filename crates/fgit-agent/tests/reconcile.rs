#![forbid(unsafe_code)]
//! Public-path tests for complete Intent Run effect reconciliation.

use fgit_agent::{
    AgentInstanceId, AuthorityReadReceipt, CapabilityId, ClassSet, EffectClass, EffectId,
    EffectRecord, EffectResolutionAction, EffectTerminalOutcome, IntentRun, LogicalTime,
    OperationClass, RunId, RunReconciliationReadiness, RunReconciliationRefusal,
    RunReconciliationReport,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    authority_head_identity, initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::IdentityDomain;
use fgit_resource::{
    EscalationReason, Grade, IdempotencyKey, ObligationClass, ObligationState, ResourceVector,
    TerminalFailureReason,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, PrincipalId,
    RegistryEpoch, RepositoryCommitId, RepositorySequence,
};

fn digest(byte: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width digest"),
    )
}

fn rcr_id(byte: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width RCR identity digest"),
    )
}

fn authority_receipt(store_id: u64, repository_byte: u8) -> AuthorityReadReceipt {
    let repository_id = fgit_types::RepositoryId::from_bytes([repository_byte; 16]);
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    let head = RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: Some(rcr_id(repository_byte)),
        latest_repository_sequence: Some(RepositorySequence::FIRST),
        ref_root: root,
        forge_position_root: root,
        outcome_index_root: root,
        retention_root: root,
        outbox_root: root,
        configuration_root: digest(repository_byte.wrapping_add(1)),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let expected_head_id = authority_head_identity(&head)
        .expect("a complete canonical authority head re-identifies itself");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let head_key = HeadKey::new(format!("agent-reconcile-test-head-{store_id}").into_bytes())
        .expect("bounded nonempty head key");
    let head_read = match initialize_repository(&store, &head_key, &head)
        .expect("the reference store initializes one complete authority head")
    {
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

fn run(receipt: &AuthorityReadReceipt, bytes: u64) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(7),
        receipt.clone(),
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
            OperationClass::ExecuteSandboxedProcess,
            OperationClass::ExternalIntegration,
            OperationClass::SubmitEvidence,
        ]),
        ResourceVector::from_grades(&[(Grade::Bytes, bytes), (Grade::CpuMicros, 10_000)]),
        LogicalTime::new(100),
    )
    .expect("authenticated run opens")
}

const fn effect_class(operation: OperationClass) -> EffectClass {
    match operation {
        OperationClass::ReadCanonicalObject => EffectClass::PureCanonicalRead,
        OperationClass::CreateCandidateObject => EffectClass::ImmutableCandidateCreation,
        OperationClass::PreparePublication => EffectClass::PreparedCanonicalMutation,
        OperationClass::SubmitEvidence | OperationClass::MutateForgeEntity => {
            EffectClass::CanonicalMutation
        }
        OperationClass::ExternalIntegration => EffectClass::ExternalEffect,
        OperationClass::ReadDerivedGeneration
        | OperationClass::TreeFsWorkspace
        | OperationClass::ExecuteSandboxedProcess
        | OperationClass::NetworkDestination
        | OperationClass::SecretHandle
        | OperationClass::DelegateSubIntent
        | OperationClass::ConsumeBudget => EffectClass::DerivedLocalWrite,
    }
}

#[allow(clippy::too_many_arguments)]
fn record(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    id: u128,
    operation: OperationClass,
    state: ObligationState,
    terminal_outcome: Option<EffectTerminalOutcome>,
    parent_effect_id: Option<EffectId>,
    accepted_at: u64,
    reserved: u64,
    consumed: u64,
) -> EffectRecord {
    let class = effect_class(operation);
    EffectRecord {
        effect_id: EffectId::new(id),
        run_id: run.run_id(),
        run_commitment: run.commitment().expect("complete run commitment"),
        agent_instance_id: AgentInstanceId::new(1),
        parent_effect_id,
        capability_id: CapabilityId::new(2),
        effect_class: class,
        operation,
        input_commitment: [u8::try_from(id).unwrap_or(0xff); 32],
        source_authority_receipt: Some(receipt.clone()),
        budget_reserved: ResourceVector::single(Grade::Bytes, reserved),
        budget_consumed: ResourceVector::single(Grade::Bytes, consumed),
        external_idempotency_key: (class == EffectClass::ExternalEffect)
            .then(|| IdempotencyKey::new(digest(u8::try_from(id).unwrap_or(0xee)))),
        obligation_state: state,
        obligation_class: (class == EffectClass::ExternalEffect)
            .then_some(ObligationClass::OutboxEffectPermit),
        terminal_outcome,
        output_commitments: vec![[u8::try_from(id).unwrap_or(0xdd); 32]],
        reconciliation_evidence: None,
        accepted_at: LogicalTime::new(accepted_at),
    }
}

#[test]
fn report_is_order_independent_and_preserves_every_lifecycle_class() {
    let receipt = authority_receipt(131, 0x22);
    let run = run(&receipt, 10_000);
    let mut records = vec![
        record(
            &receipt,
            &run,
            1,
            OperationClass::SubmitEvidence,
            ObligationState::Acknowledged,
            Some(EffectTerminalOutcome::Acknowledged),
            None,
            20,
            40,
            20,
        ),
        record(
            &receipt,
            &run,
            2,
            OperationClass::TreeFsWorkspace,
            ObligationState::Reserved,
            None,
            None,
            21,
            40,
            0,
        ),
        record(
            &receipt,
            &run,
            3,
            OperationClass::ExternalIntegration,
            ObligationState::DeferredExternally,
            None,
            None,
            22,
            40,
            10,
        ),
        record(
            &receipt,
            &run,
            4,
            OperationClass::ExternalIntegration,
            ObligationState::Escalated,
            Some(EffectTerminalOutcome::Escalated {
                owner: PrincipalId::from_bytes([0x44; 16]),
                reason: EscalationReason::IndeterminateDelivery,
            }),
            None,
            23,
            40,
            10,
        ),
        record(
            &receipt,
            &run,
            5,
            OperationClass::ExecuteSandboxedProcess,
            ObligationState::Aborted,
            Some(EffectTerminalOutcome::Aborted),
            None,
            24,
            40,
            5,
        ),
        record(
            &receipt,
            &run,
            6,
            OperationClass::ExternalIntegration,
            ObligationState::TerminallyFailed,
            Some(EffectTerminalOutcome::TerminallyFailed {
                reason: TerminalFailureReason::PermanentDownstreamRejection,
            }),
            None,
            25,
            40,
            10,
        ),
        record(
            &receipt,
            &run,
            7,
            OperationClass::TreeFsWorkspace,
            ObligationState::Leaked,
            None,
            None,
            26,
            40,
            0,
        ),
    ];

    let first = RunReconciliationReport::build(&run, records.clone(), LogicalTime::new(50))
        .expect("complete run inventory reconciles");
    records.reverse();
    let second = RunReconciliationReport::build(&run, records, LogicalTime::new(50))
        .expect("input ordering cannot change the report");

    assert_eq!(first.report_id(), second.report_id());
    assert_eq!(
        first.run_commitment(),
        run.commitment().expect("complete run commitment")
    );
    assert_eq!(first.counts().total(), 7);
    assert_eq!(first.counts().reserved(), 1);
    assert_eq!(first.counts().committed_or_deferred(), 1);
    assert_eq!(first.counts().escalated(), 1);
    assert_eq!(first.counts().acknowledged(), 1);
    assert_eq!(first.counts().aborted(), 1);
    assert_eq!(first.counts().terminally_failed(), 1);
    assert_eq!(first.counts().leaked(), 1);
    assert_eq!(
        first.readiness(),
        RunReconciliationReadiness::ContainmentFailure
    );
    assert_eq!(first.effects()[0].record().effect_id, EffectId::new(1));
    assert_eq!(
        first.effects()[1].required_action(),
        EffectResolutionAction::AbortReservation
    );
    assert_eq!(
        first.effects()[2].required_action(),
        EffectResolutionAction::ReconcileCommittedEffect
    );
    assert_eq!(
        first.effects()[3].required_action(),
        EffectResolutionAction::ResolveEscalation
    );
    assert_eq!(
        first.effects()[6].required_action(),
        EffectResolutionAction::ContainLeak
    );
}

#[test]
fn state_and_terminal_marker_must_agree() {
    let receipt = authority_receipt(132, 0x23);
    let run = run(&receipt, 1_000);
    let malformed = record(
        &receipt,
        &run,
        1,
        OperationClass::TreeFsWorkspace,
        ObligationState::Reserved,
        Some(EffectTerminalOutcome::Acknowledged),
        None,
        20,
        40,
        0,
    );

    assert_eq!(
        RunReconciliationReport::build(&run, vec![malformed], LogicalTime::new(30))
            .expect_err("reserved effect cannot claim acknowledgement"),
        RunReconciliationRefusal::TerminalStateMismatch {
            effect_id: EffectId::new(1),
            state: ObligationState::Reserved,
        }
    );
}

#[test]
fn parent_graph_must_be_complete_and_acyclic() {
    let receipt = authority_receipt(133, 0x24);
    let run = run(&receipt, 1_000);
    let first = record(
        &receipt,
        &run,
        1,
        OperationClass::TreeFsWorkspace,
        ObligationState::Reserved,
        None,
        Some(EffectId::new(2)),
        20,
        40,
        0,
    );
    let second = record(
        &receipt,
        &run,
        2,
        OperationClass::TreeFsWorkspace,
        ObligationState::Reserved,
        None,
        Some(EffectId::new(1)),
        20,
        40,
        0,
    );

    assert!(matches!(
        RunReconciliationReport::build(&run, vec![first, second], LogicalTime::new(30)),
        Err(RunReconciliationRefusal::ParentCycle { .. })
    ));
}

#[test]
fn effect_authority_cannot_be_substituted() {
    let receipt = authority_receipt(134, 0x25);
    let foreign = authority_receipt(135, 0x26);
    let run = run(&receipt, 1_000);
    let mut effect = record(
        &receipt,
        &run,
        1,
        OperationClass::TreeFsWorkspace,
        ObligationState::Reserved,
        None,
        None,
        20,
        40,
        0,
    );
    effect.source_authority_receipt = Some(foreign);

    assert_eq!(
        RunReconciliationReport::build(&run, vec![effect], LogicalTime::new(30))
            .expect_err("mixed authority must fail closed"),
        RunReconciliationRefusal::EffectAuthorityMismatch {
            effect_id: EffectId::new(1),
        }
    );
}

#[test]
fn same_run_id_with_another_machine_scope_is_refused_first() {
    let receipt = authority_receipt(136, 0x27);
    let source = run(&receipt, 1_000);
    let altered = IntentRun::new_authenticated(
        source.run_id(),
        receipt.clone(),
        source.allowed_operation_classes(),
        ResourceVector::from_grades(&[(Grade::Bytes, 999), (Grade::CpuMicros, 10_000)]),
        LogicalTime::new(90),
    )
    .expect("same-ID altered run is structurally valid");
    let effect = record(
        &receipt,
        &source,
        1,
        OperationClass::TreeFsWorkspace,
        ObligationState::Reserved,
        None,
        None,
        20,
        40,
        0,
    );

    assert_eq!(
        RunReconciliationReport::build(&altered, vec![effect], LogicalTime::new(30))
            .expect_err("numeric RunId cannot substitute complete machine scope"),
        RunReconciliationRefusal::EffectRunCommitmentMismatch {
            effect_id: EffectId::new(1),
            expected: altered.commitment().expect("altered run commitment"),
            observed: source.commitment().expect("source run commitment"),
        }
    );
}

#[test]
fn cumulative_consumable_spend_cannot_exceed_the_run() {
    let receipt = authority_receipt(137, 0x28);
    let run = run(&receipt, 100);
    let first = record(
        &receipt,
        &run,
        1,
        OperationClass::SubmitEvidence,
        ObligationState::Acknowledged,
        Some(EffectTerminalOutcome::Acknowledged),
        None,
        20,
        60,
        60,
    );
    let second = record(
        &receipt,
        &run,
        2,
        OperationClass::SubmitEvidence,
        ObligationState::Acknowledged,
        Some(EffectTerminalOutcome::Acknowledged),
        None,
        21,
        60,
        60,
    );

    assert!(matches!(
        RunReconciliationReport::build(&run, vec![first, second], LogicalTime::new(30)),
        Err(RunReconciliationRefusal::ConsumableBudgetExceedsRun { .. })
    ));
}

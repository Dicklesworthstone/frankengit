#![forbid(unsafe_code)]
//! Authority-bound situation receipt and delta tests.

use fgit_agent::{
    AgentSituationReceipt, AuthorityBasisRef, AuthorityReadReceipt, ClassSet, IntentRun,
    LogicalTime, OperationClass, RunId, SITUATION_COMPONENT_COUNT, SituationAuthorityChange,
    SituationComponent, SituationComponentKind, SituationComponentTransition, SituationDelta,
    SituationOmissionReason, SituationRefusal,
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
    RepositoryCommitId, RepositoryId, RepositorySequence,
};

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x5a; 32]).expect("fixed-width RCR identity digest"),
    )
}

fn authority_receipt(
    repository_byte: u8,
    configuration_byte: u8,
    verified_at: u64,
    verifier_byte: u8,
) -> AuthorityReadReceipt {
    let repository_id = RepositoryId::from_bytes([repository_byte; 16]);
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    let configuration_root = Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[configuration_byte; 32]).expect("fixed-width configuration root"),
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(73));
    let head_key =
        HeadKey::new(b"agent-situation-test-head".to_vec()).expect("bounded nonempty head key");
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
        LogicalTime::new(verified_at),
        [verifier_byte; 32],
    )
    .expect("authenticated head makes a complete agent receipt");
    assert_eq!(receipt.authority_head_id(), expected_head_id);
    receipt
}

fn components(
    receipt: &AuthorityReadReceipt,
) -> [SituationComponent; SITUATION_COMPONENT_COUNT] {
    std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        let byte = u8::try_from(index + 1).expect("the v1 component count fits u8");
        if index % 3 == 0 {
            SituationComponent::omitted(
                kind,
                SituationOmissionReason::NotAvailable,
                [byte; 32],
            )
        } else {
            SituationComponent::observed(kind, receipt.authority_head_id(), [byte; 32])
        }
    })
}

fn authenticated_run(receipt: &AuthorityReadReceipt, run_id: u128) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(run_id),
        receipt.clone(),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        ResourceVector::single(Grade::Bytes, 4_096),
        LogicalTime::new(1_000),
    )
    .expect("authenticated run opens")
}

#[test]
fn situation_identity_is_order_independent_and_change_sensitive() {
    let receipt = authority_receipt(0x22, 0x41, 10, 0x51);
    let ordered = components(&receipt);
    let mut reversed = ordered;
    reversed.reverse();

    let first = AgentSituationReceipt::build(
        receipt.clone(),
        None,
        None,
        LogicalTime::new(20),
        ordered,
    )
    .expect("ordered situation");
    let second = AgentSituationReceipt::build(
        receipt.clone(),
        None,
        None,
        LogicalTime::new(20),
        reversed,
    )
    .expect("reordered situation");
    assert_eq!(first.situation_id(), second.situation_id());
    let canonical_kinds =
        std::array::from_fn(|index| first.components()[index].kind());
    assert_eq!(canonical_kinds, SituationComponentKind::ALL);
    assert_eq!(
        first.observed_component_count() + first.omitted_component_count(),
        SITUATION_COMPONENT_COUNT
    );

    let mut changed = components(&receipt);
    let search = changed
        .iter_mut()
        .find(|component| component.kind() == SituationComponentKind::Search)
        .expect("search component exists");
    *search = SituationComponent::observed(
        SituationComponentKind::Search,
        receipt.authority_head_id(),
        [0xee; 32],
    );
    let third = AgentSituationReceipt::build(
        receipt,
        None,
        None,
        LogicalTime::new(20),
        changed,
    )
    .expect("changed situation");
    assert_ne!(first.situation_id(), third.situation_id());
}

#[test]
fn situation_refuses_duplicates_mixed_authority_and_legacy_runs() {
    let receipt = authority_receipt(0x22, 0x41, 10, 0x51);
    let other = authority_receipt(0x33, 0x42, 10, 0x52);

    let mut duplicate = components(&receipt);
    duplicate[9] = SituationComponent::observed(
        SituationComponentKind::Search,
        receipt.authority_head_id(),
        [0xaa; 32],
    );
    assert_eq!(
        AgentSituationReceipt::build(
            receipt.clone(),
            None,
            None,
            LogicalTime::new(20),
            duplicate,
        )
        .expect_err("duplicate component must fail"),
        SituationRefusal::DuplicateComponent {
            kind: SituationComponentKind::Search,
        }
    );

    let mut mixed = components(&receipt);
    mixed[0] = SituationComponent::observed(
        SituationComponentKind::TaskProjection,
        other.authority_head_id(),
        [0x91; 32],
    );
    assert_eq!(
        AgentSituationReceipt::build(
            receipt.clone(),
            None,
            None,
            LogicalTime::new(20),
            mixed,
        )
        .expect_err("mixed authority must fail"),
        SituationRefusal::ComponentAuthorityMismatch {
            kind: SituationComponentKind::TaskProjection,
        }
    );

    assert_eq!(
        AgentSituationReceipt::build(
            receipt.clone(),
            None,
            None,
            LogicalTime::new(9),
            components(&receipt),
        )
        .expect_err("observation cannot predate verification"),
        SituationRefusal::ObservationBeforeAuthorityVerification {
            observed: LogicalTime::new(9),
            verified: LogicalTime::new(10),
        }
    );

    let other_run = authenticated_run(&other, 8);
    assert_eq!(
        AgentSituationReceipt::build(
            receipt.clone(),
            Some(&other_run),
            None,
            LogicalTime::new(20),
            components(&receipt),
        )
        .expect_err("another run receipt must fail"),
        SituationRefusal::RunAuthorityMismatch
    );

    let legacy = IntentRun::new(
        RunId::new(9),
        AuthorityBasisRef {
            repository_id: u128::from_be_bytes(*receipt.repository_id().as_bytes()),
            authority_head_generation: receipt.authority_head_generation().get(),
            authority_head_digest: [0x61; 32],
            verified_at: LogicalTime::new(10),
        },
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        ResourceVector::single(Grade::Bytes, 4_096),
        LogicalTime::new(1_000),
    )
    .expect("legacy run opens for compatibility testing");
    assert_eq!(
        AgentSituationReceipt::build(
            receipt.clone(),
            Some(&legacy),
            None,
            LogicalTime::new(20),
            components(&receipt),
        )
        .expect_err("legacy run must fail"),
        SituationRefusal::RunAuthorityReceiptRequired
    );
}

#[test]
fn situation_delta_is_minimal_and_refuses_forks_and_rollbacks() {
    let receipt = authority_receipt(0x22, 0x41, 10, 0x51);
    let before = AgentSituationReceipt::build(
        receipt.clone(),
        None,
        None,
        LogicalTime::new(20),
        components(&receipt),
    )
    .expect("before situation");

    let time_only = AgentSituationReceipt::build(
        receipt.clone(),
        None,
        None,
        LogicalTime::new(21),
        components(&receipt),
    )
    .expect("time-only situation");
    let time_delta = SituationDelta::between(&before, &time_only).expect("time delta");
    assert!(time_delta.has_no_context_changes());
    assert!(time_delta.observation_time_advanced());
    assert!(time_delta.component_changes().is_empty());

    let mut changed = components(&receipt);
    let ownership = changed
        .iter_mut()
        .find(|component| component.kind() == SituationComponentKind::Ownership)
        .expect("ownership component exists");
    *ownership = SituationComponent::observed(
        SituationComponentKind::Ownership,
        receipt.authority_head_id(),
        [0xf1; 32],
    );
    let after = AgentSituationReceipt::build(
        receipt.clone(),
        None,
        None,
        LogicalTime::new(22),
        changed,
    )
    .expect("after situation");
    let delta = SituationDelta::between(&before, &after).expect("component delta");
    assert_eq!(delta.authority_change(), SituationAuthorityChange::Unchanged);
    assert_eq!(delta.component_changes().len(), 1);
    assert_eq!(
        delta.component_changes()[0].kind(),
        SituationComponentKind::Ownership
    );
    assert_eq!(
        delta.component_changes()[0].transition(),
        SituationComponentTransition::GenerationChanged
    );

    let other_repository = authority_receipt(0x33, 0x42, 10, 0x52);
    let other_situation = AgentSituationReceipt::build(
        other_repository.clone(),
        None,
        None,
        LogicalTime::new(22),
        components(&other_repository),
    )
    .expect("other repository situation");
    assert!(matches!(
        SituationDelta::between(&before, &other_situation),
        Err(SituationRefusal::DeltaRepositoryMismatch { .. })
    ));

    let fork_receipt = authority_receipt(0x22, 0x99, 10, 0x51);
    let fork = AgentSituationReceipt::build(
        fork_receipt.clone(),
        None,
        None,
        LogicalTime::new(22),
        components(&fork_receipt),
    )
    .expect("fork situation");
    assert_eq!(
        SituationDelta::between(&before, &fork).expect_err("same-generation fork must fail"),
        SituationRefusal::AuthorityForkAtSameGeneration {
            generation: HeadGeneration::FIRST,
        }
    );

    assert_eq!(
        SituationDelta::between(&after, &before)
            .expect_err("observation-time rollback must fail"),
        SituationRefusal::ObservationTimeRollback {
            from: LogicalTime::new(22),
            to: LogicalTime::new(20),
        }
    );
}

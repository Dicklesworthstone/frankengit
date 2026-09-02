#![forbid(unsafe_code)]
//! Public-path tests for complete Intent Run identity and equivocation refusal.

use fgit_agent::{
    AuthorityReadReceipt, ClassSet, IntentRun, IntentRunBinding, IntentRunIdentityRefusal,
    IntentRunRetry, LogicalTime, OperationClass, RunId,
};
use fgit_authority::{
    AuthenticatedHead, AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::IdentityDomain;
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositoryId, RepositorySequence,
};

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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(311));
    let key = HeadKey::new(b"intent-run-identity".to_vec()).expect("bounded head key");
    let read = match initialize_repository(&store, &key, &body).expect("initialize head") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    store
        .authenticate_head_receipt(&read)
        .expect("issuing store authenticates its receipt")
}

fn run(
    receipt: AuthorityReadReceipt,
    run_id: RunId,
    operations: ClassSet,
    bytes: u64,
    expiry: u64,
) -> IntentRun {
    IntentRun::new_authenticated(
        run_id,
        receipt,
        operations,
        ResourceVector::single(Grade::Bytes, bytes),
        LogicalTime::new(expiry),
    )
    .expect("nonempty authenticated run opens")
}

#[test]
fn identical_retry_revalidates_against_one_complete_binding() {
    let authenticated = authenticated_head();
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(40),
        [0x71; 32],
    )
    .expect("authenticated receipt");
    let first = run(
        receipt.clone(),
        RunId::new(7),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        4_096,
        100,
    );
    let retry = run(
        receipt,
        RunId::new(7),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        4_096,
        100,
    );
    let binding = IntentRunBinding::establish(&first).expect("first binding");

    assert_eq!(
        binding.revalidate(&retry).expect("identical retry"),
        IntentRunRetry::Identical
    );
    assert_eq!(binding.run_id(), RunId::new(7));
    assert_ne!(binding.commitment().as_bytes(), &[0; 32]);
}

#[test]
fn same_run_id_cannot_change_scope_budget_or_expiry() {
    let authenticated = authenticated_head();
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(40),
        [0x71; 32],
    )
    .expect("authenticated receipt");
    let first = run(
        receipt.clone(),
        RunId::new(7),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        4_096,
        100,
    );
    let binding = IntentRunBinding::establish(&first).expect("first binding");

    for changed in [
        run(
            receipt.clone(),
            RunId::new(7),
            ClassSet::from_classes(&[
                OperationClass::TreeFsWorkspace,
                OperationClass::SubmitEvidence,
            ]),
            4_096,
            100,
        ),
        run(
            receipt.clone(),
            RunId::new(7),
            ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
            4_097,
            100,
        ),
        run(
            receipt,
            RunId::new(7),
            ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
            4_096,
            101,
        ),
    ] {
        let refusal = binding
            .revalidate(&changed)
            .expect_err("same run ID with changed machine fields must fail closed");
        match refusal {
            IntentRunIdentityRefusal::RunIdEquivocation { run_id, .. } => {
                assert_eq!(run_id, RunId::new(7));
            }
            other => panic!("unexpected refusal: {other:?}"),
        }
    }
}

#[test]
fn exact_read_event_is_part_of_the_run_commitment() {
    let authenticated = authenticated_head();
    let first_receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(40),
        [0x71; 32],
    )
    .expect("first receipt");
    let later_receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(41),
        [0x71; 32],
    )
    .expect("later receipt");
    let first = run(
        first_receipt,
        RunId::new(7),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        4_096,
        100,
    );
    let later = run(
        later_receipt,
        RunId::new(7),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        4_096,
        100,
    );

    assert_ne!(
        first.commitment().expect("first commitment"),
        later.commitment().expect("later commitment")
    );
}

#[test]
fn one_binding_cannot_be_queried_with_another_run_id() {
    let authenticated = authenticated_head();
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(40),
        [0x71; 32],
    )
    .expect("authenticated receipt");
    let first = run(
        receipt.clone(),
        RunId::new(7),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        4_096,
        100,
    );
    let other = run(
        receipt,
        RunId::new(8),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        4_096,
        100,
    );
    let binding = IntentRunBinding::establish(&first).expect("first binding");

    assert_eq!(
        binding
            .revalidate(&other)
            .expect_err("another run ID is not a retry"),
        IntentRunIdentityRefusal::RunIdMismatch {
            expected: RunId::new(7),
            observed: RunId::new(8),
        }
    );
}

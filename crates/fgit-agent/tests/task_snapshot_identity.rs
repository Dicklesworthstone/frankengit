#![forbid(unsafe_code)]
//! Public-path tests for state-stable task snapshot identity.

use fgit_agent::{
    AuthorityBoundTaskProjectionSnapshot, AuthorityReadReceipt, LogicalTime,
    TaskProjectionAssignment, TaskPhase, WorkTaskId,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::{IdentityDomain, NativeObjectIdentity};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositorySequence,
};

const GENERATION: [u8; 32] = [0x44; 32];

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
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width RCR digest"),
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let key = HeadKey::new(format!("task-snapshot-identity-{store_id}").into_bytes())
        .expect("bounded head key");
    let read = match initialize_repository(&store, &key, &head).expect("initialize") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("authenticate receipt");
    AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x51; 32],
    )
    .expect("complete authority receipt")
}

#[test]
fn later_reread_keeps_state_identity_but_advances_freshness() {
    let authority = authority_receipt(701, 0x22);
    let task_id = WorkTaskId::from_bytes([0x31; 32]);
    let first = AuthorityBoundTaskProjectionSnapshot::observed(
        &authority,
        task_id,
        GENERATION,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(20),
    )
    .expect("first observation");
    let later = AuthorityBoundTaskProjectionSnapshot::observed(
        &authority,
        task_id,
        GENERATION,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(40),
    )
    .expect("later observation of the same persisted row");

    assert_eq!(first.snapshot_id(), later.snapshot_id());
    assert_eq!(first.generation(), later.generation());
    assert_eq!(first.observed_at(), LogicalTime::new(20));
    assert_eq!(later.observed_at(), LogicalTime::new(40));
}

#[test]
fn repository_namespace_changes_state_identity() {
    let first_authority = authority_receipt(702, 0x23);
    let second_authority = authority_receipt(703, 0x24);
    let task_id = WorkTaskId::from_bytes([0x31; 32]);
    let first = AuthorityBoundTaskProjectionSnapshot::observed(
        &first_authority,
        task_id,
        GENERATION,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(20),
    )
    .expect("first repository observation");
    let second = AuthorityBoundTaskProjectionSnapshot::observed(
        &second_authority,
        task_id,
        GENERATION,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(20),
    )
    .expect("second repository observation");

    assert_ne!(first.repository_id(), second.repository_id());
    assert_ne!(first.snapshot_id(), second.snapshot_id());
}

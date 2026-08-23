//! Live capsule freezing reads an authenticated head twice around staging.

use fgit_authority::{
    AuthorityStore, HeadKey, HeadRead, MemoryAuthorityStore, StoreInstanceId, initialize_repository,
};
use fgit_chronicle::{BackupProfile, CapsuleClosure, LiveCapsuleRefusal, freeze_capsule};
use fgit_codec::{CryptoBodyIdentity, RepositoryAuthorityHeadBody};
use fgit_types::{
    Digest, DigestAlgorithmId, DigestBytes, HeadGeneration, OPAQUE_ID_LEN, PolicyEpoch,
    RegistryEpoch, RepositoryId,
};

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("fixture algorithm is reserved"),
        DigestBytes::try_new(&[tag; 32]).expect("fixture digest is 32 bytes"),
    )
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x43; OPAQUE_ID_LEN])
}

fn head() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(1),
        forge_position_root: digest(2),
        outcome_index_root: digest(3),
        retention_root: digest(4),
        outbox_root: digest(5),
        configuration_root: digest(6),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn closure() -> CapsuleClosure {
    CapsuleClosure {
        object_closure_root: digest(7),
        segment_manifest_root: digest(8),
        backup_profile: BackupProfile::FullClosure,
    }
}

#[test]
fn an_authenticated_current_head_yields_a_staged_root_last_candidate() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x43));
    let key = HeadKey::new(b"chronicle/live-capsule".to_vec()).expect("bounded key");
    initialize_repository(&store, &key, &head()).expect("head initializes");
    let receipt = match store.read_head(&key).expect("head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized head is present"),
    };

    let frozen = freeze_capsule(&store, &CryptoBodyIdentity, &receipt, None, closure())
        .expect("a stable authenticated head freezes into a staged capsule");

    assert_eq!(frozen.capsule().head_generation, HeadGeneration::FIRST);
    assert_eq!(frozen.pointer().capsule_id(), frozen.capsule_id());
    assert_eq!(frozen.pointer().repository_id(), repository());
}

#[test]
fn a_receipt_from_another_authority_is_refused_before_staging() {
    let source = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x44));
    let destination = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x45));
    let key = HeadKey::new(b"chronicle/live-capsule-foreign".to_vec()).expect("bounded key");
    initialize_repository(&source, &key, &head()).expect("source head initializes");
    let receipt = match source.read_head(&key).expect("source head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized source head is present"),
    };

    assert!(matches!(
        freeze_capsule(&destination, &CryptoBodyIdentity, &receipt, None, closure()),
        Err(LiveCapsuleRefusal::HeadUnauthenticated(_))
    ));
}

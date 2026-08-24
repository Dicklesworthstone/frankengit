//! FG-059: attested capsule migration halves are real authority operations,
//! never an implicit name-routing flip.

use fgit_authority::{
    AuthorityStore, HeadKey, HeadRead, MemoryAuthorityStore, StoreInstanceId, initialize_repository,
};
use fgit_chronicle::{
    CapsuleClosure, MigrationTargetRefusal, ReplayCompleteness, activate_migration_target,
    freeze_migration_source,
};
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
    RepositoryId::from_bytes([0x59; OPAQUE_ID_LEN])
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
        backup_profile: fgit_chronicle::BackupProfile::FullClosure,
    }
}

fn source_fixture() -> (
    MemoryAuthorityStore,
    HeadKey,
    fgit_authority::HeadReadReceipt,
) {
    let source = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x5901));
    let key =
        HeadKey::new(b"fg059/incarnation-migration/source".to_vec()).expect("bounded fixture key");
    initialize_repository(&source, &key, &head()).expect("source head initializes");
    let receipt = match source.read_head(&key).expect("source head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized source head is present"),
    };
    (source, key, receipt)
}

#[test]
fn source_freeze_and_target_activation_are_attested_but_never_route_the_repository() {
    let (source, _source_key, source_head) = source_fixture();
    let frozen = freeze_migration_source(
        &source,
        &CryptoBodyIdentity,
        &source_head,
        None,
        closure(),
        digest(0x60),
        digest(0x61),
    )
    .expect("source boundary freezes and has exact immutable export readback");
    assert_eq!(frozen.source_head_generation(), HeadGeneration::FIRST);
    assert_eq!(frozen.export().bundle().repository_id, repository());

    let target = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x5902));
    let target_key =
        HeadKey::new(b"fg059/incarnation-migration/target".to_vec()).expect("bounded fixture key");
    let activated = activate_migration_target(&target, &target_key, &CryptoBodyIdentity, &frozen)
        .expect("fresh target activates the exact source capsule root-last");

    assert_eq!(activated.source_capsule_id(), frozen.source_capsule_id());
    assert_eq!(
        activated.authority_boundary().replay_completeness(),
        ReplayCompleteness::VerifiableIfArtifactsSupplied,
        "attestation-only migration does not overclaim a portable archive"
    );
    assert!(
        !activated.routing_published() && !activated.authority_boundary().routing_published(),
        "target activation is not a source-to-target routing cutover"
    );
    assert!(
        activated
            .authority_boundary()
            .missing_artifact_classes()
            .contains(&"object closure bodies")
    );
}

#[test]
fn target_activation_refuses_a_nonfresh_authority_namespace_without_a_routing_side_effect() {
    let (source, _source_key, source_head) = source_fixture();
    let frozen = freeze_migration_source(
        &source,
        &CryptoBodyIdentity,
        &source_head,
        None,
        closure(),
        digest(0x62),
        digest(0x63),
    )
    .expect("source freezes");

    let target = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x5903));
    let target_key = HeadKey::new(b"fg059/incarnation-migration/occupied-target".to_vec())
        .expect("bounded fixture key");
    let mut occupied = head();
    occupied.ref_root = digest(0x64);
    initialize_repository(&target, &target_key, &occupied)
        .expect("different target head occupies key");

    assert!(matches!(
        activate_migration_target(&target, &target_key, &CryptoBodyIdentity, &frozen),
        Err(MigrationTargetRefusal::Restore(_))
    ));
    let found = target
        .read_head(&target_key)
        .expect("target head reads after refusal");
    assert!(
        matches!(found, HeadRead::Present(_)),
        "occupied target remains its preexisting authority; no routing action exists on this path"
    );
}

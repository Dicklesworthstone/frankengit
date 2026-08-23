//! Live capsule freezing reads an authenticated head twice around staging.

use fgit_authority::{
    AuthorityStore, HeadKey, HeadRead, MemoryAuthorityStore, StoreInstanceId, initialize_repository,
};
use fgit_chronicle::{
    AttestedBackupExport, BackupProfile, CapsuleClosure, LiveCapsuleRefusal, ReplayCompleteness,
    RestoreExecutionRefusal, RestoreOutcome, activate_frozen_capsule, export_frozen_capsule,
    freeze_capsule, inspect_capsule_against_authority_head_bytes, inspect_capsule_bytes,
    restore_attested_backup,
};
use fgit_codec::{
    CryptoBodyIdentity, DecodeLimits, RepositoryAuthorityHeadBody, decode_body, encode_body,
};
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
fn capsule_activation_stages_a_successor_before_advancing_the_checkpoint_pointer() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x48));
    let key = HeadKey::new(b"chronicle/live-capsule-activation".to_vec()).expect("bounded key");
    initialize_repository(&store, &key, &head()).expect("head initializes");
    let basis = match store.read_head(&key).expect("head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized head is present"),
    };
    let frozen = freeze_capsule(&store, &CryptoBodyIdentity, &basis, None, closure())
        .expect("current head freezes");

    let activated = activate_frozen_capsule(&store, &basis, &frozen)
        .expect("staged capsule activates through an exact-head CAS");

    assert_eq!(activated.pointer(), frozen.pointer());
    let activated_head: RepositoryAuthorityHeadBody =
        decode_body(activated.head().body(), DecodeLimits::DEFAULT)
            .expect("activated receipt carries canonical head bytes");
    assert_eq!(
        activated_head.last_checkpoint_id,
        Some(frozen.capsule_id()),
        "the authoritative checkpoint pointer is the last CAS field"
    );
    assert_eq!(
        activated_head.predecessor_head_id,
        Some(frozen.capsule().head_id)
    );
    assert_eq!(
        activated_head.generation,
        HeadGeneration::try_new(2).expect("second generation is valid")
    );
    assert_eq!(
        store.read_head(&key).expect("head rereads"),
        HeadRead::Present(activated.head().clone()),
        "the returned receipt is the current authority position"
    );
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

#[test]
fn inspection_derives_identity_and_predecessor_defects_from_capsule_bytes() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x46));
    let key = HeadKey::new(b"chronicle/live-capsule-inspection".to_vec()).expect("bounded key");
    initialize_repository(&store, &key, &head()).expect("head initializes");
    let receipt = match store.read_head(&key).expect("head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized head is present"),
    };
    let frozen = freeze_capsule(&store, &CryptoBodyIdentity, &receipt, None, closure())
        .expect("current head freezes");
    let mut altered = frozen.capsule().clone();
    altered.predecessor_capsule_id = Some(frozen.capsule_id());
    let bytes = encode_body(&altered).expect("altered canonical capsule encodes");

    let inspected = inspect_capsule_bytes(&CryptoBodyIdentity, frozen.capsule_id(), &bytes, None)
        .expect("inspection reads the actual bytes");

    assert_eq!(
        inspected.classification().outcome(),
        RestoreOutcome::FailClosed
    );
    assert!(
        inspected
            .classification()
            .defects()
            .iter()
            .any(|defect| matches!(
                defect,
                fgit_chronicle::CapsuleDefect::IdentityMismatch { .. }
            ))
    );
    assert!(
        inspected
            .classification()
            .defects()
            .iter()
            .any(|defect| matches!(
                defect,
                fgit_chronicle::CapsuleDefect::PredecessorStale { .. }
            ))
    );
}

#[test]
fn inspection_refuses_a_capsule_that_disagrees_with_its_named_authority_head() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x47));
    let key =
        HeadKey::new(b"chronicle/live-capsule-head-inspection".to_vec()).expect("bounded key");
    initialize_repository(&store, &key, &head()).expect("head initializes");
    let receipt = match store.read_head(&key).expect("head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized head is present"),
    };
    let frozen = freeze_capsule(&store, &CryptoBodyIdentity, &receipt, None, closure())
        .expect("current head freezes");
    let capsule_bytes = encode_body(frozen.capsule()).expect("capsule encodes");
    let mut mismatched_head = head();
    mismatched_head.ref_root = digest(0x99);
    let head_bytes = encode_body(&mismatched_head).expect("mismatched head encodes");

    let inspected = inspect_capsule_against_authority_head_bytes(
        &CryptoBodyIdentity,
        frozen.capsule_id(),
        &capsule_bytes,
        &head_bytes,
        None,
    )
    .expect("both inputs decode for inspection");

    assert_eq!(
        inspected.classification().outcome(),
        RestoreOutcome::FailClosed
    );
    assert!(
        inspected
            .classification()
            .defects()
            .iter()
            .any(|defect| matches!(
                defect,
                fgit_chronicle::CapsuleDefect::AuthorityHeadMismatch { field: "head_id" }
            ))
    );
    assert!(
        inspected
            .classification()
            .defects()
            .iter()
            .any(|defect| matches!(
                defect,
                fgit_chronicle::CapsuleDefect::AuthorityHeadMismatch { field: "ref_root" }
            ))
    );
}

#[test]
fn attested_export_restores_a_clean_authority_boundary_without_routing() {
    let source = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x51));
    let source_key =
        HeadKey::new(b"chronicle/attested-export-source".to_vec()).expect("bounded source key");
    initialize_repository(&source, &source_key, &head()).expect("source head initializes");
    let source_head = match source.read_head(&source_key).expect("source head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized source head is present"),
    };
    let frozen = freeze_capsule(&source, &CryptoBodyIdentity, &source_head, None, closure())
        .expect("source boundary freezes");
    let export = export_frozen_capsule(
        &source,
        &CryptoBodyIdentity,
        &source_head,
        &frozen,
        digest(0x52),
        digest(0x53),
    )
    .expect("source export has verified staged bytes");

    let destination = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x54));
    let destination_key = HeadKey::new(b"chronicle/attested-export-destination".to_vec())
        .expect("bounded destination key");
    let restored =
        restore_attested_backup(&destination, &destination_key, &CryptoBodyIdentity, &export)
            .expect("a clean authority namespace restores from the export boundary");

    let destination_head: RepositoryAuthorityHeadBody =
        decode_body(restored.head().body(), DecodeLimits::DEFAULT)
            .expect("restored receipt carries canonical authority bytes");
    assert_eq!(
        destination_head.last_checkpoint_id,
        Some(frozen.capsule_id())
    );
    assert_eq!(
        destination_head.generation,
        HeadGeneration::try_new(2).expect("second generation is valid"),
        "the destination publishes the checkpoint only through root-last activation"
    );
    assert_eq!(
        destination
            .read_head(&destination_key)
            .expect("destination reads"),
        HeadRead::Present(restored.head().clone())
    );
    assert_eq!(
        restored.replay_completeness(),
        ReplayCompleteness::VerifiableIfArtifactsSupplied,
        "the attestation-only export names its replay limit rather than claiming a full archive"
    );
    assert!(
        restored
            .missing_artifact_classes()
            .contains(&"object closure bodies"),
        "the receipt names a concrete external artifact class"
    );
    assert!(
        !restored.routing_published(),
        "restore has no destination-routing path before full verification"
    );
}

#[test]
fn malformed_export_bytes_refuse_before_destination_authority_exists() {
    let source = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x55));
    let source_key = HeadKey::new(b"chronicle/attested-export-malformed-source".to_vec())
        .expect("bounded source key");
    initialize_repository(&source, &source_key, &head()).expect("source head initializes");
    let source_head = match source.read_head(&source_key).expect("source head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized source head is present"),
    };
    let frozen = freeze_capsule(&source, &CryptoBodyIdentity, &source_head, None, closure())
        .expect("source boundary freezes");
    let export = export_frozen_capsule(
        &source,
        &CryptoBodyIdentity,
        &source_head,
        &frozen,
        digest(0x56),
        digest(0x57),
    )
    .expect("source export has verified staged bytes");
    let mut malformed_head = export.authority_head_bytes().to_vec();
    malformed_head[0] ^= 0xff;
    let malformed = AttestedBackupExport::new(
        export.bundle().clone(),
        export.capsule_bytes().to_vec(),
        malformed_head,
    );

    let destination = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x58));
    let destination_key = HeadKey::new(b"chronicle/attested-export-malformed-destination".to_vec())
        .expect("bounded destination key");
    assert!(matches!(
        restore_attested_backup(
            &destination,
            &destination_key,
            &CryptoBodyIdentity,
            &malformed,
        ),
        Err(RestoreExecutionRefusal::Inspection(_))
    ));
    assert_eq!(
        destination
            .read_head(&destination_key)
            .expect("destination reads"),
        HeadRead::Absent,
        "untrusted bytes cannot initialize authority before their verification completes"
    );
}

#[test]
fn overclaimed_export_profile_refuses_before_destination_authority_exists() {
    let source = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x59));
    let source_key = HeadKey::new(b"chronicle/attested-export-profile-source".to_vec())
        .expect("bounded source key");
    initialize_repository(&source, &source_key, &head()).expect("source head initializes");
    let source_head = match source.read_head(&source_key).expect("source head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized source head is present"),
    };
    let frozen = freeze_capsule(&source, &CryptoBodyIdentity, &source_head, None, closure())
        .expect("source boundary freezes");
    let export = export_frozen_capsule(
        &source,
        &CryptoBodyIdentity,
        &source_head,
        &frozen,
        digest(0x5a),
        digest(0x5b),
    )
    .expect("source export has verified staged bytes");
    let mut overclaimed_bundle = export.bundle().clone();
    overclaimed_bundle.exported_profile = BackupProfile::FullClosure;
    let overclaimed = AttestedBackupExport::new(
        overclaimed_bundle,
        export.capsule_bytes().to_vec(),
        export.authority_head_bytes().to_vec(),
    );

    let destination = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x5c));
    let destination_key = HeadKey::new(b"chronicle/attested-export-profile-destination".to_vec())
        .expect("bounded destination key");
    assert!(matches!(
        restore_attested_backup(
            &destination,
            &destination_key,
            &CryptoBodyIdentity,
            &overclaimed,
        ),
        Err(RestoreExecutionRefusal::UnsupportedExportProfile(
            BackupProfile::FullClosure
        ))
    ));
    assert_eq!(
        destination
            .read_head(&destination_key)
            .expect("destination reads"),
        HeadRead::Absent,
        "a declared full-closure archive cannot be substituted for attestation-only bytes"
    );
}

#[test]
fn attested_export_restores_a_second_generation_checkpoint() {
    let source = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x5b));
    let source_key =
        HeadKey::new(b"chronicle/attested-export-second-source".to_vec()).expect("bounded key");
    initialize_repository(&source, &source_key, &head()).expect("source head initializes");
    let first_basis = match source.read_head(&source_key).expect("head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized head is present"),
    };
    let first = freeze_capsule(&source, &CryptoBodyIdentity, &first_basis, None, closure())
        .expect("genesis checkpoint freezes");
    activate_frozen_capsule(&source, &first_basis, &first).expect("first checkpoint activates");
    let second_basis = match source.read_head(&source_key).expect("head rereads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("activated head is present"),
    };
    let second = freeze_capsule(
        &source,
        &CryptoBodyIdentity,
        &second_basis,
        Some(&first.pointer()),
        closure(),
    )
    .expect("second checkpoint freezes chained onto its predecessor");

    let export = export_frozen_capsule(
        &source,
        &CryptoBodyIdentity,
        &second_basis,
        &second,
        digest(0x5c),
        digest(0x5d),
    )
    .expect("a chaining capsule exports through the attestation-only path");

    let destination = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x5e));
    let destination_key = HeadKey::new(b"chronicle/attested-export-second-destination".to_vec())
        .expect("bounded destination key");
    let restored =
        restore_attested_backup(&destination, &destination_key, &CryptoBodyIdentity, &export)
            .expect("a non-genesis checkpoint restores from the attestation-only export");

    let restored_head: RepositoryAuthorityHeadBody =
        decode_body(restored.head().body(), DecodeLimits::DEFAULT)
            .expect("restored receipt carries canonical head bytes");
    assert_eq!(
        restored_head.last_checkpoint_id,
        Some(second.capsule_id()),
        "the restored boundary checkpoints the exported capsule, not its predecessor"
    );
    assert_eq!(
        restored_head.generation,
        HeadGeneration::try_new(3).expect("third generation is valid"),
        "restore advances exactly one activation past the imported head"
    );
}

#[test]
fn restore_refuses_a_byte_level_pair_that_disagrees_on_the_checkpoint_chain() {
    let source = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x5f));
    let source_key =
        HeadKey::new(b"chronicle/attested-export-tamper-source".to_vec()).expect("bounded key");
    initialize_repository(&source, &source_key, &head()).expect("source head initializes");
    let basis = match source.read_head(&source_key).expect("head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("initialized head is present"),
    };
    let frozen = freeze_capsule(&source, &CryptoBodyIdentity, &basis, None, closure())
        .expect("genesis capsule freezes");
    let export = export_frozen_capsule(
        &source,
        &CryptoBodyIdentity,
        &basis,
        &frozen,
        digest(0x60),
        digest(0x61),
    )
    .expect("the consistent pair exports");

    // An untrusted transport may carry a head whose checkpoint pointer names a
    // capsule the exported capsule does not follow. Every check must derive
    // from bytes alone and refuse before any destination write.
    let mut tampered_head: RepositoryAuthorityHeadBody =
        decode_body(export.authority_head_bytes(), DecodeLimits::DEFAULT)
            .expect("export carries canonical head bytes");
    tampered_head.last_checkpoint_id = Some(frozen.capsule_id());
    let tampered = AttestedBackupExport::new(
        export.bundle().clone(),
        export.capsule_bytes().to_vec(),
        encode_body(&tampered_head).expect("tampered head encodes"),
    );

    let destination = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x62));
    let destination_key = HeadKey::new(b"chronicle/attested-export-tamper-destination".to_vec())
        .expect("bounded destination key");
    assert!(matches!(
        restore_attested_backup(
            &destination,
            &destination_key,
            &CryptoBodyIdentity,
            &tampered
        ),
        Err(RestoreExecutionRefusal::NotRestorable(
            RestoreOutcome::FailClosed
        ))
    ));
    assert!(
        matches!(
            destination.read_head(&destination_key),
            Err(_) | Ok(HeadRead::Absent)
        ),
        "a refused pair never initializes destination authority"
    );
}

#![forbid(unsafe_code)]
//! Portable signed-capsule archive acceptance tests for frankengit-5blj.

use fgit_authority::{
    HeadKey, MemoryAuthorityStore, StoreInstanceId, authority_head_identity, outcome_index_root,
};
use fgit_chronicle::archive::{
    CapsuleArchiveSignerPolicy, PortableArchiveArtifact, PortableArchiveArtifactKind,
    PortableArchiveRefusal, SignedPortableCapsuleArchive, TrustedCapsuleArchivePolicy,
};
use fgit_chronicle::{BackupProfile, ReplayCompleteness, RepositoryCapsuleBody};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::{
    Capsule, DigestAlgorithm, DigestBytes, KeyEpoch, KeyScope, RootSecret, SecretKey,
};
use fgit_types::{
    Digest, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositoryId, RepositorySequence,
};

fn digest(fill: u8) -> Digest {
    Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&[fill; 32]).expect("SHA-256 digest has a valid width"),
    )
}

fn source() -> (RepositoryCapsuleBody, RepositoryAuthorityHeadBody) {
    let repository_id = RepositoryId::from_bytes([0x51; 16]);
    let root = outcome_index_root(&[]).expect("empty outcome index is canonical");
    let head = RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: Some(RepositorySequence::FIRST),
        ref_root: root,
        forge_position_root: root,
        outcome_index_root: root,
        retention_root: root,
        outbox_root: root,
        configuration_root: root,
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let head_id = authority_head_identity(&head).expect("head identity is canonical");
    let capsule = RepositoryCapsuleBody::at_head(
        head_id,
        &head,
        None,
        digest(0x61),
        digest(0x62),
        BackupProfile::FullClosureWithRepair,
    );
    (capsule, head)
}

fn artifacts() -> Vec<PortableArchiveArtifact> {
    [
        (
            PortableArchiveArtifactKind::DecisionSuffix,
            b"decision-suffix".as_slice(),
        ),
        (
            PortableArchiveArtifactKind::ObjectClosure,
            b"object-closure".as_slice(),
        ),
        (
            PortableArchiveArtifactKind::SegmentManifest,
            b"segment-manifest".as_slice(),
        ),
        (
            PortableArchiveArtifactKind::RepairSymbols,
            b"repair-symbols".as_slice(),
        ),
        (
            PortableArchiveArtifactKind::Materializations,
            b"materializations".as_slice(),
        ),
    ]
    .into_iter()
    .map(|(kind, bytes)| {
        PortableArchiveArtifact::new(kind, bytes.to_vec())
            .expect("fixture artifact is bounded and nonempty")
    })
    .collect()
}

fn signer_and_policy() -> (
    SecretKey<Capsule>,
    CapsuleArchiveSignerPolicy,
    TrustedCapsuleArchivePolicy,
) {
    let signer = SecretKey::<Capsule>::derive(
        &RootSecret::from_bytes([0x7a; 32]),
        KeyEpoch::FIRST,
        KeyScope::OPERATOR,
    );
    let policy = CapsuleArchiveSignerPolicy::active_issuer([0x91; 32], &signer);
    let trusted = TrustedCapsuleArchivePolicy::from_out_of_band(policy)
        .expect("the independently obtained active capsule policy is trusted");
    (signer, policy, trusted)
}

fn archive() -> (SignedPortableCapsuleArchive, TrustedCapsuleArchivePolicy) {
    let (capsule, head) = source();
    let (signer, policy, trusted) = signer_and_policy();
    let archive = SignedPortableCapsuleArchive::sign(
        &capsule,
        &head,
        artifacts(),
        b"fgit-chronicle verifier 0.0.1".to_vec(),
        digest(0x63),
        policy,
        &signer,
    )
    .expect("complete archive input signs under the active capsule policy");
    (archive, trusted)
}

#[test]
fn signed_archive_round_trips_transfer_verification_and_authority_restore() {
    let (archive, trusted) = archive();
    let exported = archive
        .to_bytes()
        .expect("archive serializes deterministically");
    assert_eq!(
        exported,
        archive
            .to_bytes()
            .expect("repeated export is byte-identical"),
        "portable archive export must not depend on map order, wall clock, or transport"
    );

    let transferred = SignedPortableCapsuleArchive::from_bytes(&exported)
        .expect("bounded canonical archive survives byte-for-byte transfer");
    let verification = transferred
        .verify(&trusted)
        .expect("independent policy, both signatures, inventory, and capsule/head agree");
    assert_eq!(
        verification.replay_completeness(),
        ReplayCompleteness::StructuralReplay,
        "full closure plus repair bytes earns a structural, not a proof-grade, replay claim"
    );

    let destination = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x5b));
    let restored = transferred
        .restore(
            &destination,
            &HeadKey::new(b"portable-archive-destination".to_vec())
                .expect("bounded destination key"),
            &trusted,
        )
        .expect("verified archive restores its authority boundary root-last");
    assert_eq!(restored.artifacts().len(), 5);
    assert_eq!(
        restored.replay_completeness(),
        ReplayCompleteness::StructuralReplay
    );
    assert!(
        !restored.authority_boundary().routing_published(),
        "restore leaves routing publication to a later authenticated consumer"
    );
}

#[test]
fn tampered_bytes_stale_policy_and_truncation_are_typed_refusals() {
    let (archive, trusted) = archive();
    let exported = archive.to_bytes().expect("archive serializes");

    let mut tampered = exported.clone();
    let bundle_length = usize::try_from(u32::from_be_bytes(
        tampered[10..14]
            .try_into()
            .expect("wire carries the bounded bundle length"),
    ))
    .expect("u32 bundle length fits usize");
    let capsule_length_offset = 14 + bundle_length;
    let capsule_length = usize::try_from(u32::from_be_bytes(
        tampered[capsule_length_offset..capsule_length_offset + 4]
            .try_into()
            .expect("wire carries the bounded capsule length"),
    ))
    .expect("u32 capsule length fits usize");
    let capsule_last = capsule_length_offset + 4 + capsule_length - 1;
    tampered[capsule_last] ^= 0x01;
    let tampered = SignedPortableCapsuleArchive::from_bytes(&tampered)
        .expect("one capsule-byte mutation remains a representable archive");
    assert!(matches!(
        tampered.verify(&trusted),
        Err(PortableArchiveRefusal::InventoryMismatch)
    ));

    let (signer, _, _) = signer_and_policy();
    let stale = TrustedCapsuleArchivePolicy::from_out_of_band(
        CapsuleArchiveSignerPolicy::active_issuer([0x92; 32], &signer),
    )
    .expect("distinct out-of-band policy is well formed");
    assert!(matches!(
        archive.verify(&stale),
        Err(PortableArchiveRefusal::PolicyNotTrusted)
    ));
    assert!(matches!(
        SignedPortableCapsuleArchive::from_bytes(&exported[..exported.len() - 1]),
        Err(PortableArchiveRefusal::Truncated)
    ));
}

//! Backup bundle and restore report bodies.
//!
//! The property worth the most here is the domain separation: a backup bundle
//! attests to a capsule, and a restore report describes abandoning one. Neither
//! is a capsule, and neither may be usable where a capsule is expected.

use fgit_chronicle::{
    AuditedRestore, BackupExportBundleBody, BackupProfile, CapsulePointer, CapsuleVerification,
    ChronicleRefusal, HaltReason, RepositoryCapsuleBody, RestoreReportBody, capsule_identity,
    plan_recovery,
};
use fgit_codec::CryptoBodyIdentity;
use fgit_codec::DecodeLimits;
use fgit_codec::attest::body_id;
use fgit_codec::schema::RepositoryAuthorityHeadBody;
use fgit_codec::wire::{decode_body, encode_body};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, HeadGeneration, OPAQUE_ID_LEN,
    PolicyEpoch, PrincipalId, RegistryEpoch, RepositoryAuthorityHeadId, RepositoryCapsuleId,
    RepositoryId,
};

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("code point one is valid"),
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest"),
    )
}

fn head_id(tag: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).expect("code point one is valid"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest"),
    )
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([7; OPAQUE_ID_LEN])
}

const fn operator() -> PrincipalId {
    PrincipalId::from_bytes([9; OPAQUE_ID_LEN])
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("a non-zero generation")
}

fn head_at(value: u64) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: generation(value),
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(0x10),
        forge_position_root: digest(0x11),
        outcome_index_root: digest(0x12),
        retention_root: digest(0x13),
        outbox_root: digest(0x14),
        configuration_root: digest(0x15),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn capsule_at(value: u64, predecessor: Option<RepositoryCapsuleId>) -> RepositoryCapsuleBody {
    RepositoryCapsuleBody::at_head(
        head_id(u8::try_from(value).unwrap_or(0xF0)),
        &head_at(value),
        predecessor,
        digest(0x20),
        digest(0x21),
        BackupProfile::FullClosure,
    )
}

fn identity_of(capsule: &RepositoryCapsuleBody) -> RepositoryCapsuleId {
    capsule_identity(&CryptoBodyIdentity, capsule).expect("a capsule has an identity")
}

fn bundle_for(capsule_id: RepositoryCapsuleId) -> BackupExportBundleBody {
    BackupExportBundleBody {
        repository_id: repository(),
        capsule_id,
        exported_profile: BackupProfile::DecisionHistoryOnly,
        export_inventory_root: digest(0x30),
        durability_evidence_root: digest(0x31),
    }
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

#[test]
fn a_backup_bundle_round_trips_and_identifies() {
    let capsule = capsule_at(4, None);
    let bundle = bundle_for(identity_of(&capsule));
    let bytes = encode_body(&bundle).expect("a bundle encodes");
    let decoded =
        decode_body::<BackupExportBundleBody>(&bytes, DecodeLimits::default()).expect("decodes");
    assert_eq!(decoded, bundle, "encoding is lossless in both directions");

    assert!(
        body_id(&CryptoBodyIdentity, &bundle).is_ok(),
        "the registered backup-export-bundle domain yields an identity"
    );
}

#[test]
fn a_restore_report_round_trips_and_identifies() {
    let report = report_for(None);
    let bytes = encode_body(&report).expect("a report encodes");
    let decoded =
        decode_body::<RestoreReportBody>(&bytes, DecodeLimits::default()).expect("decodes");
    assert_eq!(decoded, report);
    assert!(
        body_id(&CryptoBodyIdentity, &report).is_ok(),
        "the registered restore-report domain yields an identity"
    );
}

fn report_for(abandoned: Option<RepositoryCapsuleId>) -> RestoreReportBody {
    let older = capsule_at(3, None);
    let older_id = identity_of(&older);
    let newer = capsule_at(7, Some(older_id));
    let newer_id = identity_of(&newer);
    let pointer = CapsulePointer::genesis(older_id, &older)
        .expect("a first capsule points")
        .advance(newer_id, &newer)
        .expect("the successor advances");
    let plan = plan_recovery(&pointer, CapsuleVerification::PresentButUnverified);
    let restore = AuditedRestore::authorize(
        &pointer,
        plan,
        operator(),
        older_id,
        generation(3),
        generation(8),
    )
    .expect("a restore that advances is authorized");
    let mut report = RestoreReportBody::of(
        repository(),
        &restore,
        HaltReason::AcknowledgedRootUnverified,
    );
    if let Some(id) = abandoned {
        report.abandoned_capsule_id = Some(id);
    }
    report
}

// ---------------------------------------------------------------------------
// Domain separation: the reason these are separate bodies at all
// ---------------------------------------------------------------------------

#[test]
fn a_bundle_and_a_capsule_never_share_an_identity() {
    // If a bundle shared the capsule's domain, a bundle's bytes could be
    // presented where a capsule pointer expects a target and the pointer would
    // accept an attestation as the thing it attests to. Distinct domains make
    // that unrepresentable rather than something a check has to catch.
    let capsule = capsule_at(4, None);
    let capsule_id = identity_of(&capsule);
    let bundle = bundle_for(capsule_id);

    let capsule_object = body_id(&CryptoBodyIdentity, &capsule).expect("capsule identity");
    let bundle_object = body_id(&CryptoBodyIdentity, &bundle).expect("bundle identity");
    assert_ne!(
        capsule_object, bundle_object,
        "an attestation is not the thing it attests to"
    );
    assert_ne!(
        capsule_object.domain(),
        bundle_object.domain(),
        "and they are separated by domain, not merely by content"
    );

    // A bundle's frame cannot be decoded as a capsule.
    let bundle_bytes = encode_body(&bundle).expect("a bundle encodes");
    assert!(
        decode_body::<RepositoryCapsuleBody>(&bundle_bytes, DecodeLimits::default()).is_err(),
        "a bundle's bytes are refused where a capsule is expected"
    );
}

#[test]
fn a_restore_report_is_not_a_capsule_either() {
    let report = report_for(None);
    let report_bytes = encode_body(&report).expect("a report encodes");
    assert!(
        decode_body::<RepositoryCapsuleBody>(&report_bytes, DecodeLimits::default()).is_err(),
        "a restore report's bytes are refused where a capsule is expected"
    );
    assert!(
        decode_body::<BackupExportBundleBody>(&report_bytes, DecodeLimits::default()).is_err(),
        "and where a bundle is expected"
    );
}

// ---------------------------------------------------------------------------
// The report re-checks what the authorization enforced
// ---------------------------------------------------------------------------

#[test]
fn a_report_that_does_not_advance_is_refused_on_the_data_path() {
    let mut report = report_for(None);
    assert_eq!(report.verify(), Ok(()), "an authorized report verifies");

    // Planted negative: a report arriving as data claiming a restore that
    // rewinds. No AuditedRestore stands behind a replayed report, so the
    // property has to be re-checked here rather than assumed.
    report.new_generation = report.restored_from_generation;
    assert_eq!(
        report.verify(),
        Err(ChronicleRefusal::RestoreDoesNotAdvance {
            abandoned: report.restored_from_generation,
            proposed: report.new_generation,
        }),
        "a report that re-enters the restored generation is refused"
    );

    // Near-identical permitted case: one generation later.
    report.new_generation = generation(report.restored_from_generation.get() + 1);
    assert_eq!(report.verify(), Ok(()));
}

#[test]
fn a_report_carries_exactly_what_the_authorization_recorded() {
    let older = capsule_at(3, None);
    let older_id = identity_of(&older);
    let newer = capsule_at(7, Some(older_id));
    let newer_id = identity_of(&newer);
    let pointer = CapsulePointer::genesis(older_id, &older)
        .expect("a first capsule points")
        .advance(newer_id, &newer)
        .expect("the successor advances");
    let plan = plan_recovery(&pointer, CapsuleVerification::PresentButUnverified);
    let restore = AuditedRestore::authorize(
        &pointer,
        plan,
        operator(),
        older_id,
        generation(3),
        generation(8),
    )
    .expect("authorized");

    let report = RestoreReportBody::of(
        repository(),
        &restore,
        HaltReason::AcknowledgedRootUnverified,
    );
    assert_eq!(report.authorized_by, restore.authorized_by());
    assert_eq!(report.abandoned_capsule_id, restore.abandoned());
    assert_eq!(report.abandoned_capsule_id, Some(newer_id));
    assert_eq!(report.restored_capsule_id, restore.restored_to());
    assert_eq!(
        report.restored_from_generation,
        restore.restored_from_generation()
    );
    assert_eq!(report.new_generation, restore.new_generation());
    assert_eq!(report.verify(), Ok(()));
}

#[test]
fn an_unknown_exported_profile_is_refused_rather_than_defaulted() {
    // The discriminant is the only free byte in a bundle, so it is the one
    // place a newer writer could hand this build something it cannot mean.
    assert_eq!(
        BackupProfile::from_discriminant(0),
        Err(ChronicleRefusal::BackupProfileUnknown { observed: 0 })
    );
    assert_eq!(
        BackupProfile::from_discriminant(200),
        Err(ChronicleRefusal::BackupProfileUnknown { observed: 200 })
    );

    // Near-identical permitted case: every profile a bundle may declare.
    for profile in [
        BackupProfile::DecisionHistoryOnly,
        BackupProfile::FullClosure,
        BackupProfile::FullClosureWithRepair,
    ] {
        let capsule = capsule_at(4, None);
        let mut bundle = bundle_for(identity_of(&capsule));
        bundle.exported_profile = profile;
        let bytes = encode_body(&bundle).expect("a bundle encodes");
        let decoded = decode_body::<BackupExportBundleBody>(&bytes, DecodeLimits::default())
            .expect("a declared profile decodes");
        assert_eq!(decoded.exported_profile, profile);
    }
}

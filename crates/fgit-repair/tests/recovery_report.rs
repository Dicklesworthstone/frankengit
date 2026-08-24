#![forbid(unsafe_code)]
//! Recovery-drill evidence is canonical and cannot be substituted under an
//! existing S5 export attestation.

use fgit_chronicle::{AttestedBackupExport, BackupExportBundleBody, BackupProfile};
use fgit_codec::DecodeLimits;
use fgit_codec::wire::{decode_body, encode_body};
use fgit_repair::recovery_report::{
    IncidentOutcome, IncidentVerdict, RecoveryIncident, RecoveryReport, RecoveryReportRefusal,
    RpoRtoSample,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, DomainTag, InternalObjectId,
    OPAQUE_ID_LEN, RepositoryCapsuleId, RepositoryId,
};

fn report(rto_millis: u64) -> RecoveryReport {
    RecoveryReport::new(
        BackupProfile::FullClosureWithRepair,
        vec![
            RpoRtoSample::new(1, 0xA11CE, 4, rto_millis),
            RpoRtoSample::new(2, 0xB0B, 3, rto_millis + 1),
        ],
        vec![
            IncidentOutcome::new(
                RecoveryIncident::MaterializationOrIndexLoss,
                1,
                IncidentVerdict::Recovered,
            ),
            IncidentOutcome::new(
                RecoveryIncident::RaptorQRepair,
                2,
                IncidentVerdict::Recovered,
            ),
            IncidentOutcome::new(
                RecoveryIncident::RepairVsNewerWrite,
                3,
                IncidentVerdict::Refused,
            ),
            IncidentOutcome::new(
                RecoveryIncident::GcAuthorityRace,
                4,
                IncidentVerdict::Refused,
            ),
            IncidentOutcome::new(
                RecoveryIncident::LegalHoldRestore,
                5,
                IncidentVerdict::Recovered,
            ),
            IncidentOutcome::new(
                RecoveryIncident::InterruptedCapsulePublication,
                6,
                IncidentVerdict::Refused,
            ),
            IncidentOutcome::new(
                RecoveryIncident::CryptographicErasure,
                7,
                IncidentVerdict::Refused,
            ),
            IncidentOutcome::new(
                RecoveryIncident::ResidualSymbolResurrection,
                8,
                IncidentVerdict::Refused,
            ),
        ],
    )
    .expect("the complete ordered matrix is reportable")
}

fn capsule_id() -> RepositoryCapsuleId {
    let internal = InternalObjectId::new(
        DigestAlgorithmId::try_new(1).expect("non-zero fixture algorithm"),
        DomainTag::from_static("frankengit/repository-capsule/v1"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0xC1; 32]).expect("fixture digest is sized"),
    );
    RepositoryCapsuleId::from_internal_object_id(internal)
        .expect("fixture identity names a repository capsule")
}

fn inventory_root() -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("non-zero fixture algorithm"),
        DigestBytes::try_new(&[0x1D; 32]).expect("fixture digest is sized"),
    )
}

fn export_attesting(report: &RecoveryReport) -> AttestedBackupExport {
    AttestedBackupExport::new(
        BackupExportBundleBody {
            repository_id: RepositoryId::from_bytes([0x77; OPAQUE_ID_LEN]),
            capsule_id: capsule_id(),
            exported_profile: report.profile(),
            export_inventory_root: inventory_root(),
            durability_evidence_root: report
                .durability_evidence_root()
                .expect("registered report identity produces a root"),
        },
        Vec::new(),
        Vec::new(),
    )
}

#[test]
fn report_round_trips_and_binds_to_the_existing_export_attestation() {
    let report = report(17);
    let bytes = encode_body(&report).expect("the report has canonical bytes");
    let decoded =
        decode_body::<RecoveryReport>(&bytes, DecodeLimits::DEFAULT).expect("the report decodes");
    assert_eq!(
        decoded, report,
        "canonical codec round-trips every measurement"
    );

    report
        .clone()
        .bind_to_export(export_attesting(&report))
        .expect("the existing S5 export attests to the exact report body");
}

#[test]
fn changing_measured_rto_after_attestation_is_refused() {
    let original = report(17);
    let export = export_attesting(&original);
    let tampered = report(18);

    assert_eq!(
        tampered.bind_to_export(export),
        Err(RecoveryReportRefusal::AttestationBodyMismatch),
        "a bundle for one canonical report must not attest to altered RTO evidence"
    );
}

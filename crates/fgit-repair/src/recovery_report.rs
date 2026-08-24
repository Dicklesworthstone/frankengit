//! Canonical evidence emitted by an executed recovery drill.
//!
//! A backup capsule proves neither present readability nor an RPO/RTO target;
//! those are measured properties of a drill.  This module keeps that evidence
//! separate from recovery authority: it uses the existing S5
//! [`AttestedBackupExport`] vocabulary and only checks that the bundle's
//! `durability_evidence_root` commits to this canonical report.  It introduces
//! no signing key, signing policy, or publication authority.

use core::fmt;
use std::error::Error;

use fgit_chronicle::{AttestedBackupExport, BackupProfile};
use fgit_codec::attest::body_id;
use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, CryptoBodyIdentity, Decoder, Encoder};
use fgit_types::{Digest, DomainTag, SchemaFamily};

/// Bounded number of completed recovery-drill samples in one report.
pub const MAX_RPO_RTO_SAMPLES: usize = 128;
/// The report carries every scenario in the fixed FG-033c incident matrix.
pub const INCIDENT_MATRIX_LEN: usize = 8;

/// One measured RPO/RTO observation from a reproducible recovery drill.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RpoRtoSample {
    drill_sequence: u64,
    seed: u64,
    rpo_millis: u64,
    rto_millis: u64,
}

impl RpoRtoSample {
    /// Records one completed drill observation.  Durations may be zero: a
    /// zero is a measured result, not an omitted value.
    #[must_use]
    pub const fn new(
        drill: u64,
        replay_seed: u64,
        recovery_point_millis: u64,
        recovery_time_millis: u64,
    ) -> Self {
        Self {
            drill_sequence: drill,
            seed: replay_seed,
            rpo_millis: recovery_point_millis,
            rto_millis: recovery_time_millis,
        }
    }

    /// Monotone position of this drill within the selected profile's history.
    #[must_use]
    pub const fn drill_sequence(self) -> u64 {
        self.drill_sequence
    }

    /// Replay seed supplied to the drill script.
    #[must_use]
    pub const fn seed(self) -> u64 {
        self.seed
    }

    /// Observed recovery-point lag in milliseconds.
    #[must_use]
    pub const fn rpo_millis(self) -> u64 {
        self.rpo_millis
    }

    /// Observed recovery duration in milliseconds.
    #[must_use]
    pub const fn rto_millis(self) -> u64 {
        self.rto_millis
    }
}

/// One closed scenario in FG-033c's recovery incident matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecoveryIncident {
    /// Total materialization or index loss while service remains active.
    MaterializationOrIndexLoss,
    /// Bounded microsegment corruption repaired under the declared profile.
    RaptorQRepair,
    /// A repair competes with a newer placement write.
    RepairVsNewerWrite,
    /// GC races force-pushes, new commits, and retention-hold changes.
    GcAuthorityRace,
    /// A legal hold must survive recovery and remain restorable.
    LegalHoldRestore,
    /// Capsule publication is interrupted before its root-last transition.
    InterruptedCapsulePublication,
    /// Cryptographically erased material cannot be restored.
    CryptographicErasure,
    /// Residual repair symbols cannot resurrect deleted material.
    ResidualSymbolResurrection,
}

impl RecoveryIncident {
    const ALL: [Self; INCIDENT_MATRIX_LEN] = [
        Self::MaterializationOrIndexLoss,
        Self::RaptorQRepair,
        Self::RepairVsNewerWrite,
        Self::GcAuthorityRace,
        Self::LegalHoldRestore,
        Self::InterruptedCapsulePublication,
        Self::CryptographicErasure,
        Self::ResidualSymbolResurrection,
    ];

    const fn discriminant(self) -> u8 {
        match self {
            Self::MaterializationOrIndexLoss => 1,
            Self::RaptorQRepair => 2,
            Self::RepairVsNewerWrite => 3,
            Self::GcAuthorityRace => 4,
            Self::LegalHoldRestore => 5,
            Self::InterruptedCapsulePublication => 6,
            Self::CryptographicErasure => 7,
            Self::ResidualSymbolResurrection => 8,
        }
    }

    fn from_discriminant(value: u8, offset: u64) -> Result<Self, CodecRefusal> {
        match value {
            1 => Ok(Self::MaterializationOrIndexLoss),
            2 => Ok(Self::RaptorQRepair),
            3 => Ok(Self::RepairVsNewerWrite),
            4 => Ok(Self::GcAuthorityRace),
            5 => Ok(Self::LegalHoldRestore),
            6 => Ok(Self::InterruptedCapsulePublication),
            7 => Ok(Self::CryptographicErasure),
            8 => Ok(Self::ResidualSymbolResurrection),
            _ => Err(CodecRefusal::VariantUnknown {
                field: "recovery_incident",
                observed: u32::from(value),
                offset,
            }),
        }
    }
}

/// The observed result of one incident drill.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncidentVerdict {
    /// The scenario recovered with no data loss or unauthorized resurrection.
    Recovered,
    /// The scenario reached the intended typed safety refusal.
    Refused,
    /// The scenario exhausted its declared repair envelope.
    Unrecoverable,
}

impl IncidentVerdict {
    const fn discriminant(self) -> u8 {
        match self {
            Self::Recovered => 1,
            Self::Refused => 2,
            Self::Unrecoverable => 3,
        }
    }

    fn from_discriminant(value: u8, offset: u64) -> Result<Self, CodecRefusal> {
        match value {
            1 => Ok(Self::Recovered),
            2 => Ok(Self::Refused),
            3 => Ok(Self::Unrecoverable),
            _ => Err(CodecRefusal::VariantUnknown {
                field: "incident_verdict",
                observed: u32::from(value),
                offset,
            }),
        }
    }
}

/// One replayable result in the fixed incident matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IncidentOutcome {
    incident: RecoveryIncident,
    seed: u64,
    verdict: IncidentVerdict,
}

impl IncidentOutcome {
    /// Records the outcome and replay seed for one named incident.
    #[must_use]
    pub const fn new(incident: RecoveryIncident, seed: u64, verdict: IncidentVerdict) -> Self {
        Self {
            incident,
            seed,
            verdict,
        }
    }

    /// The exact matrix scenario exercised.
    #[must_use]
    pub const fn incident(self) -> RecoveryIncident {
        self.incident
    }

    /// Seed that permits exact scenario replay.
    #[must_use]
    pub const fn seed(self) -> u64 {
        self.seed
    }

    /// Measured terminal verdict of this scenario.
    #[must_use]
    pub const fn verdict(self) -> IncidentVerdict {
        self.verdict
    }
}

/// A canonical, per-profile account of one executed recovery-drill window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryReport {
    profile: BackupProfile,
    samples: Vec<RpoRtoSample>,
    incidents: Vec<IncidentOutcome>,
}

impl RecoveryReport {
    /// Builds a report only when it carries reproducible RPO/RTO observations
    /// and the complete, ordered incident matrix.
    pub fn new(
        profile: BackupProfile,
        samples: Vec<RpoRtoSample>,
        incidents: Vec<IncidentOutcome>,
    ) -> Result<Self, RecoveryReportRefusal> {
        let report = Self {
            profile,
            samples,
            incidents,
        };
        report.validate()?;
        Ok(report)
    }

    /// Backup coverage profile against which RPO/RTO were measured.
    #[must_use]
    pub const fn profile(&self) -> BackupProfile {
        self.profile
    }

    /// Ordered observed RPO/RTO samples for this profile.
    #[must_use]
    pub fn samples(&self) -> &[RpoRtoSample] {
        &self.samples
    }

    /// Complete ordered FG-033c incident-matrix results.
    #[must_use]
    pub fn incidents(&self) -> &[IncidentOutcome] {
        &self.incidents
    }

    /// The existing export-bundle field commits to this canonical body's
    /// registered identity digest.  This is a binding, not a signature or new
    /// authority source.
    pub fn durability_evidence_root(&self) -> Result<Digest, RecoveryReportRefusal> {
        self.validate()?;
        let identity =
            body_id(&CryptoBodyIdentity, self).map_err(RecoveryReportRefusal::CanonicalEncoding)?;
        Ok(Digest::new(identity.algorithm(), *identity.digest()))
    }

    /// Binds this report to the existing attestation-only export vocabulary.
    /// The operation consumes no signing material and performs no publication.
    pub fn bind_to_export(
        self,
        export: AttestedBackupExport,
    ) -> Result<AttestedRecoveryReport, RecoveryReportRefusal> {
        let bound = AttestedRecoveryReport {
            report: self,
            export,
        };
        bound.verify()?;
        Ok(bound)
    }

    fn validate(&self) -> Result<(), RecoveryReportRefusal> {
        if self.samples.is_empty() {
            return Err(RecoveryReportRefusal::EmptySamples);
        }
        if self.samples.len() > MAX_RPO_RTO_SAMPLES {
            return Err(RecoveryReportRefusal::TooManySamples {
                offered: self.samples.len(),
                maximum: MAX_RPO_RTO_SAMPLES,
            });
        }
        for (index, pair) in self.samples.windows(2).enumerate() {
            if pair[0].drill_sequence >= pair[1].drill_sequence {
                return Err(RecoveryReportRefusal::SamplesNotMonotone {
                    index: index + 1,
                    previous: pair[0].drill_sequence,
                    observed: pair[1].drill_sequence,
                });
            }
        }
        if self.incidents.len() != INCIDENT_MATRIX_LEN {
            return Err(RecoveryReportRefusal::IncidentMatrixIncomplete {
                observed: self.incidents.len(),
                expected: INCIDENT_MATRIX_LEN,
            });
        }
        for (index, (outcome, expected)) in
            self.incidents.iter().zip(RecoveryIncident::ALL).enumerate()
        {
            if outcome.incident != expected {
                return Err(RecoveryReportRefusal::IncidentMatrixOutOfOrder {
                    index,
                    expected,
                    observed: outcome.incident,
                });
            }
        }
        Ok(())
    }

    fn validation_codec_refusal(error: RecoveryReportRefusal) -> CodecRefusal {
        match error {
            RecoveryReportRefusal::EmptySamples => CodecRefusal::ValueUnrepresentable {
                field: "rpo_rto_samples",
                observed: 0,
                limit: 1,
            },
            RecoveryReportRefusal::TooManySamples { offered, maximum } => {
                CodecRefusal::CountBoundExceeded {
                    field: "rpo_rto_samples",
                    observed: u64::try_from(offered).unwrap_or(u64::MAX),
                    limit: u64::try_from(maximum).unwrap_or(u64::MAX),
                }
            }
            RecoveryReportRefusal::SamplesNotMonotone { index, .. }
            | RecoveryReportRefusal::IncidentMatrixOutOfOrder { index, .. } => {
                CodecRefusal::CollectionUnordered {
                    field: "recovery_report_order",
                    index: u64::try_from(index).unwrap_or(u64::MAX),
                    offset: 0,
                }
            }
            RecoveryReportRefusal::IncidentMatrixIncomplete { observed, expected } => {
                CodecRefusal::ValueUnrepresentable {
                    field: "incident_matrix",
                    observed: u64::try_from(observed).unwrap_or(u64::MAX),
                    limit: u64::try_from(expected).unwrap_or(u64::MAX),
                }
            }
            RecoveryReportRefusal::AttestationProfileMismatch { .. }
            | RecoveryReportRefusal::AttestationBodyMismatch
            | RecoveryReportRefusal::CanonicalEncoding(_) => CodecRefusal::ValueUnrepresentable {
                field: "recovery_report",
                observed: 0,
                limit: 0,
            },
        }
    }
}

impl CanonicalBody for RecoveryReport {
    // `RestoreReportBody` already owns the durable restore-record schema.  A
    // drill is distinct evidence, so its separate family prevents either body
    // from being decoded as the other while reusing the registered restore
    // identity domain and existing S5 attestation vocabulary.
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/restore-report/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("recovery-drill-report");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate().map_err(Self::validation_codec_refusal)?;
        out.write_raw_byte(self.profile.discriminant());
        out.write_sequence("rpo_rto_samples", &self.samples, |out, sample| {
            out.write_scalar(sample.drill_sequence);
            out.write_scalar(sample.seed);
            out.write_scalar(sample.rpo_millis);
            out.write_scalar(sample.rto_millis);
            Ok(())
        })?;
        out.write_sequence("incident_matrix", &self.incidents, |out, incident| {
            out.write_raw_byte(incident.incident.discriminant());
            out.write_scalar(incident.seed);
            out.write_raw_byte(incident.verdict.discriminant());
            Ok(())
        })
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let profile_offset = input.offset();
        let profile_value = input.read_raw_byte("backup_profile")?;
        let profile = BackupProfile::from_discriminant(profile_value).map_err(|_| {
            CodecRefusal::VariantUnknown {
                field: "backup_profile",
                observed: u32::from(profile_value),
                offset: profile_offset,
            }
        })?;
        let samples = input.read_sequence("rpo_rto_samples", |input| {
            Ok(RpoRtoSample::new(
                input.read_scalar("drill_sequence")?,
                input.read_scalar("seed")?,
                input.read_scalar("rpo_millis")?,
                input.read_scalar("rto_millis")?,
            ))
        })?;
        let incidents = input.read_sequence("incident_matrix", |input| {
            let incident_offset = input.offset();
            let incident = RecoveryIncident::from_discriminant(
                input.read_raw_byte("recovery_incident")?,
                incident_offset,
            )?;
            let seed = input.read_scalar("incident_seed")?;
            let verdict_offset = input.offset();
            let verdict = IncidentVerdict::from_discriminant(
                input.read_raw_byte("incident_verdict")?,
                verdict_offset,
            )?;
            Ok(IncidentOutcome::new(incident, seed, verdict))
        })?;
        Self::new(profile, samples, incidents).map_err(Self::validation_codec_refusal)
    }
}

/// A recovery report paired with the existing attestation-only export type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedRecoveryReport {
    report: RecoveryReport,
    export: AttestedBackupExport,
}

impl AttestedRecoveryReport {
    /// The measured recovery evidence.
    #[must_use]
    pub const fn report(&self) -> &RecoveryReport {
        &self.report
    }

    /// Existing S5 attestation-only export that commits to the report root.
    #[must_use]
    pub const fn export(&self) -> &AttestedBackupExport {
        &self.export
    }

    /// Verifies profile equality and the report-body commitment before a
    /// consumer treats this as measured recovery evidence.
    pub fn verify(&self) -> Result<(), RecoveryReportRefusal> {
        self.report.validate()?;
        let bundle = self.export.bundle();
        if bundle.exported_profile != self.report.profile {
            return Err(RecoveryReportRefusal::AttestationProfileMismatch {
                report: self.report.profile,
                attested: bundle.exported_profile,
            });
        }
        if bundle.durability_evidence_root != self.report.durability_evidence_root()? {
            return Err(RecoveryReportRefusal::AttestationBodyMismatch);
        }
        Ok(())
    }
}

/// Why a recovery report cannot be encoded or trusted as attested evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryReportRefusal {
    /// An RPO/RTO claim without a completed drill is not a measurement.
    EmptySamples,
    /// Bounded report storage refused a sample set that is too large.
    TooManySamples { offered: usize, maximum: usize },
    /// Drill sequences must be strictly increasing so one history has one encoding.
    SamplesNotMonotone {
        index: usize,
        previous: u64,
        observed: u64,
    },
    /// Every report has the complete fixed FG-033c matrix.
    IncidentMatrixIncomplete { observed: usize, expected: usize },
    /// Matrix rows must use the fixed scenario order and have no duplicates.
    IncidentMatrixOutOfOrder {
        index: usize,
        expected: RecoveryIncident,
        observed: RecoveryIncident,
    },
    /// The attestation declares a different coverage profile.
    AttestationProfileMismatch {
        report: BackupProfile,
        attested: BackupProfile,
    },
    /// The existing attestation's evidence root does not commit to this body.
    AttestationBodyMismatch,
    /// Canonical bytes could not obtain their registered identity.
    CanonicalEncoding(CodecRefusal),
}

impl fmt::Display for RecoveryReportRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySamples => {
                formatter.write_str("recovery report has no measured RPO/RTO samples")
            }
            Self::TooManySamples { offered, maximum } => write!(
                formatter,
                "recovery report carries {offered} samples; maximum is {maximum}"
            ),
            Self::SamplesNotMonotone {
                index,
                previous,
                observed,
            } => write!(
                formatter,
                "recovery sample {index} is not monotone: {observed} follows {previous}"
            ),
            Self::IncidentMatrixIncomplete { observed, expected } => write!(
                formatter,
                "recovery incident matrix has {observed} rows; exactly {expected} are required"
            ),
            Self::IncidentMatrixOutOfOrder {
                index,
                expected,
                observed,
            } => write!(
                formatter,
                "recovery incident matrix row {index} is {observed:?}; expected {expected:?}"
            ),
            Self::AttestationProfileMismatch { report, attested } => write!(
                formatter,
                "recovery report profile {} does not match attested export profile {}",
                report.as_str(),
                attested.as_str(),
            ),
            Self::AttestationBodyMismatch => formatter
                .write_str("attested durability evidence root does not match recovery report"),
            Self::CanonicalEncoding(error) => {
                write!(
                    formatter,
                    "recovery report canonical encoding failed: {error}"
                )
            }
        }
    }
}

impl Error for RecoveryReportRefusal {}

//! Backup bundle and restore report bodies.
//!
//! These are the two durable records section 23 needs beside the capsule
//! itself. A backup bundle *attests to* a capsule — it says which capsule some
//! exported copy covers and under what profile — without being one. A restore
//! report is the audit trail for the one operation that may abandon an
//! acknowledged position.
//!
//! They carry distinct domain separation tags, `frankengit/backup-export-bundle/v1`
//! and `frankengit/restore-report/v1`, both registered in `fgit-crypto`. That
//! separation is doing real work rather than being tidy: if a bundle shared the
//! capsule's domain, a bundle's bytes could be presented where a capsule
//! pointer expects a target, and the pointer would accept an attestation as
//! the thing it attests to. Distinct domains make that unrepresentable instead
//! of something a check has to catch.
//!
//! # Identity
//!
//! Neither type carries a typed identity accessor yet. `fgit-types` has no
//! derived id for either domain, and minting one locally is exactly the
//! parallel-vocabulary mistake the type crate's owner asked everyone to avoid.
//! Identity still works today — `fgit_codec::body_id` takes the domain from
//! `B::DOMAIN`, so both bodies identify correctly and are domain-separated —
//! it just returns an `InternalObjectId` rather than a pinned wrapper. When the
//! ids land, the accessors become two thin functions and nothing here changes.

use fgit_codec::error::CodecRefusal;
use fgit_codec::reader::Decoder;
use fgit_codec::wire::CanonicalBody;
use fgit_codec::writer::Encoder;
use fgit_types::{
    Digest, DomainTag, HeadGeneration, PrincipalId, RepositoryCapsuleId, RepositoryId, SchemaFamily,
};

use crate::capsule::BackupProfile;
use crate::recovery::{AuditedRestore, HaltReason};
use crate::refusal::ChronicleRefusal;

/// One exported copy of a repository, attesting to the capsule it covers.
///
/// The bundle does not restate the capsule's roots. Duplicating them would
/// create a second place for the same fact to be wrong, and the capsule is
/// already immutable and identified — naming it is strictly better than
/// copying it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupExportBundleBody {
    /// Repository this bundle exports.
    pub repository_id: RepositoryId,
    /// The capsule whose position this bundle covers.
    pub capsule_id: RepositoryCapsuleId,
    /// How much of the repository the exported data covers.
    ///
    /// Kept here as well as in the capsule because an export may legitimately
    /// carry less than the capsule describes — a decision-history-only bundle
    /// of a full-closure capsule is a real thing, and a restore has to know.
    pub exported_profile: BackupProfile,
    /// Root over the exported byte inventory.
    pub export_inventory_root: Digest,
    /// Root over the durability evidence collected for the export.
    pub durability_evidence_root: Digest,
}

impl CanonicalBody for BackupExportBundleBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/backup-export-bundle/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("backup-export-bundle");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_internal_object_id(self.capsule_id.as_internal_object_id())?;
        out.write_raw_byte(self.exported_profile.discriminant());
        out.write_digest(&self.export_inventory_root)?;
        out.write_digest(&self.durability_evidence_root)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let capsule_id =
            RepositoryCapsuleId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)?;
        let profile_byte = input.read_raw_byte("exported_profile")?;
        let exported_profile = BackupProfile::from_discriminant(profile_byte).map_err(|_| {
            CodecRefusal::from(fgit_types::TypeRefusal::CodePointUnknown {
                field: "exported_profile",
                observed: u32::from(profile_byte),
            })
        })?;
        let export_inventory_root = input.read_digest()?;
        let durability_evidence_root = input.read_digest()?;
        Ok(Self {
            repository_id,
            capsule_id,
            exported_profile,
            export_inventory_root,
            durability_evidence_root,
        })
    }
}

/// The durable record of one audited restore.
///
/// This is what makes "older-state recovery is an explicit audited restore"
/// auditable rather than merely stated. It names who authorized abandoning an
/// acknowledged position, what was abandoned, what was restored to, and both
/// generations — the one the restored content came from and the one the
/// authority now occupies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreReportBody {
    /// Repository that was restored.
    pub repository_id: RepositoryId,
    /// Principal who authorized abandoning the acknowledged position.
    pub authorized_by: PrincipalId,
    /// The capsule that was abandoned, absent when no bytes were there at all.
    pub abandoned_capsule_id: Option<RepositoryCapsuleId>,
    /// The capsule whose content the repository was restored to.
    pub restored_capsule_id: RepositoryCapsuleId,
    /// Generation the restored content was originally taken at.
    pub restored_from_generation: HeadGeneration,
    /// Generation the authority occupies after the restore.
    ///
    /// Strictly greater than the abandoned position, because a restore moves
    /// the authority forward to a position carrying older content rather than
    /// rewinding it.
    pub new_generation: HeadGeneration,
    /// Why automated recovery halted and a human had to decide.
    pub halt_reason: HaltReason,
}

impl RestoreReportBody {
    /// Builds the durable record from an authorized restore.
    ///
    /// Taking the [`AuditedRestore`] rather than loose fields is the point: the
    /// report cannot describe a restore that was never authorized, and cannot
    /// disagree with the authorization about what was abandoned.
    #[must_use]
    pub const fn of(
        repository_id: RepositoryId,
        restore: &AuditedRestore,
        halt_reason: HaltReason,
    ) -> Self {
        Self {
            repository_id,
            authorized_by: restore.authorized_by(),
            abandoned_capsule_id: restore.abandoned(),
            restored_capsule_id: restore.restored_to(),
            restored_from_generation: restore.restored_from_generation(),
            new_generation: restore.new_generation(),
            halt_reason,
        }
    }

    /// Re-checks the invariant the authorization enforced.
    ///
    /// A report can arrive as data — replayed, or read back from a store — with
    /// no `AuditedRestore` behind it, so the property is checked here too.
    pub const fn verify(&self) -> Result<(), ChronicleRefusal> {
        if self.abandoned_generation_check() {
            Ok(())
        } else {
            Err(ChronicleRefusal::RestoreDoesNotAdvance {
                abandoned: self.restored_from_generation,
                proposed: self.new_generation,
            })
        }
    }

    const fn abandoned_generation_check(&self) -> bool {
        self.new_generation.get() > self.restored_from_generation.get()
    }
}

/// Wire discriminant for a halt reason.
const fn halt_discriminant(reason: HaltReason) -> u8 {
    match reason {
        HaltReason::AcknowledgedRootUnverified => 1,
        HaltReason::AcknowledgedRootAbsent => 2,
    }
}

/// Reads a halt discriminant, refusing one this build does not define.
const fn halt_from_discriminant(value: u8) -> Option<HaltReason> {
    match value {
        1 => Some(HaltReason::AcknowledgedRootUnverified),
        2 => Some(HaltReason::AcknowledgedRootAbsent),
        _ => None,
    }
}

impl CanonicalBody for RestoreReportBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/restore-report/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("restore-report");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_opaque_id(self.authorized_by.as_bytes());
        out.write_option(self.abandoned_capsule_id.as_ref(), |out, id| {
            out.write_internal_object_id(id.as_internal_object_id())
        })?;
        out.write_internal_object_id(self.restored_capsule_id.as_internal_object_id())?;
        out.write_scalar(self.restored_from_generation.get());
        out.write_scalar(self.new_generation.get());
        out.write_raw_byte(halt_discriminant(self.halt_reason));
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let authorized_by = PrincipalId::from_bytes(input.read_opaque_id("authorized_by")?);
        let abandoned_capsule_id = input.read_option("abandoned_capsule_id", |input| {
            RepositoryCapsuleId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)
        })?;
        let restored_capsule_id =
            RepositoryCapsuleId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)?;
        let restored_from_generation =
            HeadGeneration::try_new(input.read_scalar::<u64>("restored_from_generation")?)?;
        let new_generation = HeadGeneration::try_new(input.read_scalar::<u64>("new_generation")?)?;
        let halt_byte = input.read_raw_byte("halt_reason")?;
        let halt_reason = halt_from_discriminant(halt_byte).ok_or_else(|| {
            CodecRefusal::from(fgit_types::TypeRefusal::CodePointUnknown {
                field: "halt_reason",
                observed: u32::from(halt_byte),
            })
        })?;
        Ok(Self {
            repository_id,
            authorized_by,
            abandoned_capsule_id,
            restored_capsule_id,
            restored_from_generation,
            new_generation,
            halt_reason,
        })
    }
}

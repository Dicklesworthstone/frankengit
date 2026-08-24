//! Routing-independent halves of repository incarnation migration.
//!
//! A migration may freeze one exact source authority position and activate its
//! attested capsule at a fresh target authority namespace.  Those are useful
//! and independently verifiable operations, but they are deliberately not a
//! rename, owner transfer, or routing cutover.  In particular, this module
//! does not expose a routing mutation: the authority that may perform that
//! later cross-repository decision is outside Chronicle's one-head contract.

use core::fmt;

use fgit_authority::{AuthorityStore, HeadKey, HeadReadReceipt};
use fgit_codec::attest::BodyIdentity;
use fgit_types::{Digest, HeadGeneration, RepositoryCapsuleId};

use crate::{
    AttestedBackupExport, BackupExportRefusal, CapsuleClosure, CapsulePointer, FrozenCapsule,
    LiveCapsuleRefusal, RestoreExecutionRefusal, RestoredAuthorityBoundary, export_frozen_capsule,
    freeze_capsule, restore_attested_backup,
};

/// The source half of an incarnation migration.
///
/// The export contains the exact capsule and authority-head bytes frozen from
/// the source receipt.  It carries no source-name mutation or target routing
/// publication capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenMigrationSource {
    export: AttestedBackupExport,
    source_capsule_id: RepositoryCapsuleId,
    source_head_generation: HeadGeneration,
}

impl FrozenMigrationSource {
    /// The attestation-only export supplied to the target half.
    #[must_use]
    pub const fn export(&self) -> &AttestedBackupExport {
        &self.export
    }

    /// The exact capsule checkpointed at the source authority boundary.
    #[must_use]
    pub const fn source_capsule_id(&self) -> RepositoryCapsuleId {
        self.source_capsule_id
    }

    /// The source authority generation the capsule froze.
    #[must_use]
    pub const fn source_head_generation(&self) -> HeadGeneration {
        self.source_head_generation
    }
}

/// A target authority position activated from [`FrozenMigrationSource`].
///
/// The target has a local checkpoint receipt, but no source routing record has
/// been changed.  A caller cannot mistake target activation for a cutover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivatedMigrationTarget {
    source_capsule_id: RepositoryCapsuleId,
    boundary: RestoredAuthorityBoundary,
}

impl ActivatedMigrationTarget {
    /// Capsule supplied by the frozen source half.
    #[must_use]
    pub const fn source_capsule_id(&self) -> RepositoryCapsuleId {
        self.source_capsule_id
    }

    /// The target's root-last authority-boundary receipt.
    #[must_use]
    pub const fn authority_boundary(&self) -> &RestoredAuthorityBoundary {
        &self.boundary
    }

    /// Whether this operation published a name/owner route.
    ///
    /// This remains false by construction.  Source→target cutover is a later
    /// owner-authorized routing transaction and cannot be inferred from a
    /// capsule becoming readable or from target authority activation.
    #[must_use]
    pub const fn routing_published(&self) -> bool {
        false
    }
}

/// Why the source half did not produce an attested export.
#[derive(Debug)]
pub enum MigrationSourceRefusal {
    /// The exact source receipt could not be frozen into a capsule.
    Freeze(Box<LiveCapsuleRefusal>),
    /// The frozen source capsule could not be exported with exact readback.
    Export(Box<BackupExportRefusal>),
}

impl fmt::Display for MigrationSourceRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Freeze(error) => write!(formatter, "migration source freeze refused: {error}"),
            Self::Export(error) => write!(formatter, "migration source export refused: {error}"),
        }
    }
}

impl std::error::Error for MigrationSourceRefusal {}

/// Why the target half did not activate a fresh authority namespace.
#[derive(Debug)]
pub enum MigrationTargetRefusal {
    /// Capsule/head verification, target staging, or root-last activation
    /// refused before a target authority boundary was returned.
    Restore(Box<RestoreExecutionRefusal>),
}

impl fmt::Display for MigrationTargetRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Restore(error) => {
                write!(formatter, "migration target activation refused: {error}")
            }
        }
    }
}

impl std::error::Error for MigrationTargetRefusal {}

/// Freeze and export one exact source authority position for migration.
///
/// The same authenticated receipt is used for capsule freezing and for its
/// attestation-only export.  A moved source head therefore refuses in the
/// existing freeze boundary instead of yielding a stale migration candidate.
pub fn freeze_migration_source<S, I>(
    source: &S,
    identity: &I,
    source_head: &HeadReadReceipt,
    current_pointer: Option<&CapsulePointer>,
    closure: CapsuleClosure,
    export_inventory_root: Digest,
    durability_evidence_root: Digest,
) -> Result<FrozenMigrationSource, MigrationSourceRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let frozen: FrozenCapsule =
        freeze_capsule(source, identity, source_head, current_pointer, closure)
            .map_err(|error| MigrationSourceRefusal::Freeze(Box::new(error)))?;
    let export = export_frozen_capsule(
        source,
        identity,
        source_head,
        &frozen,
        export_inventory_root,
        durability_evidence_root,
    )
    .map_err(|error| MigrationSourceRefusal::Export(Box::new(error)))?;
    Ok(FrozenMigrationSource {
        export,
        source_capsule_id: frozen.capsule_id(),
        source_head_generation: source_head.generation(),
    })
}

/// Activate the frozen source boundary at a fresh target authority namespace.
///
/// This is the target half only.  It intentionally delegates to the existing
/// attestation-only restore boundary, whose receipt discloses omitted archive
/// material and whose API has no routing publication operation.
pub fn activate_migration_target<S, I>(
    target: &S,
    target_key: &HeadKey,
    identity: &I,
    source: &FrozenMigrationSource,
) -> Result<ActivatedMigrationTarget, MigrationTargetRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let boundary = restore_attested_backup(target, target_key, identity, source.export())
        .map_err(|error| MigrationTargetRefusal::Restore(Box::new(error)))?;
    Ok(ActivatedMigrationTarget {
        source_capsule_id: source.source_capsule_id,
        boundary,
    })
}

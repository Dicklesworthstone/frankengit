//! What recovery may do when the newest capsule does not verify.
//!
//! Section 23 states the rule negatively, and the negative is the whole point:
//! recovery **must not** silently fall back to an older valid capsule when the
//! newest acknowledged root is structurally present but fails authentication or
//! closure. Older-state recovery is an explicit audited restore that advances a
//! new authority generation.
//!
//! The failure that rule exists to prevent is quiet and total. A newest capsule
//! that is present but unverifiable is exactly the shape corruption, truncation,
//! and tampering all take. An older capsule sitting behind it will usually
//! verify perfectly — it was valid when it was written — so a recovery path that
//! "helpfully" retreats to the last thing that checks out will come up, look
//! healthy, and have silently discarded every decision made since. Nobody gets
//! an error, because from the inside nothing went wrong.
//!
//! So the retreat is not merely discouraged here. [`plan_recovery`] cannot
//! return an older capsule at all: the only value that names one is
//! [`AuditedRestore`], which a caller has to construct deliberately, with an
//! authorizing principal, and which refuses unless it advances the authority
//! generation past the position being abandoned. Losing history becomes
//! something a person did on the record, not something a program chose.

use fgit_types::{HeadGeneration, PrincipalId, RepositoryCapsuleId};

use crate::capsule::CapsulePointer;
use crate::refusal::ChronicleRefusal;

/// What checking the newest acknowledged capsule found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapsuleVerification {
    /// Bytes present, identity and closure both check out.
    Verified,
    /// Bytes present, but authentication or closure failed.
    ///
    /// This is the dangerous state, and it is deliberately distinct from
    /// [`CapsuleVerification::Absent`]: something is there, so a reader that
    /// only asked "is a capsule present?" would say yes.
    PresentButUnverified,
    /// No capsule bytes at the acknowledged root at all.
    Absent,
}

/// What recovery is permitted to do next.
///
/// There is no variant naming an older capsule. That absence is the safety
/// property: a recovery path cannot express a silent retreat, so it cannot
/// perform one by accident.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryPlan {
    /// Resume from the acknowledged capsule, which verified.
    Resume {
        /// The capsule to resume from.
        capsule_id: RepositoryCapsuleId,
        /// The generation it was taken at.
        head_generation: HeadGeneration,
    },
    /// Stop. The acknowledged root cannot be used and no automatic alternative
    /// exists; a human must authorize an [`AuditedRestore`].
    HaltForAudit {
        /// The acknowledged capsule that failed to verify, if bytes were there.
        acknowledged: Option<RepositoryCapsuleId>,
        /// Why automation stopped.
        reason: HaltReason,
    },
}

/// Why recovery stopped rather than choosing for itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HaltReason {
    /// The acknowledged capsule is present but failed authentication or
    /// closure. Falling back to an older one would discard every decision made
    /// since it, silently.
    AcknowledgedRootUnverified,
    /// No capsule is present at the acknowledged root.
    AcknowledgedRootAbsent,
}

/// Decides what recovery may do, given the acknowledged capsule's verdict.
///
/// Total, and deliberately unable to suggest an older capsule.
pub const fn plan_recovery(
    pointer: &CapsulePointer,
    verification: CapsuleVerification,
) -> RecoveryPlan {
    match verification {
        CapsuleVerification::Verified => RecoveryPlan::Resume {
            capsule_id: pointer.capsule_id(),
            head_generation: pointer.head_generation(),
        },
        CapsuleVerification::PresentButUnverified => RecoveryPlan::HaltForAudit {
            acknowledged: Some(pointer.capsule_id()),
            reason: HaltReason::AcknowledgedRootUnverified,
        },
        CapsuleVerification::Absent => RecoveryPlan::HaltForAudit {
            acknowledged: None,
            reason: HaltReason::AcknowledgedRootAbsent,
        },
    }
}

/// A deliberate, attributed decision to recover from an older capsule.
///
/// Constructing one is the audit trail. It records who authorized abandoning
/// the acknowledged position, which capsule is being restored to, and the new
/// authority generation the repository will occupy afterwards — because a
/// restore does not rewind the authority, it moves it forward to a position
/// that happens to carry older content.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditedRestore {
    authorized_by: PrincipalId,
    abandoned: Option<RepositoryCapsuleId>,
    restored_to: RepositoryCapsuleId,
    restored_from_generation: HeadGeneration,
    new_generation: HeadGeneration,
}

impl AuditedRestore {
    /// Authorizes recovery from an older capsule.
    ///
    /// Refuses unless the restore advances the authority generation past the
    /// position being abandoned. That is what stops a restore from being a
    /// rollback: the repository never re-enters a generation it has already
    /// left, so an observer who saw the abandoned position can tell that
    /// something happened rather than seeing history quietly rewind.
    pub fn authorize(
        pointer: &CapsulePointer,
        plan: RecoveryPlan,
        authorized_by: PrincipalId,
        restored_to: RepositoryCapsuleId,
        restored_from_generation: HeadGeneration,
        new_generation: HeadGeneration,
    ) -> Result<Self, ChronicleRefusal> {
        let RecoveryPlan::HaltForAudit { acknowledged, .. } = plan else {
            return Err(ChronicleRefusal::RestoreNotHalted);
        };
        if new_generation <= pointer.head_generation() {
            return Err(ChronicleRefusal::RestoreDoesNotAdvance {
                abandoned: pointer.head_generation(),
                proposed: new_generation,
            });
        }
        Ok(Self {
            authorized_by,
            abandoned: acknowledged,
            restored_to,
            restored_from_generation,
            new_generation,
        })
    }

    /// The principal who authorized abandoning the acknowledged position.
    #[must_use]
    pub const fn authorized_by(&self) -> PrincipalId {
        self.authorized_by
    }

    /// The capsule that was abandoned, if bytes were present at all.
    #[must_use]
    pub const fn abandoned(&self) -> Option<RepositoryCapsuleId> {
        self.abandoned
    }

    /// The capsule whose content the repository is restored to.
    #[must_use]
    pub const fn restored_to(&self) -> RepositoryCapsuleId {
        self.restored_to
    }

    /// The generation the restored capsule's content was originally taken at.
    ///
    /// Kept distinct from the new generation so the record shows both how far
    /// back the content came from and where the authority now sits.
    #[must_use]
    pub const fn restored_from_generation(&self) -> HeadGeneration {
        self.restored_from_generation
    }

    /// The generation the repository occupies after the restore.
    #[must_use]
    pub const fn new_generation(&self) -> HeadGeneration {
        self.new_generation
    }
}

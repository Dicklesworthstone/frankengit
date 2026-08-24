//! Typed, incarnation-bound repository deletion disclosure.
//!
//! The GC worker owns object-level reachability and physical-placement work;
//! this module owns the user-visible repository deletion vocabulary from plan
//! §19.4.  It is deliberately a value transition model, not a second mutable
//! authority: publication of a lifecycle record remains an authority decision.
//! What this type prevents locally is an equally dangerous mistake: describing
//! a stale incarnation or an early deletion stage as a later, stronger claim.

use core::fmt;

use fgit_types::{RepositoryId, RepositoryIncarnationId};

/// The six distinct deletion claims a repository API may surface.
///
/// The spelling and order are stable because clients must not collapse a
/// retained tombstone, removal from one hot tier, and cryptographic erasure
/// into one ambiguous "deleted" response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RepositoryDeletionState {
    /// Repository is hidden from ordinary discovery but its recovery window is
    /// not yet represented by a tombstone.
    Hidden,
    /// A root-proof-carrying tombstone exists and the recovery grace horizon is
    /// still active.
    TombstonedWithinRecoveryGrace,
    /// Current authority and all applicable horizons have authorized physical
    /// placement deletion, but a placement has not yet been removed.
    PhysicalDeletionAuthorized,
    /// Hot placements were removed idempotently.  Repair, replica, or archive
    /// material can still retain a recovery path.
    DeletedFromHotPlacements,
    /// The declared repair, replica, and archive recovery materials expired.
    ExpiredFromRecoveryMaterial,
    /// Applicable key material was cryptographically erased.  This says
    /// nothing about unrelated caller copies or media outside that key scope.
    CryptographicallyErased,
}

impl RepositoryDeletionState {
    /// Every permitted user-visible state in lifecycle order.
    pub const ALL: [Self; 6] = [
        Self::Hidden,
        Self::TombstonedWithinRecoveryGrace,
        Self::PhysicalDeletionAuthorized,
        Self::DeletedFromHotPlacements,
        Self::ExpiredFromRecoveryMaterial,
        Self::CryptographicallyErased,
    ];

    /// Stable API spelling for this exact claim.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hidden => "hidden",
            Self::TombstonedWithinRecoveryGrace => "tombstoned_within_recovery_grace",
            Self::PhysicalDeletionAuthorized => "physical_deletion_authorized",
            Self::DeletedFromHotPlacements => "deleted_from_hot_placements",
            Self::ExpiredFromRecoveryMaterial => "expired_from_recovery_material",
            Self::CryptographicallyErased => "cryptographically_erased",
        }
    }

    /// The only later state an ordinary lifecycle transition may claim.
    #[must_use]
    pub const fn successor(self) -> Option<Self> {
        match self {
            Self::Hidden => Some(Self::TombstonedWithinRecoveryGrace),
            Self::TombstonedWithinRecoveryGrace => Some(Self::PhysicalDeletionAuthorized),
            Self::PhysicalDeletionAuthorized => Some(Self::DeletedFromHotPlacements),
            Self::DeletedFromHotPlacements => Some(Self::ExpiredFromRecoveryMaterial),
            Self::ExpiredFromRecoveryMaterial => Some(Self::CryptographicallyErased),
            Self::CryptographicallyErased => None,
        }
    }

    /// Whether this stage carries a claim that physical hot placement work ran.
    #[must_use]
    pub const fn hot_placements_deleted(self) -> bool {
        matches!(
            self,
            Self::DeletedFromHotPlacements
                | Self::ExpiredFromRecoveryMaterial
                | Self::CryptographicallyErased
        )
    }

    /// Whether this stage carries a claim that the named recovery material has
    /// expired.
    #[must_use]
    pub const fn recovery_material_expired(self) -> bool {
        matches!(
            self,
            Self::ExpiredFromRecoveryMaterial | Self::CryptographicallyErased
        )
    }

    /// Whether this stage carries an applicable cryptographic-erasure claim.
    #[must_use]
    pub const fn key_material_erased(self) -> bool {
        matches!(self, Self::CryptographicallyErased)
    }
}

/// An incarnation-bound repository deletion status supplied by an authority
/// projection.
///
/// Construction only represents the first, hidden state.  Each later claim
/// must be reached one evidence stage at a time, making a UI/API unable to
/// jump directly from "hidden" to "erased" by selecting a stronger enum arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RepositoryDeletionStatus {
    repository_id: RepositoryId,
    repository_incarnation_id: RepositoryIncarnationId,
    state: RepositoryDeletionState,
}

impl RepositoryDeletionStatus {
    /// Starts deletion disclosure for the exact currently selected incarnation.
    #[must_use]
    pub const fn hidden(
        repository_id: RepositoryId,
        repository_incarnation_id: RepositoryIncarnationId,
    ) -> Self {
        Self {
            repository_id,
            repository_incarnation_id,
            state: RepositoryDeletionState::Hidden,
        }
    }

    /// Repository named by this lifecycle status.
    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    /// Incarnation to which every deletion claim is bound.
    #[must_use]
    pub const fn repository_incarnation_id(self) -> RepositoryIncarnationId {
        self.repository_incarnation_id
    }

    /// Exact user-visible deletion claim currently permitted.
    #[must_use]
    pub const fn state(self) -> RepositoryDeletionState {
        self.state
    }

    /// Refuses a record carried over from a deleted/recreated repository.
    pub fn require_current_incarnation(
        self,
        current: RepositoryIncarnationId,
    ) -> Result<(), RepositoryDeletionRefusal> {
        if self.repository_incarnation_id == current {
            Ok(())
        } else {
            Err(RepositoryDeletionRefusal::StaleIncarnation {
                record: self.repository_incarnation_id,
                current,
            })
        }
    }

    /// Advances by exactly one evidence stage.
    ///
    /// The authority/GC/retention owner must verify evidence before publishing
    /// the returned value.  This total transition guard still rejects skipped,
    /// repeated, and revival claims before a caller can expose them.
    pub fn advance(
        self,
        requested: RepositoryDeletionState,
    ) -> Result<Self, RepositoryDeletionRefusal> {
        match self.state.successor() {
            Some(expected) if expected == requested => Ok(Self {
                repository_id: self.repository_id,
                repository_incarnation_id: self.repository_incarnation_id,
                state: requested,
            }),
            _ => Err(RepositoryDeletionRefusal::InvalidTransition {
                current: self.state,
                requested,
            }),
        }
    }
}

/// Refusal while binding or advancing a repository deletion claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryDeletionRefusal {
    /// The status belongs to a superseded repository incarnation.
    StaleIncarnation {
        /// Incarnation carried by the status, token, or cache record.
        record: RepositoryIncarnationId,
        /// Incarnation selected by current authority.
        current: RepositoryIncarnationId,
    },
    /// The requested visible claim was not the sole immediate successor.
    InvalidTransition {
        /// Current visible claim.
        current: RepositoryDeletionState,
        /// Claim the caller attempted to expose.
        requested: RepositoryDeletionState,
    },
}

impl fmt::Display for RepositoryDeletionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleIncarnation { record, current } => write!(
                formatter,
                "deletion status names stale repository incarnation {record}; current incarnation is {current}"
            ),
            Self::InvalidTransition { current, requested } => write!(
                formatter,
                "cannot expose deletion state {} directly after {}",
                requested.as_str(),
                current.as_str()
            ),
        }
    }
}

impl std::error::Error for RepositoryDeletionRefusal {}

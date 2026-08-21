//! The workspace-lease obligation.
//!
//! A workspace overlay acquires responsibility: it holds staged bodies and, on
//! the way to a published snapshot, reserved budget. AGENTS.md §3.2 requires
//! such an effect to be a typed obligation with reserve/commit/abort rather
//! than a value that is merely dropped, and `fgit-resource` owns that
//! machinery. This module binds TreeFS to it instead of inventing a parallel
//! lifecycle.
//!
//! The class is [`ObligationClass::WorkspaceLease`] — "one workspace overlay
//! and its outputs" — which is precisely what a [`crate::overlay::Overlay`]
//! plus its snapshot is.
//!
//! # Why this is an internal effect
//!
//! There is no external recipient to observe. A workspace lease settles at
//! commit with a trivial acknowledgement; there is no committed-but-
//! unacknowledged window to reason about. Declaring it
//! [`ObservationMode::Internal`] is a claim about the effect, and marking it
//! [`InternalEffect`] is what makes the one-call settlement path available.
//! Exporting to Git or publishing to a remote *is* externally observed, and
//! that obligation belongs to FG-026c, not here.

use crate::capability::WorkspaceId;
use crate::overlay::OverlayStats;
use crate::snapshot::EpochSet;
use fgit_resource::{Grade, InternalEffect, ObligationClass, ObligationKind, ObservationMode};

/// What the reserve phase of a workspace lease records.
///
/// The budget is recorded at reservation time, before any body is staged, so an
/// overlay cannot grow past what was reserved and then have the reservation
/// back-fitted to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceLeaseReservation {
    /// Which workspace the lease belongs to.
    pub workspace_id: WorkspaceId,
    /// Overlay body bytes reserved.
    pub reserved_bytes: u64,
    /// Overlay entries reserved.
    pub reserved_entries: u64,
}

/// What the commit phase records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceLeaseCommit {
    /// Which workspace the lease belonged to.
    pub workspace_id: WorkspaceId,
    /// Identity of the snapshot that was published.
    pub snapshot_digest: [u8; 32],
    /// The epochs that snapshot carried.
    pub epochs: EpochSet,
    /// What the overlay actually held at publication.
    pub observed: OverlayStats,
}

/// Why a workspace lease was aborted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceAbortReason {
    /// The caller discarded the workspace deliberately.
    Discarded,
    /// Evaluation produced statement errors and nothing was published.
    IntentErrors {
        /// How many source intents failed.
        count: usize,
    },
    /// The overlay exceeded what was reserved.
    BudgetExceeded {
        /// Bytes reserved.
        reserved_bytes: u64,
        /// Bytes observed.
        observed_bytes: u64,
    },
    /// The session refused the snapshot as a rollback.
    RollbackRefused,
}

/// What the abort phase records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceLeaseAbort {
    /// Which workspace the lease belonged to.
    pub workspace_id: WorkspaceId,
    /// Why it aborted.
    pub reason: WorkspaceAbortReason,
    /// What was discarded rather than published.
    pub discarded: OverlayStats,
}

/// The workspace-lease obligation kind.
///
/// A marker type: it carries no data and exists to name the class and its three
/// phase records to `fgit-resource`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceLease;

impl ObligationKind for WorkspaceLease {
    const CLASS: ObligationClass = ObligationClass::WorkspaceLease;
    const OBSERVATION: ObservationMode = ObservationMode::Internal;
    /// Bytes for staged bodies, objects for overlay entries. Both are
    /// consumable: an overlay that stages a body has spent that capacity until
    /// the lease settles.
    const REQUIRED_GRADES: &'static [Grade] = &[Grade::Bytes, Grade::Objects];

    type Reservation = WorkspaceLeaseReservation;
    type CommitReceipt = WorkspaceLeaseCommit;
    type AbortReceipt = WorkspaceLeaseAbort;
    type AckEvidence = fgit_resource::TrivialAck;
}

impl InternalEffect for WorkspaceLease {}

impl WorkspaceLeaseReservation {
    /// Whether `observed` fits inside this reservation.
    ///
    /// Checked rather than assumed: a lease whose overlay outgrew its
    /// reservation must abort with [`WorkspaceAbortReason::BudgetExceeded`],
    /// not commit and reconcile afterwards.
    #[must_use]
    pub const fn admits(&self, observed: &OverlayStats) -> bool {
        (observed.body_bytes as u64) <= self.reserved_bytes
            && (observed.entry_count as u64) <= self.reserved_entries
    }

    /// Builds the abort record for an overlay that outgrew this reservation.
    #[must_use]
    pub const fn budget_exceeded(&self, observed: OverlayStats) -> WorkspaceLeaseAbort {
        WorkspaceLeaseAbort {
            workspace_id: self.workspace_id,
            reason: WorkspaceAbortReason::BudgetExceeded {
                reserved_bytes: self.reserved_bytes,
                observed_bytes: observed.body_bytes as u64,
            },
            discarded: observed,
        }
    }
}

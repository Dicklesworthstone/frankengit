//! The export journal: named crash boundaries, idempotent replay, and
//! request → drain → finalize cancellation.
//!
//! `docs/GIT_TREE_FS.md` §6 and §14, AGENTS.md §3.2 and §5.4.
//!
//! # Why a journal and not a flag
//!
//! An export crosses several boundaries where a crash leaves different amounts
//! of work behind. Recording *which* boundary was reached is what makes restart
//! decidable: after a crash each staged object is either absent, present and
//! re-derivable, or explicitly abandoned — never "possibly published". A single
//! in-progress flag cannot distinguish those, and the difference is exactly
//! where a partial publication would hide.
//!
//! # The rule this module exists to enforce
//!
//! **No valid partial publication before authority selection.** Objects reach
//! [`ExportPhase::Staged`] and stop. Nothing in `TreeFS` can move them to visible
//! or durable, because a workspace never holds publication authority — only a
//! successful conditional replace of the exact predecessor authority head
//! publishes anything (AGENTS.md §5.1), and that happens elsewhere.
//!
//! Reading a staged export as durable is therefore a typed refusal, not a
//! best-effort answer: those are three different facts about the same bytes and
//! conflating them is how a workspace comes to believe it committed something.

use crate::capability::WorkspaceId;
use crate::obligation::{WorkspaceAbortReason, WorkspaceLeaseAbort, WorkspaceLeaseReservation};
use crate::overlay::OverlayStats;
use crate::snapshot::{EpochSet, WorkspaceEpoch};
use core::fmt::{self, Display, Formatter};

/// A named boundary an export can be interrupted at.
///
/// Ordered: a later phase implies every earlier one completed. The names match
/// the interruption points enumerated in `docs/GIT_TREE_FS.md` §14 that fall
/// inside export; the wider eleven-point matrix is FG-076's.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExportPhase {
    /// Nothing has been reserved. A crash here leaves no trace at all.
    Unstarted,
    /// Budget reserved, no object built. A crash here leaks only a reservation,
    /// which settles by abort.
    Reserved,
    /// The plan is computed but no object is written. A crash here leaves
    /// nothing on disk; the plan is a pure function of base and overlay and is
    /// simply recomputed.
    Planned,
    /// Objects are written to quarantine. A crash here leaves objects that are
    /// unreferenced by any authority and therefore collectable.
    Staged,
    /// The proposal is sealed and handed to the transaction layer. A crash here
    /// leaves a proposal that either was or was not accepted — `TreeFS` cannot
    /// tell, and must not guess.
    Proposed,
    /// The lease settled, one way or the other. Terminal.
    Settled,
}

impl ExportPhase {
    /// Every phase in order.
    pub const ALL: &'static [Self] = &[
        Self::Unstarted,
        Self::Reserved,
        Self::Planned,
        Self::Staged,
        Self::Proposed,
        Self::Settled,
    ];

    /// Compile-time completeness for [`ExportPhase::ALL`].
    ///
    /// `ALL` is hand-written, so nothing in the language forces it to list
    /// every variant, and several tests rely on it doing so —
    /// `crash_matrix.rs` drives five cells over `ALL` precisely *"so a new
    /// phase is automatically covered"*, including the durability tripwire.
    /// That claim was not enforced.
    ///
    /// The gap is narrow and specific. `export.rs` already pins the code
    /// points of `ALL` to the literal `[0, 1, 2, 3, 4, 5]`, which catches a
    /// reorder, a dropped entry, and a variant added to *both* enum and
    /// `ALL`. What it cannot catch is a variant added to the enum and left
    /// out of `ALL`: `code_point` below is exhaustive and forces the author
    /// to assign a code point, but that sends them to `code_point`, not
    /// here — the crate compiles, the literal still reads `[0..5]`, and every
    /// `ALL`-driven test silently covers one phase fewer.
    ///
    /// This match is exhaustive with no wildcard, so a seventh phase fails to
    /// compile *at this site*, where the doc says what to do about it. It
    /// mirrors `fgit-crypto`'s guard at `registry.rs:110` and the one
    /// `fgit-types` carries in `vocabulary.rs`: the type system holds an
    /// invariant a reader would otherwise have to remember.
    ///
    /// HONEST LIMIT: it forces the addition to be *considered*, not made. An
    /// author can add the arm here and still not touch `ALL`. That is
    /// strictly more than the array had, and less than a derived list would
    /// give.
    ///
    /// DELETION CONDITION: goes if `ExportPhase` ever gains a derived
    /// enumeration, which would let `ALL` be generated rather than maintained.
    const fn _every_phase_is_listed_in_all(phase: Self) {
        match phase {
            Self::Unstarted
            | Self::Reserved
            | Self::Planned
            | Self::Staged
            | Self::Proposed
            | Self::Settled => {}
        }
    }

    /// Stable code point for evidence records.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::Unstarted => 0,
            Self::Reserved => 1,
            Self::Planned => 2,
            Self::Staged => 3,
            Self::Proposed => 4,
            Self::Settled => 5,
        }
    }

    /// Whether a crash at this phase can have left objects behind.
    #[must_use]
    pub const fn may_have_staged_objects(self) -> bool {
        matches!(self, Self::Staged | Self::Proposed | Self::Settled)
    }

    /// Whether `TreeFS` can still decide the outcome by itself.
    ///
    /// False from [`Self::Proposed`] onwards: once a proposal is handed over,
    /// only the authority layer knows whether it was accepted, and a client
    /// disconnect never proves non-commit (AGENTS.md §5.2).
    #[must_use]
    pub const fn outcome_is_locally_decidable(self) -> bool {
        matches!(
            self,
            Self::Unstarted | Self::Reserved | Self::Planned | Self::Staged
        )
    }
}

impl Display for ExportPhase {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Unstarted => "unstarted",
            Self::Reserved => "reserved",
            Self::Planned => "planned",
            Self::Staged => "staged",
            Self::Proposed => "proposed",
            Self::Settled => "settled",
        };
        formatter.write_str(text)
    }
}

/// Where a cancellation request currently stands.
///
/// AGENTS.md §3.2: cancellation is request → drain → finalize, and dropping a
/// future is not a complete protocol. Each state is observable so a caller can
/// tell "asked to stop" from "stopped and cleaned up".
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CancellationState {
    /// No cancellation requested.
    #[default]
    Running,
    /// Cancellation requested; in-flight work is still draining.
    Requested,
    /// Work has drained; cleanup has not yet run.
    Drained,
    /// Cleanup completed and every staged artifact was accounted for.
    Finalized,
    /// Cleanup could not account for everything.
    ///
    /// A containment failure is reported, never swallowed: an unaccounted
    /// staged object is exactly what a later GC or a later export must know
    /// about.
    ContainmentFailed,
}

impl Display for CancellationState {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Running => "running",
            Self::Requested => "requested",
            Self::Drained => "drained",
            Self::Finalized => "finalized",
            Self::ContainmentFailed => "containment-failed",
        };
        formatter.write_str(text)
    }
}

/// Why a journal transition was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalRefusal {
    /// The requested phase is not the immediate successor of the current one.
    NonSequentialPhase {
        /// The phase the journal holds.
        current: ExportPhase,
        /// The phase that was requested.
        requested: ExportPhase,
    },
    /// A phase transition was attempted after cancellation was requested.
    CancellationInProgress {
        /// The cancellation state at the time.
        state: CancellationState,
    },
    /// A durability claim was made about work that is only staged.
    NotDurable {
        /// The phase the export actually reached.
        phase: ExportPhase,
    },
    /// A visibility claim was made about work that is only staged.
    NotVisible {
        /// The phase the export actually reached.
        phase: ExportPhase,
    },
    /// `TreeFS` was asked to decide an outcome only the authority layer knows.
    OutcomeNotLocallyDecidable {
        /// The phase the export reached.
        phase: ExportPhase,
    },
    /// Finalizing was attempted before draining completed.
    DrainIncomplete {
        /// The cancellation state at the time.
        state: CancellationState,
    },
}

impl Display for JournalRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonSequentialPhase { current, requested } => write!(
                formatter,
                "cannot move from {current} to {requested}: phases advance one step at a time"
            ),
            Self::CancellationInProgress { state } => {
                write!(
                    formatter,
                    "cancellation is {state}; no new work is admitted"
                )
            }
            Self::NotDurable { phase } => write!(
                formatter,
                "export reached {phase}; durability is not a TreeFS claim to make"
            ),
            Self::NotVisible { phase } => write!(
                formatter,
                "export reached {phase}; visibility requires authority publication"
            ),
            Self::OutcomeNotLocallyDecidable { phase } => write!(
                formatter,
                "at {phase} only the authority layer knows the outcome"
            ),
            Self::DrainIncomplete { state } => {
                write!(formatter, "cannot finalize while cancellation is {state}")
            }
        }
    }
}

impl core::error::Error for JournalRefusal {}

/// One recorded journal step, for replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalStep {
    /// The phase entered.
    pub phase: ExportPhase,
    /// Objects staged as of this step.
    pub staged_objects: usize,
    /// Bytes staged as of this step.
    pub staged_bytes: usize,
}

/// The export journal.
///
/// Advancing is strictly sequential and idempotent: re-entering the phase the
/// journal already holds is a no-op that succeeds, which is what makes replay
/// after a crash safe to run more than once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportJournal {
    workspace_id: WorkspaceId,
    phase: ExportPhase,
    cancellation: CancellationState,
    epochs: EpochSet,
    steps: Vec<JournalStep>,
    staged_objects: usize,
    staged_bytes: usize,
    reservation: Option<WorkspaceLeaseReservation>,
}

impl ExportJournal {
    /// Opens a journal at [`ExportPhase::Unstarted`].
    #[must_use]
    pub const fn open(workspace_id: WorkspaceId) -> Self {
        Self {
            workspace_id,
            phase: ExportPhase::Unstarted,
            cancellation: CancellationState::Running,
            epochs: EpochSet::new(),
            steps: Vec::new(),
            staged_objects: 0,
            staged_bytes: 0,
            reservation: None,
        }
    }

    /// The workspace this journal belongs to.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// The phase reached.
    #[must_use]
    pub const fn phase(&self) -> ExportPhase {
        self.phase
    }

    /// The cancellation state.
    #[must_use]
    pub const fn cancellation(&self) -> CancellationState {
        self.cancellation
    }

    /// The epochs this export has reached.
    ///
    /// `visible` and `durable` stay at zero for the whole life of an export,
    /// because `TreeFS` cannot advance them.
    #[must_use]
    pub const fn epochs(&self) -> EpochSet {
        self.epochs
    }

    /// The recorded steps, in order.
    #[must_use]
    pub fn steps(&self) -> &[JournalStep] {
        &self.steps
    }

    /// Objects staged so far.
    #[must_use]
    pub const fn staged_objects(&self) -> usize {
        self.staged_objects
    }

    /// Bytes staged so far.
    #[must_use]
    pub const fn staged_bytes(&self) -> usize {
        self.staged_bytes
    }

    /// Records the lease reservation this export runs under.
    pub const fn reserve(&mut self, reservation: WorkspaceLeaseReservation) {
        self.reservation = Some(reservation);
    }

    /// The recorded reservation, if any.
    #[must_use]
    pub const fn reservation(&self) -> Option<&WorkspaceLeaseReservation> {
        self.reservation.as_ref()
    }

    /// Advances to `next`.
    ///
    /// Re-entering the current phase succeeds and changes nothing, so a replay
    /// that repeats the last step is safe. Skipping a phase is refused: the
    /// point of named boundaries is lost if an export can jump over one.
    pub fn advance(&mut self, next: ExportPhase) -> Result<(), JournalRefusal> {
        if next == self.phase {
            return Ok(());
        }
        if self.cancellation != CancellationState::Running {
            return Err(JournalRefusal::CancellationInProgress {
                state: self.cancellation,
            });
        }
        let expected = match self.phase {
            ExportPhase::Unstarted => ExportPhase::Reserved,
            ExportPhase::Reserved => ExportPhase::Planned,
            ExportPhase::Planned => ExportPhase::Staged,
            ExportPhase::Staged => ExportPhase::Proposed,
            ExportPhase::Proposed | ExportPhase::Settled => ExportPhase::Settled,
        };
        if next != expected {
            return Err(JournalRefusal::NonSequentialPhase {
                current: self.phase,
                requested: next,
            });
        }
        self.phase = next;
        // Staging is the only phase that produces workspace-local content, so
        // it is the only one that advances the staged epoch. visible and
        // durable are never touched here, by construction.
        if next == ExportPhase::Staged {
            self.epochs = self.epochs.stage();
        }
        self.steps.push(JournalStep {
            phase: next,
            staged_objects: self.staged_objects,
            staged_bytes: self.staged_bytes,
        });
        Ok(())
    }

    /// Records that objects were staged.
    pub const fn record_staged(&mut self, objects: usize, bytes: usize) {
        self.staged_objects = objects;
        self.staged_bytes = bytes;
    }

    /// Answers whether the exported work is durable.
    ///
    /// Always a refusal. `TreeFS` stages; it never makes anything durable, and a
    /// method that could return `true` here would be a lie waiting to happen.
    pub const fn assert_durable(&self) -> Result<(), JournalRefusal> {
        Err(JournalRefusal::NotDurable { phase: self.phase })
    }

    /// Answers whether the exported work is visible to repository readers.
    ///
    /// Always a refusal, for the same reason: visibility follows authority
    /// publication, which happens outside this crate.
    pub const fn assert_visible(&self) -> Result<(), JournalRefusal> {
        Err(JournalRefusal::NotVisible { phase: self.phase })
    }

    /// Whether `TreeFS` can still decide this export's outcome alone.
    pub const fn local_outcome(&self) -> Result<ExportPhase, JournalRefusal> {
        if self.phase.outcome_is_locally_decidable() {
            Ok(self.phase)
        } else {
            Err(JournalRefusal::OutcomeNotLocallyDecidable { phase: self.phase })
        }
    }

    // --- cancellation: request -> drain -> finalize ------------------------

    /// Requests cancellation. Idempotent.
    pub const fn request_cancel(&mut self) {
        if matches!(self.cancellation, CancellationState::Running) {
            self.cancellation = CancellationState::Requested;
        }
    }

    /// Marks in-flight work as drained.
    pub const fn drain(&mut self) {
        if matches!(
            self.cancellation,
            CancellationState::Requested | CancellationState::Drained
        ) {
            self.cancellation = CancellationState::Drained;
        }
    }

    /// Finalizes cancellation, accounting for every staged artifact.
    ///
    /// `reclaimed` is how many staged objects the caller actually removed. If
    /// that does not match what the journal staged, the result is
    /// [`CancellationState::ContainmentFailed`] and the abort record says so —
    /// an unaccounted staged object is a fact a later GC needs, not a detail to
    /// round away.
    pub fn finalize_cancel(
        &mut self,
        reclaimed: usize,
    ) -> Result<WorkspaceLeaseAbort, JournalRefusal> {
        if self.cancellation != CancellationState::Drained {
            return Err(JournalRefusal::DrainIncomplete {
                state: self.cancellation,
            });
        }
        let discarded = OverlayStats {
            entry_count: self.staged_objects,
            body_count: self.staged_objects,
            body_bytes: self.staged_bytes,
        };
        self.cancellation = if reclaimed == self.staged_objects {
            CancellationState::Finalized
        } else {
            CancellationState::ContainmentFailed
        };
        self.phase = ExportPhase::Settled;
        self.steps.push(JournalStep {
            phase: ExportPhase::Settled,
            staged_objects: self.staged_objects,
            staged_bytes: self.staged_bytes,
        });
        Ok(WorkspaceLeaseAbort {
            workspace_id: self.workspace_id,
            reason: WorkspaceAbortReason::Discarded,
            discarded,
        })
    }

    /// Whether a cancelled export left anything a consumer could mistake for a
    /// result.
    ///
    /// The acceptance rule is that cancellation leaves no consumable artifact.
    /// A finalized cancellation satisfies it; a containment failure does not,
    /// and says so rather than reporting success.
    #[must_use]
    pub const fn left_consumable_artifact(&self) -> bool {
        matches!(self.cancellation, CancellationState::ContainmentFailed)
    }

    /// Replays a recorded step sequence onto a fresh journal.
    ///
    /// Replay is idempotent: applying the same steps twice yields the same
    /// journal. That is what makes crash recovery safe to retry, and it is why
    /// [`Self::advance`] treats re-entering the current phase as success.
    pub fn replay(
        workspace_id: WorkspaceId,
        steps: &[JournalStep],
    ) -> Result<Self, JournalRefusal> {
        let mut journal = Self::open(workspace_id);
        for step in steps {
            journal.record_staged(step.staged_objects, step.staged_bytes);
            journal.advance(step.phase)?;
        }
        Ok(journal)
    }

    /// The staged epoch this export reached.
    #[must_use]
    pub const fn staged_epoch(&self) -> WorkspaceEpoch {
        self.epochs.staged()
    }
}

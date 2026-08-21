//! Worker and transaction lifecycle, and what cancellation means at each phase.
//!
//! §3.3 of the integration profile states two rules that are easy to write down
//! and easy to violate by accident:
//!
//! > Every connection/worker has an owner, capacity limit, shutdown budget, and
//! > explicit `close(&Cx)`/join path. **Drop-triggered cleanup is a backstop and
//! > cannot prove quiescent shutdown.**
//!
//! > A transaction is finalized by awaited `commit` or `rollback`. **Drop
//! > rollback is deferred cleanup, not successful abort evidence.**
//!
//! Both rules are about the difference between *cleanup happening* and *cleanup
//! being proven*, and both are lost the moment someone writes `impl Drop` and
//! treats the resulting state as success. So the states are modelled here as a
//! total, pure transition function, and the two "cleanup happened but nothing
//! was proven" outcomes are **distinct terminal states** rather than aliases of
//! the proven ones. A caller cannot reach [`WorkerState::Closed`] except
//! through an awaited close, because no event leads there from anywhere else.
//!
//! # Why this is here before the engine
//!
//! This is the law the `AsyncConnection`-owning worker will be written against,
//! and it is exhaustively testable now. It is not a substitute for the
//! engine-level proof: the acceptance line "explicit close proves no live DB
//! worker, thread, descriptor or unfinalized transaction" is about a real
//! process and will be demonstrated against one. What is settled here is that
//! the *protocol* admits no path where dropping something counts as closing it.

/// The lifecycle of one connection-owning worker.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkerState {
    /// Opened and accepting commands.
    Open,
    /// Drain requested: no new commands admitted, in-flight ones finishing.
    Draining,
    /// Awaited close completed and the worker joined.
    ///
    /// The only state that proves quiescence, and reachable only through
    /// [`WorkerEvent::CloseCompleted`] from [`Self::Draining`].
    Closed,
    /// Dropped without an awaited close.
    ///
    /// Terminal, and deliberately **not** [`Self::Closed`]. The backstop may
    /// well have released everything; nothing observed it do so.
    AbandonedByDrop,
    /// Close was attempted and the worker did not come back.
    ///
    /// Reported rather than swallowed: a join that times out means a thread,
    /// descriptor, or transaction may still be live.
    ContainmentFailure,
}

impl WorkerState {
    /// Whether this state is evidence that nothing is still running.
    #[must_use]
    pub const fn proves_quiescent(self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Whether no further transition is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Closed | Self::AbandonedByDrop | Self::ContainmentFailure
        )
    }
}

/// What can happen to a worker.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkerEvent {
    /// A drain was requested (the `request` of request-drain-finalize).
    DrainRequested,
    /// The drain finished and the awaited close returned (`finalize`).
    CloseCompleted,
    /// The close budget expired before the worker joined.
    JoinTimedOut,
    /// The handle was dropped without an awaited close.
    Dropped,
}

/// Why a lifecycle event is not admissible in the current state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LifecycleError {
    /// The event does not apply in this state.
    NotApplicable {
        /// The state the subject was in.
        state: &'static str,
        /// The event that was attempted.
        event: &'static str,
    },
    /// The subject is already terminal.
    AlreadyTerminal {
        /// The terminal state.
        state: &'static str,
    },
}

impl core::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::NotApplicable { state, event } => {
                write!(f, "{event} does not apply in state {state}")
            }
            Self::AlreadyTerminal { state } => write!(f, "{state} is terminal"),
        }
    }
}

impl std::error::Error for LifecycleError {}

impl WorkerState {
    /// A stable name for receipts and refusals.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::AbandonedByDrop => "abandoned_by_drop",
            Self::ContainmentFailure => "containment_failure",
        }
    }

    /// The total transition function.
    ///
    /// Note what is absent: no event carries [`Self::Open`] straight to
    /// [`Self::Closed`], and no event carries anything to [`Self::Closed`]
    /// except an awaited close after a drain. Dropping always lands in
    /// [`Self::AbandonedByDrop`].
    pub const fn apply(self, event: WorkerEvent) -> Result<Self, LifecycleError> {
        if self.is_terminal() {
            return Err(LifecycleError::AlreadyTerminal {
                state: self.as_str(),
            });
        }
        match (self, event) {
            (Self::Open, WorkerEvent::DrainRequested) => Ok(Self::Draining),
            // Closing without draining first would abandon in-flight commands,
            // which is the thing the drain phase exists to prevent.
            (Self::Open, WorkerEvent::CloseCompleted) => Err(LifecycleError::NotApplicable {
                state: "open",
                event: "close_completed",
            }),
            (Self::Draining, WorkerEvent::CloseCompleted) => Ok(Self::Closed),
            (Self::Open | Self::Draining, WorkerEvent::JoinTimedOut) => {
                Ok(Self::ContainmentFailure)
            }
            (Self::Open | Self::Draining, WorkerEvent::Dropped) => Ok(Self::AbandonedByDrop),
            (Self::Draining, WorkerEvent::DrainRequested) => Err(LifecycleError::NotApplicable {
                state: "draining",
                event: "drain_requested",
            }),
            (Self::Closed | Self::AbandonedByDrop | Self::ContainmentFailure, _) => {
                Err(LifecycleError::AlreadyTerminal {
                    state: self.as_str(),
                })
            }
        }
    }
}

/// The lifecycle of one SQL transaction on a worker.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TransactionState {
    /// Begun and awaiting a finalizer.
    Begun,
    /// An awaited commit returned successfully.
    Committed,
    /// An awaited rollback returned successfully.
    ///
    /// The only state that is evidence of a successful abort.
    RolledBack,
    /// Cancelled or interrupted while the commit may have executed.
    ///
    /// Terminal for this handle and **not** an abort: the effect may exist, so
    /// the outcome has to be looked up rather than assumed away.
    CommitAmbiguous,
    /// Dropped without an awaited finalizer.
    ///
    /// The engine's deferred rollback may well run. Nothing observed it, so
    /// this is not abort evidence.
    AbandonedByDrop,
}

impl TransactionState {
    /// A stable name for receipts and refusals.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Begun => "begun",
            Self::Committed => "committed",
            Self::RolledBack => "rolled_back",
            Self::CommitAmbiguous => "commit_ambiguous",
            Self::AbandonedByDrop => "abandoned_by_drop",
        }
    }

    /// Whether no further transition is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Begun)
    }

    /// Whether this state is evidence that the transaction did not apply.
    ///
    /// True only for an awaited rollback. A dropped transaction is deferred
    /// cleanup, and an ambiguous commit may well have applied.
    #[must_use]
    pub const fn proves_abort(self) -> bool {
        matches!(self, Self::RolledBack)
    }

    /// Whether the caller must resolve the outcome by looking it up.
    #[must_use]
    pub const fn requires_outcome_lookup(self) -> bool {
        matches!(self, Self::CommitAmbiguous | Self::AbandonedByDrop)
    }

    /// The total transition function.
    pub const fn apply(self, event: TransactionEvent) -> Result<Self, LifecycleError> {
        if self.is_terminal() {
            return Err(LifecycleError::AlreadyTerminal {
                state: self.as_str(),
            });
        }
        match event {
            TransactionEvent::CommitAwaited => Ok(Self::Committed),
            TransactionEvent::RollbackAwaited => Ok(Self::RolledBack),
            TransactionEvent::CancelledDuringCommit => Ok(Self::CommitAmbiguous),
            TransactionEvent::Dropped => Ok(Self::AbandonedByDrop),
        }
    }
}

/// What can happen to a transaction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TransactionEvent {
    /// An awaited commit returned.
    CommitAwaited,
    /// An awaited rollback returned.
    RollbackAwaited,
    /// Cancellation reached a commit that may already have executed.
    CancelledDuringCommit,
    /// The handle was dropped without an awaited finalizer.
    Dropped,
}

/// Where a cancellation caught an operation.
///
/// The six phases the bead enumerates, in the order an operation passes them.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CancellationPhase {
    /// Before the command was handed to the lane at all.
    BeforeDispatch,
    /// Sitting in the worker's bounded queue, not yet taken.
    Queued,
    /// A statement is running on the connection.
    Executing,
    /// A commit is in flight.
    CommitInFlight,
    /// The effect finished; the reply had not reached the caller.
    AwaitingReply,
    /// Cancellation arrived during shutdown.
    DuringClose,
}

/// What a cancellation at a given phase licenses the caller to conclude.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CancellationOutcome {
    /// No effect can have occurred; the caller may conclude non-commit.
    ///
    /// Only sound while the worker meets its obligation to remove a queued
    /// command atomically before dispatch. If that obligation is ever broken,
    /// [`CancellationPhase::Queued`] must move to [`Self::Ambiguous`].
    NoEffect,
    /// The effect status is unknown; resolve by exact-key read, then by lookup.
    Ambiguous,
    /// The operation is unaffected, but quiescence is now in question.
    ContainmentRisk,
}

/// Classify a cancellation by the phase it caught.
///
/// The load-bearing entry is [`CancellationPhase::CommitInFlight`]: a
/// cancellation there must never be reported as a refusal, because the commit
/// may have applied. That is the storage-layer form of the rule that a client
/// cancellation never proves non-commit.
#[must_use]
pub const fn classify_cancellation(phase: CancellationPhase) -> CancellationOutcome {
    match phase {
        // Nothing left our process, and a queued command is removed before
        // dispatch, so both are provably effect-free.
        CancellationPhase::BeforeDispatch | CancellationPhase::Queued => {
            CancellationOutcome::NoEffect
        }
        CancellationPhase::Executing
        | CancellationPhase::CommitInFlight
        | CancellationPhase::AwaitingReply => CancellationOutcome::Ambiguous,
        CancellationPhase::DuringClose => CancellationOutcome::ContainmentRisk,
    }
}

/// Every phase, for exhaustive iteration in tests and campaigns.
pub const CANCELLATION_PHASES: [CancellationPhase; 6] = [
    CancellationPhase::BeforeDispatch,
    CancellationPhase::Queued,
    CancellationPhase::Executing,
    CancellationPhase::CommitInFlight,
    CancellationPhase::AwaitingReply,
    CancellationPhase::DuringClose,
];

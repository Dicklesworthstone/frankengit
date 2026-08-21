#![forbid(unsafe_code)]
//! Budgets, charges, and obligation-typed effects for `FrankenGit`.
//!
//! An effect that can be abandoned by cancellation is not a function call; it
//! is a responsibility somebody has to close. This crate is the vocabulary for
//! that responsibility: the graded resource algebra an effect spends, the
//! two-phase lifecycle it moves through, the eleven concrete obligation classes
//! the system actually has, the region custody that decides whether closing
//! reached quiescence, and the reconciliation machine for the one window where
//! an effect is committed but not yet observed.
//!
//! The crate is layer L0. It depends on nothing but `std`, performs no I/O,
//! spawns nothing, and knows nothing about the runtime. That is deliberate:
//! the runtime binds these types to regions, cancellation, and budgets, and it
//! can only do so if the vocabulary is smaller than the runtime rather than
//! entangled with it.
//!
//! # Design choice: type-state for possession, runtime state for records
//!
//! The bead this crate answers asked for either a type-state or a runtime-state
//! design. It uses both, at different boundaries, because the two failure
//! modes live in different places.
//!
//! **Type-state, for a value you own.** `Reserved`, `Committed`, and settled
//! are three distinct types, and every transition consumes the value it starts
//! from. Double-commit and commit-after-abort are therefore not errors that get
//! caught; after
//! [`ReservedObligation::commit`](twophase::ReservedObligation::commit) there is
//! no reserved value left to commit again, and after
//! [`ReservedObligation::abort`](twophase::ReservedObligation::abort) there is
//! nothing to commit at all. Acknowledgement exists only on
//! [`CommittedObligation`](twophase::CommittedObligation), so acknowledging
//! something that never committed does not typecheck. This is the strongest
//! available guarantee and it costs nothing at run time.
//!
//! **Runtime state, for a value you only have a record of.** Type-state cannot
//! help three real situations: a region holding a heterogeneous set of live
//! obligations and needing to decide whether it is quiescent; an outbox row
//! recovered after a crash, where the lifecycle is data rather than possession;
//! and a journal replayed to reconstruct what a region owed. For those,
//! [`ObligationState::apply`](custody::ObligationState::apply) is a total,
//! public, pure state machine that returns
//! [`LifecycleError::IllegalTransition`](custody::LifecycleError::IllegalTransition)
//! for exactly the pairs the type-state makes unrepresentable. The two halves
//! agree by construction because the owned values are the ledger's only writer:
//! `LedgerHandle::mark` is crate-private on purpose, so no caller can
//! desynchronize the record from the possession.
//!
//! **The gap both leave, and how it is closed.** Neither discipline can stop a
//! program from dropping a live obligation on the floor. Every owned type here
//! is `#[must_use]` *and* carries a drop guard, so a dropped reservation,
//! committed obligation, unacknowledged-effect record, budget grant, or ledger
//! becomes a typed [`LeakRecord`](custody::LeakRecord) and a
//! [`ContainmentFailure`](custody::ContainmentFailure) at region close. There
//! is no silent path: [`LeakPolicy`](custody::LeakPolicy) has no `Silent`
//! variant and no log-only variant to select.
//!
//! # Conservation
//!
//! Budget enters a region exactly once, through a declared root capacity, and
//! is never created again. [`ResourceVector::combine`](algebra::ResourceVector::combine)
//! composes grades; [`ResourceVector::split`](algebra::ResourceVector::split)
//! is the only division and refuses any part that exceeds the whole in any
//! grade. The owned form, [`BudgetGrant`](algebra::BudgetGrant), can only be
//! obtained from a ledger or carved out of a grant you already hold, and a
//! child region is funded solely by a grant handed to it — which is how "a
//! child region cannot mint authority or budget from nothing" is enforced
//! rather than asserted.
//!
//! The operational form of the guarantee is the region's accounting identity,
//! [`PoolSnapshot::is_conserved`](custody::PoolSnapshot::is_conserved):
//! available plus granted plus reserved plus consumed plus delegated always
//! equals capacity. It survives split, combine, reserve, settle, abort,
//! delegation, and leaks — a leak reclaims its budget while still recording the
//! lifecycle failure, so a leak is never also an accounting hole.
//!
//! # Non-claims
//!
//! This crate does not integrate with the runtime, does not implement
//! cancellation, and does not enforce a leak policy across tasks: it defines
//! the policy value and produces the records that a runtime acts on.
//! [`ObligationLedger::close`](custody::ObligationLedger::close) observes and
//! reports; it does not drain, cancel, or reap. Grades are integer amounts with
//! declared overflow refusal, not a physical measurement of anything.

pub mod algebra;
pub mod custody;
pub mod ids;
pub mod kinds;
pub mod settlement;
pub mod twophase;

pub use algebra::{
    BudgetGrant, Grade, GradeDisposition, ReleaseReceipt, ResourceError, ResourceVector,
    GRADE_COUNT,
};
pub use custody::{
    ContainmentFailure, LeakClass, LeakPolicy, LeakRecord, LeakSubject, LedgerHandle,
    LifecycleError, LifecycleEvent, ObligationLedger, ObligationState, OutstandingObligation,
    PoolSnapshot, QuiescenceReceipt, RegionCloseOutcome, ReserveError,
};
pub use ids::{BoundIdentity, GrantId, IdempotencyKey, IdentityError, ObligationId, RegionId};
pub use settlement::{
    reconcile, DownstreamChannel, DownstreamIdempotency, ReconcileOutcome, ReconcilePlan,
    ReconcilePolicy, ReconcileState,
};
pub use twophase::{
    CommittedObligation, DeferralReason, EscalationReason, EscalationReceipt, ExternallyObserved,
    InternalEffect, ObligationClass, ObligationKind, ObservationMode, ReservedObligation,
    SettledObligation, SettlementRefused, SettlementSummary, TerminalEvidence,
    TerminalFailureReason, TrivialAck, UnacknowledgedEffect,
};

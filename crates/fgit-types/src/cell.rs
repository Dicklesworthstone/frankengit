//! Cell readiness states and multi-region read modes.
//!
//! Two closed vocabularies from the plan, plus the decisions that depend only
//! on them. `frankengit-fg036a`.
//!
//! # Why these live at L0 rather than in the node
//!
//! A cell state decides what a cell may be *asked* to do, and a read mode is a
//! label that travels with an answer to a client. Both are named by layers that
//! must not depend on a node: admission decides whether to route work to a
//! cell, the wire layer labels a response, and the node is only the process
//! that happens to hold the state. Putting the vocabulary here is the same
//! placement [`crate::layout::RootLayoutVersion`] has, and for the same reason —
//! a vocabulary that lives above its readers cannot be named by them.
//!
//! # What is deliberately NOT here
//!
//! No routing, no gossip, no disclosure filtering. Routing needs a hash and
//! lives in `fgit-crypto`; disclosure needs `RefVisibility` and belongs with
//! the wire layer that owns it. This module holds vocabulary and the decisions
//! that are pure functions of it, so that nothing here can become a second
//! place where those policies are decided.

use core::fmt;
use core::time::Duration;

use crate::error::TypeRefusal;
use crate::hint::Hint;
use crate::identity::CellId;
use crate::numeric::HeadGeneration;

/// What a cell is currently able to serve.
///
/// The closed set from plan §37.3. Ordering is declaration order and carries no
/// meaning: a cell does not "progress" through these, it moves between them
/// along the edges [`CellState::may_transition_to`] admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum CellState {
    /// Coming up; not yet serving anything.
    #[default]
    Bootstrapping,
    /// Serving reads it can verify, and nothing else.
    VerifiedReadOnly,
    /// Fully serving, including mutation.
    Serving,
    /// Accepting uploads as noncanonical staging only, per §22.6.
    StagingOnly,
    /// Finishing in-flight work and accepting no new work.
    Draining,
    /// Serving reads under an explicit staleness bound.
    DegradedRead,
    /// Repairing local state; not serving.
    Repairing,
    /// Moving its responsibilities elsewhere.
    Evacuating,
    /// Failed, and not serving until repaired or retired.
    Failed,
    /// Permanently out of service.
    Retired,
}

impl CellState {
    /// Every state, in declaration order.
    pub const ALL: [Self; 10] = [
        Self::Bootstrapping,
        Self::VerifiedReadOnly,
        Self::Serving,
        Self::StagingOnly,
        Self::Draining,
        Self::DegradedRead,
        Self::Repairing,
        Self::Evacuating,
        Self::Failed,
        Self::Retired,
    ];

    /// The wire code point for this state.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::Bootstrapping => 0,
            Self::VerifiedReadOnly => 1,
            Self::Serving => 2,
            Self::StagingOnly => 3,
            Self::Draining => 4,
            Self::DegradedRead => 5,
            Self::Repairing => 6,
            Self::Evacuating => 7,
            Self::Failed => 8,
            Self::Retired => 9,
        }
    }

    /// Recover a state from its wire code point.
    ///
    /// # Errors
    ///
    /// [`TypeRefusal::CodePointUnknown`] for a code point this build does not
    /// know. A cell reporting a state we cannot read is not "bootstrapping by
    /// default" — it is a peer newer than us, and guessing its capabilities is
    /// how a cell gets sent work it cannot do.
    pub fn from_code_point(code_point: u16) -> Result<Self, TypeRefusal> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.code_point() == code_point)
            .ok_or_else(|| TypeRefusal::CodePointUnknown {
                field: "CellState",
                observed: u32::from(code_point),
            })
    }

    /// Whether this state admits publishing new canonical state.
    #[must_use]
    pub const fn admits_mutation(self) -> bool {
        matches!(self, Self::Serving)
    }

    /// Whether this state admits a read verified against the current head.
    #[must_use]
    pub const fn admits_current_read(self) -> bool {
        matches!(self, Self::VerifiedReadOnly | Self::Serving)
    }

    /// Whether this state admits a read under an explicit staleness bound.
    ///
    /// Note this is *wider* than [`Self::admits_current_read`]: a cell that has
    /// lost the authority but still holds verified older state is exactly the
    /// §22.6 partition case that bounded-stale exists to serve.
    #[must_use]
    pub const fn admits_bounded_stale_read(self) -> bool {
        matches!(
            self,
            Self::VerifiedReadOnly | Self::Serving | Self::DegradedRead | Self::Draining
        )
    }

    /// Whether this state admits noncanonical staging uploads.
    #[must_use]
    pub const fn admits_staging(self) -> bool {
        matches!(self, Self::Serving | Self::StagingOnly)
    }

    /// Whether no transition leaves this state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Retired)
    }

    /// Whether `self -> next` is an admissible transition.
    ///
    /// # The shape of this table, and the two rules that are not obvious
    ///
    /// Any state may fail, and any non-terminal state may be retired: those are
    /// the two edges that must always exist, because refusing them would leave
    /// a cell stuck in a state it cannot leave. Everything else is explicit.
    ///
    /// [`Self::Retired`] admits nothing, including itself. A cell does not come
    /// back from retirement under the same identity — reusing one would let an
    /// operator resurrect a cell whose capabilities were deliberately withdrawn,
    /// and the audit trail would show a transition rather than a new cell.
    #[must_use]
    pub fn may_transition_to(self, next: Self) -> bool {
        if self.is_terminal() {
            return false;
        }
        if self == next {
            // A no-op is not a transition. Admitting it would let an audit log
            // fill with entries that record nothing, and callers could not tell
            // "we re-affirmed the state" from "the state changed".
            return false;
        }
        if next == Self::Failed || next == Self::Retired {
            return true;
        }
        match self {
            Self::Bootstrapping => matches!(next, Self::VerifiedReadOnly | Self::Repairing),
            Self::VerifiedReadOnly => matches!(
                next,
                Self::Serving | Self::DegradedRead | Self::Draining | Self::Repairing
            ),
            Self::Serving => matches!(
                next,
                Self::VerifiedReadOnly
                    | Self::StagingOnly
                    | Self::DegradedRead
                    | Self::Draining
                    | Self::Repairing
                    | Self::Evacuating
            ),
            Self::StagingOnly => matches!(next, Self::Serving | Self::Draining | Self::Repairing),
            Self::Draining => matches!(next, Self::Evacuating | Self::Repairing),
            Self::DegradedRead => matches!(
                next,
                Self::VerifiedReadOnly | Self::Serving | Self::Draining | Self::Repairing
            ),
            Self::Repairing => matches!(next, Self::VerifiedReadOnly | Self::Bootstrapping),
            Self::Failed => matches!(next, Self::Repairing),
            // Evacuating hands its work away and then fails or retires, both of
            // which the early return above already admitted. Retired is
            // terminal and never reaches here.
            Self::Evacuating | Self::Retired => false,
        }
    }
}

impl fmt::Display for CellState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Bootstrapping => "BOOTSTRAPPING",
            Self::VerifiedReadOnly => "VERIFIED_READ_ONLY",
            Self::Serving => "SERVING",
            Self::StagingOnly => "STAGING_ONLY",
            Self::Draining => "DRAINING",
            Self::DegradedRead => "DEGRADED_READ",
            Self::Repairing => "REPAIRING",
            Self::Evacuating => "EVACUATING",
            Self::Failed => "FAILED",
            Self::Retired => "RETIRED",
        })
    }
}

/// Why a cell changed state.
///
/// Carried so the audit answers "why" and not only "when". A transition with no
/// reason is indistinguishable from an unexplained one after the fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CellTransitionCause {
    /// An operator or control-plane instruction.
    Operator,
    /// The cell observed the authority and changed what it can serve.
    AuthorityObservation,
    /// A local health check or resource condition.
    LocalHealth,
    /// Repair or recovery machinery.
    Repair,
    /// The process brought itself into service as part of its own start-up.
    ///
    /// # Why this is not [`Self::Operator`]
    ///
    /// `Operator` says an instruction arrived from outside the cell. A process
    /// that is started in order to carry traffic decides for itself, at
    /// start-up, that it must leave [`CellState::Bootstrapping`] — nobody sent
    /// it anything. Recording that as an operator instruction would put an
    /// instruction in the audit that was never given, and an audit whose
    /// entries cannot be told apart from real control-plane traffic answers
    /// "why" with a fiction.
    ///
    /// # Why it is not [`Self::AuthorityObservation`] either
    ///
    /// That cause is for a cell that *watched the authority change* and
    /// adjusted what it can serve. Bringing a freshly opened cell up is not an
    /// observation of a change: the authority head was authenticated as a
    /// precondition of opening at all, and the transition follows from the
    /// process having been started, not from anything the authority did.
    ServiceBringUp,
}

/// One audited state change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellTransition {
    from: CellState,
    to: CellState,
    cause: CellTransitionCause,
    at_generation: HeadGeneration,
}

impl CellTransition {
    /// The state left behind.
    #[must_use]
    pub const fn from(&self) -> CellState {
        self.from
    }

    /// The state entered.
    #[must_use]
    pub const fn to(&self) -> CellState {
        self.to
    }

    /// Why it happened.
    #[must_use]
    pub const fn cause(&self) -> CellTransitionCause {
        self.cause
    }

    /// The head generation the cell believed current when it moved.
    #[must_use]
    pub const fn at_generation(&self) -> HeadGeneration {
        self.at_generation
    }
}

/// A cell's readiness, with the audit of how it got there.
///
/// The log is not decoration. Plan §37.3 requires transitions to be audited
/// *and* to enforce capability changes, and the only way both hold is if the
/// same call that changes what the cell may serve is the call that records it.
/// Exposing a setter beside a separate logger would make the two separable, and
/// then one of them would eventually be skipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellReadiness {
    state: CellState,
    audit: Vec<CellTransition>,
}

impl CellReadiness {
    /// A cell that has just started.
    #[must_use]
    pub const fn bootstrapping() -> Self {
        Self {
            state: CellState::Bootstrapping,
            audit: Vec::new(),
        }
    }

    /// What the cell may serve right now.
    #[must_use]
    pub const fn state(&self) -> CellState {
        self.state
    }

    /// Every transition this cell has made, oldest first.
    #[must_use]
    pub fn audit(&self) -> &[CellTransition] {
        &self.audit
    }

    /// Move to `next`, recording why.
    ///
    /// # Errors
    ///
    /// [`CellRefusal::IllegalTransition`] when the edge is not admitted. The
    /// refusal names both ends, because "illegal transition" without them is
    /// unactionable in a log.
    pub fn transition_to(
        &mut self,
        next: CellState,
        cause: CellTransitionCause,
        at_generation: HeadGeneration,
    ) -> Result<&CellTransition, CellRefusal> {
        if !self.state.may_transition_to(next) {
            return Err(CellRefusal::IllegalTransition {
                from: self.state,
                to: next,
            });
        }
        self.audit.push(CellTransition {
            from: self.state,
            to: next,
            cause,
            at_generation,
        });
        self.state = next;
        Ok(self
            .audit
            .last()
            .expect("a transition was just pushed onto the audit"))
    }
}

impl Default for CellReadiness {
    fn default() -> Self {
        Self::bootstrapping()
    }
}

/// How current an answer is, and what the client is being promised.
///
/// The closed set from plan §22.5. The label travels with the answer: a client
/// that cannot tell which of these it received cannot tell a current read from
/// an offline one, and the difference is the whole point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReadMode {
    /// Verified against the current authority head.
    Current,
    /// A verified older answer, within an explicit bound.
    BoundedStale(StalenessBound),
    /// An exact requested revision, regardless of newer state.
    Snapshot,
    /// A locally verified capsule, with no currentness claim at all.
    Offline,
}

impl ReadMode {
    /// The wire code point for this mode.
    ///
    /// The bound is not part of the code point: it is data the label carries,
    /// not a distinct mode.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::Current => 0,
            Self::BoundedStale(_) => 1,
            Self::Snapshot => 2,
            Self::Offline => 3,
        }
    }

    /// Whether this mode asserts anything about being current.
    ///
    /// [`Self::Offline`] deliberately does not, and [`Self::Snapshot`] does not
    /// either — a snapshot is exact about *which* revision, and silent about
    /// whether a newer one exists.
    #[must_use]
    pub const fn claims_currentness(self) -> bool {
        matches!(self, Self::Current)
    }
}

/// The explicit limit a bounded-stale answer is promised to respect.
///
/// Both halves are required. An age bound alone permits unbounded divergence
/// during a burst of head transitions, and a sequence bound alone permits an
/// arbitrarily old answer in a quiet repository. §22.5 says "age/sequence
/// bound"; carrying only one of them would be a weaker promise wearing the
/// same name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StalenessBound {
    max_age: Duration,
    max_generation_lag: u64,
}

impl StalenessBound {
    /// Declare a bound.
    #[must_use]
    pub const fn new(max_age: Duration, max_generation_lag: u64) -> Self {
        Self {
            max_age,
            max_generation_lag,
        }
    }

    /// The oldest an answer may be.
    #[must_use]
    pub const fn max_age(&self) -> Duration {
        self.max_age
    }

    /// How many head generations behind an answer may be.
    #[must_use]
    pub const fn max_generation_lag(&self) -> u64 {
        self.max_generation_lag
    }

    /// Whether an observed staleness is inside this bound.
    #[must_use]
    pub const fn admits(&self, observed: StalenessObservation) -> bool {
        observed.age.as_nanos() <= self.max_age.as_nanos()
            && observed.generation_lag <= self.max_generation_lag
    }
}

/// How stale an answer actually is, measured rather than promised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StalenessObservation {
    age: Duration,
    generation_lag: u64,
}

impl StalenessObservation {
    /// Record a measurement.
    #[must_use]
    pub const fn new(age: Duration, generation_lag: u64) -> Self {
        Self {
            age,
            generation_lag,
        }
    }

    /// How old the served answer is.
    #[must_use]
    pub const fn age(&self) -> Duration {
        self.age
    }

    /// How many generations behind the current head it is.
    #[must_use]
    pub const fn generation_lag(&self) -> u64 {
        self.generation_lag
    }
}

/// The label that travels with a served answer.
///
/// # Why the observation is carried and not just the bound
///
/// Acceptance for this work says a bounded-stale answer must label staleness
/// *with the exact bound*. A label carrying only the bound tells a client the
/// worst case it agreed to, not what it got, and those differ by however much
/// slack the cell had. Carrying both is what makes staleness verifiable by the
/// client rather than asserted by the server, which is the same standard the
/// rest of this system holds proofs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadLabel {
    mode: ReadMode,
    observed: Option<StalenessObservation>,
}

impl ReadLabel {
    /// Label an answer verified against the current head.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            mode: ReadMode::Current,
            observed: None,
        }
    }

    /// Label an exact-revision answer.
    #[must_use]
    pub const fn snapshot() -> Self {
        Self {
            mode: ReadMode::Snapshot,
            observed: None,
        }
    }

    /// Label a locally verified capsule with no currentness claim.
    #[must_use]
    pub const fn offline() -> Self {
        Self {
            mode: ReadMode::Offline,
            observed: None,
        }
    }

    /// Label a bounded-stale answer, refusing one that exceeds its bound.
    ///
    /// This is the only constructor that can fail, and it fails closed. A cell
    /// that has drifted past its bound has not produced a worse answer — it has
    /// produced an answer it is not allowed to describe this way, and relabelling
    /// it [`ReadMode::Offline`] silently would drop the currentness question a
    /// client asked.
    ///
    /// # Errors
    ///
    /// [`CellRefusal::StalenessExceedsBound`] when the observation is outside
    /// the bound.
    pub const fn bounded_stale(
        bound: StalenessBound,
        observed: StalenessObservation,
    ) -> Result<Self, CellRefusal> {
        if !bound.admits(observed) {
            return Err(CellRefusal::StalenessExceedsBound { bound, observed });
        }
        Ok(Self {
            mode: ReadMode::BoundedStale(bound),
            observed: Some(observed),
        })
    }

    /// Which mode this answer was served under.
    #[must_use]
    pub const fn mode(&self) -> ReadMode {
        self.mode
    }

    /// The measured staleness, for a bounded-stale answer.
    #[must_use]
    pub const fn observed(&self) -> Option<StalenessObservation> {
        self.observed
    }
}

/// Which cell produced an answer, or the explicit fact that nothing named one.
///
/// `frankengit-1egm`. In a deployment where several cells share one authority
/// backend, nothing in an authenticated read said which cell served it. The
/// field that appeared to — `AuthenticatedHead`'s former `authenticated_by` —
/// carried the *store's* identity, which `establish()` hands identically to
/// every cell on that backend, so three cells all reported one.
///
/// # Why this is an enum and not `Option<Hint<CellId>>`
///
/// `None` is an absence with no name. A reader cannot tell "this deployment
/// does not identify its cells" from "someone forgot to set it" from "this
/// call site had nothing to pass", and a caller that needs an answer will
/// invent one rather than propagate a bare `None`. [`Self::Unidentified`] says
/// which of those it is, so an audit that finds one records a fact instead of
/// a gap.
///
/// # Why the identified case is a hint
///
/// A cell's statement about its own name is a *claim*. §5.1 puts claims,
/// routing preferences and gossip on the same footing: they may guide work and
/// may never decide it. So the identity travels as [`Hint<CellId>`], whose only
/// route to an owned value is a check — and nothing in a serving path should
/// need one. **This names who answered. It authorizes nothing.** A cell that
/// could name itself into a privilege would be a cell that could name itself
/// into someone else's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServingCell {
    /// The serving cell named itself. The name is a claim, not a credential.
    Identified(Hint<CellId>),
    /// No cell identity was attached, and that is recorded rather than absent.
    ///
    /// Reached by a deployment that does not name its cells, and by every
    /// advertisement built through the constructor that predates cell identity.
    /// A `Bootstrapping` cell never reaches here because it serves nothing at
    /// all — see [`CellState::admits_current_read`] and friends.
    Unidentified,
}

impl ServingCell {
    /// Name the cell that produced this answer.
    #[must_use]
    pub const fn identified(cell: Hint<CellId>) -> Self {
        Self::Identified(cell)
    }

    /// The claimed identity, if one was attached.
    ///
    /// Returns the hint rather than a `CellId`, so a caller that wants the bare
    /// identity has to go through [`Hint::verified_by`] and say what verified
    /// it. Peeking is free and is what logging, tracing and an operator's
    /// "which cell was that?" actually need.
    #[must_use]
    pub const fn claimed(&self) -> Option<&Hint<CellId>> {
        match self {
            Self::Identified(cell) => Some(cell),
            Self::Unidentified => None,
        }
    }

    /// Whether any cell named itself.
    #[must_use]
    pub const fn is_identified(&self) -> bool {
        matches!(self, Self::Identified(_))
    }
}

/// Refusals from the cell vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellRefusal {
    /// The requested state change is not an admitted edge.
    IllegalTransition {
        /// The state the cell is in.
        from: CellState,
        /// The state that was asked for.
        to: CellState,
    },
    /// The answer is older than the bound it would have been labelled with.
    StalenessExceedsBound {
        /// What was promised.
        bound: StalenessBound,
        /// What was measured.
        observed: StalenessObservation,
    },
    /// The cell's current state does not admit taking work in at all.
    ///
    /// The write-side twin of [`Self::StateAdmitsNoSuchRead`]. Raised BEFORE
    /// intake, so a cell that cannot stage never quarantines bytes it has no
    /// business holding.
    StateAdmitsNoStaging {
        /// The state observed when the receive was attempted.
        state: CellState,
    },
    /// The cell's current state does not admit this kind of read.
    StateAdmitsNoSuchRead {
        /// The state the cell is in.
        state: CellState,
        /// The mode that was asked for.
        mode: ReadMode,
    },
}

impl fmt::Display for CellRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalTransition { from, to } => {
                write!(formatter, "a cell may not move from {from} to {to}")
            }
            Self::StalenessExceedsBound { bound, observed } => write!(
                formatter,
                "the answer is {:?} old and {} generations behind, outside the bound of {:?} and {}",
                observed.age(),
                observed.generation_lag(),
                bound.max_age(),
                bound.max_generation_lag()
            ),
            Self::StateAdmitsNoStaging { state } => {
                write!(formatter, "a cell in {state} cannot take receive work in")
            }
            Self::StateAdmitsNoSuchRead { state, mode } => {
                write!(formatter, "a cell in {state} cannot serve a {mode:?} read")
            }
        }
    }
}

impl core::error::Error for CellRefusal {}

/// Whether this cell may take receive work in at all.
///
/// The write-side twin of [`admits_read`], and deliberately a SEPARATE question
/// from whether the result may be published. §22.6 gives a partitioned cell
/// three responses, and staging-only is the one that says *accept and hold, but
/// publish nothing*: quarantine and validation proceed so the work is not lost,
/// while the §5.4 staged/visible split keeps it from ever becoming canonical.
///
/// A cell that fails this check must refuse before intake rather than after,
/// because quarantining bytes a cell has no business holding is a cost with no
/// corresponding benefit — nothing downstream can ever use them.
///
/// # Errors
///
/// [`CellRefusal::StateAdmitsNoStaging`] naming the observed state.
pub const fn admits_staging_intake(state: CellState) -> Result<(), CellRefusal> {
    if state.admits_staging() {
        Ok(())
    } else {
        Err(CellRefusal::StateAdmitsNoStaging { state })
    }
}

/// Whether a cell in `state` may answer under `mode`.
///
/// # Errors
///
/// [`CellRefusal::StateAdmitsNoSuchRead`] naming both, so a caller can report
/// which half was wrong.
pub const fn admits_read(state: CellState, mode: ReadMode) -> Result<(), CellRefusal> {
    let admitted = match mode {
        ReadMode::Current => state.admits_current_read(),
        ReadMode::BoundedStale(_) => state.admits_bounded_stale_read(),
        // A snapshot names an exact revision and an offline capsule claims
        // nothing about currentness, so neither depends on the cell's view of
        // the authority. They are refused only by states that serve nothing.
        ReadMode::Snapshot | ReadMode::Offline => !matches!(
            state,
            CellState::Bootstrapping
                | CellState::Repairing
                | CellState::Failed
                | CellState::Retired
                | CellState::Evacuating
        ),
    };
    if admitted {
        Ok(())
    } else {
        Err(CellRefusal::StateAdmitsNoSuchRead { state, mode })
    }
}

//! Deterministic forge-state bisection engine over decision intervals.
//!
//! Because canonical state is an immutable decision stream, predicates evaluated
//! over historical positions form a well-defined discrete function `f(seq) -> Outcome`.
//! When a predicate actually satisfies a declared monotonicity contract, the first decision
//! sequence where the predicate transitions can be located in logarithmic `O(log N)`
//! probes. Sampled checks cannot prove monotonicity or detect every violation.
//! Monotone results are CONDITIONAL on that caller contract. For unknown shapes,
//! bounded linear/segmented search visits every preceding position; no gaps are
//! treated as evidence of absence.
//!
//! # Invariants
//!
//! 1. **Deterministic Probing:** Midpoints and tie-break rules are deterministic
//!    and platform-independent (`start + (end - start) / 2`).
//! 2. **Monotonicity Integrity:** Contradictory observed endpoints refuse with
//!    [`BisectionRefusal::NonMonotoneDetected`]. Unobserved interior reversals
//!    cannot be detected by logarithmic sampling; callers must supply the proof
//!    or select exhaustive search.
//! 3. **Audit Receipt Completeness:** Every probe, its inputs, evaluated outcomes,
//!    and final termination status are captured in a byte-deterministic [`BisectionReceipt`].
//! 4. **Current-Policy Disclosure:** All historical snapshot evaluations apply the
//!    active caller's disclosure policy, preventing revoked access leakage.

use core::fmt;
use std::collections::BTreeMap;

use fgit_codec::schema::RepositoryAuthorityHeadBody;
use fgit_crypto::sha256_digest;
use fgit_types::{
    DecisionSequence, Digest, DigestBytes, GitOid, PolicyEpoch, RepositoryAuthorityHeadId,
    RepositoryId,
};

use crate::aggregate::PullRequestNumber;
use crate::snapshot::{
    CandidateCapsule, ForgeSnapshot, HistoricalBatch, PositionTarget, PullRequestState,
    SnapshotDisclosurePolicy, SnapshotLimits, SnapshotRefusal, project_snapshot_from_history,
};

/// The binary outcome of evaluating a pure position-bound predicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum PredicateOutcome {
    /// The predicate condition is satisfied / true.
    Satisfied,
    /// The predicate condition is not satisfied / false.
    Unsatisfied,
}

impl PredicateOutcome {
    /// Returns true if the outcome is `Satisfied`.
    #[must_use]
    pub const fn is_satisfied(&self) -> bool {
        matches!(self, Self::Satisfied)
    }

    /// Returns true if the outcome is `Unsatisfied`.
    #[must_use]
    pub const fn is_unsatisfied(&self) -> bool {
        matches!(self, Self::Unsatisfied)
    }
}

impl fmt::Display for PredicateOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Satisfied => formatter.write_str("satisfied"),
            Self::Unsatisfied => formatter.write_str("unsatisfied"),
        }
    }
}

/// The expected direction of transition for a monotone predicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TransitionDirection {
    /// Predicate transitions from `Unsatisfied` at earlier positions to `Satisfied` at later positions.
    UnsatisfiedToSatisfied,
    /// Predicate transitions from `Satisfied` at earlier positions to `Unsatisfied` at later positions.
    SatisfiedToUnsatisfied,
}

impl fmt::Display for TransitionDirection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsatisfiedToSatisfied => formatter.write_str("unsatisfied -> satisfied"),
            Self::SatisfiedToUnsatisfied => formatter.write_str("satisfied -> unsatisfied"),
        }
    }
}

/// Contract governing the search strategy and monotonicity guarantees.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MonotonicityShape {
    /// Caller-declared at-most-one-transition contract. The engine does not
    /// prove this shape; successful answers are conditional on its truth.
    GuaranteedMonotone {
        /// Optional declared transition direction. If None, inferred from boundary probes.
        expected_direction: Option<TransitionDirection>,
    },
    /// Bounded segmented search for predicates whose shape is non-monotone or unknown.
    BoundedSegmented {
        /// Maximum contiguous segment size. Every position inside a segment
        /// is examined: an unsatisfied endpoint cannot rule out interior flips.
        segment_size: usize,
        /// Maximum total probes permitted.
        max_steps: usize,
    },
    /// Linear search over the range bounded by a maximum step budget.
    LinearOnly {
        /// Maximum total probes permitted.
        max_steps: usize,
    },
}

/// An inclusive interval of decision sequences `[start, end]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BisectionRange {
    start: DecisionSequence,
    end: DecisionSequence,
}

impl BisectionRange {
    /// Creates a new valid bisection range where `start <= end`.
    pub const fn new(
        start: DecisionSequence,
        end: DecisionSequence,
    ) -> Result<Self, BisectionRefusal> {
        if start.get() > end.get() {
            return Err(BisectionRefusal::InvalidRange {
                start: start.get(),
                end: end.get(),
            });
        }
        Ok(Self { start, end })
    }

    /// The starting sequence of the interval (inclusive).
    #[must_use]
    pub const fn start(&self) -> DecisionSequence {
        self.start
    }

    /// The ending sequence of the interval (inclusive).
    #[must_use]
    pub const fn end(&self) -> DecisionSequence {
        self.end
    }

    /// The total count of discrete decision positions in this interval.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.get() - self.start.get() + 1
    }

    /// Returns true if the interval contains exactly one decision position.
    #[must_use]
    pub const fn is_singleton(&self) -> bool {
        self.start.get() == self.end.get()
    }

    /// Returns the deterministic integer midpoint: `start + (end - start) / 2`.
    #[must_use]
    pub fn midpoint(&self) -> DecisionSequence {
        compute_midpoint(self.start, self.end)
    }
}

impl fmt::Display for BisectionRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "[{}..={}]", self.start.get(), self.end.get())
    }
}

/// Computes the deterministic midpoint for two decision sequences.
#[must_use]
pub fn compute_midpoint(start: DecisionSequence, end: DecisionSequence) -> DecisionSequence {
    let s = start.get();
    let e = end.get();
    let mid = s + (e - s) / 2;
    DecisionSequence::try_new(mid).unwrap_or(start)
}

/// Trait implemented by typed, position-bound predicates evaluated during bisection.
pub trait BisectionPredicate {
    /// Error type produced if evaluation fails.
    type Error: fmt::Display + fmt::Debug;

    /// Evaluates the predicate on the given historical snapshot.
    fn evaluate(&self, snapshot: &ForgeSnapshot) -> Result<PredicateOutcome, Self::Error>;

    /// Human-readable label for receipt diagnostics.
    fn description(&self) -> &'static str {
        "unnamed_predicate"
    }
}

impl<F, E> BisectionPredicate for F
where
    F: Fn(&ForgeSnapshot) -> Result<PredicateOutcome, E>,
    E: fmt::Display + fmt::Debug,
{
    type Error = E;

    fn evaluate(&self, snapshot: &ForgeSnapshot) -> Result<PredicateOutcome, Self::Error> {
        (self)(snapshot)
    }
}

/// Predicate checking whether a specific ref matches an expected Git OID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefTargetPredicate {
    /// Full reference name (e.g. `b"refs/heads/main"`).
    pub reference_name: Vec<u8>,
    /// Expected object identity.
    pub expected_oid: GitOid,
}

impl BisectionPredicate for RefTargetPredicate {
    type Error = core::convert::Infallible;

    fn evaluate(&self, snapshot: &ForgeSnapshot) -> Result<PredicateOutcome, Self::Error> {
        match snapshot.refs.get(&self.reference_name) {
            Some(oid) if *oid == self.expected_oid => Ok(PredicateOutcome::Satisfied),
            _ => Ok(PredicateOutcome::Unsatisfied),
        }
    }

    fn description(&self) -> &'static str {
        "ref_target_match"
    }
}

/// Predicate checking whether a pull request has reached a specific state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestStatePredicate {
    /// Pull request number.
    pub pull_request: PullRequestNumber,
    /// Target state required for satisfaction.
    pub expected_state: PullRequestState,
}

impl BisectionPredicate for PullRequestStatePredicate {
    type Error = core::convert::Infallible;

    fn evaluate(&self, snapshot: &ForgeSnapshot) -> Result<PredicateOutcome, Self::Error> {
        match snapshot.pull_requests.get(&self.pull_request) {
            Some(pr) if pr.state == self.expected_state => Ok(PredicateOutcome::Satisfied),
            _ => Ok(PredicateOutcome::Unsatisfied),
        }
    }

    fn description(&self) -> &'static str {
        "pull_request_state_match"
    }
}

/// Predicate checking whether the historical policy epoch is at or above a target epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyEpochPredicate {
    /// Target policy epoch.
    pub target_epoch: PolicyEpoch,
}

impl BisectionPredicate for PolicyEpochPredicate {
    type Error = core::convert::Infallible;

    fn evaluate(&self, snapshot: &ForgeSnapshot) -> Result<PredicateOutcome, Self::Error> {
        if snapshot.historical_policy_epoch.get() >= self.target_epoch.get() {
            Ok(PredicateOutcome::Satisfied)
        } else {
            Ok(PredicateOutcome::Unsatisfied)
        }
    }

    fn description(&self) -> &'static str {
        "policy_epoch_threshold"
    }
}

/// Individual probe record capturing one evaluated point during bisection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeRecord {
    /// 0-indexed sequential probe step.
    pub step_index: usize,
    /// Evaluated decision sequence.
    pub sequence: DecisionSequence,
    /// Outcome of the predicate evaluation or error description.
    pub outcome: Result<PredicateOutcome, String>,
    /// Effective authority head ID of the snapshot at this probe.
    pub head_id: RepositoryAuthorityHeadId,
    /// Historical policy epoch at this probe.
    pub policy_epoch: PolicyEpoch,
    /// Count of batches replayed from checkpoint to project this probe.
    pub replayed_batches: usize,
}

/// Terminal decision outcome of the bisection engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BisectionTermination {
    /// Search successfully converged to the exact first transition decision sequence.
    Converged {
        /// The earliest sequence where the predicate became satisfied.
        transition_sequence: DecisionSequence,
    },
    /// No transition occurred across the entire interval (uniform outcome).
    NoTransition {
        /// The uniform outcome observed across all examined points.
        uniform_outcome: PredicateOutcome,
    },
    /// Search terminated with a typed refusal.
    Refused {
        /// The specific cause of refusal.
        reason: BisectionRefusal,
    },
}

impl fmt::Display for BisectionTermination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Converged {
                transition_sequence,
            } => {
                write!(formatter, "converged at decision {transition_sequence}")
            }
            Self::NoTransition { uniform_outcome } => {
                write!(formatter, "no transition (all {uniform_outcome})")
            }
            Self::Refused { reason } => write!(formatter, "refused: {reason}"),
        }
    }
}

/// Immutable, byte-deterministic audit receipt capturing the full bisection execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BisectionReceipt {
    /// Repository identity.
    pub repository_id: RepositoryId,
    /// Evaluated decision sequence range.
    pub range: BisectionRange,
    /// Monotonicity shape contract under which bisection was executed.
    pub monotonicity_shape: MonotonicityShape,
    /// Total probes evaluated during this execution.
    pub steps_taken: usize,
    /// Configured maximum probe budget.
    pub max_budget: usize,
    /// Chronological list of every probe evaluated.
    pub probes: Vec<ProbeRecord>,
    /// Selected transition, or the first satisfied position for exhaustive search.
    pub transition_found: Option<DecisionSequence>,
    /// Terminal outcome status.
    pub termination: BisectionTermination,
    /// Deterministic hash digest over every receipt field: repository, range,
    /// declared shape, probe count, transition, terminal status, refusal
    /// text, and each individual probe record.
    pub receipt_digest: Digest,
}

impl BisectionReceipt {
    /// Generates the canonical deterministic digest over the full receipt.
    ///
    /// Every observation an auditor would verify is inside the hash: the
    /// declared [`MonotonicityShape`], and each [`ProbeRecord`] with its
    /// sequence, outcome, observed head id, policy epoch, and replay count,
    /// plus the refusal text on a refused termination. Two executions that
    /// differ anywhere in those observations produce different digests;
    /// leaving any of them out would let a tampered or fabricated probe
    /// history verify against an untouched digest.
    #[must_use]
    pub fn compute_digest(
        repository_id: RepositoryId,
        range: &BisectionRange,
        monotonicity_shape: &MonotonicityShape,
        steps_taken: usize,
        transition_found: Option<DecisionSequence>,
        termination: &BisectionTermination,
        probes: &[ProbeRecord],
    ) -> Digest {
        let mut canonical_bytes = Vec::with_capacity(128);
        canonical_bytes.extend_from_slice(repository_id.as_bytes());
        fold_shape(&mut canonical_bytes, monotonicity_shape);
        canonical_bytes.extend_from_slice(&range.start().get().to_be_bytes());
        canonical_bytes.extend_from_slice(&range.end().get().to_be_bytes());
        canonical_bytes.extend_from_slice(&(steps_taken as u64).to_be_bytes());
        match transition_found {
            Some(seq) => {
                canonical_bytes.push(1);
                canonical_bytes.extend_from_slice(&seq.get().to_be_bytes());
            }
            None => canonical_bytes.push(0),
        }
        match termination {
            BisectionTermination::Converged {
                transition_sequence,
            } => {
                canonical_bytes.push(1);
                canonical_bytes.extend_from_slice(&transition_sequence.get().to_be_bytes());
            }
            BisectionTermination::NoTransition { uniform_outcome } => {
                canonical_bytes.push(2);
                canonical_bytes.push(u8::from(uniform_outcome.is_satisfied()));
            }
            BisectionTermination::Refused { reason } => {
                canonical_bytes.push(3);
                let reason_text = reason.to_string();
                canonical_bytes.extend_from_slice(&(reason_text.len() as u64).to_be_bytes());
                canonical_bytes.extend_from_slice(reason_text.as_bytes());
            }
        }
        canonical_bytes.extend_from_slice(&(probes.len() as u64).to_be_bytes());
        for probe in probes {
            fold_probe(&mut canonical_bytes, probe);
        }
        let raw = sha256_digest(&canonical_bytes);
        let digest_bytes =
            DigestBytes::try_new(&raw).expect("32-byte sha256 output is valid digest length");
        Digest::new(fgit_crypto::DigestAlgorithm::Sha256.id(), digest_bytes)
    }
}

/// Folds the declared search contract into the canonical digest bytes.
fn fold_shape(bytes: &mut Vec<u8>, shape: &MonotonicityShape) {
    match shape {
        MonotonicityShape::GuaranteedMonotone { expected_direction } => {
            bytes.push(1);
            match expected_direction {
                None => bytes.push(0),
                Some(TransitionDirection::UnsatisfiedToSatisfied) => bytes.push(1),
                Some(TransitionDirection::SatisfiedToUnsatisfied) => bytes.push(2),
            }
        }
        MonotonicityShape::BoundedSegmented {
            segment_size,
            max_steps,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&(*segment_size as u64).to_be_bytes());
            bytes.extend_from_slice(&(*max_steps as u64).to_be_bytes());
        }
        MonotonicityShape::LinearOnly { max_steps } => {
            bytes.push(3);
            bytes.extend_from_slice(&(*max_steps as u64).to_be_bytes());
        }
    }
}

/// Folds one probe record into the canonical digest bytes, length-prefixing
/// variable-length fields so distinct observations cannot collide by
/// concatenation.
fn fold_probe(bytes: &mut Vec<u8>, probe: &ProbeRecord) {
    bytes.extend_from_slice(&(probe.step_index as u64).to_be_bytes());
    bytes.extend_from_slice(&probe.sequence.get().to_be_bytes());
    match &probe.outcome {
        Ok(outcome) => {
            bytes.push(0);
            bytes.push(u8::from(outcome.is_satisfied()));
        }
        Err(error) => {
            bytes.push(1);
            bytes.extend_from_slice(&(error.len() as u64).to_be_bytes());
            bytes.extend_from_slice(error.as_bytes());
        }
    }
    bytes.extend_from_slice(probe.head_id.as_internal_object_id().digest().as_bytes());
    bytes.extend_from_slice(&probe.policy_epoch.get().to_be_bytes());
    bytes.extend_from_slice(&(probe.replayed_batches as u64).to_be_bytes());
}

/// Ways the bisection engine refuses to proceed or declines an invalid operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BisectionRefusal {
    /// Range is invalid (`start > end`).
    InvalidRange {
        /// Start sequence.
        start: u64,
        /// End sequence.
        end: u64,
    },
    /// A predicate declared as monotone exhibited a non-monotone transition during search.
    NonMonotoneDetected {
        /// Decision sequence where contradiction occurred.
        sequence: u64,
        /// Expected outcome according to monotonicity.
        expected: String,
        /// Observed outcome.
        observed: String,
    },
    /// Target decision sequence does not exist in repository history.
    MissingPosition {
        /// Missing sequence number.
        sequence: u64,
    },
    /// Snapshot at the requested sequence could not be decoded or verified.
    CorruptSnapshot {
        /// Target sequence.
        sequence: u64,
        /// Error description.
        reason: String,
    },
    /// Active disclosure policy revoked access to required content at this sequence.
    RevokedDisclosure {
        /// Target sequence.
        sequence: u64,
    },
    /// Search range is ambiguous or indeterminate.
    AmbiguousRange {
        /// Context message.
        message: String,
    },
    /// The caller stopped before a probe could produce a usable observation.
    Cancelled { sequence: u64 },
    /// Search exceeded declared maximum step budget.
    BudgetExhausted {
        /// Steps evaluated before exhaustion.
        steps_taken: usize,
        /// Declared maximum budget.
        max_budget: usize,
    },
    /// Underlying snapshot projection engine failed.
    SnapshotRefusal(SnapshotRefusal),
    /// Predicate evaluation returned a domain error.
    PredicateEvaluationFailed {
        /// Decision sequence.
        sequence: u64,
        /// Domain error message.
        error: String,
    },
}

impl fmt::Display for BisectionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled { sequence } => {
                write!(formatter, "bisection cancelled at decision {sequence}")
            }
            Self::InvalidRange { start, end } => {
                write!(
                    formatter,
                    "invalid bisection range: start {start} > end {end}"
                )
            }
            Self::NonMonotoneDetected {
                sequence,
                expected,
                observed,
            } => {
                write!(
                    formatter,
                    "non-monotone behavior at sequence {sequence}: expected {expected}, observed {observed}"
                )
            }
            Self::MissingPosition { sequence } => {
                write!(
                    formatter,
                    "decision sequence {sequence} not found in history"
                )
            }
            Self::CorruptSnapshot { sequence, reason } => {
                write!(
                    formatter,
                    "corrupt snapshot at sequence {sequence}: {reason}"
                )
            }
            Self::RevokedDisclosure { sequence } => {
                write!(
                    formatter,
                    "revoked access prevents disclosure at sequence {sequence}"
                )
            }
            Self::AmbiguousRange { message } => {
                write!(formatter, "ambiguous bisection range: {message}")
            }
            Self::BudgetExhausted {
                steps_taken,
                max_budget,
            } => {
                write!(
                    formatter,
                    "bisection budget exhausted: took {steps_taken} steps (max budget {max_budget})"
                )
            }
            Self::SnapshotRefusal(err) => write!(formatter, "snapshot error: {err}"),
            Self::PredicateEvaluationFailed { sequence, error } => {
                write!(
                    formatter,
                    "predicate failed at sequence {sequence}: {error}"
                )
            }
        }
    }
}

impl core::error::Error for BisectionRefusal {}

impl From<SnapshotRefusal> for BisectionRefusal {
    fn from(error: SnapshotRefusal) -> Self {
        Self::SnapshotRefusal(error)
    }
}

/// Evaluator context supplying snapshot projection capabilities for bisection.
pub struct BisectionContext<'a> {
    /// Latest authority head ID.
    pub head_id: RepositoryAuthorityHeadId,
    /// Latest authority head body.
    pub head_body: &'a RepositoryAuthorityHeadBody,
    /// Available candidate checkpoint capsules.
    pub available_capsules: &'a [CandidateCapsule],
    /// Historical decision batches.
    pub historical_batches: &'a [HistoricalBatch],
    /// Live base refs mapping.
    pub base_refs: &'a BTreeMap<Vec<u8>, GitOid>,
    /// Active disclosure policy for caller.
    pub disclosure_policy: Option<&'a SnapshotDisclosurePolicy>,
    /// Resource limits for snapshot projection.
    pub snapshot_limits: SnapshotLimits,
}

impl BisectionContext<'_> {
    /// Projects a snapshot for a specific decision sequence.
    pub fn project_sequence(
        &self,
        sequence: DecisionSequence,
    ) -> Result<ForgeSnapshot, BisectionRefusal> {
        let target = PositionTarget::Decision(sequence);
        if self
            .historical_batches
            .iter()
            .any(|batch| batch.batch.repository_id != self.head_body.repository_id)
        {
            return Err(BisectionRefusal::CorruptSnapshot {
                sequence: sequence.get(),
                reason: "history belongs to another repository".into(),
            });
        }
        if self.historical_batches.iter().any(|batch| {
            batch.batch.first_decision_sequence <= sequence
                && batch
                    .batch
                    .decisions
                    .last()
                    .is_some_and(|last| last.decision_sequence > sequence)
        }) {
            return Err(BisectionRefusal::AmbiguousRange {
                message: format!("decision {sequence} is inside an atomic publication batch"),
            });
        }
        let mut snapshot = project_snapshot_from_history(
            target,
            self.head_id,
            self.head_body,
            self.available_capsules,
            self.historical_batches,
            self.base_refs,
            &self.snapshot_limits,
        )
        .map_err(|error| match error {
            SnapshotRefusal::TargetNotFound { .. }
            | SnapshotRefusal::TargetAheadOfAuthority { .. } => BisectionRefusal::MissingPosition {
                sequence: sequence.get(),
            },
            SnapshotRefusal::ConsistencyMismatch { .. }
            | SnapshotRefusal::Codec(_)
            | SnapshotRefusal::Chronicle(_) => BisectionRefusal::CorruptSnapshot {
                sequence: sequence.get(),
                reason: error.to_string(),
            },
            other => BisectionRefusal::SnapshotRefusal(other),
        })?;
        if snapshot.effective_decision_sequence != Some(sequence) {
            return Err(BisectionRefusal::MissingPosition {
                sequence: sequence.get(),
            });
        }

        if let Some(policy) = self.disclosure_policy {
            snapshot = policy.filter_snapshot(snapshot).map_err(|err| match err {
                SnapshotRefusal::AccessDenied { .. } => BisectionRefusal::RevokedDisclosure {
                    sequence: sequence.get(),
                },
                other => BisectionRefusal::SnapshotRefusal(other),
            })?;
        }

        Ok(snapshot)
    }
}

/// Calculates the theoretical logarithmic probe bound for a range size: `ceil(log2(N)) + 2`.
#[must_use]
pub const fn logarithmic_probe_budget(range_len: u64) -> usize {
    if range_len <= 1 {
        return 2;
    }
    let bits = 64 - (range_len - 1).leading_zeros();
    (bits as usize) + 2
}

/// Executes a dense decision search over caller-verified snapshot history.
/// `GuaranteedMonotone` is an explicit caller assumption, not a proof obtained
/// by sampling. Use bounded exhaustive search for an unknown predicate shape.
pub fn execute_bisection<P>(
    range: BisectionRange,
    shape: MonotonicityShape,
    predicate: &P,
    context: &BisectionContext<'_>,
) -> BisectionReceipt
where
    P: BisectionPredicate,
{
    execute_bisection_with_control(range, shape, predicate, context, &mut || true)
}

/// The same search under one caller-owned cooperative cancellation boundary.
/// Projection has its own finite replay bound; checkpoints surround each probe.
pub fn execute_bisection_with_control<P>(
    range: BisectionRange,
    shape: MonotonicityShape,
    predicate: &P,
    context: &BisectionContext<'_>,
    checkpoint: &mut impl FnMut() -> bool,
) -> BisectionReceipt
where
    P: BisectionPredicate,
{
    search::dense(
        context.head_body.repository_id,
        range,
        shape,
        |sequence| {
            let snapshot = context.project_sequence(sequence)?;
            Ok(ProbeObservation {
                head_id: snapshot.effective_head_id,
                policy_epoch: snapshot.historical_policy_epoch,
                replayed_batches: snapshot.replayed_batches_count,
                outcome: predicate
                    .evaluate(&snapshot)
                    .map_err(|error| error.to_string()),
            })
        },
        checkpoint,
    )
}

mod search;
pub use search::{ProbeObservation, search_published_positions};

/// Linear oracle scanning every position in `[range.start(), range.end()]` for reference verification.
pub fn linear_scan_oracle<P>(
    range: BisectionRange,
    predicate: &P,
    context: &BisectionContext<'_>,
) -> Result<(Option<DecisionSequence>, Vec<PredicateOutcome>), BisectionRefusal>
where
    P: BisectionPredicate,
{
    let mut outcomes = Vec::new();
    let mut first_satisfied = None;

    for seq_num in range.start().get()..=range.end().get() {
        let seq = DecisionSequence::try_new(seq_num).expect("seq_num > 0");
        let snapshot = context.project_sequence(seq)?;
        let outcome = predicate.evaluate(&snapshot).map_err(|e| {
            BisectionRefusal::PredicateEvaluationFailed {
                sequence: seq.get(),
                error: e.to_string(),
            }
        })?;
        if outcome.is_satisfied() && first_satisfied.is_none() {
            first_satisfied = Some(seq);
        }
        outcomes.push(outcome);
    }

    Ok((first_satisfied, outcomes))
}

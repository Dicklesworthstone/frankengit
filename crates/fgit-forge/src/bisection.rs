//! Deterministic forge-state bisection engine over decision intervals.
//!
//! Because canonical state is an immutable decision stream, predicates evaluated
//! over historical positions form a well-defined discrete function `f(seq) -> Outcome`.
//! When a predicate satisfies a declared monotonicity contract, the first decision
//! sequence where the predicate transitions can be located in logarithmic `O(log N)`
//! probes. If monotonicity is violated or undeclared, the engine refuses or executes
//! bounded segmented search, never returning a hallucinated binary-search answer.
//!
//! # Invariants
//!
//! 1. **Deterministic Probing:** Midpoints and tie-break rules are deterministic
//!    and platform-independent (`start + (end - start) / 2`).
//! 2. **Monotonicity Integrity:** If a predicate declared as monotone exhibits
//!    a non-monotone transition during probing, the search halts immediately
//!    with a typed [`BisectionRefusal::NonMonotoneDetected`] refusal.
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
    /// The predicate is guaranteed to transition at most once monotonically.
    GuaranteedMonotone {
        /// Optional declared transition direction. If None, inferred from boundary probes.
        expected_direction: Option<TransitionDirection>,
    },
    /// Bounded segmented search for predicates whose shape is non-monotone or unknown.
    BoundedSegmented {
        /// Step size between segment probes.
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
    pub fn new(start: DecisionSequence, end: DecisionSequence) -> Result<Self, BisectionRefusal> {
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
    fn description(&self) -> &str {
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

    fn description(&self) -> &str {
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

    fn description(&self) -> &str {
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

    fn description(&self) -> &str {
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
    /// The first decision sequence where transition occurred, if found.
    pub transition_found: Option<DecisionSequence>,
    /// Terminal outcome status.
    pub termination: BisectionTermination,
    /// Deterministic hash digest computed over receipt contents.
    pub receipt_digest: Digest,
}

impl BisectionReceipt {
    /// Generates the canonical deterministic digest over the receipt structure.
    #[must_use]
    pub fn compute_digest(
        repository_id: RepositoryId,
        range: &BisectionRange,
        steps_taken: usize,
        transition_found: Option<DecisionSequence>,
        termination: &BisectionTermination,
    ) -> Digest {
        let mut canonical_bytes = Vec::with_capacity(128);
        canonical_bytes.extend_from_slice(repository_id.as_bytes());
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
                canonical_bytes.push(if uniform_outcome.is_satisfied() { 1 } else { 0 });
            }
            BisectionTermination::Refused { .. } => {
                canonical_bytes.push(3);
            }
        }
        let raw = sha256_digest(&canonical_bytes);
        let digest_bytes =
            DigestBytes::try_new(&raw).expect("32-byte sha256 output is valid digest length");
        Digest::new(fgit_crypto::DigestAlgorithm::Sha256.id(), digest_bytes)
    }
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

impl<'a> BisectionContext<'a> {
    /// Projects a snapshot for a specific decision sequence.
    pub fn project_sequence(
        &self,
        sequence: DecisionSequence,
    ) -> Result<ForgeSnapshot, BisectionRefusal> {
        let target = PositionTarget::Decision(sequence);
        let mut snapshot = project_snapshot_from_history(
            target,
            self.head_id,
            self.head_body,
            self.available_capsules,
            self.historical_batches,
            self.base_refs,
            &self.snapshot_limits,
        )?;

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
pub fn logarithmic_probe_budget(range_len: u64) -> usize {
    if range_len <= 1 {
        return 2;
    }
    let bits = 64 - (range_len - 1).leading_zeros();
    (bits as usize) + 2
}

/// Executes bisection over the specified range and predicate using the given context and strategy.
pub fn execute_bisection<P>(
    range: BisectionRange,
    shape: MonotonicityShape,
    predicate: &P,
    context: &BisectionContext<'_>,
) -> BisectionReceipt
where
    P: BisectionPredicate,
{
    let repo_id = context.head_body.repository_id;
    let max_budget = match shape {
        MonotonicityShape::GuaranteedMonotone { .. } => logarithmic_probe_budget(range.len()),
        MonotonicityShape::BoundedSegmented { max_steps, .. } => max_steps,
        MonotonicityShape::LinearOnly { max_steps } => max_steps,
    };

    let mut probes = Vec::new();
    let mut step_index = 0;

    // Helper closure to evaluate a probe at sequence `seq`
    let mut eval_probe = |seq: DecisionSequence,
                          probes: &mut Vec<ProbeRecord>|
     -> Result<PredicateOutcome, BisectionRefusal> {
        if step_index >= max_budget {
            return Err(BisectionRefusal::BudgetExhausted {
                steps_taken: step_index,
                max_budget,
            });
        }
        let snapshot = context.project_sequence(seq)?;
        let outcome_res = predicate.evaluate(&snapshot).map_err(|e| {
            BisectionRefusal::PredicateEvaluationFailed {
                sequence: seq.get(),
                error: e.to_string(),
            }
        });

        match outcome_res {
            Ok(out) => {
                probes.push(ProbeRecord {
                    step_index,
                    sequence: seq,
                    outcome: Ok(out),
                    head_id: snapshot.effective_head_id,
                    policy_epoch: snapshot.historical_policy_epoch,
                    replayed_batches: snapshot.replayed_batches_count,
                });
                step_index += 1;
                Ok(out)
            }
            Err(err) => {
                probes.push(ProbeRecord {
                    step_index,
                    sequence: seq,
                    outcome: Err(err.to_string()),
                    head_id: snapshot.effective_head_id,
                    policy_epoch: snapshot.historical_policy_epoch,
                    replayed_batches: snapshot.replayed_batches_count,
                });
                step_index += 1;
                Err(err)
            }
        }
    };

    let outcome_result = match shape {
        MonotonicityShape::GuaranteedMonotone { expected_direction } => {
            bisect_monotone(range, expected_direction, &mut eval_probe, &mut probes)
        }
        MonotonicityShape::BoundedSegmented { segment_size, .. } => {
            bisect_segmented(range, segment_size, &mut eval_probe, &mut probes)
        }
        MonotonicityShape::LinearOnly { .. } => bisect_linear(range, &mut eval_probe, &mut probes),
    };

    let (transition_found, termination) = match outcome_result {
        Ok(Some(transition)) => (
            Some(transition),
            BisectionTermination::Converged {
                transition_sequence: transition,
            },
        ),
        Ok(None) => {
            let uniform = probes
                .first()
                .and_then(|p| p.outcome.as_ref().ok().copied())
                .unwrap_or(PredicateOutcome::Unsatisfied);
            (
                None,
                BisectionTermination::NoTransition {
                    uniform_outcome: uniform,
                },
            )
        }
        Err(refusal) => (None, BisectionTermination::Refused { reason: refusal }),
    };

    let receipt_digest = BisectionReceipt::compute_digest(
        repo_id,
        &range,
        step_index,
        transition_found,
        &termination,
    );

    BisectionReceipt {
        repository_id: repo_id,
        range,
        monotonicity_shape: shape,
        steps_taken: step_index,
        max_budget,
        probes,
        transition_found,
        termination,
        receipt_digest,
    }
}

fn bisect_monotone<F>(
    range: BisectionRange,
    expected_direction: Option<TransitionDirection>,
    eval_probe: &mut F,
    probes: &mut Vec<ProbeRecord>,
) -> Result<Option<DecisionSequence>, BisectionRefusal>
where
    F: FnMut(DecisionSequence, &mut Vec<ProbeRecord>) -> Result<PredicateOutcome, BisectionRefusal>,
{
    let start = range.start();
    let end = range.end();

    let start_val = eval_probe(start, probes)?;

    if range.is_singleton() {
        return if start_val.is_satisfied() {
            Ok(Some(start))
        } else {
            Ok(None)
        };
    }

    let end_val = eval_probe(end, probes)?;

    // Infer or check direction
    let direction = match expected_direction {
        Some(dir) => {
            // Verify boundaries match expected direction
            match dir {
                TransitionDirection::UnsatisfiedToSatisfied => {
                    if start_val.is_satisfied() && end_val.is_unsatisfied() {
                        return Err(BisectionRefusal::NonMonotoneDetected {
                            sequence: start.get(),
                            expected: "unsatisfied".to_string(),
                            observed: "satisfied".to_string(),
                        });
                    }
                }
                TransitionDirection::SatisfiedToUnsatisfied => {
                    if start_val.is_unsatisfied() && end_val.is_satisfied() {
                        return Err(BisectionRefusal::NonMonotoneDetected {
                            sequence: start.get(),
                            expected: "satisfied".to_string(),
                            observed: "unsatisfied".to_string(),
                        });
                    }
                }
            }
            dir
        }
        None => {
            if start_val == end_val {
                return if start_val.is_satisfied() {
                    Ok(Some(start))
                } else {
                    Ok(None)
                };
            }
            if start_val.is_unsatisfied() && end_val.is_satisfied() {
                TransitionDirection::UnsatisfiedToSatisfied
            } else {
                TransitionDirection::SatisfiedToUnsatisfied
            }
        }
    };

    if start_val == end_val {
        return if start_val.is_satisfied() {
            Ok(Some(start))
        } else {
            Ok(None)
        };
    }

    // Binary search over [low, high]
    let mut low = start.get();
    let mut high = end.get();

    match direction {
        TransitionDirection::UnsatisfiedToSatisfied => {
            // start is Unsatisfied, end is Satisfied. Find earliest Satisfied.
            while low + 1 < high {
                let mid_val = low + (high - low) / 2;
                let mid_seq = DecisionSequence::try_new(mid_val).expect("mid_val > 0");
                let outcome = eval_probe(mid_seq, probes)?;
                match outcome {
                    PredicateOutcome::Satisfied => {
                        high = mid_val;
                    }
                    PredicateOutcome::Unsatisfied => {
                        low = mid_val;
                    }
                }
            }
            let first_satisfied_seq = DecisionSequence::try_new(high).expect("high > 0");
            Ok(Some(first_satisfied_seq))
        }
        TransitionDirection::SatisfiedToUnsatisfied => {
            // start is Satisfied, end is Unsatisfied. Find earliest Unsatisfied.
            while low + 1 < high {
                let mid_val = low + (high - low) / 2;
                let mid_seq = DecisionSequence::try_new(mid_val).expect("mid_val > 0");
                let outcome = eval_probe(mid_seq, probes)?;
                match outcome {
                    PredicateOutcome::Unsatisfied => {
                        high = mid_val;
                    }
                    PredicateOutcome::Satisfied => {
                        low = mid_val;
                    }
                }
            }
            let first_unsatisfied_seq = DecisionSequence::try_new(high).expect("high > 0");
            Ok(Some(first_unsatisfied_seq))
        }
    }
}

fn bisect_segmented<F>(
    range: BisectionRange,
    segment_size: usize,
    eval_probe: &mut F,
    probes: &mut Vec<ProbeRecord>,
) -> Result<Option<DecisionSequence>, BisectionRefusal>
where
    F: FnMut(DecisionSequence, &mut Vec<ProbeRecord>) -> Result<PredicateOutcome, BisectionRefusal>,
{
    let step = if segment_size == 0 {
        1
    } else {
        segment_size as u64
    };
    let mut curr = range.start().get();
    let end = range.end().get();

    while curr <= end {
        let seq = DecisionSequence::try_new(curr).expect("curr > 0");
        let outcome = eval_probe(seq, probes)?;
        if outcome.is_satisfied() {
            // Found a satisfied probe. If step > 1 and curr > range.start(), linear scan the prior segment
            if step > 1 && curr > range.start().get() {
                let seg_start = (curr - step + 1).max(range.start().get());
                for seg_curr in seg_start..curr {
                    let seg_seq = DecisionSequence::try_new(seg_curr).expect("seg_curr > 0");
                    let seg_outcome = eval_probe(seg_seq, probes)?;
                    if seg_outcome.is_satisfied() {
                        return Ok(Some(seg_seq));
                    }
                }
            }
            return Ok(Some(seq));
        }
        if curr == end {
            break;
        }
        curr = (curr + step).min(end);
    }
    Ok(None)
}

fn bisect_linear<F>(
    range: BisectionRange,
    eval_probe: &mut F,
    probes: &mut Vec<ProbeRecord>,
) -> Result<Option<DecisionSequence>, BisectionRefusal>
where
    F: FnMut(DecisionSequence, &mut Vec<ProbeRecord>) -> Result<PredicateOutcome, BisectionRefusal>,
{
    for seq_num in range.start().get()..=range.end().get() {
        let seq = DecisionSequence::try_new(seq_num).expect("seq_num > 0");
        let outcome = eval_probe(seq, probes)?;
        if outcome.is_satisfied() {
            return Ok(Some(seq));
        }
    }
    Ok(None)
}

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

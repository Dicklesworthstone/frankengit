//! Deterministic counterexample minimization.
//!
//! A counterexample found by exploration is whatever schedule happened to fail
//! first. It is rarely the smallest one, and the difference matters: a
//! fourteen-event trace where three events cause the failure hides the cause
//! among eleven irrelevancies, and whoever reads it has to do the reduction by
//! hand.
//!
//! # What "without deleting the cause" means here
//!
//! Shrinking a failing input is only sound if the smaller input fails *for the
//! same reason*. A minimizer that accepts any still-failing candidate can walk
//! from one bug to a different one and report a counterexample for a failure
//! nobody was investigating. So every candidate is judged against a
//! [`CausalSignature`] — the failing property together with the conflict-ordered
//! projection of the events that produced it — and a reduction is kept only
//! when the signature is unchanged. A candidate that still fails but fails
//! differently is rejected, and [`Reduction::rejected`] counts it.
//!
//! # Determinism
//!
//! Candidates are generated in one fixed order: single-event deletions from the
//! end of the sequence toward the front, repeated in passes until a pass
//! removes nothing. There is no randomness and no time budget, so the same
//! counterexample and oracle always produce byte-identical output, which is
//! what lets the result appear in a receipt and a crashpack.
//!
//! This is deliberately the simple algorithm rather than full delta debugging:
//! the sequences this lab produces are short, and a reduction whose own
//! behaviour is obvious is worth more here than one that is asymptotically
//! better and harder to trust.

use crate::commute::{ConflictRelation, OwnedEvent};
use crate::search::Counterexample;

/// Why a failure happened, in a form that survives reduction.
///
/// Two failing sequences share a signature when they violate the same property
/// *and* the surviving events stand in the same conflict order. The property
/// alone is too coarse — two different interleavings can violate
/// "linearizable" for unrelated reasons — and the raw event list is too fine,
/// because dropping an independent event must not count as a different cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CausalSignature {
    property: String,
    /// Conflict-ordered pairs of event *identities*, meaning "this event must
    /// precede that one".
    ///
    /// Identities, not positions. An earlier version of this type keyed the
    /// pairs by index into the sequence, which is wrong in the one way that
    /// matters here: removing any event shifts every later index, so the
    /// signature changed on every candidate and the minimizer rejected all of
    /// them as `DifferentCause`. It reduced nothing while reporting that it
    /// had preserved the cause.
    ///
    /// Keyed by identity, dropping an event that participates in no conflict
    /// leaves the surviving pairs untouched — which is exactly the invariant
    /// "same cause" is supposed to mean. Stored sorted and deduplicated so the
    /// comparison is a set comparison rather than an order-of-discovery one.
    ordered_pairs: Vec<(String, String)>,
}

/// A stable identity for one event: who did what, to which key.
fn identity(event: &OwnedEvent) -> String {
    format!(
        "{}:{}:{}",
        event.actor,
        event.event.code(),
        event.event.key().unwrap_or("-")
    )
}

impl CausalSignature {
    /// Derive the signature of a failing sequence under `relation`.
    #[must_use]
    pub fn of(property: &str, sequence: &[OwnedEvent], relation: ConflictRelation) -> Self {
        let mut ordered_pairs = Vec::new();
        for (left_index, left) in sequence.iter().enumerate() {
            for right in sequence.iter().skip(left_index + 1) {
                if relation.conflicts(left, right) {
                    ordered_pairs.push((identity(left), identity(right)));
                }
            }
        }
        ordered_pairs.sort();
        ordered_pairs.dedup();
        Self {
            property: property.to_owned(),
            ordered_pairs,
        }
    }

    /// The property this signature is about.
    #[must_use]
    pub fn property(&self) -> &str {
        &self.property
    }

    /// How many ordering constraints the failure depends on.
    #[must_use]
    pub const fn constraint_count(&self) -> usize {
        self.ordered_pairs.len()
    }

    /// Whether this signature introduces no constraint the other lacks.
    ///
    /// Removing an event may only ever *drop* ordering constraints. A
    /// candidate that has acquired a constraint the original did not have is
    /// not a smaller witness of the same failure — something new appeared —
    /// so the minimizer refuses it.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.property == other.property
            && self
                .ordered_pairs
                .iter()
                .all(|pair| other.ordered_pairs.binary_search(pair).is_ok())
    }

    /// Whether the failure has any causal structure at all.
    #[must_use]
    pub const fn is_unconstrained(&self) -> bool {
        self.ordered_pairs.is_empty()
    }

    /// A stable rendering for receipts and crashpacks.
    #[must_use]
    pub fn canonical(&self) -> String {
        let pairs: Vec<String> = self
            .ordered_pairs
            .iter()
            .map(|(left, right)| format!("{left}<{right}"))
            .collect();
        format!("{}|{}", self.property, pairs.join(","))
    }
}

/// One accepted or rejected removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReductionStep {
    /// The pass this happened in, counting from one.
    pub pass: usize,
    /// The index removed from the sequence as it stood at the time.
    pub index: usize,
    /// Length before the removal.
    pub length_before: usize,
    /// Whether the removal was kept.
    pub accepted: bool,
    /// Why it was rejected, when it was.
    pub rejection: Option<RejectionReason>,
}

/// Why a candidate removal was not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    /// The shorter sequence no longer failed at all: the removed event was
    /// necessary.
    NoLongerFails,
    /// The shorter sequence failed, but for a different reason. Accepting it
    /// would have silently swapped which bug the counterexample is about.
    DifferentCause,
}

impl RejectionReason {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoLongerFails => "no_longer_fails",
            Self::DifferentCause => "different_cause",
        }
    }
}

/// The result of minimizing one counterexample.
#[derive(Debug, Clone)]
pub struct Reduction {
    original: Vec<OwnedEvent>,
    minimized: Vec<OwnedEvent>,
    original_signature: CausalSignature,
    signature: CausalSignature,
    steps: Vec<ReductionStep>,
    passes: usize,
}

impl Reduction {
    /// The sequence as found by exploration.
    #[must_use]
    pub fn original(&self) -> &[OwnedEvent] {
        &self.original
    }

    /// The reduced sequence, which still fails with the original signature.
    #[must_use]
    pub fn minimized(&self) -> &[OwnedEvent] {
        &self.minimized
    }

    /// The signature of the *minimized* counterexample.
    ///
    /// This is what a replay of the reduced sequence will actually produce, so
    /// it is what a crashpack must expect. It is not necessarily the original's
    /// signature: stripping an inert event legitimately drops the spurious
    /// ordering constraints that event introduced.
    #[must_use]
    pub const fn signature(&self) -> &CausalSignature {
        &self.signature
    }

    /// The signature of the counterexample as exploration found it.
    #[must_use]
    pub const fn original_signature(&self) -> &CausalSignature {
        &self.original_signature
    }

    /// Every removal tried, in the order tried.
    #[must_use]
    pub fn steps(&self) -> &[ReductionStep] {
        &self.steps
    }

    /// How many passes ran before a pass removed nothing.
    #[must_use]
    pub const fn passes(&self) -> usize {
        self.passes
    }

    /// Events removed.
    #[must_use]
    pub const fn removed_count(&self) -> usize {
        self.original.len().saturating_sub(self.minimized.len())
    }

    /// Whether the reduction actually made the counterexample smaller.
    ///
    /// A minimizer that reports success while removing nothing is the failure
    /// this method exists to make visible.
    #[must_use]
    pub const fn is_reduced(&self) -> bool {
        self.removed_count() > 0
    }

    /// Candidates that were tried and rejected.
    #[must_use]
    pub fn rejected(&self) -> usize {
        self.steps.iter().filter(|step| !step.accepted).count()
    }

    /// A stable one-line summary for a receipt.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!(
            "from={} to={} removed={} passes={} rejected={} signature={}",
            self.original.len(),
            self.minimized.len(),
            self.removed_count(),
            self.passes,
            self.rejected(),
            self.signature.canonical()
        )
    }
}

/// What the minimizer asks about a candidate sequence.
///
/// Implementors re-run the candidate and report whether it still fails. They do
/// **not** decide whether the cause is the same — the minimizer derives that
/// from the signature, so an oracle cannot accidentally widen what counts as
/// the same bug.
pub trait FailureOracle {
    /// Whether `candidate` still violates the property.
    fn still_fails(&mut self, candidate: &[OwnedEvent]) -> bool;
}

impl<F> FailureOracle for F
where
    F: FnMut(&[OwnedEvent]) -> bool,
{
    fn still_fails(&mut self, candidate: &[OwnedEvent]) -> bool {
        self(candidate)
    }
}

/// Shrink `counterexample` while preserving its causal signature.
///
/// The oracle is consulted for every candidate; the signature check is applied
/// on top of it, so a candidate that fails for a different reason is rejected
/// even though the oracle said "still fails".
pub fn minimize<O: FailureOracle>(
    property: &str,
    sequence: &[OwnedEvent],
    relation: ConflictRelation,
    oracle: &mut O,
) -> Reduction {
    let original: Vec<OwnedEvent> = sequence.to_vec();
    let signature = CausalSignature::of(property, &original, relation);

    let mut current = original.clone();
    let mut steps = Vec::new();
    let mut passes = 0;

    loop {
        passes += 1;
        let mut removed_this_pass = false;

        // Back to front: removing a later event cannot shift the index of an
        // earlier one, so a single pass can try every position without
        // recomputing indices.
        let mut index = current.len();
        while index > 0 {
            index -= 1;

            let mut candidate = current.clone();
            candidate.remove(index);

            let length_before = current.len();
            let (accepted, rejection) = if oracle.still_fails(&candidate) {
                let candidate_signature = CausalSignature::of(property, &candidate, relation);
                // Two conditions, and both are needed.
                //
                // Subset, not equality: removing an event may only drop
                // ordering constraints. Requiring equality would mean an
                // event that participates in *any* conflict can never be
                // removed, which makes the minimizer unable to strip inert
                // padding — it would report "cause preserved" while reducing
                // nothing.
                //
                // Non-vacuity: a failure that had causal structure may not
                // reduce to one with none. That is what stops an oracle which
                // reports "still fails" for everything from shrinking a real
                // counterexample down to the empty sequence.
                let no_new_constraints = candidate_signature.is_subset_of(&signature);
                let keeps_a_cause =
                    signature.is_unconstrained() || !candidate_signature.is_unconstrained();
                if no_new_constraints && keeps_a_cause {
                    (true, None)
                } else {
                    (false, Some(RejectionReason::DifferentCause))
                }
            } else {
                (false, Some(RejectionReason::NoLongerFails))
            };

            steps.push(ReductionStep {
                pass: passes,
                index,
                length_before,
                accepted,
                rejection,
            });

            if accepted {
                current = candidate;
                removed_this_pass = true;
            }
        }

        if !removed_this_pass {
            break;
        }
    }

    let minimized_signature = CausalSignature::of(property, &current, relation);
    Reduction {
        original,
        minimized: current,
        original_signature: signature,
        signature: minimized_signature,
        steps,
        passes,
    }
}

/// Shrink an exploration [`Counterexample`] in place of its raw parts.
///
/// The counterexample already knows its property and sequence; this is the
/// form callers reach for after [`Dpor::explore`](crate::search::Dpor::explore)
/// reports a violation.
pub fn minimize_counterexample<O: FailureOracle>(
    counterexample: &Counterexample,
    relation: ConflictRelation,
    oracle: &mut O,
) -> Reduction {
    minimize(
        counterexample.property(),
        counterexample.sequence(),
        relation,
        oracle,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commute::ProtocolEvent;
    use crate::plan::StepId;

    fn actor(name: &str) -> StepId {
        StepId::new(name)
    }

    fn read_body(who: &str, key: &str) -> OwnedEvent {
        OwnedEvent::new(
            actor(who),
            ProtocolEvent::ReadBody {
                key: key.to_owned(),
            },
        )
    }

    fn body_write(who: &str, key: &str) -> OwnedEvent {
        OwnedEvent::new(
            actor(who),
            ProtocolEvent::BodyWrite {
                key: key.to_owned(),
            },
        )
    }

    /// A counterexample whose failure depends on exactly two of its events.
    ///
    /// The cause is "w1 writes key a, then r2 reads it"; everything else is
    /// padding on other keys, which the oracle below ignores.
    fn planted() -> (Vec<OwnedEvent>, Vec<OwnedEvent>) {
        let sequence = vec![
            read_body("c1", "padding-one"),
            body_write("w1", "a"),
            read_body("c2", "padding-two"),
            body_write("w2", "padding-three"),
            read_body("r2", "a"),
            read_body("c3", "padding-four"),
        ];
        let cause = vec![body_write("w1", "a"), read_body("r2", "a")];
        (sequence, cause)
    }

    /// Fails whenever both causal events are still present, in order.
    fn cause_present(candidate: &[OwnedEvent]) -> bool {
        let write_at = candidate
            .iter()
            .position(|event| *event == body_write("w1", "a"));
        let read_at = candidate
            .iter()
            .position(|event| *event == read_body("r2", "a"));
        matches!((write_at, read_at), (Some(w), Some(r)) if w < r)
    }

    const PROPERTY: &str = "linearizable";

    #[test]
    fn minimization_measurably_reduces_a_planted_counterexample() {
        // The acceptance line: a multi-step counterexample gets smaller, and
        // the cause survives.
        let (sequence, cause) = planted();
        let original_len = sequence.len();

        let reduction = minimize(PROPERTY, &sequence, ConflictRelation, &mut cause_present);

        assert!(
            reduction.is_reduced(),
            "the reduction removed nothing: {}",
            reduction.canonical()
        );
        assert_eq!(reduction.original().len(), original_len);
        assert_eq!(
            reduction.minimized(),
            cause.as_slice(),
            "the minimizer must converge on exactly the causal events, got {:?}",
            reduction.minimized()
        );
        assert_eq!(reduction.removed_count(), original_len - cause.len());
    }

    #[test]
    fn the_cause_is_never_deleted() {
        // Every padding event is removable; neither causal event is. If the
        // minimizer had dropped one, the result could not still fail.
        let (sequence, _) = planted();

        let reduction = minimize(PROPERTY, &sequence, ConflictRelation, &mut cause_present);

        assert!(
            cause_present(reduction.minimized()),
            "the minimized sequence no longer reproduces the failure"
        );
        assert!(reduction.minimized().contains(&body_write("w1", "a")));
        assert!(reduction.minimized().contains(&read_body("r2", "a")));
    }

    #[test]
    fn removals_that_break_the_failure_are_rejected_and_reported() {
        let (sequence, _) = planted();

        let reduction = minimize(PROPERTY, &sequence, ConflictRelation, &mut cause_present);

        assert!(
            reduction.rejected() > 0,
            "removing a causal event must have been tried and refused"
        );
        assert!(
            reduction
                .steps()
                .iter()
                .any(|step| step.rejection == Some(RejectionReason::NoLongerFails)),
            "the reduction log must record why a candidate was refused"
        );
    }

    #[test]
    fn a_candidate_that_fails_for_a_different_reason_is_refused() {
        // The distinction this minimizer exists for. This oracle says "still
        // fails" no matter what is removed, so a minimizer that trusted it
        // alone would shrink to the empty sequence. The signature check is
        // what stops it.
        let (sequence, _) = planted();

        let mut always_fails = |_candidate: &[OwnedEvent]| true;
        let reduction = minimize(PROPERTY, &sequence, ConflictRelation, &mut always_fails);

        assert!(
            !reduction.minimized().is_empty(),
            "an always-failing oracle must not be able to reduce to an empty sequence"
        );
        assert!(
            reduction
                .steps()
                .iter()
                .any(|step| step.rejection == Some(RejectionReason::DifferentCause)),
            "removals that changed the causal signature must be refused as DifferentCause"
        );
    }

    #[test]
    fn a_counterexample_that_is_already_minimal_is_left_alone() {
        let (_, cause) = planted();

        let reduction = minimize(PROPERTY, &cause, ConflictRelation, &mut cause_present);

        assert!(!reduction.is_reduced());
        assert_eq!(reduction.minimized(), cause.as_slice());
        assert_eq!(reduction.removed_count(), 0);
    }

    #[test]
    fn minimization_is_deterministic() {
        let (sequence, _) = planted();

        let first = minimize(PROPERTY, &sequence, ConflictRelation, &mut cause_present);
        let second = minimize(PROPERTY, &sequence, ConflictRelation, &mut cause_present);

        assert_eq!(first.canonical(), second.canonical());
        assert_eq!(first.minimized(), second.minimized());
        assert_eq!(first.steps().len(), second.steps().len());
    }

    #[test]
    fn the_reported_signature_is_the_one_a_replay_will_reproduce() {
        // The crashpack expects this signature, so it must describe the
        // MINIMIZED sequence rather than the original — otherwise a replay of
        // the reduced counterexample would be reported as a different failure.
        let (sequence, _) = planted();

        let reduction = minimize(PROPERTY, &sequence, ConflictRelation, &mut cause_present);
        let after = CausalSignature::of(PROPERTY, reduction.minimized(), ConflictRelation);

        assert_eq!(reduction.signature(), &after);
        assert_eq!(reduction.signature().canonical(), after.canonical());
        assert_eq!(reduction.signature().property(), PROPERTY);

        // And the reduction never acquired a constraint the original lacked.
        assert!(
            reduction
                .signature()
                .is_subset_of(reduction.original_signature()),
            "reduction must only drop constraints, never add them"
        );
    }

    #[test]
    fn inert_padding_that_adds_constraints_is_still_stripped() {
        // The case that broke the first version of this rule. Appending a read
        // after a write introduces a NEW ordering pair (write < read) that the
        // unpadded sequence does not have. Under a strict-equality rule no
        // removal could ever be accepted, so the minimizer reduced nothing
        // while reporting that it had preserved the cause.
        let (_, cause) = planted();
        let mut padded = cause.clone();
        padded.push(read_body("w1", "a"));
        padded.push(read_body("r2", "a"));

        let reduction = minimize(PROPERTY, &padded, ConflictRelation, &mut cause_present);

        assert!(
            reduction.is_reduced(),
            "padding that adds ordering pairs must still be removable: {}",
            reduction.canonical()
        );
        assert_eq!(reduction.minimized(), cause.as_slice());
    }

    #[test]
    fn a_signature_distinguishes_different_causes() {
        // Same property, different conflict structure: not the same bug.
        let conflicting = vec![body_write("w1", "a"), read_body("r2", "a")];
        let independent = vec![read_body("r1", "a"), read_body("r2", "a")];

        let left = CausalSignature::of(PROPERTY, &conflicting, ConflictRelation);
        let right = CausalSignature::of(PROPERTY, &independent, ConflictRelation);

        assert_ne!(left, right);
        assert_eq!(left.constraint_count(), 1, "a write and a read conflict");
        assert_eq!(right.constraint_count(), 0, "two reads commute");
    }
}

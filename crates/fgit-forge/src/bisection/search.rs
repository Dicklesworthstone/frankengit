//! One search algorithm for dense sequences and sparse published-batch positions.
//! The caller authenticates history; observations here never grant authority.
use super::{
    BisectionRange, BisectionReceipt, BisectionRefusal, BisectionTermination, DecisionSequence,
    MonotonicityShape, PolicyEpoch, PredicateOutcome, ProbeRecord, RepositoryAuthorityHeadId,
    RepositoryId, TransitionDirection, logarithmic_probe_budget,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeObservation {
    pub outcome: Result<PredicateOutcome, String>,
    pub head_id: RepositoryAuthorityHeadId,
    pub policy_epoch: PolicyEpoch,
    pub replayed_batches: usize,
}

enum Positions<'a> {
    Dense(BisectionRange),
    Published(&'a [DecisionSequence]),
}
impl Positions<'_> {
    const fn len(&self) -> u64 {
        match self {
            Self::Dense(range) => range.len(),
            Self::Published(values) => values.len() as u64,
        }
    }
    fn at(&self, index: u64) -> DecisionSequence {
        match self {
            Self::Dense(range) => DecisionSequence::try_new(range.start().get() + index)
                .expect("validated range index"),
            Self::Published(values) => values[index as usize],
        }
    }
}

/// Search only actual published positions, never an imaginary state inside an
/// atomic decision batch. Endpoints must equal the supplied range and positions
/// must be strictly increasing. The caller owns authentication, disclosure,
/// history-reading bounds and the proof behind a declared monotone shape.
/// Exhaustive modes require no shape assumption and never skip an interior state.
pub fn search_published_positions(
    repository: RepositoryId,
    range: BisectionRange,
    shape: MonotonicityShape,
    positions: &[DecisionSequence],
    inspect: impl FnMut(DecisionSequence) -> Result<ProbeObservation, BisectionRefusal>,
    checkpoint: &mut impl FnMut() -> bool,
) -> BisectionReceipt {
    run(
        repository,
        range,
        shape,
        Positions::Published(positions),
        inspect,
        checkpoint,
    )
}

pub(super) fn dense(
    repository: RepositoryId,
    range: BisectionRange,
    shape: MonotonicityShape,
    inspect: impl FnMut(DecisionSequence) -> Result<ProbeObservation, BisectionRefusal>,
    checkpoint: &mut impl FnMut() -> bool,
) -> BisectionReceipt {
    run(
        repository,
        range,
        shape,
        Positions::Dense(range),
        inspect,
        checkpoint,
    )
}

fn run(
    repository: RepositoryId,
    range: BisectionRange,
    shape: MonotonicityShape,
    positions: Positions<'_>,
    mut inspect: impl FnMut(DecisionSequence) -> Result<ProbeObservation, BisectionRefusal>,
    checkpoint: &mut impl FnMut() -> bool,
) -> BisectionReceipt {
    let max_budget = match shape {
        MonotonicityShape::GuaranteedMonotone { .. } => logarithmic_probe_budget(positions.len()),
        MonotonicityShape::BoundedSegmented { max_steps, .. }
        | MonotonicityShape::LinearOnly { max_steps } => max_steps,
    };
    let mut probes = Vec::new();
    let mut probe = |index: u64| {
        let sequence = positions.at(index);
        if !checkpoint() {
            return Err(BisectionRefusal::Cancelled {
                sequence: sequence.get(),
            });
        }
        if probes.len() >= max_budget {
            return Err(BisectionRefusal::BudgetExhausted {
                steps_taken: probes.len(),
                max_budget,
            });
        }
        let observation = inspect(sequence)?;
        if !checkpoint() {
            return Err(BisectionRefusal::Cancelled {
                sequence: sequence.get(),
            });
        }
        let outcome = observation.outcome.clone().map_err(|error| {
            BisectionRefusal::PredicateEvaluationFailed {
                sequence: sequence.get(),
                error,
            }
        });
        probes.push(ProbeRecord {
            step_index: probes.len(),
            sequence,
            outcome: observation.outcome,
            head_id: observation.head_id,
            policy_epoch: observation.policy_epoch,
            replayed_batches: observation.replayed_batches,
        });
        outcome
    };
    let result = (|| {
        if let Positions::Published(values) = &positions
            && (values.first() != Some(&range.start())
                || values.last() != Some(&range.end())
                || values.windows(2).any(|pair| pair[0] >= pair[1]))
        {
            return Err(BisectionRefusal::AmbiguousRange {
                message:
                    "published positions must be ordered, unique and include both range endpoints"
                        .into(),
            });
        }
        match shape {
            MonotonicityShape::GuaranteedMonotone { expected_direction } => {
                monotone(&positions, expected_direction, &mut probe)
            }
            MonotonicityShape::BoundedSegmented { segment_size, .. } => {
                exhaustive(&positions, (segment_size as u64).max(1), &mut probe)
            }
            MonotonicityShape::LinearOnly { .. } => {
                exhaustive(&positions, positions.len(), &mut probe)
            }
        }
    })();
    let (transition_found, termination) = match result {
        Ok(Some(sequence)) => (
            Some(sequence),
            BisectionTermination::Converged {
                transition_sequence: sequence,
            },
        ),
        Ok(None) => (
            None,
            BisectionTermination::NoTransition {
                uniform_outcome: probes
                    .first()
                    .and_then(|probe| probe.outcome.as_ref().ok().copied())
                    .unwrap_or(PredicateOutcome::Unsatisfied),
            },
        ),
        Err(reason) => (None, BisectionTermination::Refused { reason }),
    };
    let steps_taken = probes.len();
    let receipt_digest = BisectionReceipt::compute_digest(
        repository,
        &range,
        &shape,
        steps_taken,
        transition_found,
        &termination,
        &probes,
    );
    BisectionReceipt {
        repository_id: repository,
        range,
        monotonicity_shape: shape,
        steps_taken,
        max_budget,
        probes,
        transition_found,
        termination,
        receipt_digest,
    }
}

fn exhaustive(
    positions: &Positions<'_>,
    segment_size: u64,
    probe: &mut impl FnMut(u64) -> Result<PredicateOutcome, BisectionRefusal>,
) -> Result<Option<DecisionSequence>, BisectionRefusal> {
    let mut begin = 0;
    while begin < positions.len() {
        let end = begin.saturating_add(segment_size).min(positions.len());
        for index in begin..end {
            if probe(index)?.is_satisfied() {
                return Ok(Some(positions.at(index)));
            }
        }
        begin = end;
    }
    Ok(None)
}

fn monotone(
    positions: &Positions<'_>,
    expected: Option<TransitionDirection>,
    probe: &mut impl FnMut(u64) -> Result<PredicateOutcome, BisectionRefusal>,
) -> Result<Option<DecisionSequence>, BisectionRefusal> {
    let first = probe(0)?;
    if positions.len() == 1 {
        return Ok(first.is_satisfied().then(|| positions.at(0)));
    }
    let last = probe(positions.len() - 1)?;
    let direction = expected.unwrap_or(if first.is_unsatisfied() {
        TransitionDirection::UnsatisfiedToSatisfied
    } else {
        TransitionDirection::SatisfiedToUnsatisfied
    });
    let wanted = match direction {
        TransitionDirection::UnsatisfiedToSatisfied => PredicateOutcome::Satisfied,
        TransitionDirection::SatisfiedToUnsatisfied => PredicateOutcome::Unsatisfied,
    };
    if first != last && first == wanted {
        return Err(BisectionRefusal::NonMonotoneDetected {
            sequence: positions.at(0).get(),
            expected: last.to_string(),
            observed: first.to_string(),
        });
    }
    if first == last {
        return Ok(first.is_satisfied().then(|| positions.at(0)));
    }
    let (mut low, mut high) = (0, positions.len() - 1);
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if probe(middle)? == wanted {
            high = middle;
        } else {
            low = middle;
        }
    }
    Ok(Some(positions.at(high)))
}

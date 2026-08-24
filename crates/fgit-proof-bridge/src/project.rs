//! Projecting a recorded reference-model history onto the Lean model.
//!
//! # Why this is a projection and not a translation
//!
//! `fgit-reference`'s `ModelInput` is richer than `OrderedResidue.lean`'s
//! `Operation`: it has staging, preparation, configuration and cancellation
//! steps that the Lean development deliberately does not model. The Lean model
//! is the *ordered residue* — the part about sealing, deciding and publishing —
//! and everything else is a **stuttering step** the abstract machine does not
//! observe.
//!
//! Stuttering is what makes the refinement direction honest. A translation that
//! invented an abstract step for every concrete one would be asserting that the
//! two vocabularies correspond one-to-one, which is false and would fail on the
//! first `StageObjects`.

use std::collections::BTreeMap;

use fgit_reference::machine::ModelInput;
use fgit_reference::trace::{GoldenTrace, ObservedOutcome};
use fgit_types::TxId;

/// The Lean model's terminal outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbstractOutcome {
    /// `TerminalOutcome.committed`.
    Committed,
    /// `TerminalOutcome.refused`.
    Refused,
}

impl AbstractOutcome {
    /// The Lean constructor name.
    #[must_use]
    pub const fn lean(self) -> &'static str {
        match self {
            Self::Committed => "TerminalOutcome.committed",
            Self::Refused => "TerminalOutcome.refused",
        }
    }
}

/// One `OrderedResidue.Operation`.
///
/// `crash`, `lostResponse` and `retry` exist in the Lean model but are not
/// produced here: the reference model records a cancellation, not a crash, and
/// mapping one onto the other would assert a correspondence nothing checks. A
/// vector set that never exercises them is a stated limit, not a silent one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbstractOp {
    /// `Operation.sealRequest`.
    SealRequest {
        /// The abstract transaction index.
        target: u64,
    },
    /// `Operation.decide`.
    Decide {
        /// The abstract transaction index.
        target: u64,
        /// What it was decided as.
        outcome: AbstractOutcome,
    },
    /// `Operation.publish`.
    Publish {
        /// Generation the batch claims to succeed.
        predecessor: u64,
        /// Generation the batch takes.
        generation: u64,
    },
    /// `Operation.interruptedPublication`.
    InterruptedPublication {
        /// Generation the batch claimed to succeed.
        predecessor: u64,
        /// Generation the batch would have taken.
        generation: u64,
    },
}

/// One projected step, with the observable the model recorded after it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedStep {
    /// Position in the concrete trace, so a divergence names a real step.
    pub concrete_index: usize,
    /// The abstract operations, empty when this step stutters.
    ///
    /// A list rather than an option because one concrete step can be several
    /// abstract ones: a won compare-and-swap both advances the head AND makes
    /// every capsule in its batch terminal, and the Lean model applies one
    /// `Operation` at a time. Collapsing that to a single op would drop every
    /// outcome the corpus contains.
    pub operations: Vec<AbstractOp>,
    /// Head generation the reference model recorded after this step.
    pub generation_after: u64,
}

/// A whole history, projected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedTrace {
    /// The golden this came from.
    pub name: String,
    /// Steps in order, stuttering included so indices stay honest.
    pub steps: Vec<ProjectedStep>,
    /// The concrete head generation the Lean model's generation 0 corresponds to.
    ///
    /// This is the abstraction function's one numeric offset, and it is carried
    /// rather than folded into the numbers so the emitted vectors keep the
    /// reference model's own generations and stay traceable to it. The Lean
    /// checker applies it explicitly, which puts the abstraction where a reader
    /// of the proof will look for it.
    pub genesis_generation: u64,
    /// Abstract index to concrete transaction identity, for traceability.
    ///
    /// Lean's `TxId` is a `Nat` and the model only ever compares it for
    /// equality, so any injective renaming preserves every property the
    /// theorems state. This table is what lets a divergence at abstract index 2
    /// be traced back to a real transaction instead of stopping at a number.
    pub transactions: Vec<(u64, String)>,
}

/// Why a history could not be projected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionRefusal {
    /// A decide named a capsule no earlier step prepared.
    ///
    /// Not recoverable by guessing: attributing an outcome to the wrong
    /// transaction is precisely what `terminal_outcome_is_unique` is about, so a
    /// bridge that guessed here would produce a green check that proves the
    /// opposite of what it claims.
    UnknownCapsule {
        /// Step that referenced it.
        concrete_index: usize,
    },
    /// A decide reported an already-terminal transaction that was never decided
    /// in this history.
    AlreadyTerminalWithoutDecision {
        /// Step that reported it.
        concrete_index: usize,
    },
    /// A step recorded a head generation below the genesis origin.
    ///
    /// The offset between the concrete generations and the Lean model's
    /// zero-based one is a constant of the reference model, not an observation,
    /// so it is guarded rather than assumed: a history that started elsewhere
    /// would otherwise be exported with a silently wrong abstraction function
    /// and check green against the wrong states.
    GenerationBelowGenesis {
        /// Step that recorded it.
        concrete_index: usize,
        /// What it recorded.
        observed: u64,
        /// The origin every generation must be at or above.
        genesis: u64,
    },
}

/// Projects one recorded history onto the abstract model.
///
/// # Errors
///
/// [`ProjectionRefusal`] when an identity cannot be resolved from the history
/// itself. The projection never invents one.
pub fn project(name: &str, trace: &GoldenTrace) -> Result<ProjectedTrace, ProjectionRefusal> {
    let mut capsules: BTreeMap<Vec<u8>, TxId> = BTreeMap::new();
    let mut indices: BTreeMap<TxId, u64> = BTreeMap::new();
    let mut order: Vec<(u64, String)> = Vec::new();
    let mut decided: BTreeMap<u64, AbstractOutcome> = BTreeMap::new();
    // batch identity -> the capsules it staged. A decision becomes canonical at
    // the head CAS, not at staging, so this is what lets the CAS step say which
    // transactions it just made terminal.
    let mut batches: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
    let mut steps = Vec::with_capacity(trace.steps.len());
    // A refusal consumes decision sequence but does NOT advance repository
    // sequence (NORMATIVE_PROTOCOL_CONTRACTS.md line 285). That is the only
    // thing a recorded trace carries which distinguishes a batch that committed
    // from one that refused: DecisionBodyIdentity holds both a commit id and a
    // refusal-record id without saying which one applies.
    let mut repository_sequence: Option<u64> = None;

    let index_of = |tx: TxId, indices: &mut BTreeMap<TxId, u64>, order: &mut Vec<(u64, String)>| {
        if let Some(found) = indices.get(&tx) {
            return *found;
        }
        let next = u64::try_from(indices.len()).unwrap_or(u64::MAX);
        indices.insert(tx, next);
        order.push((next, hex(tx.as_internal_object_id().digest().as_bytes())));
        next
    };

    for (concrete_index, step) in trace.steps.iter().enumerate() {
        let generation_after = step.head.generation.get();
        let mut operations = Vec::new();
        let projected = match (&step.input, &step.observed) {
            (
                ModelInput::Seal(request),
                ObservedOutcome::SealCreated | ObservedOutcome::SealRetry,
            ) => Some(AbstractOp::SealRequest {
                target: index_of(request.request.tx_id, &mut indices, &mut order),
            }),
            (ModelInput::Prepare(request), _) => {
                capsules.insert(
                    request
                        .capsule_id
                        .as_internal_object_id()
                        .digest()
                        .as_bytes()
                        .to_vec(),
                    request.request.tx_id,
                );
                None
            }
            (ModelInput::Stage(request), _) => {
                batches.insert(
                    request
                        .batch_id
                        .as_internal_object_id()
                        .digest()
                        .as_bytes()
                        .to_vec(),
                    request
                        .capsules
                        .iter()
                        .map(|capsule| capsule.as_internal_object_id().digest().as_bytes().to_vec())
                        .collect(),
                );
                None
            }
            (ModelInput::Decide { capsule }, observed) => {
                let key = capsule.as_internal_object_id().digest().as_bytes().to_vec();
                let tx = *capsules
                    .get(&key)
                    .ok_or(ProjectionRefusal::UnknownCapsule { concrete_index })?;
                let target = index_of(tx, &mut indices, &mut order);
                match observed {
                    ObservedOutcome::DecidedCommit => {
                        decided.insert(target, AbstractOutcome::Committed);
                        Some(AbstractOp::Decide {
                            target,
                            outcome: AbstractOutcome::Committed,
                        })
                    }
                    ObservedOutcome::DecidedRefuse(_) => {
                        decided.insert(target, AbstractOutcome::Refused);
                        Some(AbstractOp::Decide {
                            target,
                            outcome: AbstractOutcome::Refused,
                        })
                    }
                    // The Lean `decide` is already a no-op on a decided target
                    // (OrderedResidue.lean's `some _ => state` arm), so replaying
                    // the outcome this history recorded earlier reproduces the
                    // concrete step exactly. Replaying a DIFFERENT outcome would
                    // also be a no-op, which is why this reads the recorded one
                    // rather than picking either: the vector has to mean
                    // something even where the model would not notice.
                    ObservedOutcome::DecidedAlreadyTerminal => Some(AbstractOp::Decide {
                        target,
                        outcome: *decided.get(&target).ok_or(
                            ProjectionRefusal::AlreadyTerminalWithoutDecision { concrete_index },
                        )?,
                    }),
                    _ => None,
                }
            }
            (ModelInput::CompareAndSwap(request), observed) => {
                let predecessor = request.expected_generation.get();
                let generation = predecessor.saturating_add(1);
                match observed {
                    ObservedOutcome::CasWon => {
                        // The publication comes first: a decision is canonical
                        // because the head moved, not the other way round, and
                        // the Lean `decide` requires the target already sealed.
                        operations.push(AbstractOp::Publish {
                            predecessor,
                            generation,
                        });
                        let key = request
                            .batch
                            .as_internal_object_id()
                            .digest()
                            .as_bytes()
                            .to_vec();
                        let staged = batches.get(&key).cloned().unwrap_or_default();
                        let advanced = step
                            .head
                            .latest_repository_sequence
                            .map(fgit_types::RepositorySequence::get);
                        let committed_count = match (repository_sequence, advanced) {
                            (Some(before), Some(after)) => after.saturating_sub(before),
                            (None, Some(after)) => after,
                            _ => 0,
                        };
                        // Attribute an outcome only where the trace determines
                        // one. A batch that advanced the repository sequence by
                        // exactly as many positions as it staged capsules
                        // committed all of them; one that advanced it by none
                        // refused all of them. Anything between is a mixed batch
                        // whose per-capsule fate this recording does not state,
                        // and guessing there would put a fabricated outcome into
                        // a proof artifact.
                        let outcome = if committed_count == 0 {
                            Some(AbstractOutcome::Refused)
                        } else if usize::try_from(committed_count) == Ok(staged.len()) {
                            Some(AbstractOutcome::Committed)
                        } else {
                            None
                        };
                        if let Some(outcome) = outcome {
                            for capsule in staged {
                                let tx = *capsules
                                    .get(&capsule)
                                    .ok_or(ProjectionRefusal::UnknownCapsule { concrete_index })?;
                                let target = index_of(tx, &mut indices, &mut order);
                                decided.insert(target, outcome);
                                operations.push(AbstractOp::Decide { target, outcome });
                            }
                        }
                        None
                    }
                    // A lost CAS and an unsatisfied durability profile are both
                    // publications that left the visible head where it was,
                    // which is exactly `interruptedPublication`. They differ in
                    // why, and the Lean model does not model why.
                    ObservedOutcome::CasLost | ObservedOutcome::CasDurabilityUnsatisfied => {
                        Some(AbstractOp::InterruptedPublication {
                            predecessor,
                            generation,
                        })
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        repository_sequence = step
            .head
            .latest_repository_sequence
            .map(fgit_types::RepositorySequence::get)
            .or(repository_sequence);
        operations.extend(projected);
        steps.push(ProjectedStep {
            concrete_index,
            operations,
            generation_after,
        });
    }

    let genesis_generation = fgit_types::HeadGeneration::FIRST.get();
    for step in &steps {
        if step.generation_after < genesis_generation {
            return Err(ProjectionRefusal::GenerationBelowGenesis {
                concrete_index: step.concrete_index,
                observed: step.generation_after,
                genesis: genesis_generation,
            });
        }
    }
    Ok(ProjectedTrace {
        name: name.to_owned(),
        steps,
        genesis_generation,
        transactions: order,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

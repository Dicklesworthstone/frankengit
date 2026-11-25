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

use fgit_reference::decision::PublishedDecision;
use fgit_reference::intent::{ForgeStreamId, ForgeStreamPosition};
use fgit_reference::machine::ModelInput;
use fgit_reference::state::RepositoryRoots;
use fgit_reference::trace::{
    DivergenceKind, GoldenTrace, ObservedOutcome, TraceError, decode_roots, replay,
};
use fgit_types::native::GitOid;
use fgit_types::refs::RefName;
use fgit_types::{DecisionOutcome, DecisionSequence, RepositorySequence, TxId};

/// The Lean model's terminal outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbstractOutcome {
    /// `TerminalOutcome.committed`.
    Committed,
    /// `TerminalOutcome.refused`.
    Refused,
}

impl From<DecisionOutcome> for AbstractOutcome {
    fn from(outcome: DecisionOutcome) -> Self {
        match outcome {
            DecisionOutcome::Committed { .. } => Self::Committed,
            DecisionOutcome::Refused { .. } => Self::Refused,
        }
    }
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
/// `crash` and `lostResponse` exist in the Lean model but are not produced
/// here: the reference model records a cancellation, not a crash, and mapping
/// one onto the other would assert a correspondence nothing checks. `retry`
/// IS produced, exactly where the recorded history shows one: a decide that
/// found its transaction already terminal. A vector set that never exercises
/// `crash` or `lostResponse` is a stated limit, not a silent one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbstractOp {
    /// `Operation.sealRequest`.
    SealRequest {
        /// The abstract transaction index.
        target: u64,
    },
    /// `Operation.decide`, emitted only where a decision became canonical: at
    /// a won compare-and-swap that made every batch capsule terminal.
    Decide {
        /// The abstract transaction index.
        target: u64,
        /// What it was decided as.
        outcome: AbstractOutcome,
    },
    /// `Operation.retry`: a decide re-presented against an already-terminal
    /// transaction. The Lean model applies it as a no-op that preserves the
    /// recorded outcome and refuses to overwrite it, which is exactly what
    /// the reference model's §10.14 revalidation observes — so this mapping
    /// asserts only what both sides see, never a fabricated first decision.
    Retry {
        /// The abstract transaction index.
        target: u64,
        /// The outcome the history had already recorded.
        outcome: AbstractOutcome,
    },
    /// `Operation.publish`.
    Publish {
        /// Generation the batch claims to succeed.
        predecessor: u64,
        /// Generation the batch takes.
        generation: u64,
        /// Dictionary-encoded identities of every ref the publication
        /// created, changed, or removed, ascending by name. Empty when the
        /// batch moved no ref.
        ref_effects: Vec<u64>,
        /// Flattened `(stream, new position)` pairs — stream dictionary index
        /// then raw position, ascending stream order — for every forge stream
        /// the publication advanced. Empty when it advanced none.
        forge_effects: Vec<u64>,
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
    /// Final decision sequence recorded by this head, zero at genesis.
    pub decision_sequence_after: u64,
    /// Final repository sequence recorded by this head. Only commits advance it.
    pub repository_sequence_after: u64,
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
    /// An input could not be run by the reference model.
    ReplayFailed(TraceError),
    /// A recorded observation differs from a fresh execution.
    Diverged {
        /// Position of the first mismatch.
        concrete_index: usize,
        /// Observable that differed.
        kind: DivergenceKind,
    },
    /// A published decision disagrees with its recorded root or has no prior seal.
    DecisionMismatch {
        /// Winning publication that contains the decision.
        concrete_index: usize,
    },
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
    /// A step's recorded roots could not be decoded.
    ///
    /// The effect vectors come from decoding the canonical roots each step
    /// recorded; bytes that fail their own frame cannot be projected, and
    /// guessing past the refusal would put invented effects into a proof
    /// artifact.
    UnreadableRoots {
        /// Step whose roots refused to decode.
        concrete_index: usize,
    },
}

/// Projects one recorded history onto the abstract model.
///
/// # Errors
///
/// [`ProjectionRefusal`] when an identity cannot be resolved from the history
/// itself. The projection never invents one.
pub fn project(name: &str, trace: &GoldenTrace) -> Result<ProjectedTrace, ProjectionRefusal> {
    let report = replay(trace).map_err(ProjectionRefusal::ReplayFailed)?;
    if let Some(divergence) = report.divergence {
        return Err(ProjectionRefusal::Diverged {
            concrete_index: divergence.step_index,
            kind: divergence.kind,
        });
    }
    project_replayed(name, trace, report.state.decisions())
}

pub(crate) fn project_replayed(
    name: &str,
    trace: &GoldenTrace,
    published: &[PublishedDecision],
) -> Result<ProjectedTrace, ProjectionRefusal> {
    let mut decisions = published.iter().peekable();
    let mut capsules = BTreeMap::new();
    let mut indices: BTreeMap<TxId, u64> = BTreeMap::new();
    let mut order: Vec<(u64, String)> = Vec::new();
    let mut steps = Vec::with_capacity(trace.steps.len());
    // Decoded roots of the previous step, kept so a won compare-and-swap can
    // report exactly which authenticated positions its publication moved.
    let mut previous_roots: Option<RepositoryRoots> = None;
    // Dictionary encodings that keep the emitted effect vectors small enough
    // for kernel reduction: ref names and forge streams become stable small
    // indices on first sight, assigned in ascending order within each step.
    let mut ref_dictionary: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
    let mut stream_dictionary: BTreeMap<Vec<u8>, u64> = BTreeMap::new();

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
        let roots_now = decode_roots(&step.roots)
            .map_err(|_| ProjectionRefusal::UnreadableRoots { concrete_index })?;
        let mut operations = Vec::new();
        let projected = match (&step.input, &step.observed) {
            (
                ModelInput::Seal(request),
                ObservedOutcome::SealCreated | ObservedOutcome::SealRetry,
            ) => Some(AbstractOp::SealRequest {
                target: index_of(request.request.tx_id, &mut indices, &mut order),
            }),
            (ModelInput::Prepare(request), _) => {
                capsules.insert(request.capsule_id, request.request.tx_id);
                None
            }
            (ModelInput::Decide { capsule }, observed) => {
                let tx = capsules
                    .get(capsule)
                    .ok_or(ProjectionRefusal::UnknownCapsule { concrete_index })?;
                match observed {
                    // §10.14: deciding revalidates and concludes WITHOUT
                    // changing state. Emitting an abstract decide here would
                    // record an outcome the concrete step did not —
                    // fabricating exactly the pre-terminal decision
                    // `terminal_outcome_is_unique` forbids — so a fresh
                    // verdict stutters and waits for the compare-and-swap
                    // that actually makes it canonical.
                    ObservedOutcome::DecidedCommit | ObservedOutcome::DecidedRefuse(_) => None,
                    // Re-deciding a terminal transaction observes the
                    // recorded outcome without changing anything, which is
                    // precisely the Lean model's retry: `apply` preserves an
                    // existing outcome and refuses to overwrite it.
                    ObservedOutcome::DecidedAlreadyTerminal => {
                        let missing =
                            || ProjectionRefusal::AlreadyTerminalWithoutDecision { concrete_index };
                        Some(AbstractOp::Retry {
                            target: *indices.get(tx).ok_or_else(missing)?,
                            outcome: (*roots_now.outcome_index.get(tx).ok_or_else(missing)?).into(),
                        })
                    }
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
                        let ref_effects = ref_effect_identities(
                            previous_roots.as_ref().map(|roots| &roots.refs),
                            &roots_now.refs,
                            &mut ref_dictionary,
                        );
                        let forge_effects = forge_effect_identities(
                            previous_roots.as_ref().map(|roots| &roots.forge_positions),
                            &roots_now.forge_positions,
                            &mut stream_dictionary,
                        );
                        operations.push(AbstractOp::Publish {
                            predecessor,
                            generation,
                            ref_effects,
                            forge_effects,
                        });
                        // The replayed decision stream supplies actual terminal identities
                        // and ordering. The position in this recorded head bounds the
                        // batch, including refusals and excluding deferred requests.
                        while let Some(decision) = decisions.next_if(|decision| {
                            Some(decision.decision_sequence) <= step.head.latest_decision_sequence
                        }) {
                            let mismatch =
                                || ProjectionRefusal::DecisionMismatch { concrete_index };
                            let target = *indices.get(&decision.tx_id).ok_or_else(mismatch)?;
                            if roots_now.outcome_index.get(&decision.tx_id)
                                != Some(&decision.outcome)
                            {
                                return Err(mismatch());
                            }
                            operations.push(AbstractOp::Decide {
                                target,
                                outcome: decision.outcome.into(),
                            });
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
        previous_roots = Some(roots_now);
        operations.extend(projected);
        steps.push(ProjectedStep {
            concrete_index,
            operations,
            generation_after,
            decision_sequence_after: step
                .head
                .latest_decision_sequence
                .map_or(0, DecisionSequence::get),
            repository_sequence_after: step
                .head
                .latest_repository_sequence
                .map_or(0, RepositorySequence::get),
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

/// The dictionary index for `key`, assigning the next free index on first
/// sight. Indices stay stable for the whole trace because the dictionaries
/// outlive single steps.
fn dictionary_index(dictionary: &mut BTreeMap<Vec<u8>, u64>, key: &[u8]) -> u64 {
    let next = u64::try_from(dictionary.len()).unwrap_or(u64::MAX);
    *dictionary.entry(key.to_vec()).or_insert(next)
}

/// Identities of every ref the step created, changed, or removed, encoded as
/// dictionary indices and sorted ascending so the vector stays a pure
/// function of the root content rather than of map iteration order.
fn ref_effect_identities(
    previous: Option<&BTreeMap<RefName, GitOid>>,
    current: &BTreeMap<RefName, GitOid>,
    dictionary: &mut BTreeMap<Vec<u8>, u64>,
) -> Vec<u64> {
    let mut names: Vec<Vec<u8>> = Vec::new();
    for (name, oid) in current {
        if previous.is_some_and(|prev| prev.get(name) != Some(oid)) {
            names.push(name.as_bytes().to_vec());
        }
    }
    if let Some(prev) = previous {
        for name in prev.keys() {
            if !current.contains_key(name) {
                names.push(name.as_bytes().to_vec());
            }
        }
    }
    names.sort();
    names.dedup();
    names
        .iter()
        .map(|name| dictionary_index(dictionary, name))
        .collect()
}

/// Flattened `(stream, new position)` pairs for every forge stream the step
/// created or advanced, ascending by stream identity.
fn forge_effect_identities(
    previous: Option<&BTreeMap<ForgeStreamId, ForgeStreamPosition>>,
    current: &BTreeMap<ForgeStreamId, ForgeStreamPosition>,
    dictionary: &mut BTreeMap<Vec<u8>, u64>,
) -> Vec<u64> {
    let mut effects = Vec::new();
    for (stream, position) in current {
        if previous.is_some_and(|prev| prev.get(stream) != Some(position)) {
            effects.push(dictionary_index(dictionary, stream.label().as_bytes()));
            effects.push(position.get());
        }
    }
    effects
}

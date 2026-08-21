//! The transition alphabet and the one `(state, input) -> (state, output)`
//! entry point.
//!
//! Every transition in [`crate::transition`] is already a pure function.
//! [`step`] exists so a trace, a replay, or a bounded model campaign can drive
//! the model through one uniform door rather than by naming five functions,
//! and so the alphabet of things that can happen to a repository is written
//! down in one closed enum.

use fgit_types::identity::{PreparedTxnCapsuleId, RepositoryDecisionBatchId, TxId};
use fgit_types::vocabulary::DecisionOutcome;

use crate::state::{InvariantBreach, ModelResult, RepositoryState};
use crate::transition::{
    CasOutcome, CasRequest, ConfigurationOutcome, ConfigurationRequest, DecisionVerdict,
    PrepareRequest, QuarantineRequest, SealOutcome, SealRequest, StageRequest, compare_and_swap,
    decide, prepare, publish_configuration, seal, stage, stage_objects,
};

/// When a client cancelled, relative to the head compare-and-swap.
///
/// §14 gives cancellation three regimes and one prohibition that spans all of
/// them: an API must never return a cancellation in a form that proves
/// non-commit after the compare-and-swap could have happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CancellationPhase {
    /// Before any seal existed. The request may vanish without canonical
    /// trace.
    BeforeSeal,
    /// After sealing, before the head compare-and-swap. New work stops and
    /// effects drain; the sealed request stays discoverable, undecided, and
    /// retryable.
    AfterSealBeforeCas,
    /// After the head compare-and-swap. The canonical decision stands;
    /// only response, outbox, and materialization work may cancel.
    AfterCas,
}

/// What cancelling did, and — just as importantly — what it did not establish.
///
/// There is deliberately no "not committed" field. §5.3 has no canonical
/// cancelled outcome and §14 forbids reporting cancellation as proof of
/// non-commit, so the type simply cannot say it. [`CancellationReport::outcome`]
/// being `None` means *undecided and retryable*, which is a different claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CancellationReport {
    /// The phase the cancellation was requested in.
    pub phase: CancellationPhase,
    /// Whether a seal for this transaction survives the cancellation.
    pub seal_survives: bool,
    /// The terminal outcome, when the transaction already has one.
    ///
    /// `None` means the transaction is undecided and a later retry continues
    /// the same logical transaction. It is never evidence of non-commit.
    pub outcome: Option<DecisionOutcome>,
}

impl CancellationReport {
    /// True when this transaction already has a terminal decision.
    #[must_use]
    pub const fn is_decided(&self) -> bool {
        self.outcome.is_some()
    }

    /// True when the same sealed request may be retried.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.seal_survives && self.outcome.is_none()
    }
}

/// A cancellation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CancellationRequest {
    /// The transaction being cancelled.
    pub tx_id: TxId,
    /// The phase the client cancelled in.
    pub phase: CancellationPhase,
}

/// Everything that can happen to a modelled repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelInput {
    /// Canonicalize and seal one request (§5.2).
    Seal(Box<SealRequest>),
    /// Stage objects into one sealed transaction's quarantine (§16.2).
    StageObjects(QuarantineRequest),
    /// Validate one sealed transaction against the current head (§10.7–11).
    Prepare(Box<PrepareRequest>),
    /// Revalidate one capsule and conclude, without changing state
    /// (§10.14).
    Decide {
        /// The capsule to decide.
        capsule: PreparedTxnCapsuleId,
    },
    /// Stage one decision batch and its candidate head (§10.15).
    Stage(StageRequest),
    /// Attempt the one linearizable head replacement (§10.16).
    CompareAndSwap(CasRequest),
    /// Pin a new policy and configuration snapshot (§15.9, §22).
    PublishConfiguration(Box<ConfigurationRequest>),
    /// Cancel, in a named phase (§14).
    Cancel(CancellationRequest),
}

/// What one transition produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelOutput {
    /// A seal was created, matched, or the request was rejected pre-seal.
    Sealed(SealOutcome),
    /// Objects entered a transaction-scoped quarantine.
    ObjectsQuarantined {
        /// How many objects the quarantine now holds for this transaction.
        held: usize,
    },
    /// A capsule was produced.
    Prepared(PreparedTxnCapsuleId),
    /// A capsule was decided against the current head.
    Decided(DecisionVerdict),
    /// A batch and candidate head were staged, and nothing became canonical.
    Staged(RepositoryDecisionBatchId),
    /// A head compare-and-swap was attempted.
    HeadTransition(CasOutcome),
    /// A configuration head transition was attempted.
    ConfigurationTransition(ConfigurationOutcome),
    /// A cancellation was processed.
    Cancelled(CancellationReport),
}

/// One step: the state after, and what the step produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelStep {
    /// The state after the transition. The state passed in is untouched.
    pub next: RepositoryState,
    /// What the transition produced.
    pub output: ModelOutput,
}

/// Applies one input to one state.
///
/// The signature is the whole contract: `&RepositoryState` in, a new
/// `RepositoryState` out, and nothing shared between them. Calling `step`
/// twice on the same state with the same input produces two equal results —
/// there is no clock, no counter outside the state, and no hash iteration to
/// make them differ.
pub fn step(state: &RepositoryState, input: &ModelInput) -> ModelResult<ModelStep> {
    match input {
        ModelInput::Seal(request) => {
            let (next, outcome) = seal(state, request)?;
            Ok(ModelStep {
                next,
                output: ModelOutput::Sealed(outcome),
            })
        }
        ModelInput::StageObjects(request) => {
            let next = stage_objects(state, request)?;
            let held = next
                .quarantine_of(request.tx_id)
                .map_or(0, std::collections::BTreeMap::len);
            Ok(ModelStep {
                next,
                output: ModelOutput::ObjectsQuarantined { held },
            })
        }
        ModelInput::Prepare(request) => {
            let (next, capsule) = prepare(state, request)?;
            Ok(ModelStep {
                next,
                output: ModelOutput::Prepared(capsule),
            })
        }
        ModelInput::Decide { capsule } => {
            let Some(prepared) = state.capsule(*capsule) else {
                return Err(Box::new(InvariantBreach::UnknownCapsule {
                    capsule: *capsule,
                }));
            };
            let verdict = decide(state, prepared);
            // Deciding changes nothing: a decision becomes canonical only when
            // a batch containing it wins the head compare-and-swap.
            Ok(ModelStep {
                next: state.clone(),
                output: ModelOutput::Decided(verdict),
            })
        }
        ModelInput::Stage(request) => {
            let (next, batch) = stage(state, request)?;
            Ok(ModelStep {
                next,
                output: ModelOutput::Staged(batch),
            })
        }
        ModelInput::CompareAndSwap(request) => {
            let (next, outcome) = compare_and_swap(state, *request)?;
            Ok(ModelStep {
                next,
                output: ModelOutput::HeadTransition(outcome),
            })
        }
        ModelInput::PublishConfiguration(request) => {
            let (next, outcome) = publish_configuration(state, request)?;
            Ok(ModelStep {
                next,
                output: ModelOutput::ConfigurationTransition(outcome),
            })
        }
        ModelInput::Cancel(request) => Ok(cancel(state, *request)),
    }
}

/// Cancels one transaction in a named phase.
///
/// §14, phase by phase:
///
/// * **before seal** — nothing canonical exists and nothing is left behind;
/// * **after seal, before the compare-and-swap** — new work stops and staged
///   candidates may be abandoned, but the seal survives so a retry continues
///   the *same* logical transaction rather than starting a second one;
/// * **after the compare-and-swap** — the decision stands and cancellation
///   touches only response and outbox work.
///
/// In every phase the report can say "decided" or "undecided", never "not
/// committed".
fn cancel(state: &RepositoryState, request: CancellationRequest) -> ModelStep {
    let outcome = state.outcome_of(request.tx_id);
    match request.phase {
        // Before the seal there is nothing to drain, and after the
        // compare-and-swap there is nothing left to abandon: in both phases the
        // state is untouched and only the report differs by what it observes.
        CancellationPhase::BeforeSeal | CancellationPhase::AfterCas => ModelStep {
            next: state.clone(),
            output: ModelOutput::Cancelled(CancellationReport {
                phase: request.phase,
                seal_survives: state.seal_of(request.tx_id).is_some(),
                outcome,
            }),
        },
        CancellationPhase::AfterSealBeforeCas => {
            // Drain: abandon this transaction's prepared candidates. The seal,
            // the quarantine, and therefore the ability to retry the same
            // sealed request all survive.
            let mut next = state.clone();
            next.capsules
                .retain(|_, capsule| capsule.tx_id != request.tx_id);
            let seal_survives = next.seal_of(request.tx_id).is_some();
            ModelStep {
                next,
                output: ModelOutput::Cancelled(CancellationReport {
                    phase: request.phase,
                    seal_survives,
                    outcome,
                }),
            }
        }
    }
}

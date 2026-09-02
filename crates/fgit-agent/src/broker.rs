//! The effect broker and replayable effect journal (`docs/AGENT_PROTOCOL.md` §9).
//!
//! An effect identity is an idempotency boundary, not merely an audit label.
//! The broker rejects a second request for an already registered [`EffectId`]
//! before it can reserve another budget grant. The accepted record then moves
//! through the shared [`ObligationState`] machine; this module records that
//! history, while `fgit-resource` owns the actual typed obligation.
//!
//! # Boundary
//!
//! The journal is append-only and replayable for the live [`IntentRun`]. It is
//! not a durable outbox: persistence belongs to the authority/evidence path
//! that owns root-last publication. The in-process record is still a real
//! protocol boundary: it uses real `fgit-resource` reservations and the
//! external path owns a real [`OutboxEffectPermit`] through reconciliation.
//! It never converts an ambiguous downstream response into success.

use core::fmt;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use fgit_resource::{
    BudgetGrant, DeferralReason, DownstreamChannel, DownstreamIdempotency, EscalationReason,
    EscalationReceipt, IdempotencyKey, LeakDisposition, LifecycleError, LifecycleEvent,
    ObligationClass, ObligationLedger, ObligationState, ReconcileOutcome, ReconcilePlan,
    RegionCloseOutcome, RegionId, ReleaseReceipt, ReserveError, ReservedObligation, ResourceVector,
    SettledObligation, SettlementRefused, TerminalFailureReason, UnacknowledgedEffect,
    kinds::{
        DispatchAbortReason, DownstreamAck, EffectDispatched, OutboxDispatch, OutboxEffectPermit,
    },
    reconcile,
    settlement::ReconcileTransition,
};
use fgit_types::PrincipalId;

use crate::{
    capability::{Capability, CapabilityId, LogicalTime},
    classes::{ClassSet, OperationClass},
    intent::{IntentRun, RunId},
    protocol::AuthorityReadReceipt,
    run_identity::{IntentRunCommitment, IntentRunIdentityRefusal},
};

/// Opaque effect identity (`AGENT_PROTOCOL.md` §9, `effect_id`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EffectId(u128);

impl EffectId {
    /// Builds an effect identity.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// The raw value.
    #[must_use]
    pub const fn value(self) -> u128 {
        self.0
    }
}

impl fmt::Display for EffectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "effect:{:032x}", self.0)
    }
}

/// The instance that performed an effect for one run.
///
/// A run may outlive a process restart or delegate to several constrained
/// executors, so this identity is deliberately distinct from [`RunId`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AgentInstanceId(u128);

impl AgentInstanceId {
    /// Builds an agent-instance identity.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// The raw value.
    #[must_use]
    pub const fn value(self) -> u128 {
        self.0
    }
}

impl fmt::Display for AgentInstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "agent-instance:{:032x}", self.0)
    }
}

/// The six effect classes distinguished by `AGENT_PROTOCOL.md` §9.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EffectClass {
    /// A pure read of canonical state.
    PureCanonicalRead,
    /// A locally derived write that does not claim canonical authority.
    DerivedLocalWrite,
    /// Creation of an immutable candidate that is not yet canonical.
    ImmutableCandidateCreation,
    /// Preparation of a potential canonical mutation.
    PreparedCanonicalMutation,
    /// A canonical mutation that later commits or is refused.
    CanonicalMutation,
    /// An externally observed effect, such as an outbox delivery.
    ExternalEffect,
}

impl EffectClass {
    const fn for_operation(operation: OperationClass) -> Self {
        match operation {
            OperationClass::ReadCanonicalObject => Self::PureCanonicalRead,
            OperationClass::CreateCandidateObject => Self::ImmutableCandidateCreation,
            OperationClass::PreparePublication => Self::PreparedCanonicalMutation,
            OperationClass::SubmitEvidence | OperationClass::MutateForgeEntity => {
                Self::CanonicalMutation
            }
            OperationClass::ExternalIntegration => Self::ExternalEffect,
            OperationClass::ReadDerivedGeneration
            | OperationClass::TreeFsWorkspace
            | OperationClass::ExecuteSandboxedProcess
            | OperationClass::NetworkDestination
            | OperationClass::SecretHandle
            | OperationClass::DelegateSubIntent
            | OperationClass::ConsumeBudget => Self::DerivedLocalWrite,
        }
    }
}

impl fmt::Display for EffectClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::PureCanonicalRead => "pure_canonical_read",
            Self::DerivedLocalWrite => "derived_local_write",
            Self::ImmutableCandidateCreation => "immutable_candidate_creation",
            Self::PreparedCanonicalMutation => "prepared_canonical_mutation",
            Self::CanonicalMutation => "canonical_mutation",
            Self::ExternalEffect => "external_effect",
        };
        formatter.write_str(text)
    }
}

/// A request to perform one consequential operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectRequest {
    /// Stable identity, so an at-least-once retry is the same effect (§9).
    pub effect_id: EffectId,
    /// The parent effect, when this is a bounded child operation.
    pub parent_effect_id: Option<EffectId>,
    /// Which class of operation this is.
    pub operation: OperationClass,
    /// What performing it will cost.
    pub cost: ResourceVector,
    /// Commitment to the canonical input, so the record names what was asked.
    pub input_commitment: [u8; 32],
}

/// The resolved terminal fact for a broker record.
///
/// [`Self::Escalated`] is deliberately not success: it records that automation
/// reached a named owner with an unresolved downstream result. The underlying
/// resource obligation remains outstanding until that owner settles it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectTerminalOutcome {
    /// The effect was observed by its recipient.
    Acknowledged,
    /// The reservation was abandoned before it committed.
    Aborted,
    /// A committed effect was proved permanently undeliverable.
    TerminallyFailed {
        /// Why delivery can no longer proceed.
        reason: TerminalFailureReason,
    },
    /// Reconciliation could not decide and handed ownership to this principal.
    Escalated {
        /// The principal responsible for the unresolved effect.
        owner: PrincipalId,
        /// Why automation stopped.
        reason: EscalationReason,
    },
}

/// Replayable evidence from an external-effect reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationEvidence {
    /// The downstream's duplicate-suppression contract.
    pub downstream_idempotency: DownstreamIdempotency,
    /// Every dispatch and probe transition, in observed order.
    pub transitions: Vec<ReconcileTransition>,
}

/// What the broker recorded about one accepted effect (`§9 EffectRecord`).
///
/// `source_authority_receipt` is a full authenticated receipt when the run was
/// opened through [`IntentRun::new_authenticated`]. Legacy runs retain `None`;
/// their identifying reference is intentionally not promoted into a receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRecord {
    /// Stable effect identity.
    pub effect_id: EffectId,
    /// Coordination identity of the run that authorized it.
    pub run_id: RunId,
    /// Complete machine-enforced run identity that authorized it.
    pub run_commitment: IntentRunCommitment,
    /// The concrete agent executor that performed it.
    pub agent_instance_id: AgentInstanceId,
    /// The parent effect, if this operation is a child of another effect.
    pub parent_effect_id: Option<EffectId>,
    /// The capability presented.
    pub capability_id: CapabilityId,
    /// The effect class determined from the requested operation.
    pub effect_class: EffectClass,
    /// The operation class performed.
    pub operation: OperationClass,
    /// Commitment to the canonical input.
    pub input_commitment: [u8; 32],
    /// Complete authority receipt that supplied the run's base, if present.
    pub source_authority_receipt: Option<AuthorityReadReceipt>,
    /// Budget reserved at acceptance.
    pub budget_reserved: ResourceVector,
    /// Budget consumed by the typed obligation's terminal operation.
    pub budget_consumed: ResourceVector,
    /// Stable downstream idempotency key for an external effect.
    pub external_idempotency_key: Option<IdempotencyKey>,
    /// The shared obligation lifecycle state mirrored by this journal.
    pub obligation_state: ObligationState,
    /// The concrete obligation class once the grant becomes an obligation.
    pub obligation_class: Option<ObligationClass>,
    /// The terminal fact, never an untyped "maybe".
    pub terminal_outcome: Option<EffectTerminalOutcome>,
    /// Commitments to outputs retained for the terminal record.
    pub output_commitments: Vec<[u8; 32]>,
    /// External reconciliation observations, when reconciliation was needed.
    pub reconciliation_evidence: Option<ReconciliationEvidence>,
    /// When the broker accepted it.
    pub accepted_at: LogicalTime,
}

/// One append-only event in the in-process effect journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectJournalEvent {
    /// A capability-authorized effect received its initial budget reservation.
    Accepted(Box<EffectRecord>),
    /// The grant became one of the shared typed obligations.
    BoundObligation {
        /// The effect that now owns the obligation.
        effect_id: EffectId,
        /// The shared obligation class.
        obligation_class: ObligationClass,
        /// Stable downstream key for an outbox effect, if any.
        external_idempotency_key: Option<IdempotencyKey>,
    },
    /// The shared lifecycle took one legal transition.
    Lifecycle {
        /// The effect whose lifecycle advanced.
        effect_id: EffectId,
        /// The exact shared lifecycle event.
        event: LifecycleEvent,
        /// Cost charged by the operation at this transition.
        budget_consumed: ResourceVector,
        /// Output commitments newly known at this transition.
        output_commitments: Vec<[u8; 32]>,
        /// Reconciliation evidence, if this transition concluded a probe plan.
        reconciliation_evidence: Option<ReconciliationEvidence>,
        /// Typed terminal fact, if this is a terminal journal outcome.
        terminal_outcome: Option<EffectTerminalOutcome>,
    },
}

/// A sequence-numbered effect-journal event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectJournalEntry {
    /// Zero-based monotonic sequence within one broker.
    pub sequence: u64,
    /// The journal event at this sequence.
    pub event: EffectJournalEvent,
}

/// The result of independently replaying an effect journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectJournalReplay {
    records: Vec<EffectRecord>,
}

impl EffectJournalReplay {
    /// Reconstructed records in original acceptance order.
    #[must_use]
    pub fn records(&self) -> &[EffectRecord] {
        &self.records
    }
}

/// Why a journal cannot be appended or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectJournalRefusal {
    /// An accepted-effect event was structurally incomplete.
    InvalidAcceptance {
        /// The malformed effect identity.
        effect_id: EffectId,
    },
    /// One journal mixed numeric run identities.
    MixedRun {
        /// Effect that crossed the journal's run boundary.
        effect_id: EffectId,
        /// Run established by the first accepted effect.
        expected: RunId,
        /// Run carried by this effect.
        observed: RunId,
    },
    /// One journal mixed complete run identities under the same numeric ID.
    MixedRunCommitment {
        /// Effect that crossed the journal's machine-run boundary.
        effect_id: EffectId,
        /// Commitment established by the first accepted effect.
        expected: IntentRunCommitment,
        /// Commitment carried by this effect.
        observed: IntentRunCommitment,
    },
    /// The identity had already been accepted.
    DuplicateEffectId {
        /// The repeated stable identity.
        effect_id: EffectId,
    },
    /// An event referenced no accepted effect.
    UnknownEffect {
        /// The unknown identity.
        effect_id: EffectId,
    },
    /// A grant was bound to a second obligation.
    ObligationAlreadyBound {
        /// The affected effect.
        effect_id: EffectId,
    },
    /// A lifecycle event did not match the shared state machine.
    Lifecycle {
        /// The affected effect.
        effect_id: EffectId,
        /// The shared state-machine refusal.
        source: LifecycleError,
    },
    /// The terminal marker did not agree with its resulting state.
    TerminalOutcomeMismatch {
        /// The affected effect.
        effect_id: EffectId,
    },
    /// Journal sequences must remain dense and ordered.
    NonMonotonicSequence {
        /// Sequence expected by replay.
        expected: u64,
        /// Sequence observed in the journal.
        observed: u64,
    },
}

impl fmt::Display for EffectJournalRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAcceptance { effect_id } => {
                write!(
                    formatter,
                    "effect journal acceptance for {effect_id} is malformed"
                )
            }
            Self::MixedRun {
                effect_id,
                expected,
                observed,
            } => write!(
                formatter,
                "effect journal expected run {expected}, but {effect_id} belongs to {observed}"
            ),
            Self::MixedRunCommitment {
                effect_id,
                expected,
                observed,
            } => write!(
                formatter,
                "effect journal expected run commitment {expected}, but {effect_id} carries {observed}"
            ),
            Self::DuplicateEffectId { effect_id } => {
                write!(formatter, "effect journal already contains {effect_id}")
            }
            Self::UnknownEffect { effect_id } => {
                write!(formatter, "effect journal has no record for {effect_id}")
            }
            Self::ObligationAlreadyBound { effect_id } => {
                write!(
                    formatter,
                    "effect journal already bound an obligation for {effect_id}"
                )
            }
            Self::Lifecycle { effect_id, source } => {
                write!(
                    formatter,
                    "effect journal cannot advance {effect_id}: {source}"
                )
            }
            Self::TerminalOutcomeMismatch { effect_id } => {
                write!(
                    formatter,
                    "terminal outcome does not match lifecycle state for {effect_id}"
                )
            }
            Self::NonMonotonicSequence { expected, observed } => write!(
                formatter,
                "effect journal sequence must be {expected}, observed {observed}"
            ),
        }
    }
}

impl core::error::Error for EffectJournalRefusal {}

#[derive(Debug, Default)]
struct EffectJournal {
    run_id: Option<RunId>,
    run_commitment: Option<IntentRunCommitment>,
    records: Vec<EffectRecord>,
    positions: BTreeMap<EffectId, usize>,
    entries: Vec<EffectJournalEntry>,
}

impl EffectJournal {
    fn contains(&self, effect_id: EffectId) -> bool {
        self.positions.contains_key(&effect_id)
    }

    fn records(&self) -> &[EffectRecord] {
        &self.records
    }

    fn entries(&self) -> &[EffectJournalEntry] {
        &self.entries
    }

    fn append(&mut self, event: EffectJournalEvent) {
        self.entries.push(EffectJournalEntry {
            sequence: u64::try_from(self.entries.len()).unwrap_or(u64::MAX),
            event,
        });
    }

    fn accept(&mut self, record: EffectRecord) -> Result<(), EffectJournalRefusal> {
        if record.obligation_state != ObligationState::Reserved
            || record.terminal_outcome.is_some()
            || record.obligation_class.is_some()
            || record.external_idempotency_key.is_some()
            || !record.output_commitments.is_empty()
            || record.reconciliation_evidence.is_some()
        {
            return Err(EffectJournalRefusal::InvalidAcceptance {
                effect_id: record.effect_id,
            });
        }
        if let Some(expected) = self.run_id {
            if record.run_id != expected {
                return Err(EffectJournalRefusal::MixedRun {
                    effect_id: record.effect_id,
                    expected,
                    observed: record.run_id,
                });
            }
        }
        if let Some(expected) = self.run_commitment {
            if record.run_commitment != expected {
                return Err(EffectJournalRefusal::MixedRunCommitment {
                    effect_id: record.effect_id,
                    expected,
                    observed: record.run_commitment,
                });
            }
        }
        if self.contains(record.effect_id) {
            return Err(EffectJournalRefusal::DuplicateEffectId {
                effect_id: record.effect_id,
            });
        }
        if self.run_id.is_none() {
            self.run_id = Some(record.run_id);
            self.run_commitment = Some(record.run_commitment);
        }
        let position = self.records.len();
        self.positions.insert(record.effect_id, position);
        self.records.push(record.clone());
        self.append(EffectJournalEvent::Accepted(Box::new(record)));
        Ok(())
    }

    fn record_mut(
        &mut self,
        effect_id: EffectId,
    ) -> Result<&mut EffectRecord, EffectJournalRefusal> {
        let position = self
            .positions
            .get(&effect_id)
            .copied()
            .ok_or(EffectJournalRefusal::UnknownEffect { effect_id })?;
        self.records
            .get_mut(position)
            .ok_or(EffectJournalRefusal::UnknownEffect { effect_id })
    }

    fn bind(
        &mut self,
        effect_id: EffectId,
        obligation_class: ObligationClass,
        external_idempotency_key: Option<IdempotencyKey>,
    ) -> Result<(), EffectJournalRefusal> {
        let record = self.record_mut(effect_id)?;
        if record.obligation_class.is_some() {
            return Err(EffectJournalRefusal::ObligationAlreadyBound { effect_id });
        }
        record.obligation_class = Some(obligation_class);
        record.external_idempotency_key = external_idempotency_key;
        self.append(EffectJournalEvent::BoundObligation {
            effect_id,
            obligation_class,
            external_idempotency_key,
        });
        Ok(())
    }

    fn lifecycle(
        &mut self,
        effect_id: EffectId,
        event: LifecycleEvent,
        budget_consumed: ResourceVector,
        output_commitments: Vec<[u8; 32]>,
        reconciliation_evidence: Option<ReconciliationEvidence>,
        terminal_outcome: Option<EffectTerminalOutcome>,
    ) -> Result<(), EffectJournalRefusal> {
        let record = self.record_mut(effect_id)?;
        let state = record
            .obligation_state
            .apply(event)
            .map_err(|source| EffectJournalRefusal::Lifecycle { effect_id, source })?;
        let terminal_matches = matches!(
            (state, terminal_outcome),
            (
                ObligationState::Acknowledged,
                Some(EffectTerminalOutcome::Acknowledged)
            ) | (
                ObligationState::Aborted,
                Some(EffectTerminalOutcome::Aborted)
            ) | (
                ObligationState::TerminallyFailed,
                Some(EffectTerminalOutcome::TerminallyFailed { .. })
            ) | (
                ObligationState::Escalated,
                Some(EffectTerminalOutcome::Escalated { .. })
            ) | (
                ObligationState::Committed | ObligationState::DeferredExternally,
                None
            )
        );
        if !terminal_matches {
            return Err(EffectJournalRefusal::TerminalOutcomeMismatch { effect_id });
        }
        record.obligation_state = state;
        record.budget_consumed = budget_consumed;
        record.output_commitments.clone_from(&output_commitments);
        if reconciliation_evidence.is_some() {
            record
                .reconciliation_evidence
                .clone_from(&reconciliation_evidence);
        }
        record.terminal_outcome = terminal_outcome;
        self.append(EffectJournalEvent::Lifecycle {
            effect_id,
            event,
            budget_consumed,
            output_commitments,
            reconciliation_evidence,
            terminal_outcome,
        });
        Ok(())
    }

    fn replay(entries: &[EffectJournalEntry]) -> Result<EffectJournalReplay, EffectJournalRefusal> {
        let mut journal = Self::default();
        for (index, entry) in entries.iter().enumerate() {
            let expected = u64::try_from(index).unwrap_or(u64::MAX);
            if entry.sequence != expected {
                return Err(EffectJournalRefusal::NonMonotonicSequence {
                    expected,
                    observed: entry.sequence,
                });
            }
            match &entry.event {
                EffectJournalEvent::Accepted(record) => journal.accept((**record).clone())?,
                EffectJournalEvent::BoundObligation {
                    effect_id,
                    obligation_class,
                    external_idempotency_key,
                } => journal.bind(*effect_id, *obligation_class, *external_idempotency_key)?,
                EffectJournalEvent::Lifecycle {
                    effect_id,
                    event,
                    budget_consumed,
                    output_commitments,
                    reconciliation_evidence,
                    terminal_outcome,
                } => journal.lifecycle(
                    *effect_id,
                    *event,
                    *budget_consumed,
                    output_commitments.clone(),
                    reconciliation_evidence.clone(),
                    *terminal_outcome,
                )?,
            }
        }
        Ok(EffectJournalReplay {
            records: journal.records,
        })
    }
}

/// An accepted effect: its initial record and live budget reservation.
///
/// A grant must be aborted through [`EffectBroker::abort`] or converted into a
/// typed obligation with [`EffectBroker::reserve_outbox`]. It intentionally
/// does not expose a raw [`BudgetGrant`], which would let a caller release
/// budget while leaving a misleading permanently-reserved record.
#[derive(Debug)]
pub struct EffectGrant {
    record: EffectRecord,
    budget: BudgetGrant,
    journal: Rc<RefCell<EffectJournal>>,
}

impl EffectGrant {
    /// The record produced by this acceptance.
    #[must_use]
    pub const fn record(&self) -> &EffectRecord {
        &self.record
    }

    fn into_parts(self) -> (EffectRecord, BudgetGrant, Rc<RefCell<EffectJournal>>) {
        let Self {
            record,
            budget,
            journal,
        } = self;
        (record, budget, journal)
    }
}

/// A live, typed outbox effect bound to one broker record.
#[must_use = "an external effect must be aborted, dispatched, or explicitly transferred"]
#[derive(Debug)]
pub struct ReservedOutboxEffect {
    effect_id: EffectId,
    idempotency_key: IdempotencyKey,
    idempotency_strength: DownstreamIdempotency,
    obligation: ReservedObligation<OutboxEffectPermit>,
    journal: Rc<RefCell<EffectJournal>>,
}

impl ReservedOutboxEffect {
    /// The stable effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> EffectId {
        self.effect_id
    }

    /// Aborts before any external dispatch happened.
    pub fn abort_unused(
        self,
        reason: DispatchAbortReason,
    ) -> Result<SettledObligation<OutboxEffectPermit>, EffectJournalRefusal> {
        let settled = self
            .obligation
            .abort_unused(fgit_resource::kinds::DispatchAbandoned { reason });
        self.journal.borrow_mut().lifecycle(
            self.effect_id,
            LifecycleEvent::Abort,
            ResourceVector::ZERO,
            Vec::new(),
            None,
            Some(EffectTerminalOutcome::Aborted),
        )?;
        Ok(settled)
    }

    /// Marks the effect canonically dispatched and hands it to reconciliation.
    pub fn dispatch(
        self,
        attempt: u32,
        actual: &ResourceVector,
    ) -> Result<DeferredOutboxEffect, Box<OutboxCommitRefused>> {
        let Self {
            effect_id,
            idempotency_key,
            idempotency_strength,
            obligation,
            journal,
        } = self;
        let committed = obligation
            .commit(EffectDispatched { attempt }, actual)
            .map_err(|refusal| {
                Box::new(OutboxCommitRefused::Resource(Box::new(
                    ResourceOutboxCommitRefusal {
                        effect_id,
                        idempotency_key,
                        idempotency_strength,
                        refusal,
                        journal: journal.clone(),
                    },
                )))
            })?;
        let commit_recorded = journal.borrow_mut().lifecycle(
            effect_id,
            LifecycleEvent::Commit,
            *actual,
            Vec::new(),
            None,
            None,
        );
        if let Err(source) = commit_recorded {
            let obligation = committed.defer_acknowledgement(DeferralReason::CancelledAfterCommit);
            return Err(Box::new(OutboxCommitRefused::JournalAfterCommit(Box::new(
                JournalOutboxCommitRefusal {
                    effect_id,
                    idempotency_key,
                    idempotency_strength,
                    obligation,
                    journal,
                    source,
                },
            ))));
        }
        let obligation = committed.defer_acknowledgement(DeferralReason::AwaitingObservation);
        let deferral_recorded = journal.borrow_mut().lifecycle(
            effect_id,
            LifecycleEvent::Defer,
            *actual,
            Vec::new(),
            None,
            None,
        );
        if let Err(source) = deferral_recorded {
            return Err(Box::new(OutboxCommitRefused::JournalAfterCommit(Box::new(
                JournalOutboxCommitRefusal {
                    effect_id,
                    idempotency_key,
                    idempotency_strength,
                    obligation,
                    journal,
                    source,
                },
            ))));
        }
        Ok(DeferredOutboxEffect {
            effect_id,
            idempotency_key,
            idempotency_strength,
            obligation,
            journal,
        })
    }
}

/// A dispatch whose acknowledgement must be reconciled before retry.
#[must_use = "a deferred external effect must be reconciled or escalated"]
#[derive(Debug)]
pub struct DeferredOutboxEffect {
    effect_id: EffectId,
    idempotency_key: IdempotencyKey,
    idempotency_strength: DownstreamIdempotency,
    obligation: UnacknowledgedEffect<OutboxEffectPermit>,
    journal: Rc<RefCell<EffectJournal>>,
}

impl DeferredOutboxEffect {
    /// Reconciles a crash/timeout window through the downstream's stable key.
    pub fn reconcile<C, E>(
        self,
        plan: &mut ReconcilePlan,
        channel: &mut C,
        owner: PrincipalId,
        acknowledgement: E,
        output_commitments: Vec<[u8; 32]>,
    ) -> Result<ExternalEffectOutcome, ReconciliationRefused>
    where
        C: DownstreamChannel,
        E: FnOnce(u32) -> DownstreamAck,
    {
        if plan.key() != self.idempotency_key || plan.idempotency() != self.idempotency_strength {
            return Err(ReconciliationRefused::WrongPlan {
                effect: Box::new(self),
            });
        }
        let Self {
            effect_id,
            idempotency_key: _,
            idempotency_strength,
            obligation,
            journal,
        } = self;
        let outcome = reconcile(obligation, plan, channel, owner, acknowledgement);
        let evidence = ReconciliationEvidence {
            downstream_idempotency: idempotency_strength,
            transitions: plan.transitions().to_vec(),
        };
        match outcome {
            ReconcileOutcome::Acknowledged(settled) => {
                journal
                    .borrow_mut()
                    .lifecycle(
                        effect_id,
                        LifecycleEvent::Acknowledge,
                        ResourceVector::ZERO,
                        output_commitments,
                        Some(evidence),
                        Some(EffectTerminalOutcome::Acknowledged),
                    )
                    .map_err(ReconciliationRefused::AfterSettlement)?;
                Ok(ExternalEffectOutcome::Acknowledged(settled))
            }
            ReconcileOutcome::TerminallyFailed(settled) => {
                let reason = match settled.evidence() {
                    fgit_resource::TerminalEvidence::TerminallyFailed(_, reason) => *reason,
                    fgit_resource::TerminalEvidence::Aborted(_)
                    | fgit_resource::TerminalEvidence::Acknowledged(_, _) => {
                        return Err(ReconciliationRefused::AfterSettlement(
                            EffectJournalRefusal::TerminalOutcomeMismatch { effect_id },
                        ));
                    }
                };
                journal
                    .borrow_mut()
                    .lifecycle(
                        effect_id,
                        LifecycleEvent::FailTerminally,
                        ResourceVector::ZERO,
                        output_commitments,
                        Some(evidence),
                        Some(EffectTerminalOutcome::TerminallyFailed { reason }),
                    )
                    .map_err(ReconciliationRefused::AfterSettlement)?;
                Ok(ExternalEffectOutcome::TerminallyFailed(settled))
            }
            ReconcileOutcome::Escalated(receipt) => {
                let terminal_outcome = EffectTerminalOutcome::Escalated {
                    owner: receipt.owner(),
                    reason: receipt.reason(),
                };
                journal
                    .borrow_mut()
                    .lifecycle(
                        effect_id,
                        LifecycleEvent::Escalate,
                        ResourceVector::ZERO,
                        output_commitments,
                        Some(evidence),
                        Some(terminal_outcome),
                    )
                    .map_err(ReconciliationRefused::AfterSettlement)?;
                Ok(ExternalEffectOutcome::Escalated(EscalatedOutboxEffect {
                    effect_id,
                    receipt,
                    journal,
                }))
            }
        }
    }
}

/// A named-owner outcome that remains outstanding until explicitly resolved.
#[must_use = "an escalated external effect must be resolved or reported at region close"]
#[derive(Debug)]
pub struct EscalatedOutboxEffect {
    effect_id: EffectId,
    receipt: EscalationReceipt<OutboxEffectPermit>,
    journal: Rc<RefCell<EffectJournal>>,
}

impl EscalatedOutboxEffect {
    /// Records a late downstream acknowledgement obtained by the named owner.
    pub fn resolve_acknowledged(
        self,
        acknowledgement: DownstreamAck,
        output_commitments: Vec<[u8; 32]>,
    ) -> Result<SettledObligation<OutboxEffectPermit>, EffectJournalRefusal> {
        let settled = self.receipt.resolve_acknowledged(acknowledgement);
        self.journal.borrow_mut().lifecycle(
            self.effect_id,
            LifecycleEvent::Acknowledge,
            ResourceVector::ZERO,
            output_commitments,
            None,
            Some(EffectTerminalOutcome::Acknowledged),
        )?;
        Ok(settled)
    }

    /// Records the named owner's permanent-failure decision.
    pub fn resolve_failed(
        self,
        reason: TerminalFailureReason,
        output_commitments: Vec<[u8; 32]>,
    ) -> Result<SettledObligation<OutboxEffectPermit>, EffectJournalRefusal> {
        let settled = self.receipt.resolve_failed(reason);
        self.journal.borrow_mut().lifecycle(
            self.effect_id,
            LifecycleEvent::FailTerminally,
            ResourceVector::ZERO,
            output_commitments,
            None,
            Some(EffectTerminalOutcome::TerminallyFailed { reason }),
        )?;
        Ok(settled)
    }
}

/// The result of external reconciliation.
#[must_use]
#[derive(Debug)]
pub enum ExternalEffectOutcome {
    /// A downstream observation settled the effect.
    Acknowledged(SettledObligation<OutboxEffectPermit>),
    /// The downstream permanently rejected the effect.
    TerminallyFailed(SettledObligation<OutboxEffectPermit>),
    /// Automation stopped with a named owner and explicit outstanding record.
    Escalated(EscalatedOutboxEffect),
}

/// A typed outbox-reservation refusal.
#[derive(Debug)]
pub enum OutboxReservationRefused {
    /// A non-external effect cannot be silently repurposed as an outbox effect.
    WrongEffectClass {
        /// The still-live grant the caller must resolve.
        grant: Box<EffectGrant>,
        /// The actual requested class.
        observed: EffectClass,
    },
    /// The resource layer rejected the typed reservation after the record was aborted.
    Resource {
        /// The effect whose reservation failed.
        effect_id: EffectId,
        /// The resource-layer refusal.
        source: Box<ReserveError>,
    },
    /// The append-only journal rejected an otherwise live grant.
    Journal {
        /// The still-live grant the caller must resolve.
        grant: Box<EffectGrant>,
        /// The journal refusal.
        source: EffectJournalRefusal,
    },
}

impl OutboxReservationRefused {
    /// Recovers the grant when no resource reservation was attempted.
    #[must_use]
    pub fn into_grant(self) -> Option<EffectGrant> {
        match self {
            Self::WrongEffectClass { grant, .. } | Self::Journal { grant, .. } => Some(*grant),
            Self::Resource { .. } => None,
        }
    }
}

impl fmt::Display for OutboxReservationRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongEffectClass { observed, .. } => write!(
                formatter,
                "only an external effect may reserve an outbox obligation; observed {observed}"
            ),
            Self::Resource { effect_id, source } => {
                write!(
                    formatter,
                    "outbox reservation for {effect_id} was refused: {source}"
                )
            }
            Self::Journal { source, .. } => {
                write!(formatter, "outbox reservation journal refusal: {source}")
            }
        }
    }
}

impl core::error::Error for OutboxReservationRefused {}

/// A failed dispatch still owning its live typed obligation.
#[must_use]
#[derive(Debug)]
pub enum OutboxCommitRefused {
    /// The shared resource ledger rejected the requested charge.
    Resource(Box<ResourceOutboxCommitRefusal>),
    /// The resource committed, but the broker journal could not mirror it.
    JournalAfterCommit(Box<JournalOutboxCommitRefusal>),
}

/// Resource-level dispatch refusal retaining the live reservation for recovery.
#[must_use]
#[derive(Debug)]
pub struct ResourceOutboxCommitRefusal {
    effect_id: EffectId,
    idempotency_key: IdempotencyKey,
    idempotency_strength: DownstreamIdempotency,
    refusal: SettlementRefused<OutboxEffectPermit>,
    journal: Rc<RefCell<EffectJournal>>,
}

/// Journal-mirror failure after a real dispatch committed.
#[must_use]
#[derive(Debug)]
pub struct JournalOutboxCommitRefusal {
    effect_id: EffectId,
    idempotency_key: IdempotencyKey,
    idempotency_strength: DownstreamIdempotency,
    obligation: UnacknowledgedEffect<OutboxEffectPermit>,
    journal: Rc<RefCell<EffectJournal>>,
    source: EffectJournalRefusal,
}

impl OutboxCommitRefused {
    /// Recovers the reservation on the resource-refusal path.
    #[must_use]
    pub fn into_reserved(self) -> Option<ReservedOutboxEffect> {
        match self {
            Self::Resource(refusal) => {
                let ResourceOutboxCommitRefusal {
                    effect_id,
                    idempotency_key,
                    idempotency_strength,
                    refusal,
                    journal,
                } = *refusal;
                Some(ReservedOutboxEffect {
                    effect_id,
                    idempotency_key,
                    idempotency_strength,
                    obligation: refusal.into_obligation(),
                    journal,
                })
            }
            Self::JournalAfterCommit(_) => None,
        }
    }

    /// Recovers the committed external effect when its journal mirror failed.
    #[must_use]
    pub fn into_deferred(self) -> Option<DeferredOutboxEffect> {
        match self {
            Self::Resource(_) => None,
            Self::JournalAfterCommit(refusal) => Some((*refusal).into_deferred()),
        }
    }
}

impl JournalOutboxCommitRefusal {
    /// The journal failure that must be reported alongside reconciliation.
    #[must_use]
    pub const fn source(&self) -> EffectJournalRefusal {
        self.source
    }

    /// Recovers the real deferred obligation; it must still be reconciled.
    pub fn into_deferred(self) -> DeferredOutboxEffect {
        DeferredOutboxEffect {
            effect_id: self.effect_id,
            idempotency_key: self.idempotency_key,
            idempotency_strength: self.idempotency_strength,
            obligation: self.obligation,
            journal: self.journal,
        }
    }
}

/// A reconciliation refusal which preserves the deferred effect for retry.
#[must_use]
#[derive(Debug)]
pub enum ReconciliationRefused {
    /// The caller supplied a plan for a different downstream contract.
    WrongPlan {
        /// The still-owned deferred effect.
        effect: Box<DeferredOutboxEffect>,
    },
    /// The resource effect settled but its journal mirror rejected the transition.
    AfterSettlement(EffectJournalRefusal),
}

impl ReconciliationRefused {
    /// Recovers the effect on the wrong-plan path.
    #[must_use]
    pub fn into_effect(self) -> Option<DeferredOutboxEffect> {
        match self {
            Self::WrongPlan { effect } => Some(*effect),
            Self::AfterSettlement(_) => None,
        }
    }
}

impl fmt::Display for ReconciliationRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPlan { .. } => formatter
                .write_str("reconciliation plan does not match the effect's downstream key"),
            Self::AfterSettlement(source) => {
                write!(
                    formatter,
                    "reconciliation settled but journal update failed: {source}"
                )
            }
        }
    }
}

impl core::error::Error for ReconciliationRefused {}

/// Authorizes effects for one run and owns its append-only effect journal.
#[derive(Debug)]
pub struct EffectBroker {
    run: IntentRun,
    agent_instance_id: AgentInstanceId,
    ledger: ObligationLedger,
    journal: Rc<RefCell<EffectJournal>>,
}

impl EffectBroker {
    /// Opens a broker over `run`, with the run's budget as region capacity.
    #[must_use]
    pub fn open(run: IntentRun, region: RegionId, agent_instance_id: AgentInstanceId) -> Self {
        let capacity = run.resource_budget();
        Self {
            run,
            agent_instance_id,
            ledger: ObligationLedger::root(region, LeakDisposition::RecordAndContinue, capacity),
            journal: Rc::new(RefCell::new(EffectJournal::default())),
        }
    }

    /// The run this broker serves.
    #[must_use]
    pub const fn run(&self) -> &IntentRun {
        &self.run
    }

    /// The concrete agent executor this broker records.
    #[must_use]
    pub const fn agent_instance_id(&self) -> AgentInstanceId {
        self.agent_instance_id
    }

    /// Every effect accepted so far, in acceptance order.
    #[must_use]
    pub fn records(&self) -> Vec<EffectRecord> {
        self.journal.borrow().records().to_vec()
    }

    /// The append-only event history for the current run.
    #[must_use]
    pub fn journal(&self) -> Vec<EffectJournalEntry> {
        self.journal.borrow().entries().to_vec()
    }

    /// Independently reconstructs the effect history from journal events.
    pub fn replay(
        entries: &[EffectJournalEntry],
    ) -> Result<EffectJournalReplay, EffectJournalRefusal> {
        EffectJournal::replay(entries)
    }

    /// Authorizes one effect and reserves its budget.
    ///
    /// Stable identity is checked before all other checks and before budget
    /// moves, so a duplicate cannot consume a second reservation.
    pub fn request(
        &mut self,
        capability: &Capability,
        now: LogicalTime,
        request: &EffectRequest,
    ) -> Result<EffectGrant, BrokerRefusal> {
        if self.journal.borrow().contains(request.effect_id) {
            return Err(BrokerRefusal::DuplicateEffectId {
                effect_id: request.effect_id,
            });
        }
        let run_commitment = self.run.commitment()?;
        if !self.run.is_open_at(now) {
            return Err(BrokerRefusal::RunExpired {
                now,
                expiry: self.run.expiry(),
            });
        }
        if !capability.is_valid_at(now) {
            return Err(BrokerRefusal::CapabilityNotValid {
                now,
                not_before: capability.not_before(),
                expires_at: capability.expires_at(),
            });
        }
        let allowed = self.run.allowed_operation_classes();
        if !allowed.contains(request.operation) {
            return Err(BrokerRefusal::OperationOutsideRun {
                requested: request.operation,
                allowed,
            });
        }
        let held = capability.operations();
        if !held.contains(request.operation) {
            return Err(BrokerRefusal::OperationOutsideCapability {
                requested: request.operation,
                held,
            });
        }
        if let Some(deficit) = capability.quota().first_deficit(&request.cost) {
            return Err(BrokerRefusal::CapabilityQuotaExceeded { deficit });
        }

        let budget = self
            .ledger
            .grant(request.cost)
            .map_err(|deficit| BrokerRefusal::BudgetExhausted { deficit })?;
        let record = EffectRecord {
            effect_id: request.effect_id,
            run_id: self.run.run_id(),
            run_commitment,
            agent_instance_id: self.agent_instance_id,
            parent_effect_id: request.parent_effect_id,
            capability_id: capability.id(),
            effect_class: EffectClass::for_operation(request.operation),
            operation: request.operation,
            input_commitment: request.input_commitment,
            source_authority_receipt: self.run.authority_read_receipt().cloned(),
            budget_reserved: request.cost,
            budget_consumed: ResourceVector::ZERO,
            external_idempotency_key: None,
            obligation_state: ObligationState::Reserved,
            obligation_class: None,
            terminal_outcome: None,
            output_commitments: Vec::new(),
            reconciliation_evidence: None,
            accepted_at: now,
        };
        self.journal
            .borrow_mut()
            .accept(record.clone())
            .map_err(|source| BrokerRefusal::Journal { source })?;
        Ok(EffectGrant {
            record,
            budget,
            journal: self.journal.clone(),
        })
    }

    /// Aborts an accepted effect before it becomes a more specific obligation.
    pub fn abort(&mut self, grant: EffectGrant) -> Result<ReleaseReceipt, EffectJournalRefusal> {
        let (record, budget, journal) = grant.into_parts();
        let receipt = budget.release();
        journal.borrow_mut().lifecycle(
            record.effect_id,
            LifecycleEvent::Abort,
            ResourceVector::ZERO,
            Vec::new(),
            None,
            Some(EffectTerminalOutcome::Aborted),
        )?;
        Ok(receipt)
    }

    /// Converts an external-effect grant into the shared outbox obligation.
    pub fn reserve_outbox(
        &mut self,
        grant: EffectGrant,
        dispatch: OutboxDispatch,
    ) -> Result<ReservedOutboxEffect, OutboxReservationRefused> {
        if grant.record.effect_class != EffectClass::ExternalEffect {
            return Err(OutboxReservationRefused::WrongEffectClass {
                observed: grant.record.effect_class,
                grant: Box::new(grant),
            });
        }
        let (record, budget, journal) = grant.into_parts();
        let binding = journal.borrow_mut().bind(
            record.effect_id,
            ObligationClass::OutboxEffectPermit,
            Some(dispatch.idempotency),
        );
        if let Err(source) = binding {
            return Err(OutboxReservationRefused::Journal {
                grant: Box::new(EffectGrant {
                    record,
                    budget,
                    journal,
                }),
                source,
            });
        }
        let idempotency_key = dispatch.idempotency;
        let idempotency_strength = dispatch.idempotency_strength;
        let obligation = match self.ledger.reserve(dispatch, budget) {
            Ok(obligation) => obligation,
            Err(source) => {
                let _ = journal.borrow_mut().lifecycle(
                    record.effect_id,
                    LifecycleEvent::Abort,
                    ResourceVector::ZERO,
                    Vec::new(),
                    None,
                    Some(EffectTerminalOutcome::Aborted),
                );
                return Err(OutboxReservationRefused::Resource {
                    effect_id: record.effect_id,
                    source: Box::new(source),
                });
            }
        };
        Ok(ReservedOutboxEffect {
            effect_id: record.effect_id,
            idempotency_key,
            idempotency_strength,
            obligation,
            journal,
        })
    }

    /// Closes the run's region, reporting quiescence or a containment failure.
    pub fn close(self) -> RegionCloseOutcome {
        self.ledger.close()
    }
}

/// Why the broker refused an effect.
#[derive(Debug)]
pub enum BrokerRefusal {
    /// The stable identity already has one accepted record.
    DuplicateEffectId {
        /// The repeated effect identity.
        effect_id: EffectId,
    },
    /// The complete run identity could not be produced.
    RunIdentity(IntentRunIdentityRefusal),
    /// The run's expiry has passed.
    RunExpired {
        /// The instant checked.
        now: LogicalTime,
        /// The run's expiry.
        expiry: LogicalTime,
    },
    /// The capability is not valid at this instant.
    CapabilityNotValid {
        /// The instant checked.
        now: LogicalTime,
        /// Start of the capability's window.
        not_before: LogicalTime,
        /// End of the capability's window.
        expires_at: LogicalTime,
    },
    /// The run does not allow this operation class at all.
    OperationOutsideRun {
        /// What was asked for.
        requested: OperationClass,
        /// What the run allows.
        allowed: ClassSet,
    },
    /// The run allows the class but the presented capability does not hold it.
    OperationOutsideCapability {
        /// What was asked for.
        requested: OperationClass,
        /// What the capability holds.
        held: ClassSet,
    },
    /// The effect costs more than the capability's own quota ceiling.
    CapabilityQuotaExceeded {
        /// The algebra's deficit, naming the grade and both amounts.
        deficit: fgit_resource::ResourceError,
    },
    /// The run's remaining budget cannot cover the effect.
    BudgetExhausted {
        /// The algebra's deficit, naming the grade and both amounts.
        deficit: fgit_resource::ResourceError,
    },
    /// The broker's own append-only journal rejected an acceptance.
    Journal {
        /// The journal refusal.
        source: EffectJournalRefusal,
    },
}

impl fmt::Display for BrokerRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateEffectId { effect_id } => write!(
                formatter,
                "effect {effect_id} is already registered and cannot reserve again"
            ),
            Self::RunIdentity(source) => {
                write!(formatter, "effect broker could not identify its run: {source}")
            }
            Self::RunExpired { now, expiry } => {
                write!(
                    formatter,
                    "intent run expired at {expiry}; effect requested at {now}"
                )
            }
            Self::CapabilityNotValid {
                now,
                not_before,
                expires_at,
            } => write!(
                formatter,
                "capability is valid over {not_before}..{expires_at}; effect requested at {now}"
            ),
            Self::OperationOutsideRun { requested, allowed } => write!(
                formatter,
                "the run does not allow {requested}; it allows {allowed}"
            ),
            Self::OperationOutsideCapability { requested, held } => write!(
                formatter,
                "the capability does not hold {requested}; it holds {held}"
            ),
            Self::CapabilityQuotaExceeded { deficit } => {
                write!(formatter, "effect exceeds the capability quota: {deficit}")
            }
            Self::BudgetExhausted { deficit } => {
                write!(
                    formatter,
                    "the run's budget cannot cover this effect: {deficit}"
                )
            }
            Self::Journal { source } => {
                write!(formatter, "effect journal refused acceptance: {source}")
            }
        }
    }
}

impl core::error::Error for BrokerRefusal {}

impl From<IntentRunIdentityRefusal> for BrokerRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

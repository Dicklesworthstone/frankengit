//! Deterministic reconciliation of every effect owned by one Intent Run.
//!
//! A task plan is not the ownership boundary for effects: one run may have
//! accepted work before the current task, delegated work to several agent
//! instances, or reached a later plan while an older external acknowledgement
//! remains unresolved. Reconciliation therefore inventories the complete run,
//! not merely the current [`crate::AgentChangePlan`].
//!
//! The report is inert. It aborts no reservation, probes no downstream,
//! resolves no escalation, and suppresses no leak. Instead it validates every
//! supplied [`crate::EffectRecord`], retains the complete record, assigns one
//! typed next action, and commits to the canonical result. Handoff and
//! cancellation can then preserve debt by identity rather than summarize it
//! away in prose.

use core::fmt;
use std::collections::BTreeMap;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, NativeObjectIdentity, Sha256};
use fgit_resource::settlement::{
    DeliveryVerdict, Observation, ProbeVerdict, ReconcileState, ReconcileTransition,
};
use fgit_resource::{
    DownstreamIdempotency, EscalationReason, GradeDisposition, ObligationClass,
    ObligationState, ResourceError, ResourceVector, TerminalFailureReason,
};

use crate::{
    AuthorityReadReceipt, EffectClass, EffectId, EffectRecord, EffectTerminalOutcome, IntentRun,
    LogicalTime, OperationClass, RunId,
};

/// Maximum effects accepted by one run-reconciliation report.
pub const MAX_RECONCILIATION_EFFECTS: usize = 4_096;
/// Maximum output commitments retained for one effect.
pub const MAX_EFFECT_OUTPUT_COMMITMENTS: usize = 1_024;
/// Maximum reconciliation transitions retained for one effect.
pub const MAX_EFFECT_RECONCILIATION_TRANSITIONS: usize = 2_048;
const REPORT_DOMAIN: &[u8] = b"frankengit.agent.run-reconciliation/v1\0";

/// Stable SHA-256 identity of one complete run-reconciliation report.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunReconciliationReportId([u8; 32]);

impl RunReconciliationReportId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RunReconciliationReportId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("run-reconciliation:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Exact action still required for one effect.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EffectResolutionAction {
    /// The effect is terminal and owns no remaining lifecycle debt.
    NoFurtherAction,
    /// A pre-commit reservation must be explicitly aborted or completed.
    AbortReservation,
    /// A committed or externally deferred effect needs downstream
    /// reconciliation before retry or completion.
    ReconcileCommittedEffect,
    /// Automation stopped and the named escalation must be resolved or
    /// explicitly transferred.
    ResolveEscalation,
    /// The lifecycle leaked. Completion is blocked by a containment failure.
    ContainLeak,
}

impl EffectResolutionAction {
    const fn code_point(self) -> u8 {
        match self {
            Self::NoFurtherAction => 1,
            Self::AbortReservation => 2,
            Self::ReconcileCommittedEffect => 3,
            Self::ResolveEscalation => 4,
            Self::ContainLeak => 5,
        }
    }
}

/// Highest-priority run-level action exposed by a reconciliation report.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RunReconciliationReadiness {
    /// Every effect is terminal and no containment failure exists.
    Ready,
    /// Only pre-commit reservations remain.
    ReservationAbortRequired,
    /// At least one committed/deferred effect still needs reconciliation.
    EffectReconciliationRequired,
    /// At least one unresolved escalation must remain visible to a named owner.
    EscalationResolutionRequired,
    /// At least one effect leaked; ordinary completion is forbidden.
    ContainmentFailure,
}

impl RunReconciliationReadiness {
    const fn code_point(self) -> u8 {
        match self {
            Self::Ready => 1,
            Self::ReservationAbortRequired => 2,
            Self::EffectReconciliationRequired => 3,
            Self::EscalationResolutionRequired => 4,
            Self::ContainmentFailure => 5,
        }
    }
}

/// Compact lifecycle accounting that never hides a terminal failure or debt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RunReconciliationCounts {
    reserved: u32,
    committed_or_deferred: u32,
    escalated: u32,
    acknowledged: u32,
    aborted: u32,
    terminally_failed: u32,
    leaked: u32,
}

impl RunReconciliationCounts {
    /// Pre-commit reservations.
    #[must_use]
    pub const fn reserved(self) -> u32 {
        self.reserved
    }

    /// Committed or externally deferred effects awaiting a definite outcome.
    #[must_use]
    pub const fn committed_or_deferred(self) -> u32 {
        self.committed_or_deferred
    }

    /// Effects whose automation stopped and named an owner.
    #[must_use]
    pub const fn escalated(self) -> u32 {
        self.escalated
    }

    /// Effects acknowledged by their recipient.
    #[must_use]
    pub const fn acknowledged(self) -> u32 {
        self.acknowledged
    }

    /// Reservations explicitly abandoned before commit.
    #[must_use]
    pub const fn aborted(self) -> u32 {
        self.aborted
    }

    /// Effects proved permanently undeliverable.
    #[must_use]
    pub const fn terminally_failed(self) -> u32 {
        self.terminally_failed
    }

    /// Effects dropped without resolution.
    #[must_use]
    pub const fn leaked(self) -> u32 {
        self.leaked
    }

    /// Effects still carrying lifecycle debt.
    #[must_use]
    pub const fn unsettled(self) -> u32 {
        self.reserved + self.committed_or_deferred + self.escalated + self.leaked
    }

    /// Every effect represented by the report.
    #[must_use]
    pub const fn total(self) -> u32 {
        self.unsettled()
            + self.acknowledged
            + self.aborted
            + self.terminally_failed
    }
}

/// One complete effect record plus its derived next action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciledEffect {
    record: EffectRecord,
    required_action: EffectResolutionAction,
}

impl ReconciledEffect {
    /// Complete broker record; no debt-bearing detail is summarized away.
    #[must_use]
    pub const fn record(&self) -> &EffectRecord {
        &self.record
    }

    /// Exact lifecycle action still required.
    #[must_use]
    pub const fn required_action(&self) -> EffectResolutionAction {
        self.required_action
    }
}

/// Deterministic, authority-bound inventory of one run's complete effect set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunReconciliationReport {
    report_id: RunReconciliationReportId,
    run_id: RunId,
    authority_read_receipt: AuthorityReadReceipt,
    observed_at: LogicalTime,
    run_open_at_observation: bool,
    effects: Vec<ReconciledEffect>,
    counts: RunReconciliationCounts,
    readiness: RunReconciliationReadiness,
    cumulative_budget_reserved: ResourceVector,
    cumulative_budget_consumed: ResourceVector,
}

impl RunReconciliationReport {
    /// Builds a bounded report from current broker records.
    ///
    /// Records are treated as the complete effect inventory for `run`. The
    /// caller should obtain them from [`crate::EffectBroker::records`] or a
    /// successfully replayed journal. Input order is not trusted and does not
    /// affect the report identity.
    ///
    /// # Errors
    ///
    /// Refuses legacy authority, mixed runs or authority positions, future or
    /// out-of-window acceptances, duplicate identities, malformed lifecycle
    /// terminal markers, operation/effect-class disagreement, invalid resource
    /// accounting, unbounded output/reconciliation evidence, missing or cyclic
    /// parent effects, cumulative consumable spend beyond the run, and
    /// unrepresentable canonical framing.
    pub fn build(
        run: &IntentRun,
        mut records: Vec<EffectRecord>,
        observed_at: LogicalTime,
    ) -> Result<Self, RunReconciliationRefusal> {
        let authority_read_receipt = run
            .authority_read_receipt()
            .ok_or(RunReconciliationRefusal::RunAuthorityReceiptRequired)?
            .clone();
        if observed_at < authority_read_receipt.verified_at_logical_time() {
            return Err(
                RunReconciliationRefusal::ObservationBeforeAuthorityVerification {
                    observed: observed_at,
                    verified: authority_read_receipt.verified_at_logical_time(),
                },
            );
        }
        if records.len() > MAX_RECONCILIATION_EFFECTS {
            return Err(RunReconciliationRefusal::TooManyEffects {
                observed: records.len(),
                limit: MAX_RECONCILIATION_EFFECTS,
            });
        }

        records.sort_unstable_by_key(|record| record.effect_id);
        for adjacent in records.windows(2) {
            if adjacent[0].effect_id == adjacent[1].effect_id {
                return Err(RunReconciliationRefusal::DuplicateEffectId {
                    effect_id: adjacent[0].effect_id,
                });
            }
        }

        let index_by_id: BTreeMap<EffectId, usize> = records
            .iter()
            .enumerate()
            .map(|(index, record)| (record.effect_id, index))
            .collect();

        let mut effects = Vec::with_capacity(records.len());
        let mut counts = RunReconciliationCounts::default();
        let mut cumulative_budget_reserved = ResourceVector::ZERO;
        let mut cumulative_budget_consumed = ResourceVector::ZERO;

        for record in records {
            validate_record(
                run,
                &authority_read_receipt,
                observed_at,
                &index_by_id,
                &effects,
                &record,
            )?;
            let required_action = classify_record(&record)?;
            update_counts(&mut counts, record.obligation_state);
            cumulative_budget_reserved = cumulative_budget_reserved
                .combine(&record.budget_reserved)
                .map_err(|source| RunReconciliationRefusal::ResourceTotalOverflow {
                    field: "cumulative_budget_reserved",
                    source,
                })?;
            cumulative_budget_consumed = cumulative_budget_consumed
                .combine(&record.budget_consumed)
                .map_err(|source| RunReconciliationRefusal::ResourceTotalOverflow {
                    field: "cumulative_budget_consumed",
                    source,
                })?;
            effects.push(ReconciledEffect {
                record,
                required_action,
            });
        }

        validate_parent_graph(&effects, &index_by_id)?;

        let consumable_budget = run
            .resource_budget()
            .mask(GradeDisposition::Consumable);
        let consumable_spend = cumulative_budget_consumed.mask(GradeDisposition::Consumable);
        if let Some(deficit) = consumable_budget.first_deficit(&consumable_spend) {
            return Err(
                RunReconciliationRefusal::ConsumableBudgetExceedsRun { deficit },
            );
        }

        let readiness = readiness(counts);
        let run_open_at_observation = run.is_open_at(observed_at);
        let mut report = Self {
            report_id: RunReconciliationReportId([0; 32]),
            run_id: run.run_id(),
            authority_read_receipt,
            observed_at,
            run_open_at_observation,
            effects,
            counts,
            readiness,
            cumulative_budget_reserved,
            cumulative_budget_consumed,
        };
        report.report_id = RunReconciliationReportId(report_commitment(&report)?);
        Ok(report)
    }

    /// Stable report identity.
    #[must_use]
    pub const fn report_id(&self) -> RunReconciliationReportId {
        self.report_id
    }

    /// Run whose complete effect inventory is represented.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Exact authenticated repository position shared by every effect record.
    #[must_use]
    pub const fn authority_read_receipt(&self) -> &AuthorityReadReceipt {
        &self.authority_read_receipt
    }

    /// Logical instant at which this inventory was assembled.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// Whether the run was still open at the report observation instant.
    #[must_use]
    pub const fn run_open_at_observation(&self) -> bool {
        self.run_open_at_observation
    }

    /// Effects in stable effect-identity order.
    #[must_use]
    pub fn effects(&self) -> &[ReconciledEffect] {
        &self.effects
    }

    /// Compact lifecycle accounting.
    #[must_use]
    pub const fn counts(&self) -> RunReconciliationCounts {
        self.counts
    }

    /// Highest-priority action blocking ordinary completion.
    #[must_use]
    pub const fn readiness(&self) -> RunReconciliationReadiness {
        self.readiness
    }

    /// Sum of original reservations across the historical effect set.
    ///
    /// This is cumulative history, not current pool occupancy; returnable
    /// capacity may have been reused between effects.
    #[must_use]
    pub const fn cumulative_budget_reserved(&self) -> ResourceVector {
        self.cumulative_budget_reserved
    }

    /// Sum of final per-effect charges across the historical effect set.
    #[must_use]
    pub const fn cumulative_budget_consumed(&self) -> ResourceVector {
        self.cumulative_budget_consumed
    }

    /// Whether any effect still carries lifecycle debt or containment failure.
    #[must_use]
    pub const fn has_unsettled_effects(&self) -> bool {
        self.counts.unsettled() != 0
    }
}

/// Why a run reconciliation report failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunReconciliationRefusal {
    /// The run uses only a legacy identifying basis.
    RunAuthorityReceiptRequired,
    /// Observation predates authentication of the run's authority receipt.
    ObservationBeforeAuthorityVerification {
        /// Proposed observation time.
        observed: LogicalTime,
        /// Authority verification time.
        verified: LogicalTime,
    },
    /// Effect inventory exceeded its hard ceiling.
    TooManyEffects {
        /// Effects supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// One effect identity appeared more than once.
    DuplicateEffectId {
        /// Repeated effect.
        effect_id: EffectId,
    },
    /// Effect belongs to another run.
    EffectRunMismatch {
        /// Effect being checked.
        effect_id: EffectId,
        /// Expected run.
        expected: RunId,
        /// Recorded run.
        observed: RunId,
    },
    /// Effect omitted its complete authority receipt.
    EffectAuthorityReceiptRequired {
        /// Effect being checked.
        effect_id: EffectId,
    },
    /// Effect was accepted under another authority position.
    EffectAuthorityMismatch {
        /// Effect being checked.
        effect_id: EffectId,
    },
    /// Effect operation is outside the run.
    OperationOutsideRun {
        /// Effect being checked.
        effect_id: EffectId,
        /// Requested operation.
        operation: OperationClass,
    },
    /// Recorded effect class disagrees with the operation class.
    EffectClassMismatch {
        /// Effect being checked.
        effect_id: EffectId,
        /// Class implied by the operation.
        expected: EffectClass,
        /// Class recorded by the broker row.
        observed: EffectClass,
    },
    /// Effect predates authentication of the authority receipt.
    EffectAcceptedBeforeAuthorityVerification {
        /// Effect being checked.
        effect_id: EffectId,
        /// Acceptance time.
        accepted_at: LogicalTime,
        /// Authority verification time.
        verified_at: LogicalTime,
    },
    /// Effect appears to have been accepted after the report observation.
    EffectAcceptedAfterObservation {
        /// Effect being checked.
        effect_id: EffectId,
        /// Acceptance time.
        accepted_at: LogicalTime,
        /// Report observation time.
        observed_at: LogicalTime,
    },
    /// Effect acceptance lies outside the run's exclusive time window.
    EffectAcceptedOutsideRun {
        /// Effect being checked.
        effect_id: EffectId,
        /// Acceptance time.
        accepted_at: LogicalTime,
        /// Run expiry.
        run_expiry: LogicalTime,
    },
    /// One effect retained too many output commitments.
    TooManyOutputCommitments {
        /// Effect being checked.
        effect_id: EffectId,
        /// Commitments supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// One effect retained too many reconciliation transitions.
    TooManyReconciliationTransitions {
        /// Effect being checked.
        effect_id: EffectId,
        /// Transitions supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// Per-effect charged resources exceed its reservation.
    EffectChargeExceedsReservation {
        /// Effect being checked.
        effect_id: EffectId,
        /// First deficient grade.
        deficit: ResourceError,
    },
    /// External-only metadata appeared on another effect class.
    ExternalMetadataOnNonExternal {
        /// Effect being checked.
        effect_id: EffectId,
    },
    /// Reconciliation evidence exists without an idempotency key.
    ReconciliationEvidenceWithoutIdempotency {
        /// Effect being checked.
        effect_id: EffectId,
    },
    /// Lifecycle state and terminal marker disagree.
    TerminalStateMismatch {
        /// Effect being checked.
        effect_id: EffectId,
        /// Lifecycle state observed.
        state: ObligationState,
    },
    /// Parent effect is absent from this complete run inventory.
    MissingParentEffect {
        /// Child effect.
        effect_id: EffectId,
        /// Missing parent.
        parent_effect_id: EffectId,
    },
    /// Effect names itself as parent.
    SelfParentEffect {
        /// Invalid effect.
        effect_id: EffectId,
    },
    /// Parent was accepted after its child.
    ParentAcceptedAfterChild {
        /// Child effect.
        effect_id: EffectId,
        /// Parent effect.
        parent_effect_id: EffectId,
    },
    /// Parent links contain a cycle.
    ParentCycle {
        /// Effect at which the cycle was detected.
        effect_id: EffectId,
    },
    /// Summing cumulative resource history overflowed one grade.
    ResourceTotalOverflow {
        /// Aggregate field.
        field: &'static str,
        /// Resource algebra refusal.
        source: ResourceError,
    },
    /// Cumulative consumable spend exceeds the run's conserved budget.
    ConsumableBudgetExceedsRun {
        /// First deficient grade.
        deficit: ResourceError,
    },
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for RunReconciliationRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunAuthorityReceiptRequired => formatter.write_str(
                "run reconciliation requires a complete authenticated authority receipt",
            ),
            Self::ObservationBeforeAuthorityVerification { observed, verified } => write!(
                formatter,
                "reconciliation observed at {observed} before authority verification at {verified}"
            ),
            Self::TooManyEffects { observed, limit } => {
                write!(formatter, "effect inventory has {observed} rows, limit {limit}")
            }
            Self::DuplicateEffectId { effect_id } => {
                write!(formatter, "effect inventory repeats {effect_id}")
            }
            Self::EffectRunMismatch {
                effect_id,
                expected,
                observed,
            } => write!(
                formatter,
                "effect {effect_id} belongs to run {observed}, expected {expected}"
            ),
            Self::EffectAuthorityReceiptRequired { effect_id } => write!(
                formatter,
                "effect {effect_id} has no complete authenticated authority receipt"
            ),
            Self::EffectAuthorityMismatch { effect_id } => {
                write!(formatter, "effect {effect_id} belongs to another authority position")
            }
            Self::OperationOutsideRun {
                effect_id,
                operation,
            } => write!(
                formatter,
                "effect {effect_id} operation {operation} is outside the run"
            ),
            Self::EffectClassMismatch {
                effect_id,
                expected,
                observed,
            } => write!(
                formatter,
                "effect {effect_id} records class {observed}, expected {expected}"
            ),
            Self::EffectAcceptedBeforeAuthorityVerification {
                effect_id,
                accepted_at,
                verified_at,
            } => write!(
                formatter,
                "effect {effect_id} accepted at {accepted_at} before authority verification {verified_at}"
            ),
            Self::EffectAcceptedAfterObservation {
                effect_id,
                accepted_at,
                observed_at,
            } => write!(
                formatter,
                "effect {effect_id} accepted at {accepted_at} after report observation {observed_at}"
            ),
            Self::EffectAcceptedOutsideRun {
                effect_id,
                accepted_at,
                run_expiry,
            } => write!(
                formatter,
                "effect {effect_id} accepted at {accepted_at} outside run expiry {run_expiry}"
            ),
            Self::TooManyOutputCommitments {
                effect_id,
                observed,
                limit,
            } => write!(
                formatter,
                "effect {effect_id} has {observed} output commitments, limit {limit}"
            ),
            Self::TooManyReconciliationTransitions {
                effect_id,
                observed,
                limit,
            } => write!(
                formatter,
                "effect {effect_id} has {observed} reconciliation transitions, limit {limit}"
            ),
            Self::EffectChargeExceedsReservation { effect_id, deficit } => write!(
                formatter,
                "effect {effect_id} charge exceeds its reservation: {deficit}"
            ),
            Self::ExternalMetadataOnNonExternal { effect_id } => write!(
                formatter,
                "non-external effect {effect_id} carries external-effect metadata"
            ),
            Self::ReconciliationEvidenceWithoutIdempotency { effect_id } => write!(
                formatter,
                "effect {effect_id} carries reconciliation evidence without an idempotency key"
            ),
            Self::TerminalStateMismatch { effect_id, state } => write!(
                formatter,
                "effect {effect_id} lifecycle state {state:?} disagrees with its terminal marker"
            ),
            Self::MissingParentEffect {
                effect_id,
                parent_effect_id,
            } => write!(
                formatter,
                "effect {effect_id} names absent parent {parent_effect_id}"
            ),
            Self::SelfParentEffect { effect_id } => {
                write!(formatter, "effect {effect_id} names itself as parent")
            }
            Self::ParentAcceptedAfterChild {
                effect_id,
                parent_effect_id,
            } => write!(
                formatter,
                "effect {effect_id} predates parent {parent_effect_id}"
            ),
            Self::ParentCycle { effect_id } => {
                write!(formatter, "effect parent graph contains a cycle at {effect_id}")
            }
            Self::ResourceTotalOverflow { field, source } => {
                write!(formatter, "{field} overflowed: {source}")
            }
            Self::ConsumableBudgetExceedsRun { deficit } => write!(
                formatter,
                "cumulative consumable effect spend exceeds the run budget: {deficit}"
            ),
            Self::Codec(refusal) => {
                write!(formatter, "run reconciliation framing refused: {refusal}")
            }
        }
    }
}

impl core::error::Error for RunReconciliationRefusal {}

impl From<CodecRefusal> for RunReconciliationRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_record(
    run: &IntentRun,
    authority: &AuthorityReadReceipt,
    observed_at: LogicalTime,
    index_by_id: &BTreeMap<EffectId, usize>,
    prior_effects: &[ReconciledEffect],
    record: &EffectRecord,
) -> Result<(), RunReconciliationRefusal> {
    if record.run_id != run.run_id() {
        return Err(RunReconciliationRefusal::EffectRunMismatch {
            effect_id: record.effect_id,
            expected: run.run_id(),
            observed: record.run_id,
        });
    }
    match record.source_authority_receipt.as_ref() {
        None => {
            return Err(RunReconciliationRefusal::EffectAuthorityReceiptRequired {
                effect_id: record.effect_id,
            });
        }
        Some(record_authority) if record_authority != authority => {
            return Err(RunReconciliationRefusal::EffectAuthorityMismatch {
                effect_id: record.effect_id,
            });
        }
        Some(_) => {}
    }
    if !run.allowed_operation_classes().contains(record.operation) {
        return Err(RunReconciliationRefusal::OperationOutsideRun {
            effect_id: record.effect_id,
            operation: record.operation,
        });
    }
    let expected_effect_class = effect_class_for(record.operation);
    if record.effect_class != expected_effect_class {
        return Err(RunReconciliationRefusal::EffectClassMismatch {
            effect_id: record.effect_id,
            expected: expected_effect_class,
            observed: record.effect_class,
        });
    }
    if record.accepted_at < authority.verified_at_logical_time() {
        return Err(
            RunReconciliationRefusal::EffectAcceptedBeforeAuthorityVerification {
                effect_id: record.effect_id,
                accepted_at: record.accepted_at,
                verified_at: authority.verified_at_logical_time(),
            },
        );
    }
    if record.accepted_at > observed_at {
        return Err(RunReconciliationRefusal::EffectAcceptedAfterObservation {
            effect_id: record.effect_id,
            accepted_at: record.accepted_at,
            observed_at,
        });
    }
    if !run.is_open_at(record.accepted_at) {
        return Err(RunReconciliationRefusal::EffectAcceptedOutsideRun {
            effect_id: record.effect_id,
            accepted_at: record.accepted_at,
            run_expiry: run.expiry(),
        });
    }
    if record.output_commitments.len() > MAX_EFFECT_OUTPUT_COMMITMENTS {
        return Err(RunReconciliationRefusal::TooManyOutputCommitments {
            effect_id: record.effect_id,
            observed: record.output_commitments.len(),
            limit: MAX_EFFECT_OUTPUT_COMMITMENTS,
        });
    }
    if let Some(evidence) = &record.reconciliation_evidence {
        if evidence.transitions.len() > MAX_EFFECT_RECONCILIATION_TRANSITIONS {
            return Err(
                RunReconciliationRefusal::TooManyReconciliationTransitions {
                    effect_id: record.effect_id,
                    observed: evidence.transitions.len(),
                    limit: MAX_EFFECT_RECONCILIATION_TRANSITIONS,
                },
            );
        }
        if record.external_idempotency_key.is_none() {
            return Err(
                RunReconciliationRefusal::ReconciliationEvidenceWithoutIdempotency {
                    effect_id: record.effect_id,
                },
            );
        }
    }
    if record.effect_class != EffectClass::ExternalEffect
        && (record.external_idempotency_key.is_some()
            || record.reconciliation_evidence.is_some())
    {
        return Err(RunReconciliationRefusal::ExternalMetadataOnNonExternal {
            effect_id: record.effect_id,
        });
    }
    if let Some(deficit) = record
        .budget_reserved
        .first_deficit(&record.budget_consumed)
    {
        return Err(RunReconciliationRefusal::EffectChargeExceedsReservation {
            effect_id: record.effect_id,
            deficit,
        });
    }
    if let Some(parent_effect_id) = record.parent_effect_id {
        if parent_effect_id == record.effect_id {
            return Err(RunReconciliationRefusal::SelfParentEffect {
                effect_id: record.effect_id,
            });
        }
        let parent_index = index_by_id.get(&parent_effect_id).copied().ok_or(
            RunReconciliationRefusal::MissingParentEffect {
                effect_id: record.effect_id,
                parent_effect_id,
            },
        )?;
        let parent = prior_effects
            .get(parent_index)
            .map(ReconciledEffect::record);
        if let Some(parent) = parent
            && parent.accepted_at > record.accepted_at
        {
            return Err(RunReconciliationRefusal::ParentAcceptedAfterChild {
                effect_id: record.effect_id,
                parent_effect_id,
            });
        }
    }
    Ok(())
}

fn validate_parent_graph(
    effects: &[ReconciledEffect],
    index_by_id: &BTreeMap<EffectId, usize>,
) -> Result<(), RunReconciliationRefusal> {
    for effect in effects {
        if let Some(parent_effect_id) = effect.record.parent_effect_id {
            let parent_index = index_by_id.get(&parent_effect_id).copied().ok_or(
                RunReconciliationRefusal::MissingParentEffect {
                    effect_id: effect.record.effect_id,
                    parent_effect_id,
                },
            )?;
            let parent = &effects[parent_index].record;
            if parent.accepted_at > effect.record.accepted_at {
                return Err(RunReconciliationRefusal::ParentAcceptedAfterChild {
                    effect_id: effect.record.effect_id,
                    parent_effect_id,
                });
            }
        }
    }

    let mut colors = vec![0_u8; effects.len()];
    for start in 0..effects.len() {
        if colors[start] != 0 {
            continue;
        }
        let mut path = Vec::new();
        let mut cursor = Some(start);
        while let Some(index) = cursor {
            match colors[index] {
                0 => {
                    colors[index] = 1;
                    path.push(index);
                    cursor = effects[index]
                        .record
                        .parent_effect_id
                        .and_then(|parent| index_by_id.get(&parent).copied());
                }
                1 => {
                    return Err(RunReconciliationRefusal::ParentCycle {
                        effect_id: effects[index].record.effect_id,
                    });
                }
                _ => break,
            }
        }
        for index in path {
            colors[index] = 2;
        }
    }
    Ok(())
}

fn classify_record(
    record: &EffectRecord,
) -> Result<EffectResolutionAction, RunReconciliationRefusal> {
    let action = match (record.obligation_state, record.terminal_outcome) {
        (ObligationState::Reserved, None) => EffectResolutionAction::AbortReservation,
        (ObligationState::Committed | ObligationState::DeferredExternally, None) => {
            EffectResolutionAction::ReconcileCommittedEffect
        }
        (
            ObligationState::Escalated,
            Some(EffectTerminalOutcome::Escalated { .. }),
        ) => EffectResolutionAction::ResolveEscalation,
        (
            ObligationState::Acknowledged,
            Some(EffectTerminalOutcome::Acknowledged),
        )
        | (ObligationState::Aborted, Some(EffectTerminalOutcome::Aborted))
        | (
            ObligationState::TerminallyFailed,
            Some(EffectTerminalOutcome::TerminallyFailed { .. }),
        ) => EffectResolutionAction::NoFurtherAction,
        (ObligationState::Leaked, None) => EffectResolutionAction::ContainLeak,
        _ => {
            return Err(RunReconciliationRefusal::TerminalStateMismatch {
                effect_id: record.effect_id,
                state: record.obligation_state,
            });
        }
    };
    Ok(action)
}

fn update_counts(counts: &mut RunReconciliationCounts, state: ObligationState) {
    match state {
        ObligationState::Reserved => counts.reserved += 1,
        ObligationState::Committed | ObligationState::DeferredExternally => {
            counts.committed_or_deferred += 1;
        }
        ObligationState::Escalated => counts.escalated += 1,
        ObligationState::Acknowledged => counts.acknowledged += 1,
        ObligationState::Aborted => counts.aborted += 1,
        ObligationState::TerminallyFailed => counts.terminally_failed += 1,
        ObligationState::Leaked => counts.leaked += 1,
    }
}

const fn readiness(counts: RunReconciliationCounts) -> RunReconciliationReadiness {
    if counts.leaked != 0 {
        RunReconciliationReadiness::ContainmentFailure
    } else if counts.escalated != 0 {
        RunReconciliationReadiness::EscalationResolutionRequired
    } else if counts.committed_or_deferred != 0 {
        RunReconciliationReadiness::EffectReconciliationRequired
    } else if counts.reserved != 0 {
        RunReconciliationReadiness::ReservationAbortRequired
    } else {
        RunReconciliationReadiness::Ready
    }
}

const fn effect_class_for(operation: OperationClass) -> EffectClass {
    match operation {
        OperationClass::ReadCanonicalObject => EffectClass::PureCanonicalRead,
        OperationClass::CreateCandidateObject => EffectClass::ImmutableCandidateCreation,
        OperationClass::PreparePublication => EffectClass::PreparedCanonicalMutation,
        OperationClass::SubmitEvidence | OperationClass::MutateForgeEntity => {
            EffectClass::CanonicalMutation
        }
        OperationClass::ExternalIntegration => EffectClass::ExternalEffect,
        OperationClass::ReadDerivedGeneration
        | OperationClass::TreeFsWorkspace
        | OperationClass::ExecuteSandboxedProcess
        | OperationClass::NetworkDestination
        | OperationClass::SecretHandle
        | OperationClass::DelegateSubIntent
        | OperationClass::ConsumeBudget => EffectClass::DerivedLocalWrite,
    }
}

fn report_commitment(
    report: &RunReconciliationReport,
) -> Result<[u8; 32], RunReconciliationRefusal> {
    let mut encoder = Encoder::with_capacity(1_024 + report.effects.len() * 512);
    encoder.write_bytes("run_reconciliation_domain", REPORT_DOMAIN)?;
    encoder.write_raw(&report.run_id.value().to_be_bytes());
    write_authority_receipt(&mut encoder, &report.authority_read_receipt)?;
    encoder.write_scalar(report.observed_at.value());
    encoder.write_bool(report.run_open_at_observation);
    encoder.write_raw_byte(report.readiness.code_point());
    write_counts(&mut encoder, report.counts);
    write_resource_vector(&mut encoder, report.cumulative_budget_reserved);
    write_resource_vector(&mut encoder, report.cumulative_budget_consumed);
    write_count(&mut encoder, "run_reconciliation.effects", report.effects.len())?;
    for effect in &report.effects {
        write_effect(&mut encoder, effect)?;
    }
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}

fn write_effect(
    encoder: &mut Encoder,
    effect: &ReconciledEffect,
) -> Result<(), RunReconciliationRefusal> {
    let record = &effect.record;
    encoder.write_raw(&record.effect_id.value().to_be_bytes());
    encoder.write_raw(&record.run_id.value().to_be_bytes());
    encoder.write_raw(&record.agent_instance_id.value().to_be_bytes());
    match record.parent_effect_id {
        Some(parent) => {
            encoder.write_bool(true);
            encoder.write_raw(&parent.value().to_be_bytes());
        }
        None => encoder.write_bool(false),
    }
    encoder.write_raw(&record.capability_id.value().to_be_bytes());
    encoder.write_raw_byte(effect_class_code(record.effect_class));
    encoder.write_raw_byte(operation_class_code(record.operation));
    encoder.write_raw(&record.input_commitment);
    write_resource_vector(encoder, record.budget_reserved);
    write_resource_vector(encoder, record.budget_consumed);
    match record.external_idempotency_key {
        Some(key) => {
            encoder.write_bool(true);
            encoder.write_digest(&key.digest())?;
        }
        None => encoder.write_bool(false),
    }
    encoder.write_raw_byte(obligation_state_code(record.obligation_state));
    match record.obligation_class {
        Some(class) => {
            encoder.write_bool(true);
            encoder.write_raw_byte(obligation_class_code(class));
        }
        None => encoder.write_bool(false),
    }
    write_terminal_outcome(encoder, record.terminal_outcome);
    write_count(
        encoder,
        "run_reconciliation.effect_outputs",
        record.output_commitments.len(),
    )?;
    for commitment in &record.output_commitments {
        encoder.write_raw(commitment);
    }
    match &record.reconciliation_evidence {
        Some(evidence) => {
            encoder.write_bool(true);
            encoder.write_raw_byte(downstream_idempotency_code(
                evidence.downstream_idempotency,
            ));
            write_count(
                encoder,
                "run_reconciliation.transitions",
                evidence.transitions.len(),
            )?;
            for transition in &evidence.transitions {
                write_reconcile_transition(encoder, *transition);
            }
        }
        None => encoder.write_bool(false),
    }
    encoder.write_scalar(record.accepted_at.value());
    encoder.write_raw_byte(effect.required_action.code_point());
    Ok(())
}

fn write_terminal_outcome(
    encoder: &mut Encoder,
    outcome: Option<EffectTerminalOutcome>,
) {
    match outcome {
        None => encoder.write_bool(false),
        Some(EffectTerminalOutcome::Acknowledged) => {
            encoder.write_bool(true);
            encoder.write_raw_byte(1);
        }
        Some(EffectTerminalOutcome::Aborted) => {
            encoder.write_bool(true);
            encoder.write_raw_byte(2);
        }
        Some(EffectTerminalOutcome::TerminallyFailed { reason }) => {
            encoder.write_bool(true);
            encoder.write_raw_byte(3);
            encoder.write_raw_byte(terminal_failure_code(reason));
        }
        Some(EffectTerminalOutcome::Escalated { owner, reason }) => {
            encoder.write_bool(true);
            encoder.write_raw_byte(4);
            encoder.write_opaque_id(owner.as_bytes());
            encoder.write_raw_byte(escalation_reason_code(reason));
        }
    }
}

fn write_reconcile_transition(encoder: &mut Encoder, transition: ReconcileTransition) {
    write_reconcile_state(encoder, transition.from());
    write_observation(encoder, transition.observation());
    write_reconcile_state(encoder, transition.to());
}

fn write_reconcile_state(encoder: &mut Encoder, state: ReconcileState) {
    match state {
        ReconcileState::Pending { attempt } => {
            encoder.write_raw_byte(1);
            encoder.write_scalar(attempt);
        }
        ReconcileState::Probing { attempt } => {
            encoder.write_raw_byte(2);
            encoder.write_scalar(attempt);
        }
        ReconcileState::Delivered { attempt } => {
            encoder.write_raw_byte(3);
            encoder.write_scalar(attempt);
        }
        ReconcileState::Undeliverable { reason } => {
            encoder.write_raw_byte(4);
            encoder.write_raw_byte(terminal_failure_code(reason));
        }
        ReconcileState::Indeterminate { reason } => {
            encoder.write_raw_byte(5);
            encoder.write_raw_byte(escalation_reason_code(reason));
        }
    }
}

fn write_observation(encoder: &mut Encoder, observation: Observation) {
    match observation {
        Observation::Delivery(verdict) => {
            encoder.write_raw_byte(1);
            encoder.write_raw_byte(delivery_verdict_code(verdict));
        }
        Observation::Probe(verdict) => {
            encoder.write_raw_byte(2);
            encoder.write_raw_byte(probe_verdict_code(verdict));
        }
    }
}

fn write_counts(encoder: &mut Encoder, counts: RunReconciliationCounts) {
    encoder.write_scalar(counts.reserved);
    encoder.write_scalar(counts.committed_or_deferred);
    encoder.write_scalar(counts.escalated);
    encoder.write_scalar(counts.acknowledged);
    encoder.write_scalar(counts.aborted);
    encoder.write_scalar(counts.terminally_failed);
    encoder.write_scalar(counts.leaked);
}

fn write_resource_vector(encoder: &mut Encoder, vector: ResourceVector) {
    for (_grade, amount) in vector.pairs() {
        encoder.write_scalar(amount);
    }
}

fn write_authority_receipt(
    encoder: &mut Encoder,
    receipt: &AuthorityReadReceipt,
) -> Result<(), CodecRefusal> {
    encoder.write_opaque_id(receipt.repository_id().as_bytes());
    encoder.write_internal_object_id(receipt.authority_head_id().as_internal_object_id())?;
    encoder.write_scalar(receipt.authority_head_generation().get());
    encoder.write_raw(&receipt.backend_version_token().to_opaque_bytes());

    let latest_decision_batch_id = receipt.latest_decision_batch_id();
    write_optional_identity(
        encoder,
        latest_decision_batch_id
            .as_ref()
            .map(fgit_types::RepositoryDecisionBatchId::as_internal_object_id),
    )?;
    write_optional_scalar(
        encoder,
        receipt
            .latest_repository_sequence()
            .map(fgit_types::RepositorySequence::get),
    );
    let latest_repository_commit_id = receipt.latest_repository_commit_id();
    write_optional_identity(
        encoder,
        latest_repository_commit_id
            .as_ref()
            .map(fgit_types::RepositoryCommitId::as_internal_object_id),
    )?;

    encoder.write_digest(&receipt.ref_root())?;
    encoder.write_digest(&receipt.forge_position_root())?;
    encoder.write_digest(&receipt.retention_root())?;
    encoder.write_scalar(receipt.policy_epoch().get());
    encoder.write_scalar(receipt.format_epoch().get());
    encoder.write_scalar(receipt.verified_at_logical_time().value());
    encoder.write_raw(&receipt.verifier_profile());
    Ok(())
}

fn write_optional_identity(
    encoder: &mut Encoder,
    value: Option<&fgit_types::InternalObjectId>,
) -> Result<(), CodecRefusal> {
    match value {
        Some(identity) => {
            encoder.write_bool(true);
            encoder.write_internal_object_id(identity)?;
        }
        None => encoder.write_bool(false),
    }
    Ok(())
}

fn write_optional_scalar(encoder: &mut Encoder, value: Option<u64>) {
    match value {
        Some(value) => {
            encoder.write_bool(true);
            encoder.write_scalar(value);
        }
        None => encoder.write_bool(false),
    }
}

fn write_count(
    encoder: &mut Encoder,
    field: &'static str,
    count: usize,
) -> Result<(), RunReconciliationRefusal> {
    let count = u32::try_from(count).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::try_from(count).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    encoder.write_scalar(count);
    Ok(())
}

const fn effect_class_code(class: EffectClass) -> u8 {
    match class {
        EffectClass::PureCanonicalRead => 1,
        EffectClass::DerivedLocalWrite => 2,
        EffectClass::ImmutableCandidateCreation => 3,
        EffectClass::PreparedCanonicalMutation => 4,
        EffectClass::CanonicalMutation => 5,
        EffectClass::ExternalEffect => 6,
    }
}

const fn operation_class_code(operation: OperationClass) -> u8 {
    match operation {
        OperationClass::ReadCanonicalObject => 1,
        OperationClass::ReadDerivedGeneration => 2,
        OperationClass::TreeFsWorkspace => 3,
        OperationClass::ExecuteSandboxedProcess => 4,
        OperationClass::NetworkDestination => 5,
        OperationClass::SecretHandle => 6,
        OperationClass::ExternalIntegration => 7,
        OperationClass::CreateCandidateObject => 8,
        OperationClass::PreparePublication => 9,
        OperationClass::SubmitEvidence => 10,
        OperationClass::MutateForgeEntity => 11,
        OperationClass::DelegateSubIntent => 12,
        OperationClass::ConsumeBudget => 13,
    }
}

const fn obligation_state_code(state: ObligationState) -> u8 {
    match state {
        ObligationState::Reserved => 1,
        ObligationState::Committed => 2,
        ObligationState::DeferredExternally => 3,
        ObligationState::Escalated => 4,
        ObligationState::Acknowledged => 5,
        ObligationState::Aborted => 6,
        ObligationState::TerminallyFailed => 7,
        ObligationState::Leaked => 8,
    }
}

const fn obligation_class_code(class: ObligationClass) -> u8 {
    match class {
        ObligationClass::ObjectAdmissionPermit => 1,
        ObligationClass::PreparedTxnSlot => 2,
        ObligationClass::HeadCasAttempt => 3,
        ObligationClass::OutboxEffectPermit => 4,
        ObligationClass::SecretLease => 5,
        ObligationClass::WorkspaceLease => 6,
        ObligationClass::RunnerSlot => 7,
        ObligationClass::RetentionPin => 8,
        ObligationClass::RepairPermit => 9,
        ObligationClass::ContextBudgetPermit => 10,
        ObligationClass::BillingReservation => 11,
    }
}

const fn terminal_failure_code(reason: TerminalFailureReason) -> u8 {
    match reason {
        TerminalFailureReason::PermanentDownstreamRejection => 1,
        TerminalFailureReason::ValidityWindowExpired => 2,
        TerminalFailureReason::OperatorDecision => 3,
    }
}

const fn escalation_reason_code(reason: EscalationReason) -> u8 {
    match reason {
        EscalationReason::IndeterminateDelivery => 1,
        EscalationReason::RetryBudgetExhausted => 2,
        EscalationReason::ProbeContractViolation => 3,
        EscalationReason::PolicyRequiresHuman => 4,
    }
}

const fn downstream_idempotency_code(idempotency: DownstreamIdempotency) -> u8 {
    match idempotency {
        DownstreamIdempotency::Strong => 1,
        DownstreamIdempotency::Weak => 2,
    }
}

const fn delivery_verdict_code(verdict: DeliveryVerdict) -> u8 {
    match verdict {
        DeliveryVerdict::Accepted => 1,
        DeliveryVerdict::DuplicateSuppressed => 2,
        DeliveryVerdict::TransientFailure => 3,
        DeliveryVerdict::PermanentRejection => 4,
        DeliveryVerdict::AmbiguousTimeout => 5,
    }
}

const fn probe_verdict_code(verdict: ProbeVerdict) -> u8 {
    match verdict {
        ProbeVerdict::Delivered => 1,
        ProbeVerdict::NotDelivered => 2,
        ProbeVerdict::Unknown => 3,
    }
}

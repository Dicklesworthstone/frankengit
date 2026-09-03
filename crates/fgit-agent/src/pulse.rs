//! Compact, authority-bound Level-0 control-plane pulses.
//!
//! `docs/AGENT_CONTROL_PLANE_ARCHITECTURE.md` defines the pulse as the small
//! machine-first view an agent can afford to inspect on every turn. This module
//! derives that view from an already authenticated [`crate::AgentSituationReceipt`]
//! and its deterministic [`crate::WorkFrontier`].
//!
//! The pulse is deliberately not another source of repository truth and not a
//! task claim. It binds the exact situation and frontier identities, preserves
//! counts for every exclusion class, and names at most one advisory next action.
//! A caller still needs the ordinary capability/effect path before doing
//! anything consequential.
//!
//! # Why the active `IntentRun` is supplied again
//!
//! A situation receipt retains the run ID and complete machine commitment, not
//! a mutable run handle. Pulse construction therefore requires the complete run
//! again and re-checks its commitment, authenticated authority receipt, and
//! logical-time window at the observation instant. A same-ID reconstructed run
//! or an expired run produces a typed refusal instead of an actionable-looking
//! summary.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_treefs::WorkspaceId;
use fgit_types::{HeadGeneration, RepositoryAuthorityHeadId, RepositoryId};

use crate::{
    AgentSituationReceipt, FrontierExclusionReason, IntentRun, IntentRunCommitment,
    IntentRunIdentityRefusal, LogicalTime, RunId, SituationComponentKind, TaskPhase, WorkAction,
    WorkCandidate, WorkFrontier, WorkFrontierId, WorkRankingWitness, WorkTaskId,
};

const PULSE_DOMAIN: &[u8] = b"frankengit.agent.control-pulse/v2\0";

/// Stable SHA-256 commitment to one complete compact pulse.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentControlPulseId([u8; 32]);

impl AgentControlPulseId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AgentControlPulseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("pulse:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// What the compact pulse says an agent can do next.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PulseState {
    /// At least one task is eligible and the first deterministic candidate is
    /// exposed as the advisory next action.
    Actionable,
    /// No authenticated Intent Run is active at this situation.
    NoActiveRun,
    /// A live run exists but every projected task was excluded or terminal.
    NoEligibleWork,
}

impl PulseState {
    const fn code_point(self) -> u8 {
        match self {
            Self::Actionable => 1,
            Self::NoActiveRun => 2,
            Self::NoEligibleWork => 3,
        }
    }
}

/// The one advisory next action exposed by the pulse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PulseSelection {
    task_id: WorkTaskId,
    phase: TaskPhase,
    action: WorkAction,
    rank: u32,
    ranking_witness: WorkRankingWitness,
}

impl PulseSelection {
    const fn from_candidate(candidate: &WorkCandidate) -> Self {
        Self {
            task_id: candidate.item().task_id(),
            phase: candidate.item().phase(),
            action: candidate.action(),
            rank: candidate.rank(),
            ranking_witness: candidate.ranking_witness(),
        }
    }

    /// Stable task identity.
    #[must_use]
    pub const fn task_id(self) -> WorkTaskId {
        self.task_id
    }

    /// Projected task phase.
    #[must_use]
    pub const fn phase(self) -> TaskPhase {
        self.phase
    }

    /// Required action.
    #[must_use]
    pub const fn action(self) -> WorkAction {
        self.action
    }

    /// Zero-based rank in the deterministic frontier.
    #[must_use]
    pub const fn rank(self) -> u32 {
        self.rank
    }

    /// Complete deterministic ordering witness.
    #[must_use]
    pub const fn ranking_witness(self) -> WorkRankingWitness {
        self.ranking_witness
    }
}

/// Compact accounting for every hard exclusion class.
///
/// These counters keep progressive disclosure honest. A pulse may omit the
/// individual task rows, but it cannot make blockers, uncertainty, conflicts,
/// stale projections, or insufficient authority disappear.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PulseExclusionCounts {
    stale_projection: u32,
    terminal_phase: u32,
    blocked_tasks: u32,
    declared_blockers: u64,
    no_intent_run: u32,
    assigned_elsewhere: u32,
    independence_required: u32,
    insufficient_capability: u32,
    conflict_unknown: u32,
    reserved_by_other: u32,
}

impl PulseExclusionCounts {
    fn from_frontier(frontier: &WorkFrontier) -> Result<Self, PulseRefusal> {
        let mut counts = Self::default();
        for excluded in frontier.excluded() {
            match excluded.reason() {
                FrontierExclusionReason::StaleProjection { .. } => {
                    counts.stale_projection += 1;
                }
                FrontierExclusionReason::TerminalPhase(_) => {
                    counts.terminal_phase += 1;
                }
                FrontierExclusionReason::Blocked { blocker_count } => {
                    counts.blocked_tasks += 1;
                    counts.declared_blockers = counts
                        .declared_blockers
                        .checked_add(u64::from(blocker_count))
                        .ok_or(PulseRefusal::DeclaredBlockerCountOverflow)?;
                }
                FrontierExclusionReason::NoIntentRun => {
                    counts.no_intent_run += 1;
                }
                FrontierExclusionReason::AssignedElsewhere { .. } => {
                    counts.assigned_elsewhere += 1;
                }
                FrontierExclusionReason::IndependenceRequired { .. } => {
                    counts.independence_required += 1;
                }
                FrontierExclusionReason::InsufficientCapability => {
                    counts.insufficient_capability += 1;
                }
                FrontierExclusionReason::ConflictUnknown => {
                    counts.conflict_unknown += 1;
                }
                FrontierExclusionReason::ReservedByOther { .. } => {
                    counts.reserved_by_other += 1;
                }
            }
        }
        Ok(counts)
    }

    /// Rows from another task-projection generation.
    #[must_use]
    pub const fn stale_projection(self) -> u32 {
        self.stale_projection
    }

    /// Rows already terminal.
    #[must_use]
    pub const fn terminal_phase(self) -> u32 {
        self.terminal_phase
    }

    /// Tasks with at least one unsatisfied declared blocker.
    #[must_use]
    pub const fn blocked_tasks(self) -> u32 {
        self.blocked_tasks
    }

    /// Sum of unsatisfied blocker edges reported by blocked rows.
    #[must_use]
    pub const fn declared_blockers(self) -> u64 {
        self.declared_blockers
    }

    /// Rows excluded because no run was active.
    #[must_use]
    pub const fn no_intent_run(self) -> u32 {
        self.no_intent_run
    }

    /// Rows assigned to another run.
    #[must_use]
    pub const fn assigned_elsewhere(self) -> u32 {
        self.assigned_elsewhere
    }

    /// Rows excluded by an independence requirement.
    #[must_use]
    pub const fn independence_required(self) -> u32 {
        self.independence_required
    }

    /// Rows outside already-issued capability.
    #[must_use]
    pub const fn insufficient_capability(self) -> u32 {
        self.insufficient_capability
    }

    /// Rows whose conflict state could not be established.
    #[must_use]
    pub const fn conflict_unknown(self) -> u32 {
        self.conflict_unknown
    }

    /// Rows reserved by another run.
    #[must_use]
    pub const fn reserved_by_other(self) -> u32 {
        self.reserved_by_other
    }

    /// Total excluded task rows represented by these counters.
    #[must_use]
    pub const fn total(self) -> u32 {
        self.stale_projection
            + self.terminal_phase
            + self.blocked_tasks
            + self.no_intent_run
            + self.assigned_elsewhere
            + self.independence_required
            + self.insufficient_capability
            + self.conflict_unknown
            + self.reserved_by_other
    }

    /// Rows blocked by coordination uncertainty or another run's reservation.
    #[must_use]
    pub const fn coordination_conflicts(self) -> u32 {
        self.conflict_unknown + self.reserved_by_other
    }
}

/// One compact, self-identifying view for an agent's next control turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentControlPulse {
    pulse_id: AgentControlPulseId,
    situation_id: [u8; 32],
    frontier_id: WorkFrontierId,
    repository_id: RepositoryId,
    authority_head_id: RepositoryAuthorityHeadId,
    authority_head_generation: HeadGeneration,
    task_projection_generation: [u8; 32],
    observed_at: LogicalTime,
    active_run: Option<RunId>,
    active_run_commitment: Option<IntentRunCommitment>,
    workspace_id: Option<WorkspaceId>,
    observed_components: u32,
    omitted_components: u32,
    candidate_count: u32,
    excluded_count: u32,
    exclusions: PulseExclusionCounts,
    state: PulseState,
    selected: Option<PulseSelection>,
}

impl AgentControlPulse {
    /// Builds a compact pulse from one exact situation/frontier pair.
    ///
    /// # Errors
    ///
    /// Refuses a frontier from another situation, a mismatched task projection
    /// or complete run identity, a missing/extra/legacy run, an
    /// authority-mismatched run, an expired run, inconsistent exclusion
    /// accounting, and unrepresentable commitment framing.
    pub fn build(
        situation: &AgentSituationReceipt,
        frontier: &WorkFrontier,
        active_run: Option<&IntentRun>,
    ) -> Result<Self, PulseRefusal> {
        let situation_id = *situation.situation_id().as_bytes();
        if frontier.situation_id() != &situation_id {
            return Err(PulseRefusal::FrontierSituationMismatch {
                expected: situation_id,
                observed: *frontier.situation_id(),
            });
        }
        if frontier.active_run() != situation.intent_run_id() {
            return Err(PulseRefusal::FrontierRunMismatch {
                situation: situation.intent_run_id(),
                frontier: frontier.active_run(),
            });
        }

        let task_projection = situation.component(SituationComponentKind::TaskProjection);
        let situation_generation = task_projection
            .generation_commitment()
            .ok_or(PulseRefusal::TaskProjectionUnavailable)?;
        if frontier.task_projection_generation() != &situation_generation {
            return Err(PulseRefusal::TaskProjectionMismatch {
                situation: situation_generation,
                frontier: *frontier.task_projection_generation(),
            });
        }

        let active_run_commitment = validate_active_run(situation, active_run)?;

        let observed_components =
            count_u32("observed_components", situation.observed_component_count())?;
        let omitted_components =
            count_u32("omitted_components", situation.omitted_component_count())?;
        let candidate_count = count_u32("candidate_count", frontier.candidates().len())?;
        let excluded_count = count_u32("excluded_count", frontier.excluded().len())?;
        let exclusions = PulseExclusionCounts::from_frontier(frontier)?;
        if exclusions.total() != excluded_count {
            return Err(PulseRefusal::ExclusionAccountingMismatch {
                expected: excluded_count,
                observed: exclusions.total(),
            });
        }

        let selected = frontier.selected().map(PulseSelection::from_candidate);
        let state = if selected.is_some() {
            PulseState::Actionable
        } else if situation.intent_run_id().is_none() {
            PulseState::NoActiveRun
        } else {
            PulseState::NoEligibleWork
        };

        let receipt = situation.authority_read_receipt();
        let workspace_id = situation
            .workspace()
            .map(|workspace| workspace.workspace_id());

        let mut pulse = Self {
            pulse_id: AgentControlPulseId([0; 32]),
            situation_id,
            frontier_id: frontier.frontier_id(),
            repository_id: receipt.repository_id(),
            authority_head_id: receipt.authority_head_id(),
            authority_head_generation: receipt.authority_head_generation(),
            task_projection_generation: situation_generation,
            observed_at: situation.observed_at(),
            active_run: situation.intent_run_id(),
            active_run_commitment,
            workspace_id,
            observed_components,
            omitted_components,
            candidate_count,
            excluded_count,
            exclusions,
            state,
            selected,
        };
        pulse.pulse_id = AgentControlPulseId(pulse_commitment(&pulse)?);
        Ok(pulse)
    }

    /// Stable identity of this compact view.
    #[must_use]
    pub const fn pulse_id(&self) -> AgentControlPulseId {
        self.pulse_id
    }

    /// Exact situation receipt summarized by this pulse.
    #[must_use]
    pub const fn situation_id(&self) -> &[u8; 32] {
        &self.situation_id
    }

    /// Exact deterministic frontier summarized by this pulse.
    #[must_use]
    pub const fn frontier_id(&self) -> WorkFrontierId {
        self.frontier_id
    }

    /// Repository governed by the authority receipt.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Authenticated head identity.
    #[must_use]
    pub const fn authority_head_id(&self) -> RepositoryAuthorityHeadId {
        self.authority_head_id
    }

    /// Authenticated head generation.
    #[must_use]
    pub const fn authority_head_generation(&self) -> HeadGeneration {
        self.authority_head_generation
    }

    /// Task projection used for frontier construction.
    #[must_use]
    pub const fn task_projection_generation(&self) -> &[u8; 32] {
        &self.task_projection_generation
    }

    /// Logical observation instant.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// Active live Intent Run coordination identity, when present.
    #[must_use]
    pub const fn active_run(&self) -> Option<RunId> {
        self.active_run
    }

    /// Complete active Intent Run identity, when present.
    #[must_use]
    pub const fn active_run_commitment(&self) -> Option<IntentRunCommitment> {
        self.active_run_commitment
    }

    /// Attached `TreeFS` workspace identity, when present.
    #[must_use]
    pub const fn workspace_id(&self) -> Option<WorkspaceId> {
        self.workspace_id
    }

    /// Number of situation components actually observed.
    #[must_use]
    pub const fn observed_components(&self) -> u32 {
        self.observed_components
    }

    /// Number of explicitly omitted situation components.
    #[must_use]
    pub const fn omitted_components(&self) -> u32 {
        self.omitted_components
    }

    /// Eligible task count.
    #[must_use]
    pub const fn candidate_count(&self) -> u32 {
        self.candidate_count
    }

    /// Excluded task count.
    #[must_use]
    pub const fn excluded_count(&self) -> u32 {
        self.excluded_count
    }

    /// Compact exclusion accounting.
    #[must_use]
    pub const fn exclusions(&self) -> PulseExclusionCounts {
        self.exclusions
    }

    /// High-level next-turn state.
    #[must_use]
    pub const fn state(&self) -> PulseState {
        self.state
    }

    /// First deterministic advisory next action, when one exists.
    #[must_use]
    pub const fn selected(&self) -> Option<PulseSelection> {
        self.selected
    }
}

/// Why a compact control pulse could not be derived safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PulseRefusal {
    /// Frontier names another situation receipt.
    FrontierSituationMismatch {
        /// Situation supplied to the builder.
        expected: [u8; 32],
        /// Situation committed into the frontier.
        observed: [u8; 32],
    },
    /// Situation and frontier disagree about the active run.
    FrontierRunMismatch {
        /// Run bound to the situation.
        situation: Option<RunId>,
        /// Run used by the frontier.
        frontier: Option<RunId>,
    },
    /// The situation does not carry an observed task projection.
    TaskProjectionUnavailable,
    /// Situation and frontier name different task-projection generations.
    TaskProjectionMismatch {
        /// Generation observed by the situation.
        situation: [u8; 32],
        /// Generation used by the frontier.
        frontier: [u8; 32],
    },
    /// Situation has a run but the caller did not supply its complete object.
    ActiveRunRequired {
        /// Run identity retained by the situation.
        expected: RunId,
    },
    /// Caller supplied a run when the situation has none.
    UnexpectedActiveRun {
        /// Extra run supplied.
        observed: RunId,
    },
    /// Complete run object has another coordination identity.
    ActiveRunIdMismatch {
        /// Run identity retained by the situation.
        expected: RunId,
        /// Run object supplied.
        observed: RunId,
    },
    /// Same coordination ID carries another complete run commitment.
    ActiveRunCommitmentMismatch {
        /// Commitment retained by the situation.
        expected: IntentRunCommitment,
        /// Commitment computed from the supplied run.
        observed: IntentRunCommitment,
    },
    /// Situation carries an impossible run ID/commitment option pair.
    InconsistentSituationRunIdentity,
    /// Supplied run uses the legacy identifying reference rather than the full
    /// authenticated authority receipt.
    ActiveRunAuthorityReceiptRequired,
    /// Supplied run and situation were authenticated at different positions.
    ActiveRunAuthorityMismatch,
    /// Complete run identity could not be produced.
    RunIdentity(IntentRunIdentityRefusal),
    /// The run was already expired at the situation's observation instant.
    ActiveRunExpired {
        /// Expired run.
        run_id: RunId,
        /// Exclusive expiry instant.
        expiry: LogicalTime,
        /// Situation observation instant.
        observed: LogicalTime,
    },
    /// A bounded count could not be represented in the compact wire profile.
    CountUnrepresentable {
        /// Count field.
        field: &'static str,
        /// Value observed.
        observed: usize,
    },
    /// Summed blocker edges overflowed the compact accounting type.
    DeclaredBlockerCountOverflow,
    /// Per-class exclusion counters do not cover every excluded frontier row.
    ExclusionAccountingMismatch {
        /// Frontier's excluded row count.
        expected: u32,
        /// Sum of per-class counters.
        observed: u32,
    },
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for PulseRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrontierSituationMismatch { .. } => {
                formatter.write_str("frontier belongs to another agent situation")
            }
            Self::FrontierRunMismatch { .. } => {
                formatter.write_str("frontier and situation disagree about the active run")
            }
            Self::TaskProjectionUnavailable => {
                formatter.write_str("agent situation has no observed task projection")
            }
            Self::TaskProjectionMismatch { .. } => {
                formatter.write_str("frontier and situation use different task projections")
            }
            Self::ActiveRunRequired { expected } => {
                write!(formatter, "complete active run {expected} is required")
            }
            Self::UnexpectedActiveRun { observed } => {
                write!(
                    formatter,
                    "run {observed} was supplied but the situation has no active run"
                )
            }
            Self::ActiveRunIdMismatch { expected, observed } => write!(
                formatter,
                "supplied run {observed} differs from situation run {expected}"
            ),
            Self::ActiveRunCommitmentMismatch { expected, observed } => write!(
                formatter,
                "supplied run commitment {observed} differs from situation run {expected}"
            ),
            Self::InconsistentSituationRunIdentity => formatter
                .write_str("agent situation carries an inconsistent run ID/commitment pair"),
            Self::ActiveRunAuthorityReceiptRequired => formatter.write_str(
                "control pulse requires a run with a complete authenticated authority receipt",
            ),
            Self::ActiveRunAuthorityMismatch => formatter
                .write_str("active run authority receipt differs from the situation receipt"),
            Self::RunIdentity(refusal) => {
                write!(formatter, "active run identity refused: {refusal}")
            }
            Self::ActiveRunExpired {
                run_id,
                expiry,
                observed,
            } => write!(
                formatter,
                "active run {run_id} expired at {expiry} before situation observation {observed}"
            ),
            Self::CountUnrepresentable { field, observed } => {
                write!(
                    formatter,
                    "{field} value {observed} is not representable as u32"
                )
            }
            Self::DeclaredBlockerCountOverflow => {
                formatter.write_str("declared blocker count overflowed u64")
            }
            Self::ExclusionAccountingMismatch { expected, observed } => write!(
                formatter,
                "frontier excludes {expected} rows but pulse counters account for {observed}"
            ),
            Self::Codec(refusal) => {
                write!(
                    formatter,
                    "agent control pulse commitment refused: {refusal}"
                )
            }
        }
    }
}

impl core::error::Error for PulseRefusal {}

impl From<IntentRunIdentityRefusal> for PulseRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<CodecRefusal> for PulseRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_active_run(
    situation: &AgentSituationReceipt,
    active_run: Option<&IntentRun>,
) -> Result<Option<IntentRunCommitment>, PulseRefusal> {
    match (
        situation.intent_run_id(),
        situation.intent_run_commitment(),
        active_run,
    ) {
        (None, None, None) => Ok(None),
        (None, None, Some(run)) => Err(PulseRefusal::UnexpectedActiveRun {
            observed: run.run_id(),
        }),
        (Some(expected), Some(_), None) => Err(PulseRefusal::ActiveRunRequired { expected }),
        (Some(expected), Some(expected_commitment), Some(run)) => {
            if run.run_id() != expected {
                return Err(PulseRefusal::ActiveRunIdMismatch {
                    expected,
                    observed: run.run_id(),
                });
            }
            let observed_commitment = run.commitment()?;
            if observed_commitment != expected_commitment {
                return Err(PulseRefusal::ActiveRunCommitmentMismatch {
                    expected: expected_commitment,
                    observed: observed_commitment,
                });
            }
            let run_receipt = run
                .authority_read_receipt()
                .ok_or(PulseRefusal::ActiveRunAuthorityReceiptRequired)?;
            if run_receipt != situation.authority_read_receipt() {
                return Err(PulseRefusal::ActiveRunAuthorityMismatch);
            }
            if !run.is_open_at(situation.observed_at()) {
                return Err(PulseRefusal::ActiveRunExpired {
                    run_id: expected,
                    expiry: run.expiry(),
                    observed: situation.observed_at(),
                });
            }
            Ok(Some(observed_commitment))
        }
        _ => Err(PulseRefusal::InconsistentSituationRunIdentity),
    }
}

fn count_u32(field: &'static str, value: usize) -> Result<u32, PulseRefusal> {
    u32::try_from(value).map_err(|_| PulseRefusal::CountUnrepresentable {
        field,
        observed: value,
    })
}

fn pulse_commitment(pulse: &AgentControlPulse) -> Result<[u8; 32], PulseRefusal> {
    let mut encoder = Encoder::with_capacity(576);
    encoder.write_bytes("agent_control_pulse_domain", PULSE_DOMAIN)?;
    encoder.write_raw(&pulse.situation_id);
    encoder.write_raw(pulse.frontier_id.as_bytes());
    encoder.write_opaque_id(pulse.repository_id.as_bytes());
    encoder.write_internal_object_id(pulse.authority_head_id.as_internal_object_id())?;
    encoder.write_scalar(pulse.authority_head_generation.get());
    encoder.write_raw(&pulse.task_projection_generation);
    encoder.write_scalar(pulse.observed_at.value());

    write_optional_run(&mut encoder, pulse.active_run, pulse.active_run_commitment)?;
    match pulse.workspace_id {
        Some(workspace_id) => {
            encoder.write_bool(true);
            encoder.write_opaque_id(workspace_id.as_bytes());
        }
        None => encoder.write_bool(false),
    }

    encoder.write_scalar(pulse.observed_components);
    encoder.write_scalar(pulse.omitted_components);
    encoder.write_scalar(pulse.candidate_count);
    encoder.write_scalar(pulse.excluded_count);
    write_exclusion_counts(&mut encoder, pulse.exclusions);
    encoder.write_raw_byte(pulse.state.code_point());

    encoder.write_option(pulse.selected.as_ref(), |encoder, selected| {
        encoder.write_raw(selected.task_id.as_bytes());
        encoder.write_raw_byte(task_phase_code(selected.phase));
        encoder.write_raw_byte(work_action_code(selected.action));
        encoder.write_scalar(selected.rank);
        let witness = selected.ranking_witness;
        encoder.write_raw_byte(witness.action_order());
        encoder.write_scalar(u32::from(witness.declared_priority()));
        encoder.write_scalar(witness.unlock_count());
        encoder.write_scalar(witness.estimated_evidence_cost());
        encoder.write_raw(witness.task_id().as_bytes());
        Ok(())
    })?;

    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}

fn write_optional_run(
    encoder: &mut Encoder,
    run_id: Option<RunId>,
    run_commitment: Option<IntentRunCommitment>,
) -> Result<(), PulseRefusal> {
    match (run_id, run_commitment) {
        (Some(run_id), Some(run_commitment)) => {
            encoder.write_bool(true);
            encoder.write_raw(&run_id.value().to_be_bytes());
            encoder.write_raw(run_commitment.as_bytes());
            Ok(())
        }
        (None, None) => {
            encoder.write_bool(false);
            Ok(())
        }
        _ => Err(PulseRefusal::InconsistentSituationRunIdentity),
    }
}

fn write_exclusion_counts(encoder: &mut Encoder, counts: PulseExclusionCounts) {
    encoder.write_scalar(counts.stale_projection);
    encoder.write_scalar(counts.terminal_phase);
    encoder.write_scalar(counts.blocked_tasks);
    encoder.write_scalar(counts.declared_blockers);
    encoder.write_scalar(counts.no_intent_run);
    encoder.write_scalar(counts.assigned_elsewhere);
    encoder.write_scalar(counts.independence_required);
    encoder.write_scalar(counts.insufficient_capability);
    encoder.write_scalar(counts.conflict_unknown);
    encoder.write_scalar(counts.reserved_by_other);
}

const fn task_phase_code(phase: TaskPhase) -> u8 {
    match phase {
        TaskPhase::Open => 1,
        TaskPhase::InProgress => 2,
        TaskPhase::ImplementationReady => 3,
        TaskPhase::VerificationPending => 4,
        TaskPhase::Rework => 5,
        TaskPhase::Verified => 6,
        TaskPhase::Closed => 7,
        TaskPhase::Superseded => 8,
    }
}

const fn work_action_code(action: WorkAction) -> u8 {
    match action {
        WorkAction::Implement => 1,
        WorkAction::Verify => 2,
        WorkAction::Rework => 3,
    }
}

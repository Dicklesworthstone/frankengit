#![forbid(unsafe_code)]
//! Deterministic work-frontier construction for the FrankenGit Agent Control Plane.
//!
//! This crate owns one narrow decision layer: given an authority-bound
//! [`fgit_agent::AgentSituationReceipt`] and a bounded set of task-projection
//! rows, determine which rows are actionable for the receipt's active Intent
//! Run, retain a typed reason for every excluded row, and order only the
//! eligible rows by one closed deterministic policy.
//!
//! It does not read or mutate Beads, grant capabilities, reserve files, edit a
//! workspace, execute evidence, or publish repository state. Task collection
//! and task-status mutation remain adapters outside this crate. Ranking is
//! advisory; the eligibility filter runs first and no score can turn an
//! ineligible row into a candidate.

use core::fmt;

use fgit_agent::{
    AgentSituationReceipt, RunId, SituationComponentKind, SituationOmissionReason,
};
use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};

/// Maximum task rows accepted by one frontier construction.
pub const MAX_WORK_ITEMS: usize = 4_096;
const MAX_WORK_ITEMS_WIRE: u32 = 4_096;
const FRONTIER_DOMAIN: &[u8] = b"frankengit.agent.work-frontier/v1\0";

/// Stable task identity supplied by the task projection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkTaskId([u8; 32]);

impl WorkTaskId {
    /// Constructs an identity from its fixed-width projection commitment.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw fixed-width identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}

impl fmt::Display for WorkTaskId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("task:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable commitment to a complete frontier result.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkFrontierId([u8; 32]);

impl WorkFrontierId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for WorkFrontierId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("frontier:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Task lifecycle phase represented by the task projection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TaskPhase {
    /// Work has not started.
    Open,
    /// Implementation is in progress.
    InProgress,
    /// Implementation exists and requires verification.
    ImplementationReady,
    /// A designated verification gate is pending.
    VerificationPending,
    /// A prior candidate failed a named gate and requires correction.
    Rework,
    /// The implementation has a successful verification receipt.
    Verified,
    /// The task is terminally closed.
    Closed,
    /// A canonical decision replaced this work.
    Superseded,
}

impl TaskPhase {
    const fn code_point(self) -> u8 {
        match self {
            Self::Open => 1,
            Self::InProgress => 2,
            Self::ImplementationReady => 3,
            Self::VerificationPending => 4,
            Self::Rework => 5,
            Self::Verified => 6,
            Self::Closed => 7,
            Self::Superseded => 8,
        }
    }

    const fn required_action(self) -> Option<WorkAction> {
        match self {
            Self::Open | Self::InProgress => Some(WorkAction::Implement),
            Self::ImplementationReady | Self::VerificationPending => Some(WorkAction::Verify),
            Self::Rework => Some(WorkAction::Rework),
            Self::Verified | Self::Closed | Self::Superseded => None,
        }
    }
}

/// Action an eligible row asks the active run to perform.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkAction {
    /// Implement the accepted task contract.
    Implement,
    /// Produce the designated revision-bound verification evidence.
    Verify,
    /// Correct a named failed gate without discarding its negative evidence.
    Rework,
}

impl WorkAction {
    const fn code_point(self) -> u8 {
        match self {
            Self::Implement => 1,
            Self::Verify => 2,
            Self::Rework => 3,
        }
    }

    const fn policy_order(self) -> u8 {
        match self {
            Self::Rework => 0,
            Self::Verify => 1,
            Self::Implement => 2,
        }
    }
}

/// Coordination state projected for one task's declared conflict surface.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkConflict {
    /// No conflicting reservation is known at this projection generation.
    Clear,
    /// The conflict surface is reserved by one Intent Run.
    ReservedBy(RunId),
    /// The projection cannot establish whether the surface is clear.
    Unknown,
}

impl WorkConflict {
    const fn code_point(self) -> u8 {
        match self {
            Self::Clear => 1,
            Self::ReservedBy(_) => 2,
            Self::Unknown => 3,
        }
    }
}

/// Advisory ordering inputs supplied by the task projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkRankingInputs {
    declared_priority: u16,
    unlock_count: u32,
    estimated_evidence_cost: u64,
}

impl WorkRankingInputs {
    /// Creates the closed v1 ranking inputs.
    #[must_use]
    pub const fn new(
        declared_priority: u16,
        unlock_count: u32,
        estimated_evidence_cost: u64,
    ) -> Self {
        Self {
            declared_priority,
            unlock_count,
            estimated_evidence_cost,
        }
    }

    /// Lower values rank before higher values after action class.
    #[must_use]
    pub const fn declared_priority(self) -> u16 {
        self.declared_priority
    }

    /// Higher values rank before lower values after declared priority.
    #[must_use]
    pub const fn unlock_count(self) -> u32 {
        self.unlock_count
    }

    /// Lower values rank before higher values after unlock count.
    #[must_use]
    pub const fn estimated_evidence_cost(self) -> u64 {
        self.estimated_evidence_cost
    }
}

/// Eligibility inputs supplied by the task and coordination projections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkEligibilityInputs {
    blocker_count: u32,
    assignee: Option<RunId>,
    independent_from: Option<RunId>,
    capability_allowed: bool,
    conflict: WorkConflict,
}

impl WorkEligibilityInputs {
    /// Creates the closed v1 eligibility inputs.
    #[must_use]
    pub const fn new(
        blocker_count: u32,
        assignee: Option<RunId>,
        independent_from: Option<RunId>,
        capability_allowed: bool,
        conflict: WorkConflict,
    ) -> Self {
        Self {
            blocker_count,
            assignee,
            independent_from,
            capability_allowed,
            conflict,
        }
    }

    /// Number of unsatisfied declared dependencies.
    #[must_use]
    pub const fn blocker_count(self) -> u32 {
        self.blocker_count
    }

    /// Run to which the task is explicitly assigned, when any.
    #[must_use]
    pub const fn assignee(self) -> Option<RunId> {
        self.assignee
    }

    /// Run whose implementation must not provide this task's independent gate.
    #[must_use]
    pub const fn independent_from(self) -> Option<RunId> {
        self.independent_from
    }

    /// Whether the active run's already-issued capability covers this action.
    #[must_use]
    pub const fn capability_allowed(self) -> bool {
        self.capability_allowed
    }

    /// Projected coordination state for the conflict surface.
    #[must_use]
    pub const fn conflict(self) -> WorkConflict {
        self.conflict
    }
}

/// One immutable row from the task projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkItem {
    task_id: WorkTaskId,
    projection_generation: [u8; 32],
    phase: TaskPhase,
    ranking: WorkRankingInputs,
    eligibility: WorkEligibilityInputs,
}

impl WorkItem {
    /// Creates one projected task row.
    #[must_use]
    pub const fn new(
        task_id: WorkTaskId,
        projection_generation: [u8; 32],
        phase: TaskPhase,
        ranking: WorkRankingInputs,
        eligibility: WorkEligibilityInputs,
    ) -> Self {
        Self {
            task_id,
            projection_generation,
            phase,
            ranking,
            eligibility,
        }
    }

    /// Stable task identity.
    #[must_use]
    pub const fn task_id(self) -> WorkTaskId {
        self.task_id
    }

    /// Task-projection generation that produced this row.
    #[must_use]
    pub const fn projection_generation(self) -> [u8; 32] {
        self.projection_generation
    }

    /// Current projected lifecycle phase.
    #[must_use]
    pub const fn phase(self) -> TaskPhase {
        self.phase
    }

    /// Advisory ordering inputs.
    #[must_use]
    pub const fn ranking(self) -> WorkRankingInputs {
        self.ranking
    }

    /// Hard eligibility inputs.
    #[must_use]
    pub const fn eligibility(self) -> WorkEligibilityInputs {
        self.eligibility
    }
}

/// Closed deterministic v1 ranking witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkRankingWitness {
    action_order: u8,
    declared_priority: u16,
    unlock_count: u32,
    estimated_evidence_cost: u64,
    task_id: WorkTaskId,
}

impl WorkRankingWitness {
    /// V1 action-class order: rework, verify, implement.
    #[must_use]
    pub const fn action_order(self) -> u8 {
        self.action_order
    }

    /// Declared priority used by the ordering policy.
    #[must_use]
    pub const fn declared_priority(self) -> u16 {
        self.declared_priority
    }

    /// Unlock count used by the ordering policy.
    #[must_use]
    pub const fn unlock_count(self) -> u32 {
        self.unlock_count
    }

    /// Estimated evidence cost used by the ordering policy.
    #[must_use]
    pub const fn estimated_evidence_cost(self) -> u64 {
        self.estimated_evidence_cost
    }

    /// Final stable lexical tie-break.
    #[must_use]
    pub const fn task_id(self) -> WorkTaskId {
        self.task_id
    }
}

/// One eligible task in advisory order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkCandidate {
    rank: u32,
    item: WorkItem,
    action: WorkAction,
    witness: WorkRankingWitness,
}

impl WorkCandidate {
    /// Zero-based position in the advisory ordering.
    #[must_use]
    pub const fn rank(self) -> u32 {
        self.rank
    }

    /// Complete source row.
    #[must_use]
    pub const fn item(self) -> WorkItem {
        self.item
    }

    /// Required action for the active run.
    #[must_use]
    pub const fn action(self) -> WorkAction {
        self.action
    }

    /// Exact deterministic ranking inputs.
    #[must_use]
    pub const fn ranking_witness(self) -> WorkRankingWitness {
        self.witness
    }
}

/// Hard reason a row was excluded before advisory ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontierExclusionReason {
    /// Row came from another task-projection generation.
    StaleProjection {
        /// Generation expected by the situation receipt.
        expected: [u8; 32],
        /// Generation carried by the row.
        observed: [u8; 32],
    },
    /// The projected lifecycle phase is terminal.
    TerminalPhase(TaskPhase),
    /// Declared task dependencies remain unsatisfied.
    Blocked {
        /// Number of unsatisfied declared blockers.
        blocker_count: u32,
    },
    /// The situation receipt has no active authenticated Intent Run.
    NoIntentRun,
    /// The task is explicitly assigned to another run.
    AssignedElsewhere {
        /// Current projected assignee.
        assignee: RunId,
    },
    /// The active run is not independent of the implementation being verified.
    IndependenceRequired {
        /// Run from which verification must be independent.
        implementation_run: RunId,
    },
    /// The already-issued capability does not cover the required action.
    InsufficientCapability,
    /// Conflict state could not be established, so eligibility fails closed.
    ConflictUnknown,
    /// Another run reserves the declared conflict surface.
    ReservedByOther {
        /// Run owning the projected reservation.
        owner: RunId,
    },
}

impl FrontierExclusionReason {
    const fn code_point(self) -> u8 {
        match self {
            Self::StaleProjection { .. } => 1,
            Self::TerminalPhase(_) => 2,
            Self::Blocked { .. } => 3,
            Self::NoIntentRun => 4,
            Self::AssignedElsewhere { .. } => 5,
            Self::IndependenceRequired { .. } => 6,
            Self::InsufficientCapability => 7,
            Self::ConflictUnknown => 8,
            Self::ReservedByOther { .. } => 9,
        }
    }
}

/// One excluded row and the first failed hard precondition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExcludedWorkItem {
    item: WorkItem,
    reason: FrontierExclusionReason,
}

impl ExcludedWorkItem {
    /// Complete source row.
    #[must_use]
    pub const fn item(self) -> WorkItem {
        self.item
    }

    /// First failed hard precondition under the closed v1 precedence.
    #[must_use]
    pub const fn reason(self) -> FrontierExclusionReason {
        self.reason
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrontierBasis {
    situation_id: [u8; 32],
    task_projection_generation: [u8; 32],
    active_run: Option<RunId>,
}

impl FrontierBasis {
    fn from_situation(situation: &AgentSituationReceipt) -> Result<Self, FrontierRefusal> {
        let task_projection = situation.component(SituationComponentKind::TaskProjection);
        let task_projection_generation = match (
            task_projection.generation_commitment(),
            task_projection.omission_reason(),
            task_projection.omission_detail_commitment(),
        ) {
            (Some(generation), None, None) => generation,
            (None, Some(reason), Some(detail_commitment)) => {
                return Err(FrontierRefusal::TaskProjectionUnavailable {
                    reason,
                    detail_commitment,
                });
            }
            _ => return Err(FrontierRefusal::InconsistentTaskProjectionComponent),
        };

        Ok(Self {
            situation_id: *situation.situation_id().as_bytes(),
            task_projection_generation,
            active_run: situation.intent_run_id(),
        })
    }
}

/// Complete deterministic work frontier for one situation receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkFrontier {
    frontier_id: WorkFrontierId,
    situation_id: [u8; 32],
    task_projection_generation: [u8; 32],
    active_run: Option<RunId>,
    candidates: Vec<WorkCandidate>,
    excluded: Vec<ExcludedWorkItem>,
}

impl WorkFrontier {
    /// Builds a bounded frontier from one authority-bound situation receipt.
    ///
    /// The hard eligibility precedence is:
    /// stale projection, terminal phase, blockers, missing run, assignment,
    /// verifier independence, capability, then conflict state. Only rows that
    /// pass every hard precondition enter advisory ordering.
    ///
    /// # Errors
    ///
    /// Refuses an omitted or internally inconsistent task-projection component,
    /// more than [`MAX_WORK_ITEMS`] rows, the all-zero task identity, duplicate
    /// task identities, and unrepresentable commitment framing.
    pub fn build(
        situation: &AgentSituationReceipt,
        items: Vec<WorkItem>,
    ) -> Result<Self, FrontierRefusal> {
        let basis = FrontierBasis::from_situation(situation)?;
        Self::build_from_basis(basis, items)
    }

    fn build_from_basis(
        basis: FrontierBasis,
        mut items: Vec<WorkItem>,
    ) -> Result<Self, FrontierRefusal> {
        if items.len() > MAX_WORK_ITEMS {
            return Err(FrontierRefusal::TooManyItems {
                observed: items.len(),
                limit: MAX_WORK_ITEMS,
            });
        }

        items.sort_unstable_by_key(|item| item.task_id);
        for item in &items {
            if item.task_id.is_zero() {
                return Err(FrontierRefusal::ZeroTaskId);
            }
        }
        for adjacent in items.windows(2) {
            if adjacent[0].task_id == adjacent[1].task_id {
                return Err(FrontierRefusal::DuplicateTaskId {
                    task_id: adjacent[0].task_id,
                });
            }
        }

        let mut candidates = Vec::with_capacity(items.len());
        let mut excluded = Vec::new();

        for item in items {
            match exclusion_reason(&basis, item) {
                Some(reason) => excluded.push(ExcludedWorkItem { item, reason }),
                None => {
                    let action = item
                        .phase
                        .required_action()
                        .ok_or(FrontierRefusal::InconsistentEligiblePhase {
                            task_id: item.task_id,
                            phase: item.phase,
                        })?;
                    candidates.push(WorkCandidate {
                        rank: 0,
                        item,
                        action,
                        witness: WorkRankingWitness {
                            action_order: action.policy_order(),
                            declared_priority: item.ranking.declared_priority,
                            unlock_count: item.ranking.unlock_count,
                            estimated_evidence_cost: item.ranking.estimated_evidence_cost,
                            task_id: item.task_id,
                        },
                    });
                }
            }
        }

        candidates.sort_unstable_by(compare_candidates);
        for (index, candidate) in candidates.iter_mut().enumerate() {
            candidate.rank = u32::try_from(index)
                .map_err(|_| FrontierRefusal::RankUnrepresentable { observed: index })?;
        }
        excluded.sort_unstable_by_key(|entry| entry.item.task_id);

        let frontier_id = WorkFrontierId(frontier_commitment(
            &basis,
            &candidates,
            &excluded,
        )?);

        Ok(Self {
            frontier_id,
            situation_id: basis.situation_id,
            task_projection_generation: basis.task_projection_generation,
            active_run: basis.active_run,
            candidates,
            excluded,
        })
    }

    /// Stable identity of the complete frontier result.
    #[must_use]
    pub const fn frontier_id(&self) -> WorkFrontierId {
        self.frontier_id
    }

    /// Situation receipt commitment from which this frontier was derived.
    #[must_use]
    pub const fn situation_id(&self) -> &[u8; 32] {
        &self.situation_id
    }

    /// Exact observed task-projection generation.
    #[must_use]
    pub const fn task_projection_generation(&self) -> &[u8; 32] {
        &self.task_projection_generation
    }

    /// Active Intent Run used for hard eligibility, when any.
    #[must_use]
    pub const fn active_run(&self) -> Option<RunId> {
        self.active_run
    }

    /// Eligible tasks in deterministic advisory order.
    #[must_use]
    pub fn candidates(&self) -> &[WorkCandidate] {
        &self.candidates
    }

    /// First eligible task, when one exists.
    #[must_use]
    pub fn selected(&self) -> Option<&WorkCandidate> {
        self.candidates.first()
    }

    /// Ineligible rows in stable task-identity order.
    #[must_use]
    pub fn excluded(&self) -> &[ExcludedWorkItem] {
        &self.excluded
    }
}

/// Why work-frontier construction was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrontierRefusal {
    /// The situation explicitly omitted its task projection.
    TaskProjectionUnavailable {
        /// Typed omission reason.
        reason: SituationOmissionReason,
        /// Commitment to detailed omission evidence.
        detail_commitment: [u8; 32],
    },
    /// The situation component violated its observed-or-omitted representation.
    InconsistentTaskProjectionComponent,
    /// The bounded input ceiling was exceeded before allocation-heavy work.
    TooManyItems {
        /// Rows supplied.
        observed: usize,
        /// Closed v1 ceiling.
        limit: usize,
    },
    /// The all-zero task identity is reserved and invalid.
    ZeroTaskId,
    /// One task identity appeared more than once.
    DuplicateTaskId {
        /// Repeated identity.
        task_id: WorkTaskId,
    },
    /// A terminal phase reached the candidate branch, indicating an internal defect.
    InconsistentEligiblePhase {
        /// Affected task.
        task_id: WorkTaskId,
        /// Terminal phase observed.
        phase: TaskPhase,
    },
    /// A candidate position could not be represented on the wire.
    RankUnrepresentable {
        /// Zero-based position that failed conversion.
        observed: usize,
    },
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for FrontierRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TaskProjectionUnavailable { reason, .. } => write!(
                formatter,
                "work frontier unavailable because task projection is omitted: {reason}"
            ),
            Self::InconsistentTaskProjectionComponent => formatter.write_str(
                "task-projection situation component is neither consistently observed nor omitted",
            ),
            Self::TooManyItems { observed, limit } => write!(
                formatter,
                "work frontier received {observed} rows, v1 limit is {limit}"
            ),
            Self::ZeroTaskId => formatter.write_str("work frontier refuses the all-zero task identity"),
            Self::DuplicateTaskId { task_id } => {
                write!(formatter, "work frontier repeats task identity {task_id}")
            }
            Self::InconsistentEligiblePhase { task_id, phase } => write!(
                formatter,
                "task {task_id} with terminal phase {phase:?} reached the eligible branch"
            ),
            Self::RankUnrepresentable { observed } => write!(
                formatter,
                "candidate rank {observed} is not representable as u32"
            ),
            Self::Codec(refusal) => write!(
                formatter,
                "work-frontier commitment refused: {refusal}"
            ),
        }
    }
}

impl core::error::Error for FrontierRefusal {}

impl From<CodecRefusal> for FrontierRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn exclusion_reason(basis: &FrontierBasis, item: WorkItem) -> Option<FrontierExclusionReason> {
    if item.projection_generation != basis.task_projection_generation {
        return Some(FrontierExclusionReason::StaleProjection {
            expected: basis.task_projection_generation,
            observed: item.projection_generation,
        });
    }
    if item.phase.required_action().is_none() {
        return Some(FrontierExclusionReason::TerminalPhase(item.phase));
    }
    if item.eligibility.blocker_count != 0 {
        return Some(FrontierExclusionReason::Blocked {
            blocker_count: item.eligibility.blocker_count,
        });
    }

    let active_run = match basis.active_run {
        Some(active_run) => active_run,
        None => return Some(FrontierExclusionReason::NoIntentRun),
    };

    if let Some(assignee) = item.eligibility.assignee {
        if assignee != active_run {
            return Some(FrontierExclusionReason::AssignedElsewhere { assignee });
        }
    }
    if item.eligibility.independent_from == Some(active_run) {
        return Some(FrontierExclusionReason::IndependenceRequired {
            implementation_run: active_run,
        });
    }
    if !item.eligibility.capability_allowed {
        return Some(FrontierExclusionReason::InsufficientCapability);
    }

    match item.eligibility.conflict {
        WorkConflict::Clear => None,
        WorkConflict::ReservedBy(owner) if owner == active_run => None,
        WorkConflict::ReservedBy(owner) => {
            Some(FrontierExclusionReason::ReservedByOther { owner })
        }
        WorkConflict::Unknown => Some(FrontierExclusionReason::ConflictUnknown),
    }
}

fn compare_candidates(left: &WorkCandidate, right: &WorkCandidate) -> core::cmp::Ordering {
    left.witness
        .action_order
        .cmp(&right.witness.action_order)
        .then_with(|| {
            left.witness
                .declared_priority
                .cmp(&right.witness.declared_priority)
        })
        .then_with(|| right.witness.unlock_count.cmp(&left.witness.unlock_count))
        .then_with(|| {
            left.witness
                .estimated_evidence_cost
                .cmp(&right.witness.estimated_evidence_cost)
        })
        .then_with(|| left.witness.task_id.cmp(&right.witness.task_id))
}

fn frontier_commitment(
    basis: &FrontierBasis,
    candidates: &[WorkCandidate],
    excluded: &[ExcludedWorkItem],
) -> Result<[u8; 32], FrontierRefusal> {
    let mut encoder = Encoder::with_capacity(256 + (candidates.len() + excluded.len()) * 192);
    encoder.write_bytes("work_frontier_domain", FRONTIER_DOMAIN)?;
    encoder.write_raw(&basis.situation_id);
    encoder.write_raw(&basis.task_projection_generation);
    write_optional_run(&mut encoder, basis.active_run);

    write_count(&mut encoder, "frontier_candidates", candidates.len())?;
    for candidate in candidates {
        encoder.write_scalar(candidate.rank);
        write_item(&mut encoder, candidate.item);
        encoder.write_raw_byte(candidate.action.code_point());
        encoder.write_raw_byte(candidate.witness.action_order);
        encoder.write_scalar(u32::from(candidate.witness.declared_priority));
        encoder.write_scalar(candidate.witness.unlock_count);
        encoder.write_scalar(candidate.witness.estimated_evidence_cost);
        encoder.write_raw(candidate.witness.task_id.as_bytes());
    }

    write_count(&mut encoder, "frontier_excluded", excluded.len())?;
    for entry in excluded {
        write_item(&mut encoder, entry.item);
        write_exclusion(&mut encoder, entry.reason);
    }

    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}

fn write_item(encoder: &mut Encoder, item: WorkItem) {
    encoder.write_raw(item.task_id.as_bytes());
    encoder.write_raw(&item.projection_generation);
    encoder.write_raw_byte(item.phase.code_point());
    encoder.write_scalar(u32::from(item.ranking.declared_priority));
    encoder.write_scalar(item.ranking.unlock_count);
    encoder.write_scalar(item.ranking.estimated_evidence_cost);
    encoder.write_scalar(item.eligibility.blocker_count);
    write_optional_run(encoder, item.eligibility.assignee);
    write_optional_run(encoder, item.eligibility.independent_from);
    encoder.write_bool(item.eligibility.capability_allowed);
    encoder.write_raw_byte(item.eligibility.conflict.code_point());
    if let WorkConflict::ReservedBy(owner) = item.eligibility.conflict {
        encoder.write_raw(&owner.value().to_be_bytes());
    }
}

fn write_exclusion(encoder: &mut Encoder, reason: FrontierExclusionReason) {
    encoder.write_raw_byte(reason.code_point());
    match reason {
        FrontierExclusionReason::StaleProjection { expected, observed } => {
            encoder.write_raw(&expected);
            encoder.write_raw(&observed);
        }
        FrontierExclusionReason::TerminalPhase(phase) => {
            encoder.write_raw_byte(phase.code_point());
        }
        FrontierExclusionReason::Blocked { blocker_count } => {
            encoder.write_scalar(blocker_count);
        }
        FrontierExclusionReason::NoIntentRun
        | FrontierExclusionReason::InsufficientCapability
        | FrontierExclusionReason::ConflictUnknown => {}
        FrontierExclusionReason::AssignedElsewhere { assignee } => {
            encoder.write_raw(&assignee.value().to_be_bytes());
        }
        FrontierExclusionReason::IndependenceRequired { implementation_run } => {
            encoder.write_raw(&implementation_run.value().to_be_bytes());
        }
        FrontierExclusionReason::ReservedByOther { owner } => {
            encoder.write_raw(&owner.value().to_be_bytes());
        }
    }
}

fn write_optional_run(encoder: &mut Encoder, run_id: Option<RunId>) {
    match run_id {
        Some(run_id) => {
            encoder.write_bool(true);
            encoder.write_raw(&run_id.value().to_be_bytes());
        }
        None => encoder.write_bool(false),
    }
}

fn write_count(
    encoder: &mut Encoder,
    field: &'static str,
    count: usize,
) -> Result<(), FrontierRefusal> {
    let count = u32::try_from(count).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::try_from(count).unwrap_or(u64::MAX),
        limit: u64::from(MAX_WORK_ITEMS_WIRE),
    })?;
    encoder.write_scalar(count);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ExcludedWorkItem, FrontierBasis, FrontierExclusionReason, FrontierRefusal,
        MAX_WORK_ITEMS, TaskPhase, WorkAction, WorkCandidate, WorkConflict,
        WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
    };
    use fgit_agent::RunId;

    const GENERATION: [u8; 32] = [0x44; 32];

    fn basis(active_run: Option<RunId>) -> FrontierBasis {
        FrontierBasis {
            situation_id: [0x33; 32],
            task_projection_generation: GENERATION,
            active_run,
        }
    }

    fn task_id(byte: u8) -> WorkTaskId {
        WorkTaskId::from_bytes([byte; 32])
    }

    fn item(
        byte: u8,
        phase: TaskPhase,
        priority: u16,
        unlock_count: u32,
        evidence_cost: u64,
    ) -> WorkItem {
        WorkItem::new(
            task_id(byte),
            GENERATION,
            phase,
            WorkRankingInputs::new(priority, unlock_count, evidence_cost),
            WorkEligibilityInputs::new(0, None, None, true, WorkConflict::Clear),
        )
    }

    fn candidate_ids(candidates: &[WorkCandidate]) -> Vec<WorkTaskId> {
        candidates
            .iter()
            .map(|candidate| candidate.item().task_id())
            .collect()
    }

    fn exclusion_reason(entry: &ExcludedWorkItem) -> FrontierExclusionReason {
        entry.reason()
    }

    #[test]
    fn ordering_is_input_independent_and_uses_closed_v1_tie_breaks() {
        let run = RunId::new(7);
        let rows = vec![
            item(5, TaskPhase::Open, 1, 10, 20),
            item(4, TaskPhase::ImplementationReady, 1, 1, 5),
            item(3, TaskPhase::Rework, 100, 0, 100),
            item(2, TaskPhase::Open, 1, 10, 10),
            item(1, TaskPhase::Open, 1, 10, 10),
        ];
        let first = WorkFrontier::build_from_basis(basis(Some(run)), rows.clone())
            .expect("bounded unique rows build");
        let mut reversed = rows;
        reversed.reverse();
        let second = WorkFrontier::build_from_basis(basis(Some(run)), reversed)
            .expect("input order does not affect the frontier");

        assert_eq!(first.frontier_id(), second.frontier_id());
        assert_eq!(
            candidate_ids(first.candidates()),
            vec![task_id(3), task_id(4), task_id(1), task_id(2), task_id(5)]
        );
        assert_eq!(first.candidates()[0].action(), WorkAction::Rework);
        assert_eq!(first.candidates()[1].action(), WorkAction::Verify);
        assert_eq!(first.candidates()[2].action(), WorkAction::Implement);
        for (index, candidate) in first.candidates().iter().enumerate() {
            assert_eq!(candidate.rank(), u32::try_from(index).expect("five ranks fit"));
        }
    }

    #[test]
    fn hard_preconditions_exclude_before_ranking_with_stable_precedence() {
        let run = RunId::new(7);
        let other = RunId::new(8);
        let rows = vec![
            WorkItem::new(
                task_id(1),
                [0x99; 32],
                TaskPhase::Open,
                WorkRankingInputs::new(0, u32::MAX, 0),
                WorkEligibilityInputs::new(0, None, None, true, WorkConflict::Clear),
            ),
            item(2, TaskPhase::Closed, 0, u32::MAX, 0),
            WorkItem::new(
                task_id(3),
                GENERATION,
                TaskPhase::Open,
                WorkRankingInputs::new(0, u32::MAX, 0),
                WorkEligibilityInputs::new(2, None, None, true, WorkConflict::Clear),
            ),
            WorkItem::new(
                task_id(4),
                GENERATION,
                TaskPhase::Open,
                WorkRankingInputs::new(0, u32::MAX, 0),
                WorkEligibilityInputs::new(0, Some(other), None, true, WorkConflict::Clear),
            ),
            WorkItem::new(
                task_id(5),
                GENERATION,
                TaskPhase::VerificationPending,
                WorkRankingInputs::new(0, u32::MAX, 0),
                WorkEligibilityInputs::new(0, None, Some(run), true, WorkConflict::Clear),
            ),
            WorkItem::new(
                task_id(6),
                GENERATION,
                TaskPhase::Open,
                WorkRankingInputs::new(0, u32::MAX, 0),
                WorkEligibilityInputs::new(0, None, None, false, WorkConflict::Clear),
            ),
            WorkItem::new(
                task_id(7),
                GENERATION,
                TaskPhase::Open,
                WorkRankingInputs::new(0, u32::MAX, 0),
                WorkEligibilityInputs::new(0, None, None, true, WorkConflict::Unknown),
            ),
            WorkItem::new(
                task_id(8),
                GENERATION,
                TaskPhase::Open,
                WorkRankingInputs::new(0, u32::MAX, 0),
                WorkEligibilityInputs::new(
                    0,
                    None,
                    None,
                    true,
                    WorkConflict::ReservedBy(other),
                ),
            ),
            WorkItem::new(
                task_id(9),
                GENERATION,
                TaskPhase::Open,
                WorkRankingInputs::new(0, 0, 0),
                WorkEligibilityInputs::new(
                    0,
                    Some(run),
                    None,
                    true,
                    WorkConflict::ReservedBy(run),
                ),
            ),
        ];
        let frontier = WorkFrontier::build_from_basis(basis(Some(run)), rows)
            .expect("typed exclusions are a successful frontier");

        assert_eq!(candidate_ids(frontier.candidates()), vec![task_id(9)]);
        assert_eq!(frontier.excluded().len(), 8);
        assert!(matches!(
            exclusion_reason(&frontier.excluded()[0]),
            FrontierExclusionReason::StaleProjection { .. }
        ));
        assert_eq!(
            exclusion_reason(&frontier.excluded()[1]),
            FrontierExclusionReason::TerminalPhase(TaskPhase::Closed)
        );
        assert_eq!(
            exclusion_reason(&frontier.excluded()[2]),
            FrontierExclusionReason::Blocked { blocker_count: 2 }
        );
        assert_eq!(
            exclusion_reason(&frontier.excluded()[3]),
            FrontierExclusionReason::AssignedElsewhere { assignee: other }
        );
        assert_eq!(
            exclusion_reason(&frontier.excluded()[4]),
            FrontierExclusionReason::IndependenceRequired {
                implementation_run: run,
            }
        );
        assert_eq!(
            exclusion_reason(&frontier.excluded()[5]),
            FrontierExclusionReason::InsufficientCapability
        );
        assert_eq!(
            exclusion_reason(&frontier.excluded()[6]),
            FrontierExclusionReason::ConflictUnknown
        );
        assert_eq!(
            exclusion_reason(&frontier.excluded()[7]),
            FrontierExclusionReason::ReservedByOther { owner: other }
        );
    }

    #[test]
    fn missing_run_is_explicit_and_does_not_override_intrinsic_blockers() {
        let blocked = WorkItem::new(
            task_id(1),
            GENERATION,
            TaskPhase::Open,
            WorkRankingInputs::new(0, 0, 0),
            WorkEligibilityInputs::new(1, None, None, true, WorkConflict::Clear),
        );
        let otherwise_ready = item(2, TaskPhase::Open, 0, 0, 0);
        let frontier = WorkFrontier::build_from_basis(
            basis(None),
            vec![otherwise_ready, blocked],
        )
        .expect("missing run yields exclusions rather than a fabricated candidate");

        assert!(frontier.candidates().is_empty());
        assert_eq!(
            frontier.excluded()[0].reason(),
            FrontierExclusionReason::Blocked { blocker_count: 1 }
        );
        assert_eq!(
            frontier.excluded()[1].reason(),
            FrontierExclusionReason::NoIntentRun
        );
    }

    #[test]
    fn duplicate_zero_and_oversized_inputs_are_refused_before_frontier_identity() {
        let run = RunId::new(7);
        let repeated = item(1, TaskPhase::Open, 0, 0, 0);
        assert_eq!(
            WorkFrontier::build_from_basis(basis(Some(run)), vec![repeated, repeated])
                .expect_err("duplicate task identity must fail"),
            FrontierRefusal::DuplicateTaskId {
                task_id: task_id(1),
            }
        );

        let zero = WorkItem::new(
            WorkTaskId::from_bytes([0; 32]),
            GENERATION,
            TaskPhase::Open,
            WorkRankingInputs::new(0, 0, 0),
            WorkEligibilityInputs::new(0, None, None, true, WorkConflict::Clear),
        );
        assert_eq!(
            WorkFrontier::build_from_basis(basis(Some(run)), vec![zero])
                .expect_err("reserved all-zero identity must fail"),
            FrontierRefusal::ZeroTaskId
        );

        let mut oversized = Vec::with_capacity(MAX_WORK_ITEMS + 1);
        for index in 0..=MAX_WORK_ITEMS {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(
                &u64::try_from(index + 1)
                    .expect("bounded test index fits u64")
                    .to_be_bytes(),
            );
            oversized.push(WorkItem::new(
                WorkTaskId::from_bytes(bytes),
                GENERATION,
                TaskPhase::Open,
                WorkRankingInputs::new(0, 0, 0),
                WorkEligibilityInputs::new(0, None, None, true, WorkConflict::Clear),
            ));
        }
        assert_eq!(
            WorkFrontier::build_from_basis(basis(Some(run)), oversized)
                .expect_err("input ceiling must fail before sorting"),
            FrontierRefusal::TooManyItems {
                observed: MAX_WORK_ITEMS + 1,
                limit: MAX_WORK_ITEMS,
            }
        );
    }

    #[test]
    fn every_advisory_input_is_committed() {
        let run = RunId::new(7);
        let first = WorkFrontier::build_from_basis(
            basis(Some(run)),
            vec![item(1, TaskPhase::Open, 1, 2, 3)],
        )
        .expect("first frontier");
        let second = WorkFrontier::build_from_basis(
            basis(Some(run)),
            vec![item(1, TaskPhase::Open, 1, 2, 4)],
        )
        .expect("changed evidence cost frontier");
        assert_ne!(first.frontier_id(), second.frontier_id());
    }
}

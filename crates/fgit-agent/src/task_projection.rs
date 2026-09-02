//! Authority-bound task projection and idempotent mutation protocol.
//!
//! Beads or another task system remains a derived coordination plane. This
//! module does not make task rows repository authority and does not parse a
//! human-readable command response. Instead, it defines the final adapter
//! contract around three exact objects:
//!
//! - [`TaskProjectionSnapshot`], an immutable, authority-bound generation;
//! - [`TaskMutationRequest`], an idempotent compare-and-mutate intent;
//! - [`TaskMutationReceipt`], a validated observation of the exact transition.
//!
//! A production adapter implements [`TaskProjectionAdapter`] over its durable
//! task system. [`execute_task_mutation`] invokes it once and never guesses after
//! an ambiguous outcome. The adapter must probe by request identity and return an
//! identical-retry observation. Test or conformance code may implement the trait
//! in memory, but this module does not describe such a model as durable storage.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::Digest;

use crate::{
    ActiveTaskClaimId, AgentChangePlanId, AgentHandoffAcceptanceId, AgentHandoffCapsuleId,
    AuthorityReadIdentityRefusal, AuthorityReadReceipt, AuthorityReadReceiptId, IntentRun,
    IntentRunCommitment, IntentRunIdentityRefusal, LogicalTime, PlanSurface, RunId, TaskPhase,
    WorkConflict, WorkEligibilityInputs, WorkItem, WorkRankingInputs, WorkTaskId,
};

/// Maximum rows in one task projection snapshot.
pub const MAX_TASK_PROJECTION_ROWS: usize = crate::MAX_WORK_ITEMS;
/// Maximum reserved surfaces retained by one projected task row.
pub const MAX_TASK_ROW_SURFACES: usize = crate::MAX_PLAN_ENTRIES;
const SNAPSHOT_DOMAIN: &[u8] = b"frankengit.agent.task-projection-snapshot/v1\0";
const REQUEST_DOMAIN: &[u8] = b"frankengit.agent.task-mutation-request/v1\0";
const RECEIPT_DOMAIN: &[u8] = b"frankengit.agent.task-mutation-receipt/v1\0";

/// Opaque immutable generation emitted by a task projection backend.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskProjectionGeneration([u8; 32]);

impl TaskProjectionGeneration {
    /// Admits a nonzero fixed-width generation.
    ///
    /// # Errors
    ///
    /// Refuses the reserved all-zero identity.
    pub fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, TaskProjectionRefusal> {
        if is_zero(&bytes) {
            return Err(TaskProjectionRefusal::ZeroGeneration);
        }
        Ok(Self(bytes))
    }

    /// Raw generation bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for TaskProjectionGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("task-generation:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable identity of one complete task projection snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskProjectionSnapshotId([u8; 32]);

impl TaskProjectionSnapshotId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Stable identity of one idempotent task mutation request.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskMutationRequestId([u8; 32]);

impl TaskMutationRequestId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for TaskMutationRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("task-mutation:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable identity of one validated task mutation result.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskMutationReceiptId([u8; 32]);

impl TaskMutationReceiptId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One internally consistent task row independent of a projection generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskProjectionRow {
    task_id: WorkTaskId,
    phase: TaskPhase,
    ranking: WorkRankingInputs,
    blocker_count: u32,
    assignee: Option<RunId>,
    independent_from: Option<RunId>,
    capability_allowed: bool,
    conflict: WorkConflict,
    plan_id: Option<AgentChangePlanId>,
    claim_expiry: Option<LogicalTime>,
    reserved_surfaces: Vec<PlanSurface>,
}

impl TaskProjectionRow {
    /// Creates one unclaimed projected task.
    ///
    /// # Errors
    ///
    /// Refuses a zero task identity or a conflict that claims another run owns
    /// an otherwise unclaimed row.
    pub fn unclaimed(
        task_id: WorkTaskId,
        phase: TaskPhase,
        ranking: WorkRankingInputs,
        blocker_count: u32,
        independent_from: Option<RunId>,
        capability_allowed: bool,
        conflict: WorkConflict,
    ) -> Result<Self, TaskProjectionRefusal> {
        validate_task_id(task_id)?;
        if matches!(conflict, WorkConflict::ReservedBy(_)) {
            return Err(TaskProjectionRefusal::UnclaimedRowReserved);
        }
        Ok(Self {
            task_id,
            phase,
            ranking,
            blocker_count,
            assignee: None,
            independent_from,
            capability_allowed,
            conflict,
            plan_id: None,
            claim_expiry: None,
            reserved_surfaces: Vec::new(),
        })
    }

    /// Creates one claimed projected task.
    ///
    /// # Errors
    ///
    /// Refuses a zero task identity, an empty/duplicate/excessive reservation
    /// surface, and an expiry that is not later than `claimed_at`.
    #[allow(clippy::too_many_arguments)]
    pub fn claimed(
        task_id: WorkTaskId,
        phase: TaskPhase,
        ranking: WorkRankingInputs,
        blocker_count: u32,
        assignee: RunId,
        independent_from: Option<RunId>,
        capability_allowed: bool,
        plan_id: AgentChangePlanId,
        claimed_at: LogicalTime,
        claim_expiry: LogicalTime,
        mut reserved_surfaces: Vec<PlanSurface>,
    ) -> Result<Self, TaskProjectionRefusal> {
        validate_task_id(task_id)?;
        if claim_expiry <= claimed_at {
            return Err(TaskProjectionRefusal::InvalidClaimWindow {
                claimed_at,
                expires_at: claim_expiry,
            });
        }
        canonicalize_surfaces(&mut reserved_surfaces)?;
        if reserved_surfaces.is_empty() {
            return Err(TaskProjectionRefusal::EmptyReservedSurface);
        }
        Ok(Self {
            task_id,
            phase,
            ranking,
            blocker_count,
            assignee: Some(assignee),
            independent_from,
            capability_allowed,
            conflict: WorkConflict::ReservedBy(assignee),
            plan_id: Some(plan_id),
            claim_expiry: Some(claim_expiry),
            reserved_surfaces,
        })
    }

    /// Stable task identity.
    #[must_use]
    pub const fn task_id(&self) -> WorkTaskId {
        self.task_id
    }

    /// Projected phase.
    #[must_use]
    pub const fn phase(&self) -> TaskPhase {
        self.phase
    }

    /// Advisory ranking inputs.
    #[must_use]
    pub const fn ranking(&self) -> WorkRankingInputs {
        self.ranking
    }

    /// Unsatisfied declared blockers.
    #[must_use]
    pub const fn blocker_count(&self) -> u32 {
        self.blocker_count
    }

    /// Current assignee, when claimed.
    #[must_use]
    pub const fn assignee(&self) -> Option<RunId> {
        self.assignee
    }

    /// Implementation run excluded from an independent verification action.
    #[must_use]
    pub const fn independent_from(&self) -> Option<RunId> {
        self.independent_from
    }

    /// Whether the current run's already-issued scope covers the projected action.
    #[must_use]
    pub const fn capability_allowed(&self) -> bool {
        self.capability_allowed
    }

    /// Projected reservation/conflict state.
    #[must_use]
    pub const fn conflict(&self) -> WorkConflict {
        self.conflict
    }

    /// Plan currently bound to the task, when claimed.
    #[must_use]
    pub const fn plan_id(&self) -> Option<AgentChangePlanId> {
        self.plan_id
    }

    /// Exclusive claim expiry, when claimed.
    #[must_use]
    pub const fn claim_expiry(&self) -> Option<LogicalTime> {
        self.claim_expiry
    }

    /// Exact claimed reservation surface.
    #[must_use]
    pub fn reserved_surfaces(&self) -> &[PlanSurface] {
        &self.reserved_surfaces
    }

    /// Converts this row into the existing frontier input vocabulary.
    #[must_use]
    pub const fn work_item(&self, generation: TaskProjectionGeneration) -> WorkItem {
        WorkItem::new(
            self.task_id,
            *generation.as_bytes(),
            self.phase,
            self.ranking,
            WorkEligibilityInputs::new(
                self.blocker_count,
                self.assignee,
                self.independent_from,
                self.capability_allowed,
                self.conflict,
            ),
        )
    }

    fn with_claim(
        &self,
        assignee: RunId,
        plan_id: AgentChangePlanId,
        phase: TaskPhase,
        claimed_at: LogicalTime,
        expires_at: LogicalTime,
        reserved_surfaces: Vec<PlanSurface>,
    ) -> Result<Self, TaskProjectionRefusal> {
        Self::claimed(
            self.task_id,
            phase,
            self.ranking,
            self.blocker_count,
            assignee,
            self.independent_from,
            self.capability_allowed,
            plan_id,
            claimed_at,
            expires_at,
            reserved_surfaces,
        )
    }

    fn without_claim(&self, phase: TaskPhase) -> Result<Self, TaskProjectionRefusal> {
        Self::unclaimed(
            self.task_id,
            phase,
            self.ranking,
            self.blocker_count,
            self.independent_from,
            self.capability_allowed,
            WorkConflict::Clear,
        )
    }
}

/// Complete immutable task projection sampled under one authenticated read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskProjectionSnapshot {
    snapshot_id: TaskProjectionSnapshotId,
    authority_read_receipt_id: AuthorityReadReceiptId,
    generation: TaskProjectionGeneration,
    observed_at: LogicalTime,
    rows: Vec<TaskProjectionRow>,
}

impl TaskProjectionSnapshot {
    /// Builds a bounded canonical task projection snapshot.
    ///
    /// # Errors
    ///
    /// Refuses a zero generation, observation before authority verification,
    /// excessive/duplicate task rows, or canonical framing failure.
    pub fn build(
        authority: &AuthorityReadReceipt,
        generation: [u8; 32],
        observed_at: LogicalTime,
        mut rows: Vec<TaskProjectionRow>,
    ) -> Result<Self, TaskProjectionRefusal> {
        if observed_at < authority.verified_at_logical_time() {
            return Err(TaskProjectionRefusal::ObservationBeforeAuthority {
                observed_at,
                verified_at: authority.verified_at_logical_time(),
            });
        }
        let generation = TaskProjectionGeneration::try_from_bytes(generation)?;
        if rows.len() > MAX_TASK_PROJECTION_ROWS {
            return Err(TaskProjectionRefusal::TooManyRows {
                observed: rows.len(),
                limit: MAX_TASK_PROJECTION_ROWS,
            });
        }
        rows.sort_unstable_by_key(TaskProjectionRow::task_id);
        for adjacent in rows.windows(2) {
            if adjacent[0].task_id == adjacent[1].task_id {
                return Err(TaskProjectionRefusal::DuplicateTask {
                    task_id: adjacent[0].task_id,
                });
            }
        }
        let authority_read_receipt_id = authority.receipt_id()?;
        let mut snapshot = Self {
            snapshot_id: TaskProjectionSnapshotId([0; 32]),
            authority_read_receipt_id,
            generation,
            observed_at,
            rows,
        };
        snapshot.snapshot_id = TaskProjectionSnapshotId(snapshot_commitment(&snapshot)?);
        Ok(snapshot)
    }

    /// Stable snapshot identity.
    #[must_use]
    pub const fn snapshot_id(&self) -> TaskProjectionSnapshotId {
        self.snapshot_id
    }

    /// Exact authenticated read event under which the projection was sampled.
    #[must_use]
    pub const fn authority_read_receipt_id(&self) -> AuthorityReadReceiptId {
        self.authority_read_receipt_id
    }

    /// Opaque task-system generation.
    #[must_use]
    pub const fn generation(&self) -> TaskProjectionGeneration {
        self.generation
    }

    /// Logical sampling instant.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// Canonically ordered task rows.
    #[must_use]
    pub fn rows(&self) -> &[TaskProjectionRow] {
        &self.rows
    }

    /// Finds one task row by stable identity.
    #[must_use]
    pub fn row(&self, task_id: WorkTaskId) -> Option<&TaskProjectionRow> {
        self.rows
            .binary_search_by_key(&task_id, TaskProjectionRow::task_id)
            .ok()
            .map(|index| &self.rows[index])
    }

    /// Produces the bounded frontier inputs for this exact generation.
    #[must_use]
    pub fn work_items(&self) -> Vec<WorkItem> {
        self.rows
            .iter()
            .map(|row| row.work_item(self.generation))
            .collect()
    }
}

/// Closed task-projection mutation classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskMutationOperation {
    /// Claim an unassigned ready row for one run and plan.
    Claim,
    /// Release one active assignment and its reservation surface.
    Release,
    /// Transfer one active assignment without losing plan or reservation state.
    Transfer {
        /// Proof-carrying source handoff capsule.
        capsule_id: AgentHandoffCapsuleId,
        /// Receiver-side acceptance of that exact capsule.
        acceptance_id: AgentHandoffAcceptanceId,
    },
}

impl TaskMutationOperation {
    const fn code_point(self) -> u8 {
        match self {
            Self::Claim => 1,
            Self::Release => 2,
            Self::Transfer { .. } => 3,
        }
    }
}

/// One exact idempotent compare-and-mutate request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskMutationRequest {
    request_id: TaskMutationRequestId,
    operation: TaskMutationOperation,
    basis_snapshot_id: TaskProjectionSnapshotId,
    authority_read_receipt_id: AuthorityReadReceiptId,
    expected_generation: TaskProjectionGeneration,
    before: TaskProjectionRow,
    after: TaskProjectionRow,
    source_run_id: RunId,
    source_run_commitment: IntentRunCommitment,
    target_run_id: Option<RunId>,
    target_run_commitment: Option<IntentRunCommitment>,
    active_claim_id: Option<ActiveTaskClaimId>,
    requested_at: LogicalTime,
    evidence_contract_root: Digest,
}

impl TaskMutationRequest {
    /// Builds a claim request from an exact task snapshot.
    ///
    /// # Errors
    ///
    /// Refuses authority/run mismatch, stale time, blocked or already assigned
    /// work, unknown conflicts, invalid phase movement, empty reservations,
    /// expiry beyond the run, and canonical framing failure.
    #[allow(clippy::too_many_arguments)]
    pub fn claim(
        snapshot: &TaskProjectionSnapshot,
        authority: &AuthorityReadReceipt,
        run: &IntentRun,
        task_id: WorkTaskId,
        plan_id: AgentChangePlanId,
        requested_at: LogicalTime,
        expires_at: LogicalTime,
        reserved_surfaces: Vec<PlanSurface>,
        evidence_contract_root: Digest,
    ) -> Result<Self, TaskMutationRefusal> {
        validate_snapshot_run(snapshot, authority, run)?;
        if requested_at < snapshot.observed_at {
            return Err(TaskMutationRefusal::RequestBeforeSnapshot {
                requested_at,
                observed_at: snapshot.observed_at,
            });
        }
        if !run.is_open_at(requested_at) {
            return Err(TaskMutationRefusal::RunExpired {
                run_id: run.run_id(),
                observed_at: requested_at,
                expires_at: run.expiry(),
            });
        }
        if expires_at <= requested_at {
            return Err(TaskMutationRefusal::InvalidClaimWindow {
                claimed_at: requested_at,
                expires_at,
            });
        }
        if expires_at > run.expiry() {
            return Err(TaskMutationRefusal::ClaimOutlivesRun {
                claim_expires_at: expires_at,
                run_expires_at: run.expiry(),
            });
        }
        let before = snapshot
            .row(task_id)
            .cloned()
            .ok_or(TaskMutationRefusal::TaskMissing { task_id })?;
        if before.blocker_count != 0 {
            return Err(TaskMutationRefusal::TaskBlocked {
                task_id,
                blocker_count: before.blocker_count,
            });
        }
        if !before.capability_allowed {
            return Err(TaskMutationRefusal::CapabilityNotAllowed { task_id });
        }
        if before.assignee.is_some() {
            return Err(TaskMutationRefusal::TaskAlreadyAssigned {
                task_id,
                assignee: before.assignee,
            });
        }
        if before.conflict != WorkConflict::Clear {
            return Err(TaskMutationRefusal::ConflictNotClear {
                task_id,
                conflict: before.conflict,
            });
        }
        let after_phase = claimed_phase(before.phase)?;
        let after = before.with_claim(
            run.run_id(),
            plan_id,
            after_phase,
            requested_at,
            expires_at,
            reserved_surfaces,
        )?;
        Self::finish(
            TaskMutationOperation::Claim,
            snapshot,
            before,
            after,
            run,
            None,
            None,
            requested_at,
            evidence_contract_root,
        )
    }

    /// Builds a release request from an exact claimed task snapshot.
    ///
    /// Release is a conservative cleanup operation. The run may already be
    /// expired; expiry prevents new work but cannot make reservation release
    /// impossible.
    ///
    /// # Errors
    ///
    /// Refuses authority, task, assignee, plan, generation, phase, time, and
    /// canonical framing mismatches.
    #[allow(clippy::too_many_arguments)]
    pub fn release(
        snapshot: &TaskProjectionSnapshot,
        authority: &AuthorityReadReceipt,
        run: &IntentRun,
        task_id: WorkTaskId,
        plan_id: AgentChangePlanId,
        active_claim_id: ActiveTaskClaimId,
        requested_at: LogicalTime,
        evidence_contract_root: Digest,
    ) -> Result<Self, TaskMutationRefusal> {
        validate_snapshot_run(snapshot, authority, run)?;
        if requested_at < snapshot.observed_at {
            return Err(TaskMutationRefusal::RequestBeforeSnapshot {
                requested_at,
                observed_at: snapshot.observed_at,
            });
        }
        let before = snapshot
            .row(task_id)
            .cloned()
            .ok_or(TaskMutationRefusal::TaskMissing { task_id })?;
        validate_claimed_owner(&before, run.run_id(), plan_id)?;
        let after = before.without_claim(released_phase(before.phase)?)?;
        Self::finish(
            TaskMutationOperation::Release,
            snapshot,
            before,
            after,
            run,
            None,
            Some(active_claim_id),
            requested_at,
            evidence_contract_root,
        )
    }

    /// Builds a handoff-backed transfer request.
    ///
    /// # Errors
    ///
    /// Refuses source/target authority mismatch, source or target expiry,
    /// same-run transfer, task/plan/assignee mismatch, changed reservation or
    /// phase state, invalid target claim lifetime, and canonical framing failure.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer(
        snapshot: &TaskProjectionSnapshot,
        source_authority: &AuthorityReadReceipt,
        source_run: &IntentRun,
        target_run: &IntentRun,
        task_id: WorkTaskId,
        plan_id: AgentChangePlanId,
        active_claim_id: ActiveTaskClaimId,
        capsule_id: AgentHandoffCapsuleId,
        acceptance_id: AgentHandoffAcceptanceId,
        requested_at: LogicalTime,
        target_expires_at: LogicalTime,
        evidence_contract_root: Digest,
    ) -> Result<Self, TaskMutationRefusal> {
        validate_snapshot_run(snapshot, source_authority, source_run)?;
        if requested_at < snapshot.observed_at {
            return Err(TaskMutationRefusal::RequestBeforeSnapshot {
                requested_at,
                observed_at: snapshot.observed_at,
            });
        }
        if source_run.run_id() == target_run.run_id() {
            return Err(TaskMutationRefusal::TransferToSourceRun {
                run_id: source_run.run_id(),
            });
        }
        if !source_run.is_open_at(requested_at) {
            return Err(TaskMutationRefusal::RunExpired {
                run_id: source_run.run_id(),
                observed_at: requested_at,
                expires_at: source_run.expiry(),
            });
        }
        if !target_run.is_open_at(requested_at) {
            return Err(TaskMutationRefusal::RunExpired {
                run_id: target_run.run_id(),
                observed_at: requested_at,
                expires_at: target_run.expiry(),
            });
        }
        let target_authority = target_run.authority_read_receipt().ok_or(
            TaskMutationRefusal::RunAuthorityReceiptRequired {
                run_id: target_run.run_id(),
            },
        )?;
        if source_authority.repository_id() != target_authority.repository_id()
            || source_authority.authority_head_id() != target_authority.authority_head_id()
            || source_authority.authority_head_generation()
                != target_authority.authority_head_generation()
        {
            return Err(TaskMutationRefusal::TransferAuthorityMismatch);
        }
        if target_expires_at <= requested_at {
            return Err(TaskMutationRefusal::InvalidClaimWindow {
                claimed_at: requested_at,
                expires_at: target_expires_at,
            });
        }
        if target_expires_at > target_run.expiry() {
            return Err(TaskMutationRefusal::ClaimOutlivesRun {
                claim_expires_at: target_expires_at,
                run_expires_at: target_run.expiry(),
            });
        }
        let before = snapshot
            .row(task_id)
            .cloned()
            .ok_or(TaskMutationRefusal::TaskMissing { task_id })?;
        validate_claimed_owner(&before, source_run.run_id(), plan_id)?;
        let after = before.with_claim(
            target_run.run_id(),
            plan_id,
            before.phase,
            requested_at,
            target_expires_at,
            before.reserved_surfaces.clone(),
        )?;
        Self::finish(
            TaskMutationOperation::Transfer {
                capsule_id,
                acceptance_id,
            },
            snapshot,
            before,
            after,
            source_run,
            Some(target_run),
            Some(active_claim_id),
            requested_at,
            evidence_contract_root,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        operation: TaskMutationOperation,
        snapshot: &TaskProjectionSnapshot,
        before: TaskProjectionRow,
        after: TaskProjectionRow,
        source_run: &IntentRun,
        target_run: Option<&IntentRun>,
        active_claim_id: Option<ActiveTaskClaimId>,
        requested_at: LogicalTime,
        evidence_contract_root: Digest,
    ) -> Result<Self, TaskMutationRefusal> {
        let source_run_commitment = source_run.commitment()?;
        let (target_run_id, target_run_commitment) = match target_run {
            Some(run) => (Some(run.run_id()), Some(run.commitment()?)),
            None => (None, None),
        };
        let mut request = Self {
            request_id: TaskMutationRequestId([0; 32]),
            operation,
            basis_snapshot_id: snapshot.snapshot_id,
            authority_read_receipt_id: snapshot.authority_read_receipt_id,
            expected_generation: snapshot.generation,
            before,
            after,
            source_run_id: source_run.run_id(),
            source_run_commitment,
            target_run_id,
            target_run_commitment,
            active_claim_id,
            requested_at,
            evidence_contract_root,
        };
        request.request_id = TaskMutationRequestId(request_commitment(&request)?);
        Ok(request)
    }

    /// Stable idempotency identity.
    #[must_use]
    pub const fn request_id(&self) -> TaskMutationRequestId {
        self.request_id
    }

    /// Mutation class.
    #[must_use]
    pub const fn operation(&self) -> TaskMutationOperation {
        self.operation
    }

    /// Exact projection snapshot used as the compare basis.
    #[must_use]
    pub const fn basis_snapshot_id(&self) -> TaskProjectionSnapshotId {
        self.basis_snapshot_id
    }

    /// Exact authenticated read event of the basis snapshot.
    #[must_use]
    pub const fn authority_read_receipt_id(&self) -> AuthorityReadReceiptId {
        self.authority_read_receipt_id
    }

    /// Opaque generation the adapter must compare.
    #[must_use]
    pub const fn expected_generation(&self) -> TaskProjectionGeneration {
        self.expected_generation
    }

    /// Exact expected row.
    #[must_use]
    pub const fn before(&self) -> &TaskProjectionRow {
        &self.before
    }

    /// Exact desired row.
    #[must_use]
    pub const fn after(&self) -> &TaskProjectionRow {
        &self.after
    }

    /// Source run.
    #[must_use]
    pub const fn source_run_id(&self) -> RunId {
        self.source_run_id
    }

    /// Complete source-run commitment.
    #[must_use]
    pub const fn source_run_commitment(&self) -> IntentRunCommitment {
        self.source_run_commitment
    }

    /// Target run, for transfer.
    #[must_use]
    pub const fn target_run_id(&self) -> Option<RunId> {
        self.target_run_id
    }

    /// Complete target-run commitment, for transfer.
    #[must_use]
    pub const fn target_run_commitment(&self) -> Option<IntentRunCommitment> {
        self.target_run_commitment
    }

    /// Activated source claim, for release or transfer.
    #[must_use]
    pub const fn active_claim_id(&self) -> Option<ActiveTaskClaimId> {
        self.active_claim_id
    }

    /// Logical request instant.
    #[must_use]
    pub const fn requested_at(&self) -> LogicalTime {
        self.requested_at
    }

    /// Evidence contract the adapter result must satisfy.
    #[must_use]
    pub const fn evidence_contract_root(&self) -> Digest {
        self.evidence_contract_root
    }
}

/// Whether an adapter applied the mutation now or recognized its prior result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskMutationReplay {
    /// The compare-and-mutate succeeded during this call.
    Applied,
    /// The adapter found the exact prior result by request ID.
    IdenticalRetry,
}

/// Untrusted adapter observation pending exact validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskMutationObservation {
    request_id: TaskMutationRequestId,
    previous_generation: TaskProjectionGeneration,
    resulting_generation: TaskProjectionGeneration,
    before: TaskProjectionRow,
    after: TaskProjectionRow,
    observed_at: LogicalTime,
    adapter_identity: [u8; 32],
    evidence_root: Digest,
    replay: TaskMutationReplay,
}

impl TaskMutationObservation {
    /// Creates one complete adapter observation.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        request_id: TaskMutationRequestId,
        previous_generation: TaskProjectionGeneration,
        resulting_generation: TaskProjectionGeneration,
        before: TaskProjectionRow,
        after: TaskProjectionRow,
        observed_at: LogicalTime,
        adapter_identity: [u8; 32],
        evidence_root: Digest,
        replay: TaskMutationReplay,
    ) -> Self {
        Self {
            request_id,
            previous_generation,
            resulting_generation,
            before,
            after,
            observed_at,
            adapter_identity,
            evidence_root,
            replay,
        }
    }

    /// Request observed by the adapter.
    #[must_use]
    pub const fn request_id(&self) -> TaskMutationRequestId {
        self.request_id
    }

    /// Generation compared by the adapter.
    #[must_use]
    pub const fn previous_generation(&self) -> TaskProjectionGeneration {
        self.previous_generation
    }

    /// New immutable generation after mutation.
    #[must_use]
    pub const fn resulting_generation(&self) -> TaskProjectionGeneration {
        self.resulting_generation
    }

    /// Row observed before mutation.
    #[must_use]
    pub const fn before(&self) -> &TaskProjectionRow {
        &self.before
    }

    /// Row observed after mutation.
    #[must_use]
    pub const fn after(&self) -> &TaskProjectionRow {
        &self.after
    }

    /// Logical observation instant.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// Adapter implementation/profile identity.
    #[must_use]
    pub const fn adapter_identity(&self) -> [u8; 32] {
        self.adapter_identity
    }

    /// Evidence supporting the task-system mutation.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }

    /// Applied-now or identical-retry classification.
    #[must_use]
    pub const fn replay(&self) -> TaskMutationReplay {
        self.replay
    }
}

/// Validated immutable result of one task projection mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskMutationReceipt {
    receipt_id: TaskMutationReceiptId,
    request_id: TaskMutationRequestId,
    operation: TaskMutationOperation,
    basis_snapshot_id: TaskProjectionSnapshotId,
    authority_read_receipt_id: AuthorityReadReceiptId,
    previous_generation: TaskProjectionGeneration,
    resulting_generation: TaskProjectionGeneration,
    before: TaskProjectionRow,
    after: TaskProjectionRow,
    observed_at: LogicalTime,
    adapter_identity: [u8; 32],
    evidence_root: Digest,
    replay: TaskMutationReplay,
}

impl TaskMutationReceipt {
    /// Validates an adapter observation against one exact request.
    ///
    /// The replay classification is deliberately excluded from semantic receipt
    /// identity: applying now and recognizing the exact prior application are
    /// the same mutation result.
    ///
    /// # Errors
    ///
    /// Refuses request, generation, row, adapter, time, and framing mismatch.
    pub fn admit(
        request: &TaskMutationRequest,
        observation: TaskMutationObservation,
        expected_adapter_identity: [u8; 32],
    ) -> Result<Self, TaskMutationRefusal> {
        if is_zero(&expected_adapter_identity) || is_zero(&observation.adapter_identity) {
            return Err(TaskMutationRefusal::ZeroAdapterIdentity);
        }
        if observation.adapter_identity != expected_adapter_identity {
            return Err(TaskMutationRefusal::AdapterIdentityMismatch {
                expected: expected_adapter_identity,
                observed: observation.adapter_identity,
            });
        }
        if observation.request_id != request.request_id {
            return Err(TaskMutationRefusal::ObservationRequestMismatch {
                expected: request.request_id,
                observed: observation.request_id,
            });
        }
        if observation.previous_generation != request.expected_generation {
            return Err(TaskMutationRefusal::ObservationBasisMismatch {
                expected: request.expected_generation,
                observed: observation.previous_generation,
            });
        }
        if observation.resulting_generation == observation.previous_generation {
            return Err(TaskMutationRefusal::GenerationUnchanged);
        }
        if observation.before != request.before {
            return Err(TaskMutationRefusal::ObservationBeforeMismatch);
        }
        if observation.after != request.after {
            return Err(TaskMutationRefusal::ObservationAfterMismatch);
        }
        if observation.observed_at < request.requested_at {
            return Err(TaskMutationRefusal::ObservationBeforeRequest {
                requested_at: request.requested_at,
                observed_at: observation.observed_at,
            });
        }

        let mut receipt = Self {
            receipt_id: TaskMutationReceiptId([0; 32]),
            request_id: request.request_id,
            operation: request.operation,
            basis_snapshot_id: request.basis_snapshot_id,
            authority_read_receipt_id: request.authority_read_receipt_id,
            previous_generation: observation.previous_generation,
            resulting_generation: observation.resulting_generation,
            before: observation.before,
            after: observation.after,
            observed_at: observation.observed_at,
            adapter_identity: observation.adapter_identity,
            evidence_root: observation.evidence_root,
            replay: observation.replay,
        };
        receipt.receipt_id = TaskMutationReceiptId(receipt_commitment(&receipt)?);
        Ok(receipt)
    }

    /// Stable semantic receipt identity.
    #[must_use]
    pub const fn receipt_id(&self) -> TaskMutationReceiptId {
        self.receipt_id
    }

    /// Idempotent request identity.
    #[must_use]
    pub const fn request_id(&self) -> TaskMutationRequestId {
        self.request_id
    }

    /// Mutation class.
    #[must_use]
    pub const fn operation(&self) -> TaskMutationOperation {
        self.operation
    }

    /// Exact task snapshot used as basis.
    #[must_use]
    pub const fn basis_snapshot_id(&self) -> TaskProjectionSnapshotId {
        self.basis_snapshot_id
    }

    /// Exact authenticated read event of the basis.
    #[must_use]
    pub const fn authority_read_receipt_id(&self) -> AuthorityReadReceiptId {
        self.authority_read_receipt_id
    }

    /// Compared generation.
    #[must_use]
    pub const fn previous_generation(&self) -> TaskProjectionGeneration {
        self.previous_generation
    }

    /// Result generation.
    #[must_use]
    pub const fn resulting_generation(&self) -> TaskProjectionGeneration {
        self.resulting_generation
    }

    /// Exact row before mutation.
    #[must_use]
    pub const fn before(&self) -> &TaskProjectionRow {
        &self.before
    }

    /// Exact row after mutation.
    #[must_use]
    pub const fn after(&self) -> &TaskProjectionRow {
        &self.after
    }

    /// Logical mutation observation.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// Adapter implementation/profile identity.
    #[must_use]
    pub const fn adapter_identity(&self) -> [u8; 32] {
        self.adapter_identity
    }

    /// Mutation evidence commitment.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }

    /// Applied-now or identical-retry classification.
    #[must_use]
    pub const fn replay(&self) -> TaskMutationReplay {
        self.replay
    }
}

/// Production adapter boundary for a durable task/coordination system.
pub trait TaskProjectionAdapter {
    /// Stable adapter implementation/profile identity.
    fn adapter_identity(&self) -> [u8; 32];

    /// Applies or recognizes one idempotent compare-and-mutate request.
    ///
    /// An ambiguous result must be returned as
    /// [`TaskAdapterRefusal::Ambiguous`]. The caller does not automatically
    /// retry; the adapter probes by request identity and later returns an
    /// identical-retry observation when the durable outcome is known.
    fn mutate(
        &mut self,
        request: &TaskMutationRequest,
    ) -> Result<TaskMutationObservation, TaskAdapterRefusal>;
}

/// Executes one adapter call and validates its complete result.
///
/// # Errors
///
/// Separates transport/policy refusal from a malformed or substituted adapter
/// observation. The function invokes `mutate` exactly once.
pub fn execute_task_mutation<A: TaskProjectionAdapter>(
    adapter: &mut A,
    request: &TaskMutationRequest,
) -> Result<TaskMutationReceipt, TaskMutationExecutionRefusal> {
    let adapter_identity = adapter.adapter_identity();
    if is_zero(&adapter_identity) {
        return Err(TaskMutationExecutionRefusal::Mutation(
            TaskMutationRefusal::ZeroAdapterIdentity,
        ));
    }
    let observation = adapter
        .mutate(request)
        .map_err(TaskMutationExecutionRefusal::Adapter)?;
    TaskMutationReceipt::admit(request, observation, adapter_identity)
        .map_err(TaskMutationExecutionRefusal::Mutation)
}

/// Closed backend refusal classes. These are operational results, not evidence
/// that a mutation did or did not commit unless the variant says so.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskAdapterRefusal {
    /// No mutation was attempted because the adapter/backend was unavailable.
    Unavailable {
        /// Request not attempted.
        request_id: TaskMutationRequestId,
    },
    /// The adapter cannot yet determine whether the mutation committed.
    Ambiguous {
        /// Request that must be probed by identity.
        request_id: TaskMutationRequestId,
        /// Commitment to the adapter's probe/recovery context.
        probe_root: Digest,
    },
    /// The durable task system definitely refused the mutation.
    Rejected {
        /// Refused request.
        request_id: TaskMutationRequestId,
        /// Closed refusal class.
        reason: TaskAdapterRejection,
    },
}

/// Definite task-system mutation refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskAdapterRejection {
    /// Expected projection generation is stale.
    StaleGeneration {
        /// Requested compare generation.
        expected: TaskProjectionGeneration,
        /// Current durable generation.
        observed: TaskProjectionGeneration,
    },
    /// A declared dependency is still unsatisfied.
    Blocked,
    /// Another run owns the task.
    AssignedElsewhere,
    /// Reservation/conflict policy refused the surface.
    Conflict,
    /// Task-system policy refused the transition.
    Policy,
    /// Backend profile does not support the requested mutation class.
    Unsupported,
}

/// Adapter execution refusal, preserving whether the backend or validation
/// boundary failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskMutationExecutionRefusal {
    /// Adapter/backend result.
    Adapter(TaskAdapterRefusal),
    /// Adapter returned an observation inconsistent with the request.
    Mutation(TaskMutationRefusal),
}

/// Why a task projection object or mutation failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskProjectionRefusal {
    /// Reserved all-zero generation.
    ZeroGeneration,
    /// Reserved all-zero task identity.
    ZeroTaskId,
    /// Snapshot observation predates authority verification.
    ObservationBeforeAuthority {
        /// Snapshot observation.
        observed_at: LogicalTime,
        /// Authority verification.
        verified_at: LogicalTime,
    },
    /// Snapshot contains too many task rows.
    TooManyRows {
        /// Rows supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// Task appears twice in one snapshot.
    DuplicateTask {
        /// Repeated task.
        task_id: WorkTaskId,
    },
    /// Unclaimed row carries a reservation owned by a run.
    UnclaimedRowReserved,
    /// Claimed row has no reservation surface.
    EmptyReservedSurface,
    /// Reservation surface exceeded its hard ceiling.
    TooManyReservedSurfaces {
        /// Entries supplied.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// Reservation surface repeated one selector.
    DuplicateReservedSurface {
        /// Repeated surface.
        surface: PlanSurface,
    },
    /// Claim window is empty or inverted.
    InvalidClaimWindow {
        /// Claim instant.
        claimed_at: LogicalTime,
        /// Exclusive expiry.
        expires_at: LogicalTime,
    },
    /// Exact authority-read identity failed.
    AuthorityIdentity(AuthorityReadIdentityRefusal),
    /// Canonical framing failed.
    Codec(CodecRefusal),
}

/// Why an exact task mutation request or observation failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskMutationRefusal {
    /// Snapshot authority and supplied authority differ.
    SnapshotAuthorityMismatch,
    /// Run lacks a complete authenticated authority receipt.
    RunAuthorityReceiptRequired {
        /// Run missing its receipt.
        run_id: RunId,
    },
    /// Run's exact read event differs from the snapshot basis.
    RunAuthorityMismatch {
        /// Snapshot receipt.
        expected: AuthorityReadReceiptId,
        /// Run receipt.
        observed: AuthorityReadReceiptId,
    },
    /// Request predates the snapshot it attempts to mutate.
    RequestBeforeSnapshot {
        /// Request time.
        requested_at: LogicalTime,
        /// Snapshot observation.
        observed_at: LogicalTime,
    },
    /// Run is expired at a mutation that would continue work.
    RunExpired {
        /// Expired run.
        run_id: RunId,
        /// Mutation instant.
        observed_at: LogicalTime,
        /// Exclusive expiry.
        expires_at: LogicalTime,
    },
    /// Task is absent from the exact snapshot.
    TaskMissing {
        /// Missing task.
        task_id: WorkTaskId,
    },
    /// Task still has declared blockers.
    TaskBlocked {
        /// Blocked task.
        task_id: WorkTaskId,
        /// Unsatisfied blockers.
        blocker_count: u32,
    },
    /// Projection says the run does not have the already-issued scope required.
    CapabilityNotAllowed {
        /// Affected task.
        task_id: WorkTaskId,
    },
    /// Task is already assigned.
    TaskAlreadyAssigned {
        /// Affected task.
        task_id: WorkTaskId,
        /// Existing assignee.
        assignee: Option<RunId>,
    },
    /// Task conflict state is not clear.
    ConflictNotClear {
        /// Affected task.
        task_id: WorkTaskId,
        /// Observed conflict.
        conflict: WorkConflict,
    },
    /// Claimed row belongs to another run.
    AssigneeMismatch {
        /// Expected assignee.
        expected: RunId,
        /// Observed assignee.
        observed: Option<RunId>,
    },
    /// Claimed row belongs to another plan.
    PlanMismatch {
        /// Expected plan.
        expected: AgentChangePlanId,
        /// Observed plan.
        observed: Option<AgentChangePlanId>,
    },
    /// Task phase cannot enter a claimed state.
    InvalidClaimPhase {
        /// Observed phase.
        phase: TaskPhase,
    },
    /// Task phase cannot be released under the closed v1 policy.
    InvalidReleasePhase {
        /// Observed phase.
        phase: TaskPhase,
    },
    /// Claim window is empty or inverted.
    InvalidClaimWindow {
        /// Claim instant.
        claimed_at: LogicalTime,
        /// Exclusive expiry.
        expires_at: LogicalTime,
    },
    /// Claim expires after its run.
    ClaimOutlivesRun {
        /// Claim expiry.
        claim_expires_at: LogicalTime,
        /// Run expiry.
        run_expires_at: LogicalTime,
    },
    /// Transfer targets the source run.
    TransferToSourceRun {
        /// Source/target run.
        run_id: RunId,
    },
    /// Source and target runs do not share the same authenticated head position.
    TransferAuthorityMismatch,
    /// Intent Run commitment failed.
    RunIdentity(IntentRunIdentityRefusal),
    /// Task row construction failed.
    Projection(TaskProjectionRefusal),
    /// Adapter identity is all zero.
    ZeroAdapterIdentity,
    /// Adapter returned another identity.
    AdapterIdentityMismatch {
        /// Expected adapter.
        expected: [u8; 32],
        /// Observed adapter.
        observed: [u8; 32],
    },
    /// Observation names another request.
    ObservationRequestMismatch {
        /// Expected request.
        expected: TaskMutationRequestId,
        /// Observed request.
        observed: TaskMutationRequestId,
    },
    /// Observation compared another projection generation.
    ObservationBasisMismatch {
        /// Expected generation.
        expected: TaskProjectionGeneration,
        /// Observed generation.
        observed: TaskProjectionGeneration,
    },
    /// Adapter reported no generation advance.
    GenerationUnchanged,
    /// Adapter's before row differs from the request.
    ObservationBeforeMismatch,
    /// Adapter's after row differs from the request.
    ObservationAfterMismatch,
    /// Adapter observation predates the request.
    ObservationBeforeRequest {
        /// Request instant.
        requested_at: LogicalTime,
        /// Adapter observation.
        observed_at: LogicalTime,
    },
    /// Canonical framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for TaskProjectionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task projection refused: {self:?}")
    }
}

impl core::error::Error for TaskProjectionRefusal {}

impl fmt::Display for TaskMutationRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task mutation refused: {self:?}")
    }
}

impl core::error::Error for TaskMutationRefusal {}

impl fmt::Display for TaskAdapterRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task adapter refused: {self:?}")
    }
}

impl core::error::Error for TaskAdapterRefusal {}

impl fmt::Display for TaskMutationExecutionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task mutation execution refused: {self:?}")
    }
}

impl core::error::Error for TaskMutationExecutionRefusal {}

impl From<AuthorityReadIdentityRefusal> for TaskProjectionRefusal {
    fn from(value: AuthorityReadIdentityRefusal) -> Self {
        Self::AuthorityIdentity(value)
    }
}

impl From<CodecRefusal> for TaskProjectionRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

impl From<IntentRunIdentityRefusal> for TaskMutationRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<TaskProjectionRefusal> for TaskMutationRefusal {
    fn from(value: TaskProjectionRefusal) -> Self {
        Self::Projection(value)
    }
}

impl From<CodecRefusal> for TaskMutationRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_snapshot_run(
    snapshot: &TaskProjectionSnapshot,
    authority: &AuthorityReadReceipt,
    run: &IntentRun,
) -> Result<(), TaskMutationRefusal> {
    let authority_id = authority
        .receipt_id()
        .map_err(TaskProjectionRefusal::from)?;
    if authority_id != snapshot.authority_read_receipt_id {
        return Err(TaskMutationRefusal::SnapshotAuthorityMismatch);
    }
    let run_authority =
        run.authority_read_receipt()
            .ok_or(TaskMutationRefusal::RunAuthorityReceiptRequired {
                run_id: run.run_id(),
            })?;
    let run_authority_id = run_authority
        .receipt_id()
        .map_err(TaskProjectionRefusal::from)?;
    if run_authority_id != snapshot.authority_read_receipt_id {
        return Err(TaskMutationRefusal::RunAuthorityMismatch {
            expected: snapshot.authority_read_receipt_id,
            observed: run_authority_id,
        });
    }
    Ok(())
}

fn validate_claimed_owner(
    row: &TaskProjectionRow,
    run_id: RunId,
    plan_id: AgentChangePlanId,
) -> Result<(), TaskMutationRefusal> {
    if row.assignee != Some(run_id) {
        return Err(TaskMutationRefusal::AssigneeMismatch {
            expected: run_id,
            observed: row.assignee,
        });
    }
    if row.plan_id != Some(plan_id) {
        return Err(TaskMutationRefusal::PlanMismatch {
            expected: plan_id,
            observed: row.plan_id,
        });
    }
    Ok(())
}

const fn claimed_phase(phase: TaskPhase) -> Result<TaskPhase, TaskMutationRefusal> {
    match phase {
        TaskPhase::Open | TaskPhase::InProgress => Ok(TaskPhase::InProgress),
        TaskPhase::Rework => Ok(TaskPhase::Rework),
        TaskPhase::ImplementationReady | TaskPhase::VerificationPending => {
            Ok(TaskPhase::VerificationPending)
        }
        TaskPhase::Verified | TaskPhase::Closed | TaskPhase::Superseded => {
            Err(TaskMutationRefusal::InvalidClaimPhase { phase })
        }
    }
}

const fn released_phase(phase: TaskPhase) -> Result<TaskPhase, TaskMutationRefusal> {
    match phase {
        TaskPhase::InProgress => Ok(TaskPhase::Open),
        TaskPhase::Rework => Ok(TaskPhase::Rework),
        TaskPhase::VerificationPending => Ok(TaskPhase::VerificationPending),
        TaskPhase::Open
        | TaskPhase::ImplementationReady
        | TaskPhase::Verified
        | TaskPhase::Closed
        | TaskPhase::Superseded => Err(TaskMutationRefusal::InvalidReleasePhase { phase }),
    }
}

fn validate_task_id(task_id: WorkTaskId) -> Result<(), TaskProjectionRefusal> {
    if is_zero(task_id.as_bytes()) {
        return Err(TaskProjectionRefusal::ZeroTaskId);
    }
    Ok(())
}

fn canonicalize_surfaces(surfaces: &mut Vec<PlanSurface>) -> Result<(), TaskProjectionRefusal> {
    if surfaces.len() > MAX_TASK_ROW_SURFACES {
        return Err(TaskProjectionRefusal::TooManyReservedSurfaces {
            observed: surfaces.len(),
            limit: MAX_TASK_ROW_SURFACES,
        });
    }
    surfaces.sort_unstable();
    for adjacent in surfaces.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(TaskProjectionRefusal::DuplicateReservedSurface {
                surface: adjacent[0],
            });
        }
    }
    Ok(())
}

fn snapshot_commitment(
    snapshot: &TaskProjectionSnapshot,
) -> Result<[u8; 32], TaskProjectionRefusal> {
    let mut encoder = Encoder::with_capacity(1_024);
    encoder.write_bytes("task_projection_snapshot_domain", SNAPSHOT_DOMAIN)?;
    encoder.write_raw(snapshot.authority_read_receipt_id.as_bytes());
    encoder.write_raw(snapshot.generation.as_bytes());
    encoder.write_scalar(snapshot.observed_at.value());
    write_count(&mut encoder, "task_projection.rows", snapshot.rows.len())?;
    for row in &snapshot.rows {
        write_row(&mut encoder, row)?;
    }
    Ok(hash(encoder.into_bytes()))
}

fn request_commitment(request: &TaskMutationRequest) -> Result<[u8; 32], TaskMutationRefusal> {
    let mut encoder = Encoder::with_capacity(1_024);
    encoder.write_bytes("task_mutation_request_domain", REQUEST_DOMAIN)?;
    encoder.write_raw_byte(request.operation.code_point());
    if let TaskMutationOperation::Transfer {
        capsule_id,
        acceptance_id,
    } = request.operation
    {
        encoder.write_raw(capsule_id.as_bytes());
        encoder.write_raw(acceptance_id.as_bytes());
    }
    encoder.write_raw(request.basis_snapshot_id.as_bytes());
    encoder.write_raw(request.authority_read_receipt_id.as_bytes());
    encoder.write_raw(request.expected_generation.as_bytes());
    write_row(&mut encoder, &request.before)?;
    write_row(&mut encoder, &request.after)?;
    encoder.write_raw(&request.source_run_id.value().to_be_bytes());
    encoder.write_raw(request.source_run_commitment.as_bytes());
    match (request.target_run_id, request.target_run_commitment) {
        (Some(run_id), Some(commitment)) => {
            encoder.write_bool(true);
            encoder.write_raw(&run_id.value().to_be_bytes());
            encoder.write_raw(commitment.as_bytes());
        }
        (None, None) => encoder.write_bool(false),
        _ => unreachable!("target run fields are constructed together"),
    }
    match request.active_claim_id {
        Some(claim_id) => {
            encoder.write_bool(true);
            encoder.write_raw(claim_id.as_bytes());
        }
        None => encoder.write_bool(false),
    }
    encoder.write_scalar(request.requested_at.value());
    encoder.write_digest(&request.evidence_contract_root)?;
    Ok(hash(encoder.into_bytes()))
}

fn receipt_commitment(receipt: &TaskMutationReceipt) -> Result<[u8; 32], TaskMutationRefusal> {
    let mut encoder = Encoder::with_capacity(384);
    encoder.write_bytes("task_mutation_receipt_domain", RECEIPT_DOMAIN)?;
    encoder.write_raw(receipt.request_id.as_bytes());
    encoder.write_raw(receipt.basis_snapshot_id.as_bytes());
    encoder.write_raw(receipt.authority_read_receipt_id.as_bytes());
    encoder.write_raw(receipt.previous_generation.as_bytes());
    encoder.write_raw(receipt.resulting_generation.as_bytes());
    encoder.write_scalar(receipt.observed_at.value());
    encoder.write_raw(&receipt.adapter_identity);
    encoder.write_digest(&receipt.evidence_root)?;
    Ok(hash(encoder.into_bytes()))
}

fn write_row(encoder: &mut Encoder, row: &TaskProjectionRow) -> Result<(), CodecRefusal> {
    encoder.write_raw(row.task_id.as_bytes());
    encoder.write_raw_byte(phase_code(row.phase));
    encoder.write_scalar(row.ranking.declared_priority());
    encoder.write_scalar(row.ranking.unlock_count());
    encoder.write_scalar(row.ranking.estimated_evidence_cost());
    encoder.write_scalar(row.blocker_count);
    write_optional_run(encoder, row.assignee);
    write_optional_run(encoder, row.independent_from);
    encoder.write_bool(row.capability_allowed);
    encoder.write_raw_byte(conflict_code(row.conflict));
    if let WorkConflict::ReservedBy(run_id) = row.conflict {
        encoder.write_raw(&run_id.value().to_be_bytes());
    }
    match row.plan_id {
        Some(plan_id) => {
            encoder.write_bool(true);
            encoder.write_raw(plan_id.as_bytes());
        }
        None => encoder.write_bool(false),
    }
    match row.claim_expiry {
        Some(expiry) => {
            encoder.write_bool(true);
            encoder.write_scalar(expiry.value());
        }
        None => encoder.write_bool(false),
    }
    write_count(
        encoder,
        "task_projection.reserved_surfaces",
        row.reserved_surfaces.len(),
    )?;
    for surface in &row.reserved_surfaces {
        encoder.write_raw_byte(surface_kind_code(surface.kind()));
        encoder.write_digest(&surface.selector())?;
    }
    Ok(())
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
) -> Result<(), CodecRefusal> {
    let count = u32::try_from(count).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::try_from(count).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    encoder.write_scalar(count);
    Ok(())
}

const fn phase_code(phase: TaskPhase) -> u8 {
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

const fn conflict_code(conflict: WorkConflict) -> u8 {
    match conflict {
        WorkConflict::Clear => 1,
        WorkConflict::ReservedBy(_) => 2,
        WorkConflict::Unknown => 3,
    }
}

const fn surface_kind_code(kind: crate::PlanSurfaceKind) -> u8 {
    match kind {
        crate::PlanSurfaceKind::RepositoryPath => 1,
        crate::PlanSurfaceKind::Ref => 2,
        crate::PlanSurfaceKind::ForgeEntity => 3,
        crate::PlanSurfaceKind::SchemaOrRegistry => 4,
        crate::PlanSurfaceKind::EvidenceTarget => 5,
        crate::PlanSurfaceKind::ExternalEffect => 6,
        crate::PlanSurfaceKind::Workspace => 7,
    }
}

fn hash(bytes: Vec<u8>) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&bytes);
    hasher.finish()
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

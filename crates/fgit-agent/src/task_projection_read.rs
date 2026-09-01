//! Read-side task projection adapter and evidence receipt.
//!
//! [`crate::TaskProjectionSnapshot`] is the canonical in-process projection
//! body, but a production system also needs evidence for where that snapshot
//! came from. This module defines a single-call read boundary over Beads or
//! another durable coordination backend without importing its storage engine or
//! shelling out from the core library.
//!
//! [`TaskProjectionReadRequest`] binds the exact situation, authenticated-read
//! event, complete Intent Run commitment, and task generation requested.
//! [`TaskProjectionReadReceipt`] retains the validated snapshot, adapter profile,
//! and collection evidence. The adapter remains responsible for bounding input
//! before allocation or parsing; the receipt rechecks the repository ceiling and
//! rejects a substituted or stale observation.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_types::Digest;

use crate::{
    AgentSituationReceipt, AuthorityReadIdentityRefusal, AuthorityReadReceiptId, IntentRun,
    IntentRunCommitment, IntentRunIdentityRefusal, LogicalTime, RunId, SituationComponentKind,
    SituationId, TaskProjectionGeneration, TaskProjectionRefusal, TaskProjectionRow,
    TaskProjectionSnapshot, WorkItem,
};

const READ_REQUEST_DOMAIN: &[u8] = b"frankengit.agent.task-projection-read/v1\0";
const READ_RECEIPT_DOMAIN: &[u8] = b"frankengit.agent.task-projection-read-receipt/v1\0";

/// Stable identity of one exact task-projection read request.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskProjectionReadRequestId([u8; 32]);

impl TaskProjectionReadRequestId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Stable identity of one evidenced task-projection read.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskProjectionReadReceiptId([u8; 32]);

impl TaskProjectionReadReceiptId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact bounded read request derived from one Agent Control Plane situation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskProjectionReadRequest {
    request_id: TaskProjectionReadRequestId,
    situation_id: SituationId,
    authority_read_receipt_id: AuthorityReadReceiptId,
    run_id: RunId,
    run_commitment: IntentRunCommitment,
    expected_generation: TaskProjectionGeneration,
    requested_at: LogicalTime,
    max_rows: u32,
}

impl TaskProjectionReadRequest {
    /// Derives one read request from the exact situation and complete run.
    ///
    /// # Errors
    ///
    /// Refuses a situation with no observed task projection, another run or
    /// authority receipt, an expired run, identity/framing failure, and an
    /// unrepresentable repository row ceiling.
    pub fn from_situation(
        situation: &AgentSituationReceipt,
        run: &IntentRun,
    ) -> Result<Self, TaskProjectionReadRefusal> {
        if situation.intent_run_id() != Some(run.run_id()) {
            return Err(TaskProjectionReadRefusal::SituationRunMismatch);
        }
        let run_authority = run
            .authority_read_receipt()
            .ok_or(TaskProjectionReadRefusal::RunAuthorityReceiptRequired)?;
        if run_authority != situation.authority_read_receipt() {
            return Err(TaskProjectionReadRefusal::RunAuthorityMismatch);
        }
        if !run.is_open_at(situation.observed_at()) {
            return Err(TaskProjectionReadRefusal::RunExpired {
                expires_at: run.expiry(),
                observed_at: situation.observed_at(),
            });
        }
        let generation = situation
            .component(SituationComponentKind::TaskProjection)
            .generation_commitment()
            .ok_or(TaskProjectionReadRefusal::TaskProjectionUnavailable)?;
        let expected_generation = TaskProjectionGeneration::try_from_bytes(generation)?;
        let authority_read_receipt_id = run_authority.receipt_id()?;
        let run_commitment = run.commitment()?;
        let max_rows = u32::try_from(crate::MAX_TASK_PROJECTION_ROWS).map_err(|_| {
            TaskProjectionReadRefusal::RowLimitUnrepresentable {
                limit: crate::MAX_TASK_PROJECTION_ROWS,
            }
        })?;
        let mut request = Self {
            request_id: TaskProjectionReadRequestId([0; 32]),
            situation_id: situation.situation_id(),
            authority_read_receipt_id,
            run_id: run.run_id(),
            run_commitment,
            expected_generation,
            requested_at: situation.observed_at(),
            max_rows,
        };
        request.request_id = TaskProjectionReadRequestId(request_commitment(&request)?);
        Ok(request)
    }

    /// Stable request identity.
    #[must_use]
    pub const fn request_id(self) -> TaskProjectionReadRequestId {
        self.request_id
    }

    /// Situation whose task component is being materialized.
    #[must_use]
    pub const fn situation_id(self) -> SituationId {
        self.situation_id
    }

    /// Exact authenticated read event.
    #[must_use]
    pub const fn authority_read_receipt_id(self) -> AuthorityReadReceiptId {
        self.authority_read_receipt_id
    }

    /// Active run.
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Complete run commitment.
    #[must_use]
    pub const fn run_commitment(self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Required immutable task generation.
    #[must_use]
    pub const fn expected_generation(self) -> TaskProjectionGeneration {
        self.expected_generation
    }

    /// Situation observation time.
    #[must_use]
    pub const fn requested_at(self) -> LogicalTime {
        self.requested_at
    }

    /// Maximum accepted rows.
    #[must_use]
    pub const fn max_rows(self) -> u32 {
        self.max_rows
    }
}

/// Adapter-produced task projection pending validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskProjectionReadObservation {
    request_id: TaskProjectionReadRequestId,
    generation: TaskProjectionGeneration,
    observed_at: LogicalTime,
    rows: Vec<TaskProjectionRow>,
    adapter_identity: [u8; 32],
    evidence_root: Digest,
}

impl TaskProjectionReadObservation {
    /// Creates one complete adapter observation.
    #[must_use]
    pub const fn new(
        request_id: TaskProjectionReadRequestId,
        generation: TaskProjectionGeneration,
        observed_at: LogicalTime,
        rows: Vec<TaskProjectionRow>,
        adapter_identity: [u8; 32],
        evidence_root: Digest,
    ) -> Self {
        Self {
            request_id,
            generation,
            observed_at,
            rows,
            adapter_identity,
            evidence_root,
        }
    }

    /// Request answered by the adapter.
    #[must_use]
    pub const fn request_id(&self) -> TaskProjectionReadRequestId {
        self.request_id
    }

    /// Generation returned by the backend.
    #[must_use]
    pub const fn generation(&self) -> TaskProjectionGeneration {
        self.generation
    }

    /// Backend observation instant.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// Returned task rows.
    #[must_use]
    pub fn rows(&self) -> &[TaskProjectionRow] {
        &self.rows
    }

    /// Adapter implementation/profile identity.
    #[must_use]
    pub const fn adapter_identity(&self) -> [u8; 32] {
        self.adapter_identity
    }

    /// Collection/query evidence commitment.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }
}

/// Validated, evidenced read of one exact task projection generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskProjectionReadReceipt {
    receipt_id: TaskProjectionReadReceiptId,
    request_id: TaskProjectionReadRequestId,
    adapter_identity: [u8; 32],
    evidence_root: Digest,
    snapshot: TaskProjectionSnapshot,
}

impl TaskProjectionReadReceipt {
    /// Stable evidenced-read identity.
    #[must_use]
    pub const fn receipt_id(&self) -> TaskProjectionReadReceiptId {
        self.receipt_id
    }

    /// Exact read request answered.
    #[must_use]
    pub const fn request_id(&self) -> TaskProjectionReadRequestId {
        self.request_id
    }

    /// Adapter implementation/profile identity.
    #[must_use]
    pub const fn adapter_identity(&self) -> [u8; 32] {
        self.adapter_identity
    }

    /// Collection/query evidence commitment.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }

    /// Canonical task projection snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &TaskProjectionSnapshot {
        &self.snapshot
    }

    /// Frontier inputs for the exact evidenced generation.
    #[must_use]
    pub fn work_items(&self) -> Vec<WorkItem> {
        self.snapshot.work_items()
    }
}

/// Production read boundary for Beads or another durable task system.
pub trait TaskProjectionReader {
    /// Stable adapter implementation/profile identity.
    fn adapter_identity(&self) -> [u8; 32];

    /// Reads one exact generation without silently substituting the current one.
    fn read(
        &mut self,
        request: &TaskProjectionReadRequest,
    ) -> Result<TaskProjectionReadObservation, TaskProjectionReadAdapterRefusal>;
}

/// Executes exactly one task projection read and validates the observation.
///
/// # Errors
///
/// Separates adapter/backend refusal from a malformed or substituted read.
pub fn read_task_projection<R: TaskProjectionReader>(
    reader: &mut R,
    situation: &AgentSituationReceipt,
    run: &IntentRun,
) -> Result<TaskProjectionReadReceipt, TaskProjectionReadExecutionRefusal> {
    let request = TaskProjectionReadRequest::from_situation(situation, run)
        .map_err(TaskProjectionReadExecutionRefusal::Read)?;
    let expected_adapter_identity = reader.adapter_identity();
    if is_zero(&expected_adapter_identity) {
        return Err(TaskProjectionReadExecutionRefusal::Read(
            TaskProjectionReadRefusal::ZeroAdapterIdentity,
        ));
    }
    let observation = reader
        .read(&request)
        .map_err(TaskProjectionReadExecutionRefusal::Adapter)?;
    validate_observation(
        request,
        expected_adapter_identity,
        observation,
        situation,
    )
    .map_err(TaskProjectionReadExecutionRefusal::Read)
}

/// Definite backend/read refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskProjectionReadAdapterRefusal {
    /// Backend was unavailable; no snapshot was returned.
    Unavailable {
        /// Request not answered.
        request_id: TaskProjectionReadRequestId,
    },
    /// Backend no longer retains the requested generation.
    GenerationUnavailable {
        /// Exact requested generation.
        generation: TaskProjectionGeneration,
    },
    /// Backend policy refused disclosure of the task projection.
    Policy {
        /// Request refused.
        request_id: TaskProjectionReadRequestId,
    },
    /// Adapter profile does not support exact-generation reads.
    UnsupportedExactGeneration {
        /// Request refused.
        request_id: TaskProjectionReadRequestId,
    },
}

/// Read orchestration refusal preserving adapter versus validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskProjectionReadExecutionRefusal {
    /// Adapter/backend refusal.
    Adapter(TaskProjectionReadAdapterRefusal),
    /// Request or observation validation refusal.
    Read(TaskProjectionReadRefusal),
}

/// Why a task projection read failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskProjectionReadRefusal {
    /// Situation names another run.
    SituationRunMismatch,
    /// Run lacks a complete authenticated receipt.
    RunAuthorityReceiptRequired,
    /// Situation and run use different authenticated read events.
    RunAuthorityMismatch,
    /// Run expired before the task projection observation.
    RunExpired {
        /// Exclusive expiry.
        expires_at: LogicalTime,
        /// Situation observation.
        observed_at: LogicalTime,
    },
    /// Situation explicitly omitted the task projection.
    TaskProjectionUnavailable,
    /// Repository row ceiling cannot be represented by the v1 wire field.
    RowLimitUnrepresentable {
        /// Repository limit.
        limit: usize,
    },
    /// Adapter identity used the reserved all-zero value.
    ZeroAdapterIdentity,
    /// Adapter identity differs from the reader profile invoked.
    AdapterIdentityMismatch {
        /// Reader profile.
        expected: [u8; 32],
        /// Observation profile.
        observed: [u8; 32],
    },
    /// Observation names another request.
    RequestMismatch {
        /// Expected request.
        expected: TaskProjectionReadRequestId,
        /// Observed request.
        observed: TaskProjectionReadRequestId,
    },
    /// Observation returned another generation.
    GenerationMismatch {
        /// Requested generation.
        expected: TaskProjectionGeneration,
        /// Returned generation.
        observed: TaskProjectionGeneration,
    },
    /// Backend observation predates the situation request.
    ObservationRollback {
        /// Situation observation.
        requested_at: LogicalTime,
        /// Backend observation.
        observed_at: LogicalTime,
    },
    /// Adapter returned more rows than the request admitted.
    TooManyRows {
        /// Rows returned.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// Exact authority-read identity failed.
    Authority(AuthorityReadIdentityRefusal),
    /// Complete run identity failed.
    RunIdentity(IntentRunIdentityRefusal),
    /// Canonical task projection validation failed.
    Projection(TaskProjectionRefusal),
    /// Canonical framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for TaskProjectionReadAdapterRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task projection adapter refused: {self:?}")
    }
}

impl core::error::Error for TaskProjectionReadAdapterRefusal {}

impl fmt::Display for TaskProjectionReadExecutionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task projection read execution refused: {self:?}")
    }
}

impl core::error::Error for TaskProjectionReadExecutionRefusal {}

impl fmt::Display for TaskProjectionReadRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task projection read refused: {self:?}")
    }
}

impl core::error::Error for TaskProjectionReadRefusal {}

impl From<AuthorityReadIdentityRefusal> for TaskProjectionReadRefusal {
    fn from(value: AuthorityReadIdentityRefusal) -> Self {
        Self::Authority(value)
    }
}

impl From<IntentRunIdentityRefusal> for TaskProjectionReadRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<TaskProjectionRefusal> for TaskProjectionReadRefusal {
    fn from(value: TaskProjectionRefusal) -> Self {
        Self::Projection(value)
    }
}

impl From<CodecRefusal> for TaskProjectionReadRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_observation(
    request: TaskProjectionReadRequest,
    expected_adapter_identity: [u8; 32],
    observation: TaskProjectionReadObservation,
    situation: &AgentSituationReceipt,
) -> Result<TaskProjectionReadReceipt, TaskProjectionReadRefusal> {
    if is_zero(&observation.adapter_identity) {
        return Err(TaskProjectionReadRefusal::ZeroAdapterIdentity);
    }
    if observation.adapter_identity != expected_adapter_identity {
        return Err(TaskProjectionReadRefusal::AdapterIdentityMismatch {
            expected: expected_adapter_identity,
            observed: observation.adapter_identity,
        });
    }
    if observation.request_id != request.request_id {
        return Err(TaskProjectionReadRefusal::RequestMismatch {
            expected: request.request_id,
            observed: observation.request_id,
        });
    }
    if observation.generation != request.expected_generation {
        return Err(TaskProjectionReadRefusal::GenerationMismatch {
            expected: request.expected_generation,
            observed: observation.generation,
        });
    }
    if observation.observed_at < request.requested_at {
        return Err(TaskProjectionReadRefusal::ObservationRollback {
            requested_at: request.requested_at,
            observed_at: observation.observed_at,
        });
    }
    if observation.rows.len() > usize::try_from(request.max_rows).unwrap_or(usize::MAX) {
        return Err(TaskProjectionReadRefusal::TooManyRows {
            observed: observation.rows.len(),
            limit: usize::try_from(request.max_rows).unwrap_or(usize::MAX),
        });
    }
    let snapshot = TaskProjectionSnapshot::build(
        situation.authority_read_receipt(),
        *observation.generation.as_bytes(),
        observation.observed_at,
        observation.rows,
    )?;
    if snapshot.authority_read_receipt_id() != request.authority_read_receipt_id {
        return Err(TaskProjectionReadRefusal::RunAuthorityMismatch);
    }
    let mut receipt = TaskProjectionReadReceipt {
        receipt_id: TaskProjectionReadReceiptId([0; 32]),
        request_id: request.request_id,
        adapter_identity: observation.adapter_identity,
        evidence_root: observation.evidence_root,
        snapshot,
    };
    receipt.receipt_id = TaskProjectionReadReceiptId(receipt_commitment(&receipt)?);
    Ok(receipt)
}

fn request_commitment(
    request: &TaskProjectionReadRequest,
) -> Result<[u8; 32], TaskProjectionReadRefusal> {
    let mut encoder = Encoder::with_capacity(256);
    encoder.write_bytes("task_projection_read_domain", READ_REQUEST_DOMAIN)?;
    encoder.write_raw(request.situation_id.as_bytes());
    encoder.write_raw(request.authority_read_receipt_id.as_bytes());
    encoder.write_raw(&request.run_id.value().to_be_bytes());
    encoder.write_raw(request.run_commitment.as_bytes());
    encoder.write_raw(request.expected_generation.as_bytes());
    encoder.write_scalar(request.requested_at.value());
    encoder.write_scalar(request.max_rows);
    Ok(hash(encoder.into_bytes()))
}

fn receipt_commitment(
    receipt: &TaskProjectionReadReceipt,
) -> Result<[u8; 32], TaskProjectionReadRefusal> {
    let mut encoder = Encoder::with_capacity(256);
    encoder.write_bytes(
        "task_projection_read_receipt_domain",
        READ_RECEIPT_DOMAIN,
    )?;
    encoder.write_raw(receipt.request_id.as_bytes());
    encoder.write_raw(&receipt.adapter_identity);
    encoder.write_digest(&receipt.evidence_root)?;
    encoder.write_raw(receipt.snapshot.snapshot_id().as_bytes());
    Ok(hash(encoder.into_bytes()))
}

fn hash(bytes: Vec<u8>) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&bytes);
    hasher.finish()
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

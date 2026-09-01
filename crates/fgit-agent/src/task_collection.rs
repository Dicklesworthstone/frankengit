//! Current-generation task projection collection for situation construction.
//!
//! [`crate::task_projection_read`] re-reads one generation already named by an
//! [`crate::AgentSituationReceipt`]. That is useful for exact refresh and audit,
//! but it cannot discover the current generation used to build the first
//! situation. This module owns that missing pre-situation boundary.
//!
//! A collection request binds one exact authenticated authority read, complete
//! Intent Run commitment, logical request instant, and hard row ceiling. A
//! production collector returns one bounded generation plus complete
//! [`crate::TaskProjectionRow`] values and a collection-evidence root. The
//! resulting receipt supplies both the canonical multi-row snapshot consumed by
//! [`crate::WorkFrontier`] and the task-projection [`crate::SituationComponent`]
//! inserted into the control turn. The receipt retains its own authority-head
//! position, so callers cannot render the same collection under another head.
//!
//! The collector is invoked exactly once. It does not mutate the task backend,
//! infer persistence, grant authority, or make task state repository authority.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, NativeObjectIdentity, Sha256};
use fgit_types::{Digest, HeadGeneration, RepositoryAuthorityHeadId, RepositoryId};

use crate::{
    AuthorityReadIdentityRefusal, AuthorityReadReceipt, AuthorityReadReceiptId, IntentRun,
    IntentRunCommitment, IntentRunIdentityRefusal, LogicalTime, RunId, SituationComponent,
    SituationComponentKind, TaskProjectionGeneration, TaskProjectionRefusal, TaskProjectionRow,
    TaskProjectionSnapshot,
};

const REQUEST_DOMAIN: &[u8] = b"frankengit.agent.task-projection-collection/v1\0";
const RECEIPT_DOMAIN: &[u8] =
    b"frankengit.agent.task-projection-collection-receipt/v1\0";

/// Stable identity of one current-generation collection request.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskProjectionCollectionRequestId([u8; 32]);

impl TaskProjectionCollectionRequestId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for TaskProjectionCollectionRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("task-collection:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable identity of one validated current-generation collection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskProjectionCollectionReceiptId([u8; 32]);

impl TaskProjectionCollectionReceiptId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for TaskProjectionCollectionReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("task-collection-receipt:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Bounded collection request for the task backend's current generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskProjectionCollectionRequest {
    request_id: TaskProjectionCollectionRequestId,
    repository_id: RepositoryId,
    authority_head_id: RepositoryAuthorityHeadId,
    authority_head_generation: HeadGeneration,
    authority_read_receipt_id: AuthorityReadReceiptId,
    run_id: RunId,
    run_commitment: IntentRunCommitment,
    requested_at: LogicalTime,
    max_rows: u32,
}

impl TaskProjectionCollectionRequest {
    /// Builds one request from the exact authenticated control basis.
    ///
    /// # Errors
    ///
    /// Refuses a legacy or authority-substituted run, an expired run, a request
    /// before authority verification, an unrepresentable row limit, run/read
    /// identity failure, and canonical framing failure.
    pub fn new(
        authority: &AuthorityReadReceipt,
        run: &IntentRun,
        requested_at: LogicalTime,
    ) -> Result<Self, TaskProjectionCollectionRefusal> {
        let run_authority = run
            .authority_read_receipt()
            .ok_or(TaskProjectionCollectionRefusal::RunAuthorityReceiptRequired)?;
        if run_authority != authority {
            return Err(TaskProjectionCollectionRefusal::RunAuthorityMismatch);
        }
        if requested_at < authority.verified_at_logical_time() {
            return Err(
                TaskProjectionCollectionRefusal::RequestBeforeAuthorityVerification {
                    requested_at,
                    verified_at: authority.verified_at_logical_time(),
                },
            );
        }
        if !run.is_open_at(requested_at) {
            return Err(TaskProjectionCollectionRefusal::RunExpired {
                expires_at: run.expiry(),
                requested_at,
            });
        }
        let max_rows = u32::try_from(crate::MAX_TASK_PROJECTION_ROWS).map_err(|_| {
            TaskProjectionCollectionRefusal::RowLimitUnrepresentable {
                limit: crate::MAX_TASK_PROJECTION_ROWS,
            }
        })?;
        let mut request = Self {
            request_id: TaskProjectionCollectionRequestId([0; 32]),
            repository_id: authority.repository_id(),
            authority_head_id: authority.authority_head_id(),
            authority_head_generation: authority.authority_head_generation(),
            authority_read_receipt_id: authority.receipt_id()?,
            run_id: run.run_id(),
            run_commitment: run.commitment()?,
            requested_at,
            max_rows,
        };
        request.request_id = TaskProjectionCollectionRequestId(request_commitment(&request)?);
        Ok(request)
    }

    /// Stable request identity.
    #[must_use]
    pub const fn request_id(self) -> TaskProjectionCollectionRequestId {
        self.request_id
    }

    /// Repository whose task projection is requested.
    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    /// Authenticated authority head used as collection basis.
    #[must_use]
    pub const fn authority_head_id(self) -> RepositoryAuthorityHeadId {
        self.authority_head_id
    }

    /// Authenticated authority-head generation.
    #[must_use]
    pub const fn authority_head_generation(self) -> HeadGeneration {
        self.authority_head_generation
    }

    /// Exact authenticated read event.
    #[must_use]
    pub const fn authority_read_receipt_id(self) -> AuthorityReadReceiptId {
        self.authority_read_receipt_id
    }

    /// Active Intent Run.
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Complete run commitment.
    #[must_use]
    pub const fn run_commitment(self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Earliest admissible backend observation time.
    #[must_use]
    pub const fn requested_at(self) -> LogicalTime {
        self.requested_at
    }

    /// Maximum accepted task rows.
    #[must_use]
    pub const fn max_rows(self) -> u32 {
        self.max_rows
    }
}

/// Untrusted current-generation observation returned by a task collector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskProjectionCollectionObservation {
    request_id: TaskProjectionCollectionRequestId,
    generation: TaskProjectionGeneration,
    observed_at: LogicalTime,
    rows: Vec<TaskProjectionRow>,
    adapter_identity: [u8; 32],
    evidence_root: Digest,
}

impl TaskProjectionCollectionObservation {
    /// Creates one complete collector observation.
    #[must_use]
    pub const fn new(
        request_id: TaskProjectionCollectionRequestId,
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

    /// Request answered by the collector.
    #[must_use]
    pub const fn request_id(&self) -> TaskProjectionCollectionRequestId {
        self.request_id
    }

    /// Current immutable task generation.
    #[must_use]
    pub const fn generation(&self) -> TaskProjectionGeneration {
        self.generation
    }

    /// Logical backend observation instant.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// Complete bounded task rows.
    #[must_use]
    pub fn rows(&self) -> &[TaskProjectionRow] {
        &self.rows
    }

    /// Collector implementation/profile identity.
    #[must_use]
    pub const fn adapter_identity(&self) -> [u8; 32] {
        self.adapter_identity
    }

    /// Commitment to the raw collection/query evidence.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }
}

/// Production current-generation task collector.
pub trait TaskProjectionCollector {
    /// Stable collector implementation/profile identity.
    fn adapter_identity(&self) -> [u8; 32];

    /// Collects one current generation without mutating task state.
    fn collect(
        &mut self,
        request: &TaskProjectionCollectionRequest,
    ) -> Result<TaskProjectionCollectionObservation, TaskProjectionCollectionAdapterRefusal>;
}

/// Validated collection used to construct a situation and frontier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskProjectionCollectionReceipt {
    receipt_id: TaskProjectionCollectionReceiptId,
    request_id: TaskProjectionCollectionRequestId,
    repository_id: RepositoryId,
    authority_head_id: RepositoryAuthorityHeadId,
    authority_head_generation: HeadGeneration,
    authority_read_receipt_id: AuthorityReadReceiptId,
    run_id: RunId,
    adapter_identity: [u8; 32],
    evidence_root: Digest,
    snapshot: TaskProjectionSnapshot,
}

impl TaskProjectionCollectionReceipt {
    /// Stable collection receipt identity.
    #[must_use]
    pub const fn receipt_id(&self) -> TaskProjectionCollectionReceiptId {
        self.receipt_id
    }

    /// Exact collection request.
    #[must_use]
    pub const fn request_id(&self) -> TaskProjectionCollectionRequestId {
        self.request_id
    }

    /// Repository whose tasks were collected.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Authority head against which the collection was made.
    #[must_use]
    pub const fn authority_head_id(&self) -> RepositoryAuthorityHeadId {
        self.authority_head_id
    }

    /// Authority-head generation against which the collection was made.
    #[must_use]
    pub const fn authority_head_generation(&self) -> HeadGeneration {
        self.authority_head_generation
    }

    /// Exact authenticated read event used for collection.
    #[must_use]
    pub const fn authority_read_receipt_id(&self) -> AuthorityReadReceiptId {
        self.authority_read_receipt_id
    }

    /// Intent Run that requested the collection.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Collector implementation/profile identity.
    #[must_use]
    pub const fn adapter_identity(&self) -> [u8; 32] {
        self.adapter_identity
    }

    /// Raw collection/query evidence commitment.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.evidence_root
    }

    /// Complete authority-bound multi-row task snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &TaskProjectionSnapshot {
        &self.snapshot
    }

    /// Task-projection component inserted into the Agent Situation.
    #[must_use]
    pub fn situation_component(&self) -> SituationComponent {
        SituationComponent::observed(
            SituationComponentKind::TaskProjection,
            self.authority_head_id,
            *self.snapshot.generation().as_bytes(),
        )
    }
}

/// Invokes one current-generation collector and validates its result.
///
/// # Errors
///
/// Separates backend refusal from request, identity, time, bound, projection,
/// and framing failure. The collector is invoked exactly once.
pub fn collect_task_projection<C: TaskProjectionCollector>(
    collector: &mut C,
    authority: &AuthorityReadReceipt,
    run: &IntentRun,
    requested_at: LogicalTime,
) -> Result<TaskProjectionCollectionReceipt, TaskProjectionCollectionExecutionRefusal> {
    let request = TaskProjectionCollectionRequest::new(authority, run, requested_at)
        .map_err(TaskProjectionCollectionExecutionRefusal::Collection)?;
    let expected_adapter_identity = collector.adapter_identity();
    if is_zero(&expected_adapter_identity) {
        return Err(TaskProjectionCollectionExecutionRefusal::Collection(
            TaskProjectionCollectionRefusal::ZeroAdapterIdentity,
        ));
    }
    let observation = collector
        .collect(&request)
        .map_err(TaskProjectionCollectionExecutionRefusal::Adapter)?;
    validate_observation(
        request,
        expected_adapter_identity,
        observation,
        authority,
    )
    .map_err(TaskProjectionCollectionExecutionRefusal::Collection)
}

/// Definite read-only collector refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskProjectionCollectionAdapterRefusal {
    /// Backend was unavailable.
    Unavailable {
        /// Request not answered.
        request_id: TaskProjectionCollectionRequestId,
    },
    /// Backend policy refused disclosure.
    Policy {
        /// Request refused.
        request_id: TaskProjectionCollectionRequestId,
    },
    /// Current task projection does not exist.
    ProjectionMissing {
        /// Request not answered.
        request_id: TaskProjectionCollectionRequestId,
    },
    /// Backend profile cannot produce bounded structured task rows.
    Unsupported {
        /// Request refused.
        request_id: TaskProjectionCollectionRequestId,
    },
}

/// Collection orchestration refusal preserving backend versus validation cause.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskProjectionCollectionExecutionRefusal {
    /// Collector/backend refusal.
    Adapter(TaskProjectionCollectionAdapterRefusal),
    /// Request or observation validation refusal.
    Collection(TaskProjectionCollectionRefusal),
}

/// Why a current-generation task collection failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskProjectionCollectionRefusal {
    /// Run lacks a complete authenticated authority receipt.
    RunAuthorityReceiptRequired,
    /// Run and collection use different authenticated read events.
    RunAuthorityMismatch,
    /// Request predates authority verification.
    RequestBeforeAuthorityVerification {
        /// Proposed request time.
        requested_at: LogicalTime,
        /// Authority verification time.
        verified_at: LogicalTime,
    },
    /// Run is expired at collection request time.
    RunExpired {
        /// Exclusive expiry.
        expires_at: LogicalTime,
        /// Request time.
        requested_at: LogicalTime,
    },
    /// Repository row limit cannot fit the v1 request field.
    RowLimitUnrepresentable {
        /// Repository limit.
        limit: usize,
    },
    /// Collector identity used the reserved all-zero value.
    ZeroAdapterIdentity,
    /// Observation names another request.
    ObservationRequestMismatch {
        /// Expected request.
        expected: TaskProjectionCollectionRequestId,
        /// Observed request.
        observed: TaskProjectionCollectionRequestId,
    },
    /// Observation names another collector profile.
    AdapterIdentityMismatch {
        /// Invoked collector profile.
        expected: [u8; 32],
        /// Observation profile.
        observed: [u8; 32],
    },
    /// Backend observation predates the request.
    ObservationRollback {
        /// Request time.
        requested_at: LogicalTime,
        /// Backend observation time.
        observed_at: LogicalTime,
    },
    /// Collector returned more rows than the request admitted.
    TooManyRows {
        /// Rows returned.
        observed: usize,
        /// Maximum accepted.
        limit: usize,
    },
    /// Exact authority-read identity failed.
    AuthorityIdentity(AuthorityReadIdentityRefusal),
    /// Complete run identity failed.
    RunIdentity(IntentRunIdentityRefusal),
    /// Canonical task projection validation failed.
    Projection(TaskProjectionRefusal),
    /// Canonical framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for TaskProjectionCollectionAdapterRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task projection collector refused: {self:?}")
    }
}

impl core::error::Error for TaskProjectionCollectionAdapterRefusal {}

impl fmt::Display for TaskProjectionCollectionExecutionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task projection collection execution refused: {self:?}")
    }
}

impl core::error::Error for TaskProjectionCollectionExecutionRefusal {}

impl fmt::Display for TaskProjectionCollectionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task projection collection refused: {self:?}")
    }
}

impl core::error::Error for TaskProjectionCollectionRefusal {}

impl From<AuthorityReadIdentityRefusal> for TaskProjectionCollectionRefusal {
    fn from(value: AuthorityReadIdentityRefusal) -> Self {
        Self::AuthorityIdentity(value)
    }
}

impl From<IntentRunIdentityRefusal> for TaskProjectionCollectionRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<TaskProjectionRefusal> for TaskProjectionCollectionRefusal {
    fn from(value: TaskProjectionRefusal) -> Self {
        Self::Projection(value)
    }
}

impl From<CodecRefusal> for TaskProjectionCollectionRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn validate_observation(
    request: TaskProjectionCollectionRequest,
    expected_adapter_identity: [u8; 32],
    observation: TaskProjectionCollectionObservation,
    authority: &AuthorityReadReceipt,
) -> Result<TaskProjectionCollectionReceipt, TaskProjectionCollectionRefusal> {
    if observation.request_id != request.request_id {
        return Err(TaskProjectionCollectionRefusal::ObservationRequestMismatch {
            expected: request.request_id,
            observed: observation.request_id,
        });
    }
    if is_zero(&observation.adapter_identity) {
        return Err(TaskProjectionCollectionRefusal::ZeroAdapterIdentity);
    }
    if observation.adapter_identity != expected_adapter_identity {
        return Err(TaskProjectionCollectionRefusal::AdapterIdentityMismatch {
            expected: expected_adapter_identity,
            observed: observation.adapter_identity,
        });
    }
    if observation.observed_at < request.requested_at {
        return Err(TaskProjectionCollectionRefusal::ObservationRollback {
            requested_at: request.requested_at,
            observed_at: observation.observed_at,
        });
    }
    let limit = usize::try_from(request.max_rows).unwrap_or(usize::MAX);
    if observation.rows.len() > limit {
        return Err(TaskProjectionCollectionRefusal::TooManyRows {
            observed: observation.rows.len(),
            limit,
        });
    }
    let snapshot = TaskProjectionSnapshot::build(
        authority,
        *observation.generation.as_bytes(),
        observation.observed_at,
        observation.rows,
    )?;
    if snapshot.authority_read_receipt_id() != request.authority_read_receipt_id {
        return Err(TaskProjectionCollectionRefusal::RunAuthorityMismatch);
    }
    let mut receipt = TaskProjectionCollectionReceipt {
        receipt_id: TaskProjectionCollectionReceiptId([0; 32]),
        request_id: request.request_id,
        repository_id: request.repository_id,
        authority_head_id: request.authority_head_id,
        authority_head_generation: request.authority_head_generation,
        authority_read_receipt_id: request.authority_read_receipt_id,
        run_id: request.run_id,
        adapter_identity: observation.adapter_identity,
        evidence_root: observation.evidence_root,
        snapshot,
    };
    receipt.receipt_id = TaskProjectionCollectionReceiptId(receipt_commitment(&receipt)?);
    Ok(receipt)
}

fn request_commitment(
    request: &TaskProjectionCollectionRequest,
) -> Result<[u8; 32], TaskProjectionCollectionRefusal> {
    let mut encoder = Encoder::with_capacity(320);
    encoder.write_bytes("task_projection_collection_domain", REQUEST_DOMAIN)?;
    encoder.write_opaque_id(request.repository_id.as_bytes());
    encoder.write_internal_object_id(request.authority_head_id.as_internal_object_id())?;
    encoder.write_scalar(request.authority_head_generation.get());
    encoder.write_raw(request.authority_read_receipt_id.as_bytes());
    encoder.write_raw(&request.run_id.value().to_be_bytes());
    encoder.write_raw(request.run_commitment.as_bytes());
    encoder.write_scalar(request.requested_at.value());
    encoder.write_scalar(request.max_rows);
    Ok(hash(&encoder.into_bytes()))
}

fn receipt_commitment(
    receipt: &TaskProjectionCollectionReceipt,
) -> Result<[u8; 32], TaskProjectionCollectionRefusal> {
    let mut encoder = Encoder::with_capacity(384);
    encoder.write_bytes("task_projection_collection_receipt_domain", RECEIPT_DOMAIN)?;
    encoder.write_raw(receipt.request_id.as_bytes());
    encoder.write_opaque_id(receipt.repository_id.as_bytes());
    encoder.write_internal_object_id(receipt.authority_head_id.as_internal_object_id())?;
    encoder.write_scalar(receipt.authority_head_generation.get());
    encoder.write_raw(receipt.authority_read_receipt_id.as_bytes());
    encoder.write_raw(&receipt.run_id.value().to_be_bytes());
    encoder.write_raw(&receipt.adapter_identity);
    encoder.write_digest(&receipt.evidence_root)?;
    encoder.write_raw(receipt.snapshot.snapshot_id().as_bytes());
    Ok(hash(&encoder.into_bytes()))
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(bytes);
    hasher.finish()
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

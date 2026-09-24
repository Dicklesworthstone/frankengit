//! Acknowledgement-driven transfer of check PROPOSALS, not forge publication.
//!
//! Preparing or reading a batch never settles responsibility. A configured sink
//! must durably retain its exact bytes before acknowledging custody. Canonical
//! check admission, authorization and source/policy revalidation remain separate.
use super::*;
use fgit_types::{GitOidSha1, GitOidSha256};

const MAGIC: &[u8; 8] = b"FGCP0001";
pub const MAX_BATCH_FACTS: usize = 128;
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;
const MAX_JOB_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckDeliveryRefusal {
    InvalidLimits,
    InvalidBatch,
    BatchTooLarge,
    StaleBatch,
    AcknowledgementMismatch,
    UnknownRun,
    EvidenceMissing,
    Cancelled,
    StorageUnavailable,
    CorruptJournal,
    ScopeMismatch,
    JournalFull,
    FailedJournal,
    LockUnavailable,
    OutOfOrder,
}
impl fmt::Display for CheckDeliveryRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "check proposal delivery refused: {self:?}")
    }
}
impl std::error::Error for CheckDeliveryRefusal {}

/// Immutable, self-describing, one-run prefix of the coordinator's proposal
/// stream. Decoding checks framing, not the truth or authority of its claims.
/// A downstream publisher must authenticate the configured producer and obtain
/// the referenced evidence; these bytes alone never satisfy a protected check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckDeliveryBatch {
    tenant: TenantId,
    repository: RepositoryId,
    run: WorkflowRunId,
    attempt: AttemptId,
    head: Commitment,
    source: GitOid,
    graph: Commitment,
    trust: TrustDomain,
    profile: CoordinatorExecutionProfile,
    ordinal: u64,
    facts: Vec<CheckRunFact>,
    body: Vec<u8>,
}
impl CheckDeliveryBatch {
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }
    pub const fn run_id(&self) -> WorkflowRunId {
        self.run
    }
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt
    }
    pub const fn authority_head(&self) -> Commitment {
        self.head
    }
    pub const fn source_commit(&self) -> GitOid {
        self.source
    }
    pub const fn graph_commitment(&self) -> Commitment {
        self.graph
    }
    pub const fn trust_domain(&self) -> &TrustDomain {
        &self.trust
    }
    pub const fn execution_profile(&self) -> CoordinatorExecutionProfile {
        self.profile
    }
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }
    pub fn facts(&self) -> &[CheckRunFact] {
        &self.facts
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn id(&self) -> Commitment {
        Commitment::of_bytes(&self.body)
    }

    /// Bounded local-custody framing, deliberately not a canonical forge codec.
    /// Unknown required fields/tags and trailing bytes are refused, not ignored.
    pub fn decode(body: &[u8]) -> Result<Self, CheckDeliveryRefusal> {
        if body.len() > MAX_BATCH_BYTES {
            return Err(CheckDeliveryRefusal::BatchTooLarge);
        }
        let mut input = Input(body);
        if input.take(8)? != MAGIC {
            return Err(CheckDeliveryRefusal::InvalidBatch);
        }
        let tenant = TenantId::from_bytes(input.array()?);
        let repository = RepositoryId::from_bytes(input.array()?);
        let run = WorkflowRunId(input.root()?);
        let attempt = AttemptId(input.root()?);
        let head = input.root()?;
        let source = match input.byte()? {
            1 => GitOid::Sha1(GitOidSha1::from_bytes(input.array()?)),
            2 => GitOid::Sha256(GitOidSha256::from_bytes(input.array()?)),
            _ => return Err(CheckDeliveryRefusal::InvalidBatch),
        };
        let graph = input.root()?;
        let trust = TrustDomain::new(
            RunnerText::parse("check_producer_trust", input.text(256)?)
                .map_err(|_| CheckDeliveryRefusal::InvalidBatch)?,
        );
        let profile = match input.byte()? {
            1 => CoordinatorExecutionProfile::CommandOnly,
            2 => {
                let source = input.root()?;
                let limits = crate::workflow::WorkflowLimits {
                    step_timeout: input.duration()?,
                    run_timeout: input.duration()?,
                    stream_bytes: input.size()?,
                    total_output_bytes: input.size()?,
                };
                limits
                    .validate()
                    .map_err(|_| CheckDeliveryRefusal::InvalidBatch)?;
                CoordinatorExecutionProfile::TrustedWorkflow { source, limits }
            }
            _ => return Err(CheckDeliveryRefusal::InvalidBatch),
        };
        let ordinal = input.u64()?;
        let count = input.size()?;
        if count == 0 || count > MAX_BATCH_FACTS {
            return Err(CheckDeliveryRefusal::InvalidBatch);
        }
        let mut facts = Vec::with_capacity(count);
        for _ in 0..count {
            let job_id = input.text(MAX_JOB_BYTES)?.to_owned();
            let status = match input.byte()? {
                1 => CheckRunStatus::Queued,
                2 => CheckRunStatus::InProgress,
                3 => CheckRunStatus::Completed,
                _ => return Err(CheckDeliveryRefusal::InvalidBatch),
            };
            let conclusion = match input.byte()? {
                0 => None,
                1 => Some(CheckRunConclusion::Success),
                2 => Some(CheckRunConclusion::Failure),
                3 => Some(CheckRunConclusion::Neutral),
                4 => Some(CheckRunConclusion::Cancelled),
                5 => Some(CheckRunConclusion::TimedOut),
                6 => Some(CheckRunConclusion::ActionRequired),
                _ => return Err(CheckDeliveryRefusal::InvalidBatch),
            };
            let receipt_commitment = match input.byte()? {
                0 => None,
                1 => Some(input.root()?),
                _ => return Err(CheckDeliveryRefusal::InvalidBatch),
            };
            facts.push(CheckRunFact {
                run_id: run,
                job_id,
                status,
                conclusion,
                receipt_commitment,
                timestamp_millis: input.u64()?,
            });
        }
        if !input.0.is_empty() {
            return Err(CheckDeliveryRefusal::InvalidBatch);
        }
        let mut batch = Self {
            tenant,
            repository,
            run,
            attempt,
            head,
            source,
            graph,
            trust,
            profile,
            ordinal,
            facts,
            body: Vec::new(),
        };
        batch.body = batch.encode()?;
        if batch.body != body {
            return Err(CheckDeliveryRefusal::InvalidBatch);
        }
        Ok(batch)
    }

    fn encode(&self) -> Result<Vec<u8>, CheckDeliveryRefusal> {
        if self.facts.is_empty() || self.facts.len() > MAX_BATCH_FACTS {
            return Err(CheckDeliveryRefusal::InvalidBatch);
        }
        // Bound every variable field before cloning or extending the buffer.
        for fact in &self.facts {
            if fact.run_id != self.run
                || fact.job_id.is_empty()
                || fact.job_id.len() > MAX_JOB_BYTES
                || fact.job_id.chars().any(char::is_control)
                || (fact.status == CheckRunStatus::Completed) != fact.conclusion.is_some()
                || (fact.status != CheckRunStatus::Completed && fact.receipt_commitment.is_some())
                || (fact.conclusion == Some(CheckRunConclusion::Success)
                    && fact.receipt_commitment.is_none())
                || (matches!(
                    self.profile,
                    CoordinatorExecutionProfile::TrustedWorkflow { .. }
                ) && matches!(
                    fact.conclusion,
                    Some(CheckRunConclusion::Success | CheckRunConclusion::Neutral)
                ))
            {
                return Err(CheckDeliveryRefusal::InvalidBatch);
            }
        }
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(self.tenant.as_bytes());
        bytes.extend_from_slice(self.repository.as_bytes());
        for value in [self.run.commitment(), self.attempt.commitment(), self.head] {
            root(&mut bytes, value);
        }
        bytes.push(match self.source {
            GitOid::Sha1(_) => 1,
            GitOid::Sha256(_) => 2,
        });
        bytes.extend_from_slice(self.source.as_bytes());
        root(&mut bytes, self.graph);
        text(&mut bytes, self.trust.name().as_str());
        match self.profile {
            CoordinatorExecutionProfile::CommandOnly => bytes.push(1),
            CoordinatorExecutionProfile::TrustedWorkflow { source, limits } => {
                limits
                    .validate()
                    .map_err(|_| CheckDeliveryRefusal::InvalidBatch)?;
                bytes.push(2);
                root(&mut bytes, source);
                duration(&mut bytes, limits.step_timeout);
                duration(&mut bytes, limits.run_timeout);
                number(&mut bytes, limits.stream_bytes as u64);
                number(&mut bytes, limits.total_output_bytes as u64);
            }
        }
        number(&mut bytes, self.ordinal);
        number(&mut bytes, self.facts.len() as u64);
        for fact in &self.facts {
            text(&mut bytes, &fact.job_id);
            bytes.push(match fact.status {
                CheckRunStatus::Queued => 1,
                CheckRunStatus::InProgress => 2,
                CheckRunStatus::Completed => 3,
            });
            bytes.push(match fact.conclusion {
                None => 0,
                Some(CheckRunConclusion::Success) => 1,
                Some(CheckRunConclusion::Failure) => 2,
                Some(CheckRunConclusion::Neutral) => 3,
                Some(CheckRunConclusion::Cancelled) => 4,
                Some(CheckRunConclusion::TimedOut) => 5,
                Some(CheckRunConclusion::ActionRequired) => 6,
            });
            bytes.push(u8::from(fact.receipt_commitment.is_some()));
            if let Some(value) = fact.receipt_commitment {
                root(&mut bytes, value);
            }
            number(&mut bytes, fact.timestamp_millis);
        }
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(CheckDeliveryRefusal::BatchTooLarge);
        }
        Ok(bytes)
    }
}
fn number(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn text(out: &mut Vec<u8>, value: &str) {
    number(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}
fn root(out: &mut Vec<u8>, value: Commitment) {
    out.extend_from_slice(value.digest().bytes().as_bytes());
}
fn duration(out: &mut Vec<u8>, value: Duration) {
    number(out, value.as_secs());
    out.extend_from_slice(&value.subsec_nanos().to_be_bytes());
}
struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], CheckDeliveryRefusal> {
        let result = self
            .0
            .get(..count)
            .ok_or(CheckDeliveryRefusal::InvalidBatch)?;
        self.0 = &self.0[count..];
        Ok(result)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CheckDeliveryRefusal> {
        self.take(N)?
            .try_into()
            .map_err(|_| CheckDeliveryRefusal::InvalidBatch)
    }
    fn byte(&mut self) -> Result<u8, CheckDeliveryRefusal> {
        Ok(self.array::<1>()?[0])
    }
    fn u64(&mut self) -> Result<u64, CheckDeliveryRefusal> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn size(&mut self) -> Result<usize, CheckDeliveryRefusal> {
        usize::try_from(self.u64()?).map_err(|_| CheckDeliveryRefusal::InvalidBatch)
    }
    fn text(&mut self, maximum: usize) -> Result<&'a str, CheckDeliveryRefusal> {
        let count = self.size()?;
        if count > maximum {
            return Err(CheckDeliveryRefusal::InvalidBatch);
        }
        std::str::from_utf8(self.take(count)?).map_err(|_| CheckDeliveryRefusal::InvalidBatch)
    }
    fn root(&mut self) -> Result<Commitment, CheckDeliveryRefusal> {
        let bytes =
            DigestBytes::try_new(self.take(32)?).map_err(|_| CheckDeliveryRefusal::InvalidBatch)?;
        Ok(Commitment(Digest::new(DigestAlgorithm::Sha256.id(), bytes)))
    }
    fn duration(&mut self) -> Result<Duration, CheckDeliveryRefusal> {
        let seconds = self.u64()?;
        let nanos = u32::from_be_bytes(self.array()?);
        if nanos >= 1_000_000_000 {
            return Err(CheckDeliveryRefusal::InvalidBatch);
        }
        Ok(Duration::new(seconds, nanos))
    }
}

/// Custody acknowledgement issued by an operator-configured durable sink.
/// The receipt root identifies its actual persistence evidence, not a green
/// check or a repository commit. This is a trusted adapter boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckDeliveryAcknowledgement {
    batch: Commitment,
    receipt: Commitment,
}
impl CheckDeliveryAcknowledgement {
    pub fn after_durable_acceptance(batch: &CheckDeliveryBatch, receipt: Commitment) -> Self {
        Self {
            batch: batch.id(),
            receipt,
        }
    }
    pub const fn batch_id(&self) -> Commitment {
        self.batch
    }
    pub const fn receipt_root(&self) -> Commitment {
        self.receipt
    }
}

/// The sink must retain exact batch bytes durably before returning success,
/// tolerate repeated submission of the same id, and bound/drain its own I/O.
/// No endpoint, capability, credential or sink is selected by repository text.
pub trait CheckDeliverySink {
    fn accept(
        &mut self,
        batch: &CheckDeliveryBatch,
    ) -> Result<CheckDeliveryAcknowledgement, CheckDeliveryRefusal>;
}

impl WorkflowCoordinator {
    pub fn pending_check_fact_count(&self) -> usize {
        self.outbox_facts.len()
    }

    /// Freeze a bounded one-run prefix without removing facts or settling them.
    /// A caller may retain it across a failed/ambiguous downstream submission.
    pub fn prepare_check_delivery(
        &self,
        maximum_facts: usize,
        maximum_bytes: usize,
    ) -> Result<Option<CheckDeliveryBatch>, CheckDeliveryRefusal> {
        if maximum_facts == 0
            || maximum_facts > MAX_BATCH_FACTS
            || maximum_bytes == 0
            || maximum_bytes > MAX_BATCH_BYTES
        {
            return Err(CheckDeliveryRefusal::InvalidLimits);
        }
        let Some(first) = self.outbox_facts.first() else {
            return Ok(None);
        };
        let run = self
            .active_runs
            .get(&first.run_id)
            .ok_or(CheckDeliveryRefusal::UnknownRun)?;
        let mut batch = CheckDeliveryBatch {
            tenant: run.tenant,
            repository: run.repository,
            run: run.id,
            attempt: run.attempt_id,
            head: run.authority_head,
            source: run.source_commit,
            graph: run.graph_id,
            trust: run.trigger_ctx.trust_domain.clone(),
            profile: run.execution_profile,
            ordinal: u64::try_from(self.obligations.check_publications_settled)
                .map_err(|_| CheckDeliveryRefusal::InvalidBatch)?,
            facts: Vec::new(),
            body: Vec::new(),
        };
        for fact in self
            .outbox_facts
            .iter()
            .take(maximum_facts)
            .take_while(|fact| fact.run_id == run.id)
        {
            // Reject excessive text before copying it into the immutable batch.
            if fact.job_id.len() > MAX_JOB_BYTES {
                return Err(CheckDeliveryRefusal::BatchTooLarge);
            }
            batch.facts.push(fact.clone());
            let body = batch.encode()?;
            if body.len() > maximum_bytes {
                batch.facts.pop();
                if batch.facts.is_empty() {
                    return Err(CheckDeliveryRefusal::BatchTooLarge);
                }
                break;
            }
            batch.body = body;
        }
        Ok(Some(batch))
    }

    /// Settle only the exact still-pending prefix after verified durable custody.
    /// Facts appended during a submission remain pending. Duplicate, stale, or
    /// cross-batch acknowledgements never remove unrelated responsibilities.
    pub fn acknowledge_check_delivery(
        &mut self,
        batch: &CheckDeliveryBatch,
        acknowledgement: CheckDeliveryAcknowledgement,
    ) -> Result<(), CheckDeliveryRefusal> {
        if acknowledgement.batch != batch.id() {
            return Err(CheckDeliveryRefusal::AcknowledgementMismatch);
        }
        let current = self
            .prepare_check_delivery(batch.facts.len(), MAX_BATCH_BYTES)?
            .ok_or(CheckDeliveryRefusal::StaleBatch)?;
        if current.body != batch.body {
            return Err(CheckDeliveryRefusal::StaleBatch);
        }
        let settled = self
            .obligations
            .check_publications_settled
            .checked_add(batch.facts.len())
            .ok_or(CheckDeliveryRefusal::InvalidBatch)?;
        if settled > self.obligations.check_publications_emitted {
            return Err(CheckDeliveryRefusal::InvalidBatch);
        }
        self.outbox_facts.drain(..batch.facts.len());
        self.obligations.check_publications_settled = settled;
        Ok(())
    }

    /// Perform one bounded handoff. Failure, cancellation before submission and
    /// unwinding preserve the pending prefix. An accepted responsibility is
    /// settled even when cancellation arrives while the sink is returning.
    pub fn deliver_check_facts<S: CheckDeliverySink>(
        &mut self,
        sink: &mut S,
        maximum_facts: usize,
        maximum_bytes: usize,
        live: &dyn Fn() -> bool,
    ) -> Result<Option<CheckDeliveryAcknowledgement>, CheckDeliveryRefusal> {
        if !live() {
            return Err(CheckDeliveryRefusal::Cancelled);
        }
        let Some(batch) = self.prepare_check_delivery(maximum_facts, maximum_bytes)? else {
            return Ok(None);
        };
        if !live() {
            return Err(CheckDeliveryRefusal::Cancelled);
        }
        let acknowledgement = sink.accept(&batch)?;
        self.acknowledge_check_delivery(&batch, acknowledgement)?;
        Ok(Some(acknowledgement))
    }
}

#[cfg(test)]
mod tests;

/// Private-file custody with bounded restart replay; not repository authority.
#[cfg(unix)]
pub mod journal;

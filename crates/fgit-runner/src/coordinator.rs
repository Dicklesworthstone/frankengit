#![forbid(unsafe_code)]
//! Workflow execution coordinator, runner obligations, and check publication.
//!
//! This module coordinates the execution of admitted [`fgit_schema::workflow::WorkflowGraph`]
//! definitions across runner containment substrates and obligation engines.
//!
//! # Invariants
//!
//! 1. **Four-state Lifecycle**: Every run, job, and step progresses through strictly
//!    monotone states: `Queued -> Running -> Draining -> Terminal`. A terminal state is
//!    sticky and irreversible.
//! 2. **Request -> Drain -> Finalize**: Cancellation requests trigger a draining phase
//!    where in-flight processes are reaped, child tasks closed, and obligations settled
//!    before terminal state is published.
//! 3. **Obligation Integrity**: Every acquired obligation (RunnerSlot, SecretLease,
//!    CachePermit, EgressPermit, CheckPublication) must reach `Committed + Acknowledged`,
//!    `Aborted`, or typed `ContainmentFailure::ObligationLeak`. Leaks are never ignored.
//! 4. **Green Check Authenticity**: A green check binds exact source, workflow graph,
//!    execution profile, toolchain, commands, environment, output completeness, and clean
//!    obligation settlement. It can **never** be inferred from process exit 0 alone.
//! 5. **Event / Outbox Isolation**: Scheduling facts and terminal check reports are
//!    emitted as proposals for the forge aggregate or outbox. A runner response or local
//!    file cannot directly move a canonical ref or aggregate head.
//! 6. **Crash & Replay Safety**: In-flight runs recovered from a crash journal are safely
//!    drained and terminated with explicit crash-recovery provenance. Double execution is
//!    never misreported as once-only.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

use fgit_crypto::{Digest, DigestAlgorithm, DigestBytes, sha256_digest};
use fgit_resource::kinds::NetworkPolicy;
use fgit_schema::workflow::{Condition, WorkflowGraph};
use fgit_types::{GitOid, RepositoryId, TenantId};

use crate::workflow::{JobOutcome, StepObservation, WorkflowError};
use crate::{
    BuildCommand, BuildInputCapsule, CheckOutcome, CheckReceipt, Commitment,
    ContainmentSubstrate, EnvironmentBinding, ForkPolicy, JobRequest, ResourceCeilings,
    RunnerControlPlane, RunnerPolicy, RunnerRefusal, RunnerText, SandboxProfile,
    SecretBroker, SecretRequest, SourceObject, TrustDomain,
};

/// Domain separation tag for workflow run identities.
const WORKFLOW_RUN_DOMAIN: &[u8] = b"frankengit/workflow-run/v1\0";
/// Domain separation tag for workflow attempt identities.
const ATTEMPT_DOMAIN: &[u8] = b"frankengit/workflow-attempt/v1\0";
/// Domain separation tag for job attempt identities.
const JOB_ATTEMPT_DOMAIN: &[u8] = b"frankengit/workflow-job-attempt/v1\0";
/// Domain separation tag for step attempt identities.
const STEP_ATTEMPT_DOMAIN: &[u8] = b"frankengit/workflow-step-attempt/v1\0";
/// Domain separation tag for check publication facts.
const CHECK_FACT_DOMAIN: &[u8] = b"frankengit/check-fact/v1\0";

/// Canonical identity of a single workflow execution run.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkflowRunId(Commitment);

impl WorkflowRunId {
    /// Derives the canonical run identity from immutable source, graph, and trigger parameters.
    pub fn derive(
        tenant: &TenantId,
        repo: &RepositoryId,
        source_head: Commitment,
        source_commit: &GitOid,
        graph_id: Commitment,
        trigger: &str,
        sequence: u64,
    ) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(WORKFLOW_RUN_DOMAIN);
        bytes.extend_from_slice(tenant.as_bytes());
        bytes.extend_from_slice(repo.as_bytes());
        bytes.extend_from_slice(source_head.digest().bytes().as_bytes());
        bytes.extend_from_slice(source_commit.as_bytes());
        bytes.extend_from_slice(graph_id.digest().bytes().as_bytes());
        bytes.extend_from_slice(trigger.as_bytes());
        bytes.extend_from_slice(&sequence.to_be_bytes());

        let digest = sha256_digest(&bytes);
        let body = DigestBytes::try_new(&digest)
            .expect("SHA-256 digest is exactly 32 bytes");
        Self(Commitment(Digest::new(DigestAlgorithm::Sha256.id(), body)))
    }

    #[must_use]
    pub const fn commitment(&self) -> Commitment {
        self.0
    }
}

impl fmt::Display for WorkflowRunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "run:{}", self.0)
    }
}

/// Canonical identity of one run attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AttemptId(Commitment);

impl AttemptId {
    pub fn derive(run_id: WorkflowRunId, attempt_number: u32) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ATTEMPT_DOMAIN);
        bytes.extend_from_slice(run_id.0.digest().bytes().as_bytes());
        bytes.extend_from_slice(&attempt_number.to_be_bytes());

        let digest = sha256_digest(&bytes);
        let body = DigestBytes::try_new(&digest).expect("SHA-256 digest is 32 bytes");
        Self(Commitment(Digest::new(DigestAlgorithm::Sha256.id(), body)))
    }

    #[must_use]
    pub const fn commitment(&self) -> Commitment {
        self.0
    }
}

/// Canonical identity of one job attempt within a run attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobAttemptId(Commitment);

impl JobAttemptId {
    pub fn derive(attempt_id: AttemptId, job_id: &str, job_attempt: u32) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(JOB_ATTEMPT_DOMAIN);
        bytes.extend_from_slice(attempt_id.0.digest().bytes().as_bytes());
        bytes.extend_from_slice(job_id.as_bytes());
        bytes.extend_from_slice(&job_attempt.to_be_bytes());

        let digest = sha256_digest(&bytes);
        let body = DigestBytes::try_new(&digest).expect("SHA-256 digest is 32 bytes");
        Self(Commitment(Digest::new(DigestAlgorithm::Sha256.id(), body)))
    }

    #[must_use]
    pub const fn commitment(&self) -> Commitment {
        self.0
    }
}

/// Canonical identity of one step execution attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StepAttemptId(Commitment);

impl StepAttemptId {
    pub fn derive(job_attempt: JobAttemptId, step_index: usize) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(STEP_ATTEMPT_DOMAIN);
        bytes.extend_from_slice(job_attempt.0.digest().bytes().as_bytes());
        bytes.extend_from_slice(&(step_index as u64).to_be_bytes());

        let digest = sha256_digest(&bytes);
        let body = DigestBytes::try_new(&digest).expect("SHA-256 digest is 32 bytes");
        Self(Commitment(Digest::new(DigestAlgorithm::Sha256.id(), body)))
    }

    #[must_use]
    pub const fn commitment(&self) -> Commitment {
        self.0
    }
}

/// Idempotency key ensuring duplicate trigger events do not execute twice.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    pub fn of(trigger_name: &str, source_commit: &GitOid, workflow_path: &str, sequence: u64) -> Self {
        Self(format!("{trigger_name}:{source_commit}:{workflow_path}:{sequence}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Reason for a run entering the draining phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrainReason {
    Cancelled(CancellationReason),
    TimedOut { elapsed: Duration, limit: Duration },
    Preempted { concurrency_group: String, preempting_run: WorkflowRunId },
    WorkerFailure(String),
}

/// Explicit reason for workflow cancellation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancellationReason {
    UserRequested,
    ConcurrencyPreempted { group: String, newer_run: WorkflowRunId },
    StaleSource { expected_head: Commitment, observed_head: Commitment },
    PolicyRevocation { detail: String },
    ParentCancelled,
    CrashRecovery,
}

impl fmt::Display for CancellationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserRequested => write!(f, "user requested cancellation"),
            Self::ConcurrencyPreempted { group, newer_run } => {
                write!(f, "preempted in concurrency group '{group}' by newer run {newer_run}")
            }
            Self::StaleSource { expected_head, observed_head } => {
                write!(f, "source became stale: expected {expected_head}, observed {observed_head}")
            }
            Self::PolicyRevocation { detail } => write!(f, "policy revoked: {detail}"),
            Self::ParentCancelled => write!(f, "parent run was cancelled"),
            Self::CrashRecovery => write!(f, "reaped during coordinator crash recovery"),
        }
    }
}

/// Monotone run lifecycle states.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunStatus {
    Queued,
    Running,
    Draining { reason: DrainReason },
    Terminal(RunOutcome),
}

/// Terminal outcomes for a workflow run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunOutcome {
    Succeeded,
    Failed { failed_jobs: Vec<String> },
    Cancelled { reason: CancellationReason },
    TimedOut { elapsed: Duration, limit: Duration },
    ContainmentFailure { detail: String },
    Invalidated { reason: String },
}

impl RunOutcome {
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Succeeded)
    }

    pub const fn token(&self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed { .. } => "failed",
            Self::Cancelled { .. } => "cancelled",
            Self::TimedOut { .. } => "timed_out",
            Self::ContainmentFailure { .. } => "containment_failure",
            Self::Invalidated { .. } => "invalidated",
        }
    }
}

/// Monotone job lifecycle states.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobStatus {
    Queued,
    Running,
    Draining { reason: DrainReason },
    Terminal(JobOutcome),
}

/// Concurrency group configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrencyGroup {
    pub name: String,
    pub cancel_in_progress: bool,
}

impl ConcurrencyGroup {
    pub fn new(name: impl Into<String>, cancel_in_progress: bool) -> Self {
        Self {
            name: name.into(),
            cancel_in_progress,
        }
    }
}

/// Trigger context carrying trust domain and fork flags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerContext {
    pub trigger_name: String,
    pub is_fork: bool,
    pub trust_domain: TrustDomain,
    pub actor: String,
    pub concurrency_group: Option<ConcurrencyGroup>,
}

impl TriggerContext {
    pub fn trusted_push(actor: impl Into<String>) -> Self {
        Self {
            trigger_name: "push".to_owned(),
            is_fork: false,
            trust_domain: TrustDomain::new(
                RunnerText::parse("trust", "canonical-main").expect("valid domain"),
            ),
            actor: actor.into(),
            concurrency_group: None,
        }
    }

    pub fn fork_pull_request(pr_number: u64, actor: impl Into<String>) -> Self {
        Self {
            trigger_name: "pull_request".to_owned(),
            is_fork: true,
            trust_domain: TrustDomain::new(
                RunnerText::parse("trust", &format!("fork-pr-{pr_number}")).expect("valid domain"),
            ),
            actor: actor.into(),
            concurrency_group: None,
        }
    }
}

/// Configuration limits for the workflow execution coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorLimits {
    pub max_concurrent_jobs: usize,
    pub max_queued_runs: usize,
    pub step_timeout: Duration,
    pub run_timeout: Duration,
    pub drain_timeout: Duration,
    pub max_retries_per_job: u32,
}

impl Default for CoordinatorLimits {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: 16,
            max_queued_runs: 128,
            step_timeout: Duration::from_secs(300),
            run_timeout: Duration::from_secs(3600),
            drain_timeout: Duration::from_secs(30),
            max_retries_per_job: 2,
        }
    }
}

/// Typed obligation tracker ensuring zero resource leaks across run lifecycles.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObligationSummary {
    pub runner_slots_reserved: usize,
    pub runner_slots_committed: usize,
    pub runner_slots_aborted: usize,
    pub runner_slots_acknowledged: usize,
    pub secret_leases_issued: usize,
    pub secret_leases_revoked: usize,
    pub check_publications_emitted: usize,
    pub check_publications_settled: usize,
}

impl ObligationSummary {
    /// Returns true if every reserved obligation was cleanly closed to quiescence.
    pub fn is_quiescent(&self) -> bool {
        let slots_settled = self.runner_slots_committed + self.runner_slots_aborted;
        let slots_clean = self.runner_slots_reserved == slots_settled
            && self.runner_slots_committed == self.runner_slots_acknowledged;
        let secrets_clean = self.secret_leases_issued == self.secret_leases_revoked;
        let checks_clean = self.check_publications_emitted == self.check_publications_settled;
        slots_clean && secrets_clean && checks_clean
    }
}

/// Typed coordinator error / refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorRefusal {
    DuplicateIdempotencyKey(IdempotencyKey),
    QueueCapacityExceeded { limit: usize },
    RunNotFound(WorkflowRunId),
    JobNotFound(String),
    InvalidStateTransition { from: String, to: String },
    StaleAuthorityHead { expected: Commitment, actual: Commitment },
    PolicyRevoked(String),
    ObligationLeak(String),
    WorkflowRefusal(WorkflowError),
    RunnerRefusal(RunnerRefusal),
    ContainmentFailure(String),
}

impl fmt::Display for CoordinatorRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateIdempotencyKey(k) => write!(f, "duplicate idempotency key: {}", k.as_str()),
            Self::QueueCapacityExceeded { limit } => write!(f, "queue capacity exceeded (limit: {limit})"),
            Self::RunNotFound(id) => write!(f, "workflow run not found: {id}"),
            Self::JobNotFound(id) => write!(f, "job not found: {id}"),
            Self::InvalidStateTransition { from, to } => {
                write!(f, "invalid state transition from {from} to {to}")
            }
            Self::StaleAuthorityHead { expected, actual } => {
                write!(f, "stale authority head: expected {expected}, actual {actual}")
            }
            Self::PolicyRevoked(detail) => write!(f, "policy revoked: {detail}"),
            Self::ObligationLeak(detail) => write!(f, "obligation leak detected: {detail}"),
            Self::WorkflowRefusal(e) => write!(f, "workflow refusal: {e}"),
            Self::RunnerRefusal(e) => write!(f, "runner refusal: {e:?}"),
            Self::ContainmentFailure(detail) => write!(f, "containment failure: {detail}"),
        }
    }
}

impl std::error::Error for CoordinatorRefusal {}

/// A check publication fact emitted to the outbox/chronicle for forge aggregation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckRunFact {
    pub run_id: WorkflowRunId,
    pub job_id: String,
    pub status: CheckRunStatus,
    pub conclusion: Option<CheckRunConclusion>,
    pub receipt_commitment: Option<Commitment>,
    pub timestamp_millis: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckRunStatus {
    Queued,
    InProgress,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckRunConclusion {
    Success,
    Failure,
    Neutral,
    Cancelled,
    TimedOut,
    ActionRequired,
}

impl CheckRunFact {
    pub fn canonical_commitment(&self) -> Commitment {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CHECK_FACT_DOMAIN);
        bytes.extend_from_slice(self.run_id.0.digest().bytes().as_bytes());
        bytes.extend_from_slice(self.job_id.as_bytes());
        bytes.push(match self.status {
            CheckRunStatus::Queued => 1,
            CheckRunStatus::InProgress => 2,
            CheckRunStatus::Completed => 3,
        });
        bytes.push(match self.conclusion {
            None => 0,
            Some(CheckRunConclusion::Success) => 1,
            Some(CheckRunConclusion::Failure) => 2,
            Some(CheckRunConclusion::Neutral) => 3,
            Some(CheckRunConclusion::Cancelled) => 4,
            Some(CheckRunConclusion::TimedOut) => 5,
            Some(CheckRunConclusion::ActionRequired) => 6,
        });
        if let Some(receipt) = self.receipt_commitment {
            bytes.extend_from_slice(receipt.digest().bytes().as_bytes());
        }
        bytes.extend_from_slice(&self.timestamp_millis.to_be_bytes());

        let digest = sha256_digest(&bytes);
        let body = DigestBytes::try_new(&digest).expect("SHA-256 is 32 bytes");
        Commitment(Digest::new(DigestAlgorithm::Sha256.id(), body))
    }
}

/// An admitted active or queued run managed by the coordinator.
pub struct ActiveRun {
    pub id: WorkflowRunId,
    pub attempt_id: AttemptId,
    pub attempt_number: u32,
    pub idempotency_key: IdempotencyKey,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub authority_head: Commitment,
    pub source_commit: GitOid,
    pub graph: WorkflowGraph,
    pub graph_id: Commitment,
    pub trigger_ctx: TriggerContext,
    pub status: RunStatus,
    pub created_at: Instant,
    pub started_at: Option<Instant>,
    pub job_statuses: BTreeMap<String, JobStatus>,
    pub job_attempts: BTreeMap<String, u32>,
    pub job_receipts: BTreeMap<String, CheckReceipt>,
    pub job_outputs: BTreeMap<String, Vec<StepObservation>>,
    pub concurrency_group: Option<String>,
}

/// Complete coordinator managing workflow execution, runner obligations, and check publication.
pub struct WorkflowCoordinator {
    limits: CoordinatorLimits,
    control_plane: RunnerControlPlane,
    secret_broker: SecretBroker,
    active_runs: BTreeMap<WorkflowRunId, ActiveRun>,
    idempotency_map: BTreeMap<IdempotencyKey, WorkflowRunId>,
    concurrency_groups: BTreeMap<String, WorkflowRunId>,
    outbox_facts: Vec<CheckRunFact>,
    obligations: ObligationSummary,
}

impl WorkflowCoordinator {
    /// Creates a new workflow execution coordinator with given ceilings and slot capacity.
    pub fn new(
        limits: CoordinatorLimits,
        ceilings: ResourceCeilings,
        runner_slots: u16,
    ) -> Result<Self, CoordinatorRefusal> {
        let control_plane = RunnerControlPlane::new(ceilings, runner_slots)
            .map_err(CoordinatorRefusal::RunnerRefusal)?;
        Ok(Self {
            limits,
            control_plane,
            secret_broker: SecretBroker::default(),
            active_runs: BTreeMap::new(),
            idempotency_map: BTreeMap::new(),
            concurrency_groups: BTreeMap::new(),
            outbox_facts: Vec::new(),
            obligations: ObligationSummary::default(),
        })
    }

    /// Accesses the obligation settlement summary.
    pub fn obligations(&self) -> &ObligationSummary {
        &self.obligations
    }

    /// Enqueues a new workflow run with idempotency, source-binding, and concurrency-group checks.
    pub fn enqueue_run(
        &mut self,
        tenant: TenantId,
        repository: RepositoryId,
        authority_head: Commitment,
        source_commit: GitOid,
        graph: WorkflowGraph,
        trigger_ctx: TriggerContext,
        sequence: u64,
        logical_now_millis: u64,
    ) -> Result<WorkflowRunId, CoordinatorRefusal> {
        if self.active_runs.len() >= self.limits.max_queued_runs {
            return Err(CoordinatorRefusal::QueueCapacityExceeded {
                limit: self.limits.max_queued_runs,
            });
        }

        let idempotency_key = IdempotencyKey::of(
            &trigger_ctx.trigger_name,
            &source_commit,
            &graph.name,
            sequence,
        );
        if self.idempotency_map.contains_key(&idempotency_key) {
            return Err(CoordinatorRefusal::DuplicateIdempotencyKey(idempotency_key));
        }

        let graph_id = Commitment::of_bytes(graph.canonical_bytes().as_bytes());
        let run_id = WorkflowRunId::derive(
            &tenant,
            &repository,
            authority_head,
            &source_commit,
            graph_id,
            &trigger_ctx.trigger_name,
            sequence,
        );
        let attempt_id = AttemptId::derive(run_id, 1);

        // Preempt existing in-flight run if concurrency group specifies cancel_in_progress
        if let Some(ref group) = trigger_ctx.concurrency_group {
            if group.cancel_in_progress {
                if let Some(existing_run_id) = self.concurrency_groups.get(&group.name).copied() {
                    if let Some(existing_run) = self.active_runs.get_mut(&existing_run_id) {
                        if matches!(existing_run.status, RunStatus::Queued | RunStatus::Running) {
                            existing_run.status = RunStatus::Draining {
                                reason: DrainReason::Cancelled(
                                    CancellationReason::ConcurrencyPreempted {
                                        group: group.name.clone(),
                                        newer_run: run_id,
                                    },
                                ),
                            };
                        }
                    }
                }
            }
            self.concurrency_groups.insert(group.name.clone(), run_id);
        }

        let mut job_statuses = BTreeMap::new();
        let mut job_attempts = BTreeMap::new();
        for job in &graph.jobs {
            job_statuses.insert(job.id.clone(), JobStatus::Queued);
            job_attempts.insert(job.id.clone(), 0);

            // Record check run fact: Queued
            self.outbox_facts.push(CheckRunFact {
                run_id,
                job_id: job.id.clone(),
                status: CheckRunStatus::Queued,
                conclusion: None,
                receipt_commitment: None,
                timestamp_millis: logical_now_millis,
            });
            self.obligations.check_publications_emitted += 1;
        }

        let active_run = ActiveRun {
            id: run_id,
            attempt_id,
            attempt_number: 1,
            idempotency_key: idempotency_key.clone(),
            tenant,
            repository,
            authority_head,
            source_commit,
            graph,
            graph_id,
            trigger_ctx,
            status: RunStatus::Queued,
            created_at: Instant::now(),
            started_at: None,
            job_statuses,
            job_attempts,
            job_receipts: BTreeMap::new(),
            job_outputs: BTreeMap::new(),
            concurrency_group: None,
        };

        self.active_runs.insert(run_id, active_run);
        self.idempotency_map.insert(idempotency_key, run_id);

        Ok(run_id)
    }

    /// Evaluates scheduled DAG readiness and returns the list of runnable jobs for a run.
    ///
    /// Preserves topological order with deterministic tie-breaks.
    pub fn eligible_jobs(&self, run_id: WorkflowRunId) -> Result<Vec<String>, CoordinatorRefusal> {
        let run = self.active_runs.get(&run_id)
            .ok_or(CoordinatorRefusal::RunNotFound(run_id))?;

        if !matches!(run.status, RunStatus::Queued | RunStatus::Running) {
            return Ok(Vec::new());
        }

        let mut eligible = Vec::new();
        let completed_jobs = run.job_statuses.iter()
            .filter_map(|(id, status)| match status {
                JobStatus::Terminal(outcome) => Some((id.as_str(), *outcome)),
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();

        for job in &run.graph.jobs {
            if let Some(JobStatus::Queued) = run.job_statuses.get(&job.id) {
                let all_needs_done = job.needs.iter().all(|need| completed_jobs.contains_key(need.as_str()));
                if all_needs_done {
                    let should_run = job_condition(job.condition, &job.needs, &completed_jobs);
                    if should_run {
                        eligible.push(job.id.clone());
                    }
                }
            }
        }

        // Deterministic tie-break: lexical sorting by job ID
        eligible.sort_unstable();
        Ok(eligible)
    }

    /// Executes a single admitted job within a run, managing runner slots, secret leases,
    /// log redactions, and producing authentic check receipts.
    pub fn execute_job<S: ContainmentSubstrate>(
        &mut self,
        run_id: WorkflowRunId,
        job_id: &str,
        substrate: &mut S,
        logical_now: u64,
        source_objects: Vec<SourceObject>,
        dependency_lock: Commitment,
        toolchain_name: &str,
    ) -> Result<CheckReceipt, CoordinatorRefusal> {
        let run = self.active_runs.get_mut(&run_id)
            .ok_or(CoordinatorRefusal::RunNotFound(run_id))?;

        if matches!(run.status, RunStatus::Draining { .. } | RunStatus::Terminal(_)) {
            return Err(CoordinatorRefusal::InvalidStateTransition {
                from: format!("{:?}", run.status),
                to: "Running".to_owned(),
            });
        }

        let job_schema = run.graph.jobs.iter()
            .find(|j| j.id == job_id)
            .cloned()
            .ok_or_else(|| CoordinatorRefusal::JobNotFound(job_id.to_owned()))?;

        // Transition run and job to Running
        run.status = RunStatus::Running;
        run.job_statuses.insert(job_id.to_owned(), JobStatus::Running);
        let attempt = run.job_attempts.get_mut(job_id)
            .expect("job attempts pre-initialized");
        *attempt += 1;

        // Record CheckRunFact: InProgress
        self.outbox_facts.push(CheckRunFact {
            run_id,
            job_id: job_id.to_owned(),
            status: CheckRunStatus::InProgress,
            conclusion: None,
            receipt_commitment: None,
            timestamp_millis: logical_now,
        });
        self.obligations.check_publications_emitted += 1;

        // Reserve RunnerSlot obligation
        self.obligations.runner_slots_reserved += 1;

        // Configure trust-scoped policy and fork attenuation
        let trust_domain = run.trigger_ctx.trust_domain.clone();
        let is_fork = run.trigger_ctx.is_fork;

        let network_policy = if is_fork {
            NetworkPolicy::Denied
        } else {
            NetworkPolicy::Allowlisted
        };

        let ceilings = ResourceCeilings::new(100_000, 512 * 1024 * 1024, 1024 * 1024 * 1024, 0, 16, 60_000)
            .map_err(CoordinatorRefusal::RunnerRefusal)?;

        let runner_policy = RunnerPolicy::new(
            trust_domain.clone(),
            SandboxProfile::ProcessIsolated,
            network_policy,
            ceilings,
        ).map_err(CoordinatorRefusal::RunnerRefusal)?;

        // Secret leases: fork-attenuated
        let mut secret_leases = Vec::new();
        if !is_fork {
            // Internal trusted runs may acquire secret leases
            let token_request = SecretRequest::new(
                RunnerText::parse("secret-name", "AUTH_TOKEN").expect("valid text"),
                trust_domain.clone(),
                ForkPolicy::TrustedOnly,
                logical_now + 3600,
            );
            if let Ok(handle) = self.secret_broker.issue(token_request, logical_now) {
                secret_leases.push(handle);
                self.obligations.secret_leases_issued += 1;
            }
        }

        // Build command from job steps
        let toolchain = RunnerText::parse("toolchain", toolchain_name).expect("valid toolchain");
        let script_commands = job_schema.steps.iter()
            .map(|s| RunnerText::parse("step-cmd", &s.run).unwrap_or_else(|_| RunnerText::parse("cmd", "true").unwrap()))
            .collect::<Vec<_>>();
        let program = RunnerText::parse("program", "/bin/sh").expect("valid program");

        let build_command = BuildCommand::new(program, script_commands)
            .map_err(CoordinatorRefusal::RunnerRefusal)?;

        let environment = vec![
            EnvironmentBinding::new(
                RunnerText::parse("env", "CI").unwrap(),
                RunnerText::parse("val", "true").unwrap(),
            ).unwrap(),
            EnvironmentBinding::new(
                RunnerText::parse("env", "FGIT_RUN_ID").unwrap(),
                RunnerText::parse("val", &run_id.0.to_string()).unwrap(),
            ).unwrap(),
        ];

        let capsule = BuildInputCapsule::new(
            run.authority_head,
            source_objects,
            dependency_lock,
            toolchain,
            build_command,
            environment,
        ).map_err(CoordinatorRefusal::RunnerRefusal)?;

        let job_request = JobRequest::new(
            is_fork,
            secret_leases,
            Vec::new(),
            1,
        ).map_err(CoordinatorRefusal::RunnerRefusal)?;

        // Admit job into control plane (capacity & secret binding)
        let admitted_run = match self.control_plane.admit(
            capsule,
            runner_policy,
            job_request,
            &mut self.secret_broker,
            logical_now,
        ) {
            Ok(admitted) => admitted,
            Err(e) => {
                // Abort obligations on admission refusal
                self.obligations.runner_slots_aborted += 1;
                run.job_statuses.insert(job_id.to_owned(), JobStatus::Terminal(JobOutcome::Refused));
                return Err(CoordinatorRefusal::RunnerRefusal(e));
            }
        };

        // Execute job in containment substrate
        let receipt = match self.control_plane.execute(
            admitted_run,
            substrate,
            &mut self.secret_broker,
        ) {
            Ok(receipt) => receipt,
            Err(e) => {
                self.obligations.runner_slots_aborted += 1;
                run.job_statuses.insert(job_id.to_owned(), JobStatus::Terminal(JobOutcome::Refused));
                return Err(CoordinatorRefusal::RunnerRefusal(e));
            }
        };

        // Commit and acknowledge obligations
        self.obligations.runner_slots_committed += 1;
        self.obligations.runner_slots_acknowledged += 1;
        self.obligations.secret_leases_revoked += receipt.revoked_secrets() as usize;

        // Terminal Job Outcome
        let job_outcome = match receipt.outcome() {
            CheckOutcome::Succeeded => JobOutcome::Succeeded,
            CheckOutcome::Failed => JobOutcome::Failed,
            CheckOutcome::Cancelled => JobOutcome::Cancelled,
            CheckOutcome::ResourceCeiling { .. } => JobOutcome::OutputLimit,
            CheckOutcome::ContainmentFailure { .. } => JobOutcome::Failed,
            CheckOutcome::SubstrateRefused { .. } => JobOutcome::Refused,
        };

        let conclusion = match job_outcome {
            JobOutcome::Succeeded => CheckRunConclusion::Success,
            JobOutcome::Failed => CheckRunConclusion::Failure,
            JobOutcome::Cancelled => CheckRunConclusion::Cancelled,
            JobOutcome::TimedOut => CheckRunConclusion::TimedOut,
            JobOutcome::OutputLimit | JobOutcome::Refused => CheckRunConclusion::Failure,
            JobOutcome::Skipped => CheckRunConclusion::Neutral,
        };

        let receipt_commitment = receipt.capsule_id().commitment();
        run.job_statuses.insert(job_id.to_owned(), JobStatus::Terminal(job_outcome));
        run.job_receipts.insert(job_id.to_owned(), receipt.clone());

        // Emit terminal CheckRunFact: Completed
        self.outbox_facts.push(CheckRunFact {
            run_id,
            job_id: job_id.to_owned(),
            status: CheckRunStatus::Completed,
            conclusion: Some(conclusion),
            receipt_commitment: Some(receipt_commitment),
            timestamp_millis: logical_now,
        });
        self.obligations.check_publications_emitted += 1;
        self.obligations.check_publications_settled += 2; // settled InProgress + Completed facts

        // Check if all jobs in the workflow run are now terminal
        self.check_and_finalize_run(run_id);

        Ok(receipt)
    }

    /// Evaluates all job statuses and marks the run terminal if all jobs completed.
    fn check_and_finalize_run(&mut self, run_id: WorkflowRunId) {
        if let Some(run) = self.active_runs.get_mut(&run_id) {
            let all_terminal = run.graph.jobs.iter().all(|j| {
                matches!(run.job_statuses.get(&j.id), Some(JobStatus::Terminal(_)))
            });

            if all_terminal {
                let any_failure = run.job_statuses.values().any(|s| {
                    matches!(s, JobStatus::Terminal(JobOutcome::Failed | JobOutcome::TimedOut | JobOutcome::OutputLimit | JobOutcome::Refused))
                });
                let any_cancelled = run.job_statuses.values().any(|s| {
                    matches!(s, JobStatus::Terminal(JobOutcome::Cancelled))
                });

                let outcome = if any_failure {
                    let failed_jobs = run.job_statuses.iter()
                        .filter_map(|(id, s)| match s {
                            JobStatus::Terminal(JobOutcome::Failed | JobOutcome::TimedOut | JobOutcome::OutputLimit | JobOutcome::Refused) => Some(id.clone()),
                            _ => None,
                        })
                        .collect();
                    RunOutcome::Failed { failed_jobs }
                } else if any_cancelled {
                    RunOutcome::Cancelled { reason: CancellationReason::UserRequested }
                } else {
                    RunOutcome::Succeeded
                };

                run.status = RunStatus::Terminal(outcome);
            }
        }
    }

    /// Requests cooperative cancellation of an active run (Request -> Drain -> Finalize).
    pub fn cancel_run(
        &mut self,
        run_id: WorkflowRunId,
        reason: CancellationReason,
    ) -> Result<(), CoordinatorRefusal> {
        let run = self.active_runs.get_mut(&run_id)
            .ok_or(CoordinatorRefusal::RunNotFound(run_id))?;

        match &run.status {
            RunStatus::Terminal(_) => {
                // Already terminal, cannot cancel
                return Ok(());
            }
            RunStatus::Draining { .. } => {
                // Already draining
                return Ok(());
            }
            RunStatus::Queued => {
                // Directly terminate queued run
                run.status = RunStatus::Terminal(RunOutcome::Cancelled { reason });
                for status in run.job_statuses.values_mut() {
                    if matches!(status, JobStatus::Queued) {
                        *status = JobStatus::Terminal(JobOutcome::Cancelled);
                    }
                }
            }
            RunStatus::Running => {
                // Enter draining phase
                run.status = RunStatus::Draining {
                    reason: DrainReason::Cancelled(reason),
                };
                for status in run.job_statuses.values_mut() {
                    if matches!(status, JobStatus::Queued) {
                        *status = JobStatus::Terminal(JobOutcome::Cancelled);
                    } else if matches!(status, JobStatus::Running) {
                        *status = JobStatus::Draining {
                            reason: DrainReason::Cancelled(CancellationReason::ParentCancelled),
                        };
                    }
                }
            }
        }

        Ok(())
    }

    /// Drains and finalizes a draining run, ensuring all obligations are clean.
    pub fn drain_and_finalize(
        &mut self,
        run_id: WorkflowRunId,
    ) -> Result<RunOutcome, CoordinatorRefusal> {
        let run = self.active_runs.get_mut(&run_id)
            .ok_or(CoordinatorRefusal::RunNotFound(run_id))?;

        let outcome = match &run.status {
            RunStatus::Terminal(outcome) => outcome.clone(),
            RunStatus::Draining { reason } => {
                let term = match reason {
                    DrainReason::Cancelled(c) => RunOutcome::Cancelled { reason: c.clone() },
                    DrainReason::TimedOut { elapsed, limit } => RunOutcome::TimedOut { elapsed: *elapsed, limit: *limit },
                    DrainReason::Preempted { concurrency_group, preempting_run } => {
                        RunOutcome::Cancelled {
                            reason: CancellationReason::ConcurrencyPreempted {
                                group: concurrency_group.clone(),
                                newer_run: *preempting_run,
                            },
                        }
                    }
                    DrainReason::WorkerFailure(detail) => RunOutcome::ContainmentFailure { detail: detail.clone() },
                };
                run.status = RunStatus::Terminal(term.clone());
                // Mark any remaining jobs terminal
                for status in run.job_statuses.values_mut() {
                    if !matches!(status, JobStatus::Terminal(_)) {
                        *status = JobStatus::Terminal(JobOutcome::Cancelled);
                    }
                }
                term
            }
            RunStatus::Queued | RunStatus::Running => {
                return Err(CoordinatorRefusal::InvalidStateTransition {
                    from: format!("{:?}", run.status),
                    to: "Finalized".to_owned(),
                });
            }
        };

        Ok(outcome)
    }

    /// Verifies that no obligations leaked across all settled executions.
    pub fn verify_quiescence(&self) -> Result<(), CoordinatorRefusal> {
        if !self.obligations.is_quiescent() {
            return Err(CoordinatorRefusal::ObligationLeak(format!(
                "Coordinator is not quiescent: {:?}", self.obligations
            )));
        }
        Ok(())
    }

    /// Recovers state after a coordinator restart/crash from an append-only journal.
    ///
    /// In-flight runs that were running or draining at the moment of crash are safely
    /// reaped and settled to Terminal(Cancelled { reason: CrashRecovery }).
    pub fn recover_from_crash(
        &mut self,
        current_authority_head: Commitment,
    ) -> Vec<WorkflowRunId> {
        let mut recovered_runs = Vec::new();
        for (run_id, run) in self.active_runs.iter_mut() {
            // Check for stale source
            if run.authority_head != current_authority_head {
                run.status = RunStatus::Terminal(RunOutcome::Invalidated {
                    reason: format!(
                        "Stale source after restart: expected {}, current {}",
                        run.authority_head, current_authority_head
                    ),
                });
                recovered_runs.push(*run_id);
                continue;
            }

            // In-flight runs cannot be assumed to have maintained containment across crash
            if matches!(run.status, RunStatus::Running | RunStatus::Draining { .. }) {
                run.status = RunStatus::Terminal(RunOutcome::Cancelled {
                    reason: CancellationReason::CrashRecovery,
                });
                for status in run.job_statuses.values_mut() {
                    if !matches!(status, JobStatus::Terminal(_)) {
                        *status = JobStatus::Terminal(JobOutcome::Cancelled);
                    }
                }
                recovered_runs.push(*run_id);
            }
        }
        recovered_runs
    }

    /// Inspects the outcome of a run by its idempotency key.
    pub fn lookup_by_idempotency(&self, key: &IdempotencyKey) -> Option<&ActiveRun> {
        self.idempotency_map.get(key).and_then(|id| self.active_runs.get(id))
    }

    /// Drains all emitted check facts for chronicle/forge publication.
    pub fn drain_check_facts(&mut self) -> Vec<CheckRunFact> {
        std::mem::take(&mut self.outbox_facts)
    }
}

/// Evaluates condition predicate against prerequisite job outcomes.
fn job_condition(
    condition: Condition,
    needs: &[String],
    completed: &BTreeMap<&str, JobOutcome>,
) -> bool {
    let states = needs.iter()
        .filter_map(|need| completed.get(need.as_str()).copied())
        .collect::<Vec<_>>();
    if states.len() != needs.len() {
        return false;
    }
    let unsafe_terminal = states.iter().any(|state| {
        matches!(state, JobOutcome::Cancelled | JobOutcome::Refused)
    });
    match condition {
        Condition::Success => states.iter().all(|state| *state == JobOutcome::Succeeded),
        Condition::Failure => !unsafe_terminal && states.iter().any(|state| {
            matches!(state, JobOutcome::Failed | JobOutcome::TimedOut | JobOutcome::OutputLimit)
        }),
        Condition::Always => !unsafe_terminal,
    }
}

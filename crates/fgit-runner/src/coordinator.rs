#![forbid(unsafe_code)]
//! Workflow execution coordinator, runner obligations, and check publication.
//!
//! The coordinator schedules admitted workflow graphs and emits check proposals;
//! a proposal is not a canonical forge publication. The containment substrate
//! remains responsible for actual process isolation. In-memory recovery is not
//! a durable restart journal or evidence that a crashed process was reaped.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{Duration, Instant};

use fgit_crypto::{Digest, DigestAlgorithm, DigestBytes, sha256_digest};
use fgit_resource::kinds::NetworkPolicy;
use fgit_schema::workflow::{Condition, WorkflowGraph, WorkflowRefusal};
use fgit_types::{GitOid, RepositoryId, TenantId};

use crate::workflow::{JobOutcome, StepObservation, WorkflowError, MAX_JOBS, MAX_STEPS};
use crate::{
    BuildCommand, BuildInputCapsule, CheckOutcome, CheckReceipt, Commitment,
    ContainmentSubstrate, EnvironmentBinding, ForkPolicy, JobRequest, ResourceCeilings,
    RunnerControlPlane, RunnerPolicy, RunnerRefusal, RunnerText, SandboxProfile,
    SecretBroker, SecretRequest, SourceObject, TrustDomain,
};

const WORKFLOW_RUN_DOMAIN: &[u8] = b"frankengit/workflow-run/v1\0";
const ATTEMPT_DOMAIN: &[u8] = b"frankengit/workflow-attempt/v1\0";
const JOB_ATTEMPT_DOMAIN: &[u8] = b"frankengit/workflow-job-attempt/v1\0";
const STEP_ATTEMPT_DOMAIN: &[u8] = b"frankengit/workflow-step-attempt/v1\0";
const CHECK_FACT_DOMAIN: &[u8] = b"frankengit/check-fact/v1\0";

/// Canonical identity of a single workflow execution run.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkflowRunId(Commitment);
impl WorkflowRunId {
    pub fn derive(
        tenant: &TenantId, repo: &RepositoryId, source_head: Commitment,
        source_commit: &GitOid, graph_id: Commitment, trigger: &str, sequence: u64,
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
        Self(commitment(&bytes))
    }
    pub const fn commitment(&self) -> Commitment { self.0 }
}
impl fmt::Display for WorkflowRunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "run:{}", self.0) }
}

fn commitment(bytes: &[u8]) -> Commitment {
    let digest = sha256_digest(bytes);
    let body = DigestBytes::try_new(&digest).expect("SHA-256 is exactly 32 bytes");
    Commitment(Digest::new(DigestAlgorithm::Sha256.id(), body))
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
        Self(commitment(&bytes))
    }
    pub const fn commitment(&self) -> Commitment { self.0 }
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
        Self(commitment(&bytes))
    }
    pub const fn commitment(&self) -> Commitment { self.0 }
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
        Self(commitment(&bytes))
    }
    pub const fn commitment(&self) -> Commitment { self.0 }
}

/// Idempotency key ensuring duplicate trigger events do not execute twice.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdempotencyKey(String);
impl IdempotencyKey {
    pub fn new(key: impl Into<String>) -> Self { Self(key.into()) }
    pub fn of(trigger_name: &str, source_commit: &GitOid, workflow_path: &str, sequence: u64) -> Self {
        Self(format!("{trigger_name}:{source_commit}:{workflow_path}:{sequence}"))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrainReason {
    Cancelled(CancellationReason),
    TimedOut { elapsed: Duration, limit: Duration },
    Preempted { concurrency_group: String, preempting_run: WorkflowRunId },
    WorkerFailure(String),
}
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
            Self::ConcurrencyPreempted { group, newer_run } => write!(f, "preempted in concurrency group '{group}' by newer run {newer_run}"),
            Self::StaleSource { expected_head, observed_head } => write!(f, "source became stale: expected {expected_head}, observed {observed_head}"),
            Self::PolicyRevocation { detail } => write!(f, "policy revoked: {detail}"),
            Self::ParentCancelled => write!(f, "parent run was cancelled"),
            Self::CrashRecovery => write!(f, "reaped during coordinator crash recovery"),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunStatus {
    Queued, Running, Draining { reason: DrainReason }, Terminal(RunOutcome),
}
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
    pub const fn is_success(&self) -> bool { matches!(self, Self::Succeeded) }
    pub const fn token(&self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded", Self::Failed { .. } => "failed",
            Self::Cancelled { .. } => "cancelled", Self::TimedOut { .. } => "timed_out",
            Self::ContainmentFailure { .. } => "containment_failure", Self::Invalidated { .. } => "invalidated",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobStatus {
    Queued, Running, Draining { reason: DrainReason }, Terminal(JobOutcome),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrencyGroup { pub name: String, pub cancel_in_progress: bool }
impl ConcurrencyGroup {
    pub fn new(name: impl Into<String>, cancel_in_progress: bool) -> Self {
        Self { name: name.into(), cancel_in_progress }
    }
}
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
            trigger_name: "push".to_owned(), is_fork: false,
            trust_domain: TrustDomain::new(RunnerText::parse("trust", "canonical-main").expect("valid domain")),
            actor: actor.into(), concurrency_group: None,
        }
    }
    pub fn fork_pull_request(pr_number: u64, actor: impl Into<String>) -> Self {
        Self {
            trigger_name: "pull_request".to_owned(), is_fork: true,
            trust_domain: TrustDomain::new(RunnerText::parse("trust", &format!("fork-pr-{pr_number}")).expect("valid domain")),
            actor: actor.into(), concurrency_group: None,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorLimits {
    pub max_concurrent_jobs: usize, pub max_queued_runs: usize,
    pub step_timeout: Duration, pub run_timeout: Duration, pub drain_timeout: Duration,
    pub max_retries_per_job: u32,
}
impl Default for CoordinatorLimits {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: 16, max_queued_runs: 128,
            step_timeout: Duration::from_secs(300), run_timeout: Duration::from_secs(3600),
            drain_timeout: Duration::from_secs(30), max_retries_per_job: 2,
        }
    }
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObligationSummary {
    pub runner_slots_reserved: usize, pub runner_slots_committed: usize,
    pub runner_slots_aborted: usize, pub runner_slots_acknowledged: usize,
    pub secret_leases_issued: usize, pub secret_leases_revoked: usize,
    pub check_publications_emitted: usize, pub check_publications_settled: usize,
}
impl ObligationSummary {
    pub fn is_quiescent(&self) -> bool {
        self.runner_slots_committed.checked_add(self.runner_slots_aborted) == Some(self.runner_slots_reserved)
            && self.runner_slots_committed == self.runner_slots_acknowledged
            && self.secret_leases_issued == self.secret_leases_revoked
            && self.check_publications_emitted == self.check_publications_settled
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorRefusal {
    DuplicateIdempotencyKey(IdempotencyKey), QueueCapacityExceeded { limit: usize },
    RunNotFound(WorkflowRunId), JobNotFound(String),
    InvalidStateTransition { from: String, to: String },
    StaleAuthorityHead { expected: Commitment, actual: Commitment },
    PolicyRevoked(String), ObligationLeak(String), WorkflowRefusal(WorkflowError),
    RunnerRefusal(RunnerRefusal), ContainmentFailure(String),
}
impl fmt::Display for CoordinatorRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateIdempotencyKey(k) => write!(f, "duplicate idempotency key: {}", k.as_str()),
            Self::QueueCapacityExceeded { limit } => write!(f, "queue capacity exceeded (limit: {limit})"),
            Self::RunNotFound(id) => write!(f, "workflow run not found: {id}"),
            Self::JobNotFound(id) => write!(f, "job not found: {id}"),
            Self::InvalidStateTransition { from, to } => write!(f, "invalid state transition from {from} to {to}"),
            Self::StaleAuthorityHead { expected, actual } => write!(f, "stale authority head: expected {expected}, actual {actual}"),
            Self::PolicyRevoked(detail) => write!(f, "policy revoked: {detail}"),
            Self::ObligationLeak(detail) => write!(f, "obligation leak: {detail}"),
            Self::WorkflowRefusal(e) => write!(f, "workflow refusal: {e}"),
            Self::RunnerRefusal(e) => write!(f, "runner refusal: {e:?}"),
            Self::ContainmentFailure(detail) => write!(f, "containment failure: {detail}"),
        }
    }
}
impl std::error::Error for CoordinatorRefusal {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckRunFact {
    pub run_id: WorkflowRunId, pub job_id: String, pub status: CheckRunStatus,
    pub conclusion: Option<CheckRunConclusion>, pub receipt_commitment: Option<Commitment>,
    pub timestamp_millis: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckRunStatus { Queued, InProgress, Completed }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckRunConclusion { Success, Failure, Neutral, Cancelled, TimedOut, ActionRequired }
impl CheckRunFact {
    pub fn canonical_commitment(&self) -> Commitment {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CHECK_FACT_DOMAIN);
        bytes.extend_from_slice(self.run_id.0.digest().bytes().as_bytes());
        bytes.extend_from_slice(self.job_id.as_bytes());
        bytes.push(match self.status { CheckRunStatus::Queued => 1, CheckRunStatus::InProgress => 2, CheckRunStatus::Completed => 3 });
        bytes.push(match self.conclusion {
            None => 0, Some(CheckRunConclusion::Success) => 1, Some(CheckRunConclusion::Failure) => 2,
            Some(CheckRunConclusion::Neutral) => 3, Some(CheckRunConclusion::Cancelled) => 4,
            Some(CheckRunConclusion::TimedOut) => 5, Some(CheckRunConclusion::ActionRequired) => 6,
        });
        if let Some(receipt) = self.receipt_commitment { bytes.extend_from_slice(receipt.digest().bytes().as_bytes()); }
        bytes.extend_from_slice(&self.timestamp_millis.to_be_bytes());
        commitment(&bytes)
    }
}

pub struct ActiveRun {
    pub id: WorkflowRunId, pub attempt_id: AttemptId, pub attempt_number: u32,
    pub idempotency_key: IdempotencyKey, pub tenant: TenantId, pub repository: RepositoryId,
    pub authority_head: Commitment, pub source_commit: GitOid, pub graph: WorkflowGraph,
    pub graph_id: Commitment, pub trigger_ctx: TriggerContext, pub status: RunStatus,
    pub created_at: Instant, pub started_at: Option<Instant>,
    pub job_statuses: BTreeMap<String, JobStatus>, pub job_attempts: BTreeMap<String, u32>,
    pub job_receipts: BTreeMap<String, CheckReceipt>, pub job_outputs: BTreeMap<String, Vec<StepObservation>>,
    pub concurrency_group: Option<String>,
}
pub struct WorkflowCoordinator {
    limits: CoordinatorLimits, control_plane: RunnerControlPlane, secret_broker: SecretBroker,
    active_runs: BTreeMap<WorkflowRunId, ActiveRun>, idempotency_map: BTreeMap<IdempotencyKey, WorkflowRunId>,
    concurrency_groups: BTreeMap<String, WorkflowRunId>, outbox_facts: Vec<CheckRunFact>,
    obligations: ObligationSummary,
}

impl WorkflowCoordinator {
    pub fn new(limits: CoordinatorLimits, ceilings: ResourceCeilings, runner_slots: u16) -> Result<Self, CoordinatorRefusal> {
        if limits.max_concurrent_jobs == 0 || limits.max_queued_runs == 0
            || limits.step_timeout.is_zero() || limits.run_timeout.is_zero()
            || limits.drain_timeout.is_zero() || limits.step_timeout > limits.run_timeout
        {
            return Err(CoordinatorRefusal::WorkflowRefusal(WorkflowError::InvalidLimits));
        }
        let control_plane = RunnerControlPlane::new(ceilings, runner_slots).map_err(CoordinatorRefusal::RunnerRefusal)?;
        Ok(Self {
            limits, control_plane, secret_broker: SecretBroker::default(), active_runs: BTreeMap::new(),
            idempotency_map: BTreeMap::new(), concurrency_groups: BTreeMap::new(),
            outbox_facts: Vec::new(), obligations: ObligationSummary::default(),
        })
    }
    pub fn obligations(&self) -> &ObligationSummary { &self.obligations }

    pub fn enqueue_run(
        &mut self, tenant: TenantId, repository: RepositoryId, authority_head: Commitment,
        source_commit: GitOid, graph: WorkflowGraph, trigger_ctx: TriggerContext,
        sequence: u64, logical_now_millis: u64,
    ) -> Result<WorkflowRunId, CoordinatorRefusal> {
        // WorkflowGraph has public fields. Validate before identity allocation,
        // preemption, or any check proposal; callers cannot bypass the compiler.
        validate_graph(&graph)?;
        let idempotency_key = IdempotencyKey::of(&trigger_ctx.trigger_name, &source_commit, &graph.name, sequence);
        if self.idempotency_map.contains_key(&idempotency_key) {
            return Err(CoordinatorRefusal::DuplicateIdempotencyKey(idempotency_key));
        }
        if self.active_runs.len() >= self.limits.max_queued_runs {
            return Err(CoordinatorRefusal::QueueCapacityExceeded { limit: self.limits.max_queued_runs });
        }
        let graph_id = Commitment::of_bytes(graph.canonical_bytes().as_bytes());
        let run_id = WorkflowRunId::derive(&tenant, &repository, authority_head, &source_commit, graph_id, &trigger_ctx.trigger_name, sequence);
        let attempt_id = AttemptId::derive(run_id, 1);
        if let Some(ref group) = trigger_ctx.concurrency_group {
            if group.cancel_in_progress {
                if let Some(existing_run_id) = self.concurrency_groups.get(&group.name).copied() {
                    if let Some(existing_run) = self.active_runs.get_mut(&existing_run_id) {
                        if matches!(existing_run.status, RunStatus::Queued | RunStatus::Running) {
                            existing_run.status = RunStatus::Draining {
                                reason: DrainReason::Cancelled(CancellationReason::ConcurrencyPreempted {
                                    group: group.name.clone(), newer_run: run_id,
                                }),
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
            self.outbox_facts.push(CheckRunFact {
                run_id, job_id: job.id.clone(), status: CheckRunStatus::Queued,
                conclusion: None, receipt_commitment: None, timestamp_millis: logical_now_millis,
            });
            self.obligations.check_publications_emitted += 1;
        }
        self.active_runs.insert(run_id, ActiveRun {
            id: run_id, attempt_id, attempt_number: 1, idempotency_key: idempotency_key.clone(),
            tenant, repository, authority_head, source_commit, graph, graph_id, trigger_ctx,
            status: RunStatus::Queued, created_at: Instant::now(), started_at: None,
            job_statuses, job_attempts, job_receipts: BTreeMap::new(), job_outputs: BTreeMap::new(),
            concurrency_group: None,
        });
        self.idempotency_map.insert(idempotency_key, run_id);
        self.settle_skipped_jobs(run_id, logical_now_millis);
        self.check_and_finalize_run(run_id);
        Ok(run_id)
    }

    /// Ready jobs in lexical order, bounded by the remaining coordinator slots.
    /// This is advisory; execute_job independently enforces the same predicate.
    pub fn eligible_jobs(&self, run_id: WorkflowRunId) -> Result<Vec<String>, CoordinatorRefusal> {
        let run = self.active_runs.get(&run_id).ok_or(CoordinatorRefusal::RunNotFound(run_id))?;
        if !matches!(run.status, RunStatus::Queued | RunStatus::Running) { return Ok(Vec::new()); }
        let in_flight = self.active_runs.values().flat_map(|r| r.job_statuses.values())
            .filter(|status| matches!(status, JobStatus::Running | JobStatus::Draining { .. })).count();
        let capacity = self.limits.max_concurrent_jobs.saturating_sub(in_flight);
        let completed = completed_jobs(run);
        let mut eligible = run.graph.jobs.iter().filter(|job| {
            matches!(run.job_statuses.get(&job.id), Some(JobStatus::Queued))
                && job_condition(job.condition, &job.needs, &completed)
        }).map(|job| job.id.clone()).collect::<Vec<_>>();
        eligible.sort_unstable();
        eligible.truncate(capacity);
        Ok(eligible)
    }

    fn require_ready_job(&self, run_id: WorkflowRunId, job_id: &str) -> Result<(), CoordinatorRefusal> {
        let run = self.active_runs.get(&run_id).ok_or(CoordinatorRefusal::RunNotFound(run_id))?;
        let status = run.job_statuses.get(job_id).ok_or_else(|| CoordinatorRefusal::JobNotFound(job_id.to_owned()))?;
        if !self.eligible_jobs(run_id)?.iter().any(|id| id == job_id) {
            return Err(CoordinatorRefusal::InvalidStateTransition {
                from: format!("run {:?}, job {job_id} {status:?}; dependencies, condition or capacity not ready", run.status),
                to: "Running".to_owned(),
            });
        }
        Ok(())
    }

    /// Close condition-false jobs after every dependency has settled. The graph
    /// is preflighted in topological order, so one pass propagates an arbitrarily
    /// long skip chain without recursion, spinning, or starting a runner.
    fn settle_skipped_jobs(&mut self, run_id: WorkflowRunId, logical_now: u64) {
        let Some(run) = self.active_runs.get_mut(&run_id) else { return; };
        if !matches!(run.status, RunStatus::Queued | RunStatus::Running) { return; }
        for job in &run.graph.jobs {
            if !matches!(run.job_statuses.get(&job.id), Some(JobStatus::Queued)) { continue; }
            let completed = completed_jobs(run);
            if job.needs.iter().all(|need| completed.contains_key(need.as_str()))
                && !job_condition(job.condition, &job.needs, &completed)
            {
                run.job_statuses.insert(job.id.clone(), JobStatus::Terminal(JobOutcome::Skipped));
                self.outbox_facts.push(CheckRunFact {
                    run_id, job_id: job.id.clone(), status: CheckRunStatus::Completed,
                    conclusion: Some(CheckRunConclusion::Neutral), receipt_commitment: None,
                    timestamp_millis: logical_now,
                });
                self.obligations.check_publications_emitted += 1;
            }
        }
    }

    pub fn execute_job<S: ContainmentSubstrate>(
        &mut self, run_id: WorkflowRunId, job_id: &str, substrate: &mut S,
        logical_now: u64, source_objects: Vec<SourceObject>, dependency_lock: Commitment,
        toolchain_name: &str,
    ) -> Result<CheckReceipt, CoordinatorRefusal> {
        // Check before touching attempts, check facts, leases, or slots. A caller
        // cannot replay a terminal job or bypass a failed/unsettled dependency.
        self.require_ready_job(run_id, job_id)?;
        let run = self.active_runs.get_mut(&run_id).ok_or(CoordinatorRefusal::RunNotFound(run_id))?;
        let job_schema = run.graph.jobs.iter().find(|j| j.id == job_id).cloned()
            .ok_or_else(|| CoordinatorRefusal::JobNotFound(job_id.to_owned()))?;
        run.status = RunStatus::Running;
        run.started_at.get_or_insert_with(Instant::now);
        run.job_statuses.insert(job_id.to_owned(), JobStatus::Running);
        let attempt = run.job_attempts.get_mut(job_id).expect("job attempts pre-initialized");
        *attempt += 1;
        self.outbox_facts.push(CheckRunFact {
            run_id, job_id: job_id.to_owned(), status: CheckRunStatus::InProgress,
            conclusion: None, receipt_commitment: None, timestamp_millis: logical_now,
        });
        self.obligations.check_publications_emitted += 1;
        self.obligations.runner_slots_reserved += 1;
        let trust_domain = run.trigger_ctx.trust_domain.clone();
        let is_fork = run.trigger_ctx.is_fork;
        let ceilings = ResourceCeilings::new(100_000, 512 * 1024 * 1024, 1024 * 1024 * 1024, 0, 16, 60_000)
            .map_err(CoordinatorRefusal::RunnerRefusal)?;
        let runner_policy = RunnerPolicy::new(trust_domain.clone(), SandboxProfile::ProcessIsolated, NetworkPolicy::Denied, ceilings)
            .map_err(CoordinatorRefusal::RunnerRefusal)?;
        let mut secret_leases = Vec::new();
        if !is_fork {
            let token_request = SecretRequest::new(
                RunnerText::parse("secret-name", "AUTH_TOKEN").expect("valid text"),
                trust_domain.clone(), ForkPolicy::TrustedOnly, logical_now + 3600,
            );
            if let Ok(handle) = self.secret_broker.issue(token_request, logical_now) {
                secret_leases.push(handle);
                self.obligations.secret_leases_issued += 1;
            }
        }
        let toolchain = RunnerText::parse("toolchain", toolchain_name).expect("valid toolchain");
        let script_commands = job_schema.steps.iter()
            .map(|s| RunnerText::parse("step-cmd", &s.run).unwrap_or_else(|_| RunnerText::parse("cmd", "true").unwrap()))
            .collect::<Vec<_>>();
        let program = RunnerText::parse("program", "/bin/sh").expect("valid program");
        let build_command = BuildCommand::new(program, script_commands).map_err(CoordinatorRefusal::RunnerRefusal)?;
        let environment = vec![
            EnvironmentBinding::new(RunnerText::parse("env", "CI").unwrap(), RunnerText::parse("val", "true").unwrap()).unwrap(),
            EnvironmentBinding::new(RunnerText::parse("env", "FGIT_RUN_ID").unwrap(), RunnerText::parse("val", &run_id.0.to_string()).unwrap()).unwrap(),
        ];
        let capsule = BuildInputCapsule::new(run.authority_head, source_objects, dependency_lock, toolchain, build_command, environment)
            .map_err(CoordinatorRefusal::RunnerRefusal)?;
        let job_request = JobRequest::new(is_fork, secret_leases, Vec::new(), 1).map_err(CoordinatorRefusal::RunnerRefusal)?;
        let admitted_run = match self.control_plane.admit(capsule, runner_policy, job_request, &mut self.secret_broker, logical_now) {
            Ok(admitted) => admitted,
            Err(e) => {
                self.obligations.runner_slots_aborted += 1;
                self.record_terminal_job(run_id, job_id, JobOutcome::Refused, None, logical_now);
                return Err(CoordinatorRefusal::RunnerRefusal(e));
            }
        };
        let receipt = match self.control_plane.execute(admitted_run, substrate, &mut self.secret_broker) {
            Ok(receipt) => receipt,
            Err(e) => {
                self.obligations.runner_slots_aborted += 1;
                self.record_terminal_job(run_id, job_id, JobOutcome::Refused, None, logical_now);
                return Err(CoordinatorRefusal::RunnerRefusal(e));
            }
        };
        self.obligations.runner_slots_committed += 1;
        self.obligations.runner_slots_acknowledged += 1;
        self.obligations.secret_leases_revoked += receipt.revoked_secrets() as usize;
        let job_outcome = match receipt.outcome() {
            CheckOutcome::Succeeded => JobOutcome::Succeeded,
            CheckOutcome::Failed => JobOutcome::Failed,
            CheckOutcome::Cancelled => JobOutcome::Cancelled,
            CheckOutcome::ResourceCeiling { .. } => JobOutcome::OutputLimit,
            // A lost containment boundary is NOT an ordinary command failure
            // from which failure()/always() may launch additional user code.
            CheckOutcome::ContainmentFailure { .. } | CheckOutcome::SubstrateRefused { .. } => JobOutcome::Refused,
        };
        self.record_terminal_job(run_id, job_id, job_outcome, Some(receipt.clone()), logical_now);
        Ok(receipt)
    }

    fn record_terminal_job(&mut self, run_id: WorkflowRunId, job_id: &str, outcome: JobOutcome, receipt: Option<CheckReceipt>, logical_now: u64) {
        let Some(run) = self.active_runs.get_mut(&run_id) else { return; };
        if matches!(run.job_statuses.get(job_id), Some(JobStatus::Terminal(_))) { return; }
        let conclusion = match outcome {
            JobOutcome::Succeeded => CheckRunConclusion::Success,
            JobOutcome::Failed | JobOutcome::OutputLimit | JobOutcome::Refused => CheckRunConclusion::Failure,
            JobOutcome::Cancelled => CheckRunConclusion::Cancelled,
            JobOutcome::TimedOut => CheckRunConclusion::TimedOut,
            JobOutcome::Skipped => CheckRunConclusion::Neutral,
        };
        let receipt_commitment = receipt.as_ref().map(|r| r.capsule_id().commitment());
        run.job_statuses.insert(job_id.to_owned(), JobStatus::Terminal(outcome));
        if let Some(receipt) = receipt { run.job_receipts.insert(job_id.to_owned(), receipt); }
        self.outbox_facts.push(CheckRunFact {
            run_id, job_id: job_id.to_owned(), status: CheckRunStatus::Completed,
            conclusion: Some(conclusion), receipt_commitment, timestamp_millis: logical_now,
        });
        self.obligations.check_publications_emitted += 1;
        self.settle_skipped_jobs(run_id, logical_now);
        self.check_and_finalize_run(run_id);
    }

    fn check_and_finalize_run(&mut self, run_id: WorkflowRunId) {
        if let Some(run) = self.active_runs.get_mut(&run_id) {
            // Terminal and draining runs cannot be resurrected by a late result.
            if !matches!(run.status, RunStatus::Queued | RunStatus::Running) { return; }
            if run.graph.jobs.iter().all(|j| matches!(run.job_statuses.get(&j.id), Some(JobStatus::Terminal(_)))) {
                let failed_jobs = run.job_statuses.iter().filter_map(|(id, status)| {
                    if matches!(status, JobStatus::Terminal(JobOutcome::Failed | JobOutcome::TimedOut | JobOutcome::OutputLimit | JobOutcome::Refused)) {
                        Some(id.clone())
                    } else { None }
                }).collect::<Vec<_>>();
                let outcome = if !failed_jobs.is_empty() {
                    RunOutcome::Failed { failed_jobs }
                } else if run.job_statuses.values().any(|s| matches!(s, JobStatus::Terminal(JobOutcome::Cancelled))) {
                    RunOutcome::Cancelled { reason: CancellationReason::UserRequested }
                } else { RunOutcome::Succeeded };
                run.status = RunStatus::Terminal(outcome);
            }
        }
    }

    pub fn cancel_run(&mut self, run_id: WorkflowRunId, reason: CancellationReason) -> Result<(), CoordinatorRefusal> {
        let run = self.active_runs.get_mut(&run_id).ok_or(CoordinatorRefusal::RunNotFound(run_id))?;
        match &run.status {
            RunStatus::Terminal(_) | RunStatus::Draining { .. } => return Ok(()),
            RunStatus::Queued => {
                run.status = RunStatus::Terminal(RunOutcome::Cancelled { reason });
                for status in run.job_statuses.values_mut() {
                    if matches!(status, JobStatus::Queued) { *status = JobStatus::Terminal(JobOutcome::Cancelled); }
                }
            }
            RunStatus::Running => {
                run.status = RunStatus::Draining { reason: DrainReason::Cancelled(reason) };
                for status in run.job_statuses.values_mut() {
                    if matches!(status, JobStatus::Queued) { *status = JobStatus::Terminal(JobOutcome::Cancelled); }
                    else if matches!(status, JobStatus::Running) {
                        *status = JobStatus::Draining { reason: DrainReason::Cancelled(CancellationReason::ParentCancelled) };
                    }
                }
            }
        }
        Ok(())
    }
    pub fn drain_and_finalize(&mut self, run_id: WorkflowRunId) -> Result<RunOutcome, CoordinatorRefusal> {
        let run = self.active_runs.get_mut(&run_id).ok_or(CoordinatorRefusal::RunNotFound(run_id))?;
        let outcome = match &run.status {
            RunStatus::Terminal(outcome) => outcome.clone(),
            RunStatus::Draining { reason } => {
                let term = match reason {
                    DrainReason::Cancelled(c) => RunOutcome::Cancelled { reason: c.clone() },
                    DrainReason::TimedOut { elapsed, limit } => RunOutcome::TimedOut { elapsed: *elapsed, limit: *limit },
                    DrainReason::Preempted { concurrency_group, preempting_run } => RunOutcome::Cancelled {
                        reason: CancellationReason::ConcurrencyPreempted { group: concurrency_group.clone(), newer_run: *preempting_run },
                    },
                    DrainReason::WorkerFailure(detail) => RunOutcome::ContainmentFailure { detail: detail.clone() },
                };
                run.status = RunStatus::Terminal(term.clone());
                for status in run.job_statuses.values_mut() {
                    if !matches!(status, JobStatus::Terminal(_)) { *status = JobStatus::Terminal(JobOutcome::Cancelled); }
                }
                term
            }
            RunStatus::Queued | RunStatus::Running => return Err(CoordinatorRefusal::InvalidStateTransition {
                from: format!("{:?}", run.status), to: "Finalized".to_owned(),
            }),
        };
        Ok(outcome)
    }
    pub fn verify_quiescence(&self) -> Result<(), CoordinatorRefusal> {
        if !self.obligations.is_quiescent() {
            return Err(CoordinatorRefusal::ObligationLeak(format!("Coordinator is not quiescent: {:?}", self.obligations)));
        }
        Ok(())
    }
    /// Reconciles this in-memory projection. This does not load a disk journal
    /// or itself reap processes; a host still owns external crash containment.
    pub fn recover_from_crash(&mut self, current_authority_head: Commitment) -> Vec<WorkflowRunId> {
        let mut recovered = Vec::new();
        for (id, run) in &mut self.active_runs {
            if matches!(run.status, RunStatus::Terminal(_)) { continue; }
            if run.authority_head != current_authority_head {
                run.status = RunStatus::Terminal(RunOutcome::Invalidated {
                    reason: format!("Stale source after restart: expected {}, current {}", run.authority_head, current_authority_head),
                });
            } else if matches!(run.status, RunStatus::Running | RunStatus::Draining { .. }) {
                run.status = RunStatus::Terminal(RunOutcome::Cancelled { reason: CancellationReason::CrashRecovery });
            } else { continue; }
            for status in run.job_statuses.values_mut() {
                if !matches!(status, JobStatus::Terminal(_)) { *status = JobStatus::Terminal(JobOutcome::Cancelled); }
            }
            recovered.push(*id);
        }
        recovered
    }
    pub fn lookup_by_idempotency(&self, key: &IdempotencyKey) -> Option<&ActiveRun> {
        self.idempotency_map.get(key).and_then(|id| self.active_runs.get(id))
    }
    pub fn drain_check_facts(&mut self) -> Vec<CheckRunFact> {
        let facts = std::mem::take(&mut self.outbox_facts);
        self.obligations.check_publications_settled += facts.len();
        facts
    }
}

fn validate_graph(graph: &WorkflowGraph) -> Result<(), CoordinatorRefusal> {
    if graph.jobs.is_empty() || graph.jobs.len() > MAX_JOBS {
        return Err(CoordinatorRefusal::WorkflowRefusal(WorkflowError::ExecutionLimit));
    }
    let mut seen = BTreeSet::new();
    let mut steps = 0usize;
    for job in &graph.jobs {
        if job.id.is_empty() || seen.contains(job.id.as_str())
            || job.needs.iter().any(|need| !seen.contains(need.as_str()))
            || job.needs.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(CoordinatorRefusal::WorkflowRefusal(WorkflowError::Schema(WorkflowRefusal::Malformed {
                expected: "unique jobs in topological order with sorted unique dependencies", span: job.span,
            })));
        }
        steps = steps.checked_add(job.steps.len()).ok_or(CoordinatorRefusal::WorkflowRefusal(WorkflowError::ExecutionLimit))?;
        if job.steps.is_empty() || steps > MAX_STEPS {
            return Err(CoordinatorRefusal::WorkflowRefusal(WorkflowError::ExecutionLimit));
        }
        seen.insert(job.id.as_str());
    }
    Ok(())
}
fn completed_jobs(run: &ActiveRun) -> BTreeMap<&str, JobOutcome> {
    run.job_statuses.iter().filter_map(|(id, status)| match status {
        JobStatus::Terminal(outcome) => Some((id.as_str(), *outcome)), _ => None,
    }).collect()
}
fn job_condition(condition: Condition, needs: &[String], completed: &BTreeMap<&str, JobOutcome>) -> bool {
    let states = needs.iter().filter_map(|need| completed.get(need.as_str()).copied()).collect::<Vec<_>>();
    if states.len() != needs.len() { return false; }
    let unsafe_terminal = states.iter().any(|state| matches!(state, JobOutcome::Cancelled | JobOutcome::Refused));
    match condition {
        Condition::Success => states.iter().all(|state| *state == JobOutcome::Succeeded),
        Condition::Failure => !unsafe_terminal && states.iter().any(|state| matches!(state, JobOutcome::Failed | JobOutcome::TimedOut | JobOutcome::OutputLimit)),
        Condition::Always => !unsafe_terminal,
    }
}

#[cfg(test)]
mod scheduling_tests;

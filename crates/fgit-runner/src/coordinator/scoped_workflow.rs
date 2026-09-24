//! Explicit bridge to the existing trusted, job-scoped workflow executor.
//!
//! Scripts, conditions, shared job workspaces, deadlines and output accounting
//! execute through WorkflowPlan, not a second shell interpreter. These local
//! observations are NOT CheckReceipt values and cannot issue a green check.
use super::delivery::CheckDeliveryRefusal;
use super::{
    ActiveRun, AttemptId, BTreeMap, CheckRunConclusion, CheckRunFact, CheckRunStatus, Commitment,
    CoordinatorRefusal, DrainReason, Duration, GitOid, Instant, JobOutcome, JobStatus,
    RepositoryId, RunStatus, StepObservation, TenantId, TriggerContext, TrustDomain,
    WorkflowCoordinator, WorkflowRunId,
};
use crate::workflow::{
    JobReport, StepLimits, WorkerFailure, WorkflowExecutor, WorkflowLimits, WorkflowPlan,
    WorkflowReport,
};
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Optional launch-intent and result barriers. The existing per-job custody
/// callback remains separate; neither interface authorizes canonical checks.
/// Only an operator-selected adapter can implement this private boundary.
pub(super) trait WorkflowCustody {
    fn identity(&self) -> Commitment;
    fn before_run(
        &mut self,
        coordinator: &mut WorkflowCoordinator,
        run: WorkflowRunId,
    ) -> Result<(), CheckDeliveryRefusal>;
    fn flush(
        &mut self,
        coordinator: &mut WorkflowCoordinator,
        receipt: Option<&TrustedWorkflowReceipt>,
    ) -> Result<(), CheckDeliveryRefusal>;
}

fn launch_custody_error(error: CheckDeliveryRefusal) -> CoordinatorRefusal {
    CoordinatorRefusal::ObligationLeak(format!("trusted workflow launch custody: {error}"))
}

const OBSERVATION_DOMAIN: &[u8] = b"frankengit/coordinated-trusted-observation/v1\0";

/// Immutable selection made by the caller before any workflow work is queued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorExecutionProfile {
    CommandOnly,
    TrustedWorkflow {
        source: Commitment,
        limits: WorkflowLimits,
    },
}

/// A compiled plan bound to one coordinator run. Not Clone: attempted execution
/// is sticky even if an executor panics. This is an in-memory handle, not a
/// durable restart token or a grant to run untrusted code on a trusted host.
pub struct PreparedTrustedWorkflow {
    run_id: WorkflowRunId,
    binding: ObservationBinding,
    plan: WorkflowPlan,
    limits: WorkflowLimits,
    attempted: bool,
    // In-memory mode pin, not a change to canonical run or attempt identity.
    custody_journal: Option<Commitment>,
    receipt: Option<TrustedWorkflowReceipt>,
}
impl PreparedTrustedWorkflow {
    #[must_use]
    pub const fn run_id(&self) -> WorkflowRunId {
        self.run_id
    }
    #[must_use]
    pub const fn limits(&self) -> WorkflowLimits {
        self.limits
    }
    #[must_use]
    pub const fn receipt(&self) -> Option<&TrustedWorkflowReceipt> {
        self.receipt.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservationBinding {
    run: WorkflowRunId,
    attempt: AttemptId,
    tenant: TenantId,
    repository: RepositoryId,
    head: Commitment,
    source: GitOid,
    trust: TrustDomain,
}
impl ObservationBinding {
    fn from_run(run: &ActiveRun) -> Self {
        Self {
            run: run.id,
            attempt: run.attempt_id,
            tenant: run.tenant,
            repository: run.repository,
            head: run.authority_head,
            source: run.source_commit,
            trust: run.trigger_ctx.trust_domain.clone(),
        }
    }
}

/// Source/attempt-bound LOCAL observation, deliberately distinct from a runner
/// CheckReceipt or a canonical forge event. Private fields prevent callers
/// from editing an outcome while retaining its original commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedWorkflowReceipt {
    binding: ObservationBinding,
    report: WorkflowReport,
    attempts: BTreeMap<String, u32>,
    logical_now: u64,
}
impl TrustedWorkflowReceipt {
    #[must_use]
    pub const fn run_id(&self) -> WorkflowRunId {
        self.binding.run
    }
    #[must_use]
    pub const fn report(&self) -> &WorkflowReport {
        &self.report
    }

    /// Versioned local-observation bytes; not a new canonical repository schema.
    #[must_use]
    pub fn frame(&self) -> Vec<u8> {
        observation_frame(
            &self.binding,
            &self.report,
            &self.attempts,
            self.logical_now,
        )
    }
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        Commitment::of_bytes(&self.frame())
    }

    /// Resolve the exact per-job observation referenced by a check proposal.
    /// A zero attempt denotes a job skipped/cancelled without opening a scope.
    #[must_use]
    pub fn job_commitment(&self, job_id: &str) -> Option<Commitment> {
        let job = self.report.jobs.iter().find(|job| job.id == job_id)?;
        let attempt = *self.attempts.get(job_id)?;
        Some(job_commitment(
            &self.binding,
            &self.report,
            job,
            attempt,
            self.logical_now,
        ))
    }

    /// Exact local per-job evidence bytes referenced by a check proposal.
    /// Persist these bytes before relinquishing the prepared receipt; the full
    /// workflow frame has a different commitment and cannot substitute for it.
    #[must_use]
    pub fn job_frame(&self, job_id: &str) -> Option<Vec<u8>> {
        let job = self.report.jobs.iter().find(|job| job.id == job_id)?;
        let attempt = *self.attempts.get(job_id)?;
        Some(job_frame(
            &self.binding,
            &self.report,
            job,
            attempt,
            self.logical_now,
        ))
    }
}

fn observation_frame(
    binding: &ObservationBinding,
    report: &WorkflowReport,
    attempts: &BTreeMap<String, u32>,
    logical_now: u64,
) -> Vec<u8> {
    let mut bytes = OBSERVATION_DOMAIN.to_vec();
    for root in [
        binding.run.commitment(),
        binding.attempt.commitment(),
        binding.head,
    ] {
        bytes.extend_from_slice(root.digest().bytes().as_bytes());
    }
    bytes.extend_from_slice(binding.tenant.as_bytes());
    bytes.extend_from_slice(binding.repository.as_bytes());
    bytes.push(match binding.source {
        GitOid::Sha1(_) => 1,
        GitOid::Sha256(_) => 2,
    });
    bytes.extend_from_slice(binding.source.as_bytes());
    field(&mut bytes, binding.trust.name().as_str().as_bytes());
    // JSON displays milliseconds; retain exact submillisecond budget identity.
    bytes.extend_from_slice(&report.limits.step_timeout.as_nanos().to_be_bytes());
    bytes.extend_from_slice(&report.limits.run_timeout.as_nanos().to_be_bytes());
    bytes.extend_from_slice(&logical_now.to_be_bytes());
    bytes.extend_from_slice(&(attempts.len() as u64).to_be_bytes());
    for (job, attempt) in attempts {
        field(&mut bytes, job.as_bytes());
        bytes.extend_from_slice(&attempt.to_be_bytes());
    }
    field(&mut bytes, report.to_json().as_bytes());
    bytes
}
fn field(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}
fn job_commitment(
    binding: &ObservationBinding,
    report: &WorkflowReport,
    job: &JobReport,
    attempt: u32,
    logical_now: u64,
) -> Commitment {
    Commitment::of_bytes(&job_frame(binding, report, job, attempt, logical_now))
}
fn job_frame(
    binding: &ObservationBinding,
    report: &WorkflowReport,
    job: &JobReport,
    attempt: u32,
    logical_now: u64,
) -> Vec<u8> {
    let fragment = WorkflowReport {
        source: report.source,
        graph: report.graph,
        limits: report.limits,
        jobs: vec![job.clone()],
    };
    observation_frame(
        binding,
        &fragment,
        &BTreeMap::from([(job.id.clone(), attempt)]),
        logical_now,
    )
}

impl WorkflowCoordinator {
    /// Queue an explicitly trusted, compiled multi-step workflow. Compilation
    /// validates every job before this call changes idempotency/concurrency or
    /// emits facts. Fork execution is refused; a caller must independently
    /// authorize trusted-host execution and supply a source-scoped executor.
    /// No implicit secrets, hostile isolation, or canonical green check.
    pub fn enqueue_trusted_workflow(
        &mut self,
        tenant: TenantId,
        repository: RepositoryId,
        authority_head: Commitment,
        source_commit: GitOid,
        plan: WorkflowPlan,
        mut limits: WorkflowLimits,
        trigger_ctx: TriggerContext,
        sequence: u64,
        logical_now: u64,
    ) -> Result<PreparedTrustedWorkflow, CoordinatorRefusal> {
        limits
            .validate()
            .map_err(CoordinatorRefusal::WorkflowRefusal)?;
        if trigger_ctx.is_fork {
            return Err(CoordinatorRefusal::UnsupportedExecution {
                job_id: String::new(),
                reason: "fork workflows require a registered hostile-code executor",
            });
        }
        limits.run_timeout = limits.run_timeout.min(self.limits.run_timeout);
        limits.step_timeout = limits
            .step_timeout
            .min(self.limits.step_timeout)
            .min(limits.run_timeout)
            .min(Duration::from_millis(self.ceilings.wall_clock_millis()));
        limits
            .validate()
            .map_err(CoordinatorRefusal::WorkflowRefusal)?;
        let profile = CoordinatorExecutionProfile::TrustedWorkflow {
            source: plan.source_commitment(),
            limits,
        };
        let run_id = self.enqueue_preflighted_run(
            tenant,
            repository,
            authority_head,
            source_commit,
            plan.graph().clone(),
            trigger_ctx,
            sequence,
            logical_now,
            profile,
        )?;
        let run = &self.active_runs[&run_id];
        let binding = ObservationBinding::from_run(run);
        Ok(PreparedTrustedWorkflow {
            run_id,
            binding,
            plan,
            limits,
            attempted: false,
            custody_journal: None,
            receipt: None,
        })
    }

    /// Execute the complete admitted plan through job scopes, not one shell
    /// process per workflow. All steps in a job share its workspace; job scopes
    /// close before dependencies are released. Execution is serial and bounded.
    /// The supplied executor owns source/workspace selection and OS cleanup.
    /// `live` must cover caller cancellation and any live source/policy fences.
    ///
    /// Repeating a completed call returns the retained observation without
    /// executing again. An interrupted/panicking invocation is never retried
    /// implicitly. A local success emits ActionRequired, not Success: separate
    /// verified check publication is required for a protected ref.
    pub fn execute_trusted_workflow<'a, E: WorkflowExecutor>(
        &mut self,
        prepared: &'a mut PreparedTrustedWorkflow,
        executor: &mut E,
        logical_now: u64,
        live: &dyn Fn() -> bool,
    ) -> Result<&'a TrustedWorkflowReceipt, CoordinatorRefusal> {
        self.execute_trusted_workflow_with_custody(
            prepared,
            executor,
            logical_now,
            live,
            &mut |_, _| Ok(()),
        )
    }

    // The custody callback runs before the first scope and after each closed
    // job. It never runs user code; a failed handoff stops subsequent work.
    fn execute_trusted_workflow_with_custody<'a, E, F>(
        &mut self,
        prepared: &'a mut PreparedTrustedWorkflow,
        executor: &mut E,
        logical_now: u64,
        live: &dyn Fn() -> bool,
        custody: &mut F,
    ) -> Result<&'a TrustedWorkflowReceipt, CoordinatorRefusal>
    where
        E: WorkflowExecutor,
        F: FnMut(&mut Self, Option<&TrustedWorkflowReceipt>) -> Result<(), CoordinatorRefusal>,
    {
        self.execute_trusted_workflow_with_launch_custody(
            prepared,
            executor,
            logical_now,
            live,
            custody,
            None,
        )
    }

    // One interpreter and one responsibility tracker for both journal profiles.
    // Strong custody adds a synchronized launch intent and a sticky mode pin;
    // it does not widen the existing compiled-plan execution semantics.
    pub(super) fn execute_trusted_workflow_with_launch_custody<'a, E, F>(
        &mut self,
        prepared: &'a mut PreparedTrustedWorkflow,
        executor: &mut E,
        logical_now: u64,
        live: &dyn Fn() -> bool,
        custody: &mut F,
        mut launch_custody: Option<&mut dyn WorkflowCustody>,
    ) -> Result<&'a TrustedWorkflowReceipt, CoordinatorRefusal>
    where
        E: WorkflowExecutor,
        F: FnMut(&mut Self, Option<&TrustedWorkflowReceipt>) -> Result<(), CoordinatorRefusal>,
    {
        let run_id = prepared.run_id;
        let run = self
            .active_runs
            .get(&run_id)
            .ok_or(CoordinatorRefusal::RunNotFound(run_id))?;
        let expected = CoordinatorExecutionProfile::TrustedWorkflow {
            source: prepared.plan.source_commitment(),
            limits: prepared.limits,
        };
        if run.execution_profile != expected
            || &run.graph != prepared.plan.graph()
            || ObservationBinding::from_run(run) != prepared.binding
        {
            return Err(CoordinatorRefusal::UnsupportedExecution {
                job_id: String::new(),
                reason: "prepared workflow does not match the admitted execution profile",
            });
        }
        let journal_identity = launch_custody.as_ref().map(|adapter| adapter.identity());
        if (prepared.custody_journal.is_some() || prepared.attempted)
            && prepared.custody_journal != journal_identity
        {
            return Err(CoordinatorRefusal::UnsupportedExecution {
                job_id: String::new(),
                reason: "prepared workflow cannot switch launch custody or retroactively acquire it",
            });
        }
        // Select before any potentially mutating I/O. Failed persistence cannot
        // be bypassed by retrying the same prepared handle through a weaker API.
        prepared.custody_journal = journal_identity;
        if let Some(receipt) = &prepared.receipt {
            if run.job_attempts != receipt.attempts
                || receipt.report.jobs.iter().any(|job| {
                    run.job_statuses.get(&job.id) != Some(&JobStatus::Terminal(job.outcome))
                })
            {
                return Err(CoordinatorRefusal::InvalidStateTransition {
                    from: "retained observation differs from this coordinator".to_owned(),
                    to: "trusted workflow outcome lookup".to_owned(),
                });
            }
            custody(self, Some(receipt))?;
            // A fresh borrow on the returning path: returning `receipt` would
            // extend the conditional borrow over the mutations below.
            return prepared.receipt.as_ref().ok_or_else(|| {
                CoordinatorRefusal::InvalidStateTransition {
                    from: "retained observation vanished".to_owned(),
                    to: "trusted workflow outcome lookup".to_owned(),
                }
            });
        }
        if prepared.attempted
            || !matches!(run.status, RunStatus::Queued)
            || !self.has_concurrency_turn(run)
        {
            return Err(CoordinatorRefusal::InvalidStateTransition {
                from: format!("{:?}; attempted={}", run.status, prepared.attempted),
                to: "trusted workflow execution".to_owned(),
            });
        }
        let in_flight = self
            .active_runs
            .values()
            .flat_map(|r| r.job_statuses.values())
            .filter(|s| matches!(s, JobStatus::Running | JobStatus::Draining { .. }))
            .count();
        if in_flight >= self.limits.max_concurrent_jobs {
            return Err(CoordinatorRefusal::QueueCapacityExceeded {
                limit: self.limits.max_concurrent_jobs,
            });
        }
        if self.obligations.workflow_scopes_opened != self.obligations.workflow_scopes_closed {
            return Err(CoordinatorRefusal::ObligationLeak(
                "a previous trusted workflow scope is unresolved".to_owned(),
            ));
        }
        let launch_fenced = launch_custody.is_some();
        if let Some(adapter) = launch_custody.as_mut() {
            adapter
                .before_run(self, run_id)
                .map_err(launch_custody_error)?;
        }
        custody(self, None)?;
        let binding = prepared.binding.clone();
        prepared.attempted = true;
        let run = self.active_runs.get_mut(&run_id).expect("admitted run");
        run.status = RunStatus::Running;
        run.started_at = Some(Instant::now());
        let custody_stopped = Cell::new(false);
        let execution_live = || live() && !custody_stopped.get();
        let (result, custody_failure) = {
            let mut adapter = CoordinatedExecutor {
                coordinator: self,
                inner: executor,
                binding: &binding,
                source: prepared.plan.source_commitment(),
                graph: prepared.plan.graph_commitment(),
                limits: prepared.limits,
                logical_now,
                scope_open: false,
                custody,
                launch_custody,
                custody_stopped: &custody_stopped,
                custody_failure: None,
            };
            let result = catch_unwind(AssertUnwindSafe(|| {
                prepared
                    .plan
                    .execute(prepared.limits, &mut adapter, &execution_live)
            }));
            if result.is_err() && adapter.scope_open {
                // Best-effort reap after unwind, without claiming clean closure
                // or erasing the outstanding responsibility on a partial report.
                let _ = catch_unwind(AssertUnwindSafe(|| adapter.inner.finish_job(true)));
            }
            (result, adapter.custody_failure.take())
        };
        if !launch_fenced && let Some(error) = custody_failure.as_ref() {
            // Preserve the existing per-job callback's refusal behavior.
            self.hold_trusted_workflow(run_id);
            return Err(error.clone());
        }
        let report = match result {
            Ok(Ok(report)) => report,
            Ok(Err(error)) => {
                self.hold_trusted_workflow(run_id);
                return Err(CoordinatorRefusal::WorkflowRefusal(error));
            }
            Err(_) => {
                self.hold_trusted_workflow(run_id);
                return Err(CoordinatorRefusal::ContainmentFailure(
                    "trusted workflow executor unwound; reconcile its scope before reuse"
                        .to_owned(),
                ));
            }
        };
        let attempts = self.active_runs[&run_id].job_attempts.clone();
        prepared.receipt = Some(TrustedWorkflowReceipt {
            binding,
            report,
            attempts,
            logical_now,
        });
        if let Some(error) = custody_failure {
            // A same-process retry may settle these exact retained results;
            // never execute a second time to reconstruct missing evidence.
            self.hold_trusted_workflow(run_id);
            return Err(error);
        }
        Ok(prepared
            .receipt
            .as_ref()
            .expect("completed local observation"))
    }

    fn hold_trusted_workflow(&mut self, run_id: WorkflowRunId) {
        let Some(run) = self.active_runs.get_mut(&run_id) else {
            return;
        };
        if matches!(run.status, RunStatus::Terminal(_)) {
            return;
        }
        let reason = DrainReason::WorkerFailure(
            "trusted workflow scope requires containment reconciliation".to_owned(),
        );
        run.status = RunStatus::Draining {
            reason: reason.clone(),
        };
        for status in run.job_statuses.values_mut() {
            if matches!(status, JobStatus::Running) {
                *status = JobStatus::Draining {
                    reason: reason.clone(),
                };
            }
        }
    }
}

struct CoordinatedExecutor<'a, 'c, E, F> {
    coordinator: &'a mut WorkflowCoordinator,
    inner: &'a mut E,
    binding: &'a ObservationBinding,
    source: Commitment,
    graph: Commitment,
    limits: WorkflowLimits,
    logical_now: u64,
    scope_open: bool,
    custody: &'a mut F,
    launch_custody: Option<&'c mut dyn WorkflowCustody>,
    custody_stopped: &'a Cell<bool>,
    custody_failure: Option<CoordinatorRefusal>,
}
impl<E, F> WorkflowExecutor for CoordinatedExecutor<'_, '_, E, F>
where
    E: WorkflowExecutor,
    F: FnMut(
        &mut WorkflowCoordinator,
        Option<&TrustedWorkflowReceipt>,
    ) -> Result<(), CoordinatorRefusal>,
{
    fn begin_job(
        &mut self,
        index: usize,
        job: &fgit_schema::workflow::Job,
        live: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        self.coordinator
            .require_eligible_job(self.binding.run, &job.id)
            .map_err(|error| WorkerFailure::new(error.to_string(), false))?;
        let run = self
            .coordinator
            .active_runs
            .get_mut(&self.binding.run)
            .expect("admitted run");
        let attempt = run.job_attempts[&job.id]
            .checked_add(1)
            .ok_or_else(|| WorkerFailure::new("job attempt limit", false))?;
        run.job_attempts.insert(job.id.clone(), attempt);
        run.job_statuses.insert(job.id.clone(), JobStatus::Running);
        self.coordinator.outbox_facts.push(CheckRunFact {
            run_id: self.binding.run,
            job_id: job.id.clone(),
            status: CheckRunStatus::InProgress,
            conclusion: None,
            receipt_commitment: None,
            timestamp_millis: self.logical_now,
        });
        self.coordinator.obligations.check_publications_emitted += 1;
        if let Some(adapter) = self.launch_custody.as_mut()
            && let Err(error) = adapter.flush(self.coordinator, None)
        {
            // No user scope exists yet. The possibly persisted InProgress
            // phase is nevertheless a conservative may-have-started fence.
            self.custody_stopped.set(true);
            self.custody_failure = Some(launch_custody_error(error));
            self.coordinator.hold_trusted_workflow(self.binding.run);
            return Err(WorkerFailure::new(error.to_string(), false));
        }
        self.coordinator.obligations.workflow_scopes_opened += 1;
        self.scope_open = true;
        let result = self.inner.begin_job(index, job, live);
        if let Err(failure) = &result {
            // A normal begin refusal owns its own cleanup by executor contract.
            if !failure.retain_workspace {
                self.coordinator.obligations.workflow_scopes_closed += 1;
                self.scope_open = false;
            }
        }
        result
    }
    fn execute_step(
        &mut self,
        index: usize,
        script: &str,
        limits: StepLimits,
        live: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        self.inner.execute_step(index, script, limits, live)
    }
    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
        let result = self.inner.finish_job(retain);
        self.scope_open = false;
        if result.is_ok() && !retain {
            self.coordinator.obligations.workflow_scopes_closed += 1;
        }
        result
    }
    fn observe_job(&mut self, report: &JobReport) {
        // Preserve legacy notification order. Launch-fenced execution instead
        // retains the result before a fallible external observer can unwind.
        let launch_fenced = self.launch_custody.is_some();
        if !launch_fenced {
            self.inner.observe_job(report);
        }
        if report.requires_containment() {
            self.coordinator.hold_trusted_workflow(self.binding.run);
        }
        let run = self
            .coordinator
            .active_runs
            .get_mut(&self.binding.run)
            .expect("admitted run");
        if matches!(
            run.job_statuses.get(&report.id),
            Some(JobStatus::Terminal(_))
        ) {
            return;
        }
        let envelope = WorkflowReport {
            source: self.source,
            graph: self.graph,
            limits: self.limits,
            jobs: Vec::new(),
        };
        let root = job_commitment(
            self.binding,
            &envelope,
            report,
            run.job_attempts[&report.id],
            self.logical_now,
        );
        run.job_statuses
            .insert(report.id.clone(), JobStatus::Terminal(report.outcome));
        run.job_outputs.insert(
            report.id.clone(),
            report
                .steps
                .iter()
                .map(|step| step.observation.clone())
                .collect(),
        );
        let conclusion = match report.outcome {
            JobOutcome::Succeeded | JobOutcome::Skipped => CheckRunConclusion::ActionRequired,
            JobOutcome::Failed | JobOutcome::Refused | JobOutcome::OutputLimit => {
                CheckRunConclusion::Failure
            }
            JobOutcome::Cancelled => CheckRunConclusion::Cancelled,
            JobOutcome::TimedOut => CheckRunConclusion::TimedOut,
        };
        self.coordinator.outbox_facts.push(CheckRunFact {
            run_id: self.binding.run,
            job_id: report.id.clone(),
            status: CheckRunStatus::Completed,
            conclusion: Some(conclusion),
            receipt_commitment: Some(root),
            timestamp_millis: self.logical_now,
        });
        self.coordinator.obligations.check_publications_emitted += 1;
        // Persist this exact normalized observation before allowing the next
        // job to become eligible. A failed callback makes liveness sticky-false;
        // WorkflowPlan closes out later jobs without opening further scopes.
        if self.custody_failure.is_none() {
            let receipt = TrustedWorkflowReceipt {
                binding: self.binding.clone(),
                report: WorkflowReport {
                    jobs: vec![report.clone()],
                    ..envelope
                },
                attempts: BTreeMap::from([(report.id.clone(), run.job_attempts[&report.id])]),
                logical_now: self.logical_now,
            };
            let launch_result = match self.launch_custody.as_mut() {
                Some(adapter) => adapter
                    .flush(self.coordinator, Some(&receipt))
                    .map_err(launch_custody_error),
                None => Ok(()),
            };
            let handoff =
                launch_result.and_then(|()| (self.custody)(self.coordinator, Some(&receipt)));
            if let Err(error) = handoff {
                self.custody_failure = Some(error);
                self.custody_stopped.set(true);
                self.coordinator.hold_trusted_workflow(self.binding.run);
                return;
            }
        }
        if launch_fenced && self.custody_failure.is_none() {
            self.inner.observe_job(report);
        }
        // WorkflowPlan reports skips itself. Do not run a second skip pass that
        // could overwrite its cancellation/containment observations.
        self.coordinator.check_and_finalize_run(self.binding.run);
    }
}

#[cfg(test)]
mod tests;

#[cfg(unix)]
pub mod journaled;

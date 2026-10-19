//! Executable, bounded workflow subset for explicitly trusted foreground tools.
//!
//! The schema compiler owns YAML semantics. This module owns dependency and
//! step ordering, cancellation, output accounting and terminal observations.
//! The node owns verified source selection and disposable job workspaces.
//! This is not a hostile-code sandbox or an authoritative green-check issuer.

use crate::Commitment;
use fgit_schema::workflow::{self, Condition, Job, WorkflowGraph};
pub use fgit_schema::workflow::{Job as WorkflowJob, StepContext};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
pub use process::{run_trusted_step, run_trusted_step_with_context};

pub const TRUSTED_RUNNER_LABEL: &str = "fgit-trusted-local";
pub const PROFILE: &str = "trusted-local-foreground-v1";
pub const MAX_JOBS: usize = 128;
pub const MAX_STEPS: usize = 512;
pub const MAX_REPORT_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Finite limits; output bounds describe retained bytes, not an OS disk quota.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowLimits {
    pub step_timeout: Duration,
    pub run_timeout: Duration,
    pub stream_bytes: usize,
    pub total_output_bytes: usize,
}
impl Default for WorkflowLimits {
    fn default() -> Self {
        Self {
            step_timeout: Duration::from_secs(60),
            run_timeout: Duration::from_secs(600),
            stream_bytes: 256 * 1024,
            total_output_bytes: MAX_REPORT_OUTPUT_BYTES,
        }
    }
}
impl WorkflowLimits {
    pub fn validate(self) -> Result<(), WorkflowError> {
        if self.step_timeout.is_zero()
            || self.run_timeout.is_zero()
            || self.step_timeout > self.run_timeout
            || self.run_timeout > Duration::from_secs(3600)
            || self.stream_bytes == 0
            || self.stream_bytes > 2 * 1024 * 1024
            || self.total_output_bytes < 2
            || self.total_output_bytes > MAX_REPORT_OUTPUT_BYTES
        {
            return Err(WorkflowError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowError {
    Schema(workflow::WorkflowRefusal),
    InvalidLimits,
    InvalidScript,
    UnsupportedStepContext,
    UnsupportedRunner(String),
    ExecutionLimit,
}
impl std::fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Schema(error) => error.fmt(f),
            _ => write!(f, "workflow refused: {self:?}"),
        }
    }
}
impl std::error::Error for WorkflowError {}

/// Immutable compiler output: callers cannot mutate a validated DAG in place.
#[derive(Clone, Debug)]
pub struct WorkflowPlan {
    graph: WorkflowGraph,
    source: Commitment,
    graph_id: Commitment,
}
impl WorkflowPlan {
    pub fn compile(source: &str) -> Result<Self, WorkflowError> {
        let graph = workflow::compile(source, &workflow::Limits::default())
            .map_err(WorkflowError::Schema)?;
        if graph.jobs.is_empty()
            || graph.jobs.len() > MAX_JOBS
            || graph.jobs.iter().map(|job| job.steps.len()).sum::<usize>() > MAX_STEPS
        {
            return Err(WorkflowError::ExecutionLimit);
        }
        // Preflight the ENTIRE graph before the first workspace or process.
        for job in &graph.jobs {
            if job.runs_on != TRUSTED_RUNNER_LABEL {
                return Err(WorkflowError::UnsupportedRunner(job.runs_on.clone()));
            }
            if job.steps.is_empty() {
                return Err(WorkflowError::ExecutionLimit);
            }
            for step in &job.steps {
                if step.run.trim().is_empty() || step.run.contains('\0') || step.run.contains("${{")
                {
                    return Err(WorkflowError::InvalidScript);
                }
            }
        }
        let graph_id = Commitment::of_bytes(graph.canonical_bytes().as_bytes());
        Ok(Self {
            graph,
            source: Commitment::of_bytes(source.as_bytes()),
            graph_id,
        })
    }
    #[must_use]
    pub const fn source_commitment(&self) -> Commitment {
        self.source
    }
    #[must_use]
    pub const fn graph_commitment(&self) -> Commitment {
        self.graph_id
    }
    #[must_use]
    pub const fn graph(&self) -> &WorkflowGraph {
        &self.graph
    }

    /// Serial topological execution is intentional: independent jobs continue
    /// after a failure, but never share a mutable working copy. Every started
    /// job is closed before its dependent can become eligible. No retry is
    /// implicit, especially after cancellation or uncertain containment.
    pub fn execute<E: WorkflowExecutor>(
        &self,
        limits: WorkflowLimits,
        executor: &mut E,
        live: &dyn Fn() -> bool,
    ) -> Result<WorkflowReport, WorkflowError> {
        let started = Instant::now();
        self.execute_with_elapsed(limits, executor, live, &|| started.elapsed())
    }

    // One production-owned monotonic clock covers all jobs. The private seam
    // lets boundary tests advance time without sleeping through minute caps.
    fn execute_with_elapsed<E: WorkflowExecutor>(
        &self,
        limits: WorkflowLimits,
        executor: &mut E,
        live: &dyn Fn() -> bool,
        elapsed: &dyn Fn() -> Duration,
    ) -> Result<WorkflowReport, WorkflowError> {
        limits.validate()?;
        if self
            .graph
            .jobs
            .iter()
            .any(|job| job.steps.iter().any(|step| !step.context.is_default()))
            && !executor.supports_step_context()
        {
            return Err(WorkflowError::UnsupportedStepContext);
        }
        let deadlines = self.graph.has_deadlines();
        let caller_cancelled = Cell::new(false);
        let caller_live = || {
            let allowed = live();
            if deadlines && !allowed {
                caller_cancelled.set(true);
            }
            allowed && !caller_cancelled.get()
        };
        let run_live = || caller_live() && elapsed() < limits.run_timeout;
        let stopped = || {
            if caller_live() && elapsed() >= limits.run_timeout {
                JobOutcome::TimedOut
            } else {
                JobOutcome::Cancelled
            }
        };
        let mut report = WorkflowReport {
            source: self.source,
            graph: self.graph_id,
            limits,
            jobs: Vec::new(),
        };
        let mut completed = BTreeMap::new();
        let mut remaining = limits.total_output_bytes;
        let mut containment_lost = false;
        let mut cancelled = false;
        for (index, job) in self.graph.jobs.iter().enumerate() {
            let mut result = JobReport {
                id: job.id.clone(),
                outcome: JobOutcome::Succeeded,
                steps: Vec::new(),
                failure: None,
            };
            if containment_lost || cancelled || !run_live() {
                result.outcome = if containment_lost || cancelled {
                    JobOutcome::Cancelled
                } else {
                    stopped()
                };
            } else if !job_condition(job.condition, &job.needs, &completed) {
                result.outcome = JobOutcome::Skipped;
            } else {
                // Workspace/custody startup consumes the same absolute job
                // budget as its steps and output capture. It never resets.
                let job_started = elapsed();
                let job_timeout = job
                    .timeout_minutes
                    .map(|cap| Duration::from_secs(cap.seconds()));
                let job_remaining = || {
                    job_timeout.map(|cap| cap.saturating_sub(elapsed().saturating_sub(job_started)))
                };
                let job_live = || run_live() && job_remaining().is_none_or(|left| !left.is_zero());
                let job_stopped = || {
                    if caller_live()
                        && (elapsed() >= limits.run_timeout
                            || job_remaining().is_some_and(|left| left.is_zero()))
                    {
                        JobOutcome::TimedOut
                    } else {
                        JobOutcome::Cancelled
                    }
                };
                match executor.begin_job(index, job, &job_live) {
                    Err(failure) => {
                        containment_lost |= failure.retain_workspace;
                        result.outcome =
                            if !failure.retain_workspace && job_timeout.is_some() && !job_live() {
                                job_stopped()
                            } else {
                                JobOutcome::Refused
                            };
                        result.failure =
                            Some(WorkerFailure::new(failure.detail, failure.retain_workspace));
                    }
                    Ok(()) => {
                        let mut ordinary_failed = false;
                        for (step_index, step) in job.steps.iter().enumerate() {
                            if !job_live() {
                                result.outcome = job_stopped();
                                break;
                            }
                            if !step_condition(step.condition, ordinary_failed) {
                                continue;
                            }
                            if remaining < 2 {
                                result.outcome = JobOutcome::OutputLimit;
                                break;
                            }
                            let step_started = elapsed();
                            let timeout = limits
                                .step_timeout
                                .min(limits.run_timeout.saturating_sub(step_started))
                                .min(job_remaining().unwrap_or(limits.run_timeout))
                                .min(step.timeout_minutes.map_or(limits.step_timeout, |cap| {
                                    Duration::from_secs(cap.seconds())
                                }));
                            if timeout.is_zero() {
                                result.outcome = job_stopped();
                                break;
                            }
                            let budget = StepLimits {
                                timeout,
                                stream_bytes: limits.stream_bytes.min(remaining / 2),
                            };
                            let capped = job_timeout.is_some() || step.timeout_minutes.is_some();
                            let step_expired = || elapsed().saturating_sub(step_started) >= timeout;
                            let deadline_observed = Cell::new(false);
                            let step_live = || {
                                let allowed = job_live() && (!capped || !step_expired());
                                if !allowed && capped && !caller_cancelled.get() && step_expired() {
                                    deadline_observed.set(true);
                                }
                                allowed
                            };
                            let observed = executor.execute_step_with_context(
                                step_index,
                                &step.run,
                                &step.context,
                                budget,
                                &step_live,
                            );
                            match observed {
                                Err(failure) => {
                                    containment_lost |= failure.retain_workspace;
                                    result.outcome =
                                        if !failure.retain_workspace && capped && !step_live() {
                                            if caller_live() && step_expired() {
                                                JobOutcome::TimedOut
                                            } else {
                                                job_stopped()
                                            }
                                        } else {
                                            JobOutcome::Refused
                                        };
                                    result.failure = Some(WorkerFailure::new(
                                        failure.detail,
                                        failure.retain_workspace,
                                    ));
                                    break;
                                }
                                Ok(mut observed) => {
                                    // Normalize safety outcomes BEFORE clamping output.
                                    // A second metadata defect must never conceal loss of
                                    // containment or turn cancellation into an output error.
                                    let invalid_success = observed.outcome
                                        == StepOutcome::Succeeded
                                        && (observed.exit_code != Some(0)
                                            || observed.retain_workspace);
                                    let explicit_failure =
                                        observed.outcome == StepOutcome::ContainmentFailure;
                                    if observed.retain_workspace
                                        || explicit_failure
                                        || invalid_success
                                    {
                                        observed.retain_workspace = true;
                                        containment_lost = true;
                                    }
                                    let output_exceeded = observed.stdout.len()
                                        > budget.stream_bytes
                                        || observed.stderr.len() > budget.stream_bytes;
                                    if output_exceeded {
                                        observed.stdout.truncate(budget.stream_bytes);
                                        observed.stderr.truncate(budget.stream_bytes);
                                        observed.output_complete = false;
                                    }
                                    if explicit_failure || invalid_success {
                                        observed.outcome = StepOutcome::ContainmentFailure;
                                    } else if capped
                                        && step_expired()
                                        && caller_live()
                                        && (observed.outcome != StepOutcome::Cancelled
                                            || deadline_observed.get())
                                    {
                                        // Executors see one liveness predicate. A
                                        // deadline is not caller cancellation, and
                                        // cannot cancel independent later jobs.
                                        // A previously observed caller stop stays
                                        // latched even if the callback rebounds.
                                        observed.outcome = StepOutcome::TimedOut;
                                    } else if observed.outcome == StepOutcome::Cancelled {
                                        cancelled = true;
                                    } else if (output_exceeded
                                        && observed.outcome != StepOutcome::TimedOut)
                                        || (!observed.output_complete
                                            && observed.outcome == StepOutcome::Succeeded)
                                    {
                                        observed.outcome = StepOutcome::OutputLimit;
                                    }
                                    remaining -= observed.stdout.len() + observed.stderr.len();
                                    let outcome = observed.outcome;
                                    result.steps.push(StepReport {
                                        index: step_index,
                                        name: step.name.clone(),
                                        script: Commitment::of_bytes(step.run.as_bytes()),
                                        observation: observed,
                                    });
                                    if outcome != StepOutcome::Succeeded {
                                        result.outcome = match outcome {
                                            StepOutcome::Cancelled => JobOutcome::Cancelled,
                                            StepOutcome::TimedOut => JobOutcome::TimedOut,
                                            StepOutcome::OutputLimit => JobOutcome::OutputLimit,
                                            _ => JobOutcome::Failed,
                                        };
                                        if outcome == StepOutcome::Failed && !containment_lost {
                                            // Ordinary command failure is inspectable state, not
                                            // cancellation or lost containment. Later failure()/always()
                                            // diagnostics may run in the SAME job workspace.
                                            ordinary_failed = true;
                                            continue;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        // Do not let a cancelled request turn its final success
                        // into a green result, but still run non-cancellable close.
                        if result.outcome == JobOutcome::Succeeded && !job_live() {
                            result.outcome = job_stopped();
                        }
                        // Persist required outputs before the quiescent working
                        // copy closes and before durable terminal observation.
                        // Legacy adapters take no extra cancellation checkpoints.
                        if executor.has_job_outputs(job)
                            && !containment_lost
                            && matches!(result.outcome, JobOutcome::Succeeded | JobOutcome::Failed)
                        {
                            // Latch this observation even if a caller-supplied
                            // liveness predicate later returns true again.
                            if !job_live() {
                                result.outcome = job_stopped();
                            } else if let Err(failure) =
                                executor.capture_job_outputs(job, &job_live)
                            {
                                containment_lost |= failure.retain_workspace;
                                result.outcome = if !failure.retain_workspace && !job_live() {
                                    job_stopped()
                                } else {
                                    JobOutcome::Refused
                                };
                                let detail = result.failure.take().map_or_else(
                                    || failure.detail.clone(),
                                    |original| {
                                        format!("{}; outputs: {}", original.detail, failure.detail)
                                    },
                                );
                                result.failure =
                                    Some(WorkerFailure::new(detail, failure.retain_workspace));
                            }
                        }
                        let retain = containment_lost;
                        if let Err(failure) = executor.finish_job(retain) {
                            containment_lost = true;
                            result.outcome = JobOutcome::Refused;
                            if let Some(original) = result.failure.take() {
                                result.failure = Some(WorkerFailure::new(
                                    format!("{}; cleanup: {}", original.detail, failure.detail),
                                    true,
                                ));
                            } else {
                                result.failure = Some(WorkerFailure::new(failure.detail, true));
                            }
                        }
                        // Cleanup can consume the remaining deadline or observe
                        // cancellation too. Never publish success before it ends.
                        if (result.outcome == JobOutcome::Succeeded
                            || (job_timeout.is_some() && result.outcome == JobOutcome::Failed))
                            && !job_live()
                        {
                            result.outcome = job_stopped();
                        }
                    }
                }
            }
            cancelled |= result.outcome == JobOutcome::Cancelled;
            completed.insert(job.id.as_str(), result.outcome);
            executor.observe_job(&result);
            report.jobs.push(result);
        }
        Ok(report)
    }
}

fn job_condition(
    condition: Condition,
    needs: &[String],
    completed: &BTreeMap<&str, JobOutcome>,
) -> bool {
    let states = needs
        .iter()
        .filter_map(|need| completed.get(need.as_str()).copied())
        .collect::<Vec<_>>();
    if states.len() != needs.len() {
        return false;
    }
    let unsafe_terminal = states
        .iter()
        .any(|state| matches!(state, JobOutcome::Cancelled | JobOutcome::Refused));
    match condition {
        Condition::Success => states.iter().all(|state| *state == JobOutcome::Succeeded),
        Condition::Failure => {
            !unsafe_terminal
                && states.iter().any(|state| {
                    matches!(
                        state,
                        JobOutcome::Failed | JobOutcome::TimedOut | JobOutcome::OutputLimit
                    )
                })
        }
        Condition::Always => !unsafe_terminal,
    }
}

const fn step_condition(condition: Condition, ordinary_failed: bool) -> bool {
    match condition {
        Condition::Success => !ordinary_failed,
        Condition::Failure => ordinary_failed,
        Condition::Always => true,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StepLimits {
    pub timeout: Duration,
    pub stream_bytes: usize,
}

/// A started job's working copy must be closed or explicitly retained. A
/// failed begin owns its own cleanup. Finish must not consult cancellation.
pub trait WorkflowExecutor {
    fn begin_job(
        &mut self,
        index: usize,
        job: &Job,
        live: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure>;
    fn execute_step(
        &mut self,
        index: usize,
        script: &str,
        limits: StepLimits,
        live: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure>;
    /// Whether this adapter implements the complete validated process context.
    fn supports_step_context(&self) -> bool {
        false
    }

    /// Default adapters refuse new inputs rather than ignoring them.
    fn execute_step_with_context(
        &mut self,
        index: usize,
        script: &str,
        context: &StepContext,
        limits: StepLimits,
        live: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        if !context.is_default() {
            return Err(WorkerFailure::new(
                "executor does not support explicit step context",
                false,
            ));
        }
        self.execute_step(index, script, limits, live)
    }
    /// Whether this job has an explicit output custody contract. Defaults keep
    /// existing adapters and their cancellation checkpoint order unchanged.
    fn has_job_outputs(&self, _job: &Job) -> bool {
        false
    }

    /// Persist explicitly selected outputs after the process scope is quiescent
    /// and before its working copy closes. Called only when has_job_outputs is
    /// true, the request is live, containment is proved, and the job reached an
    /// ordinary success or failure. Refusal prevents a successful observation;
    /// finish_job still owns unconditional, non-cancellable cleanup.
    fn capture_job_outputs(
        &mut self,
        _job: &Job,
        _live: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        Err(WorkerFailure::new(
            "executor does not implement output custody",
            false,
        ))
    }

    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure>;

    /// Receives one normalized terminal observation after cleanup, or after a
    /// job is skipped/refused before starting. Called in graph order before
    /// the next job. A coordinator may use it to advance its derived scheduler;
    /// it is NOT acknowledgement of canonical check or outbox publication.
    /// Implementations must not launch work from this notification.
    fn observe_job(&mut self, _report: &JobReport) {}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerFailure {
    pub detail: String,
    pub retain_workspace: bool,
}
impl WorkerFailure {
    pub fn new(detail: impl Into<String>, retain_workspace: bool) -> Self {
        let mut detail = detail.into();
        if detail.len() > 4096 {
            let mut end = 4096;
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
        }
        Self {
            detail,
            retain_workspace,
        }
    }
}
impl std::fmt::Display for WorkerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}
impl std::error::Error for WorkerFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepOutcome {
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    OutputLimit,
    ContainmentFailure,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobOutcome {
    Succeeded,
    Failed,
    Skipped,
    Cancelled,
    TimedOut,
    OutputLimit,
    Refused,
}
impl StepOutcome {
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::OutputLimit => "output_limit",
            Self::ContainmentFailure => "containment_failure",
        }
    }
}
impl JobOutcome {
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::OutputLimit => "output_limit",
            Self::Refused => "refused",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepObservation {
    pub outcome: StepOutcome,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed_millis: u64,
    pub output_complete: bool,
    pub retain_workspace: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepReport {
    pub index: usize,
    pub name: Option<String>,
    pub script: Commitment,
    pub observation: StepObservation,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobReport {
    pub id: String,
    pub outcome: JobOutcome,
    pub steps: Vec<StepReport>,
    pub failure: Option<WorkerFailure>,
}
impl JobReport {
    /// Whether the owning executor reported unresolved containment. An absent
    /// retention flag cannot override an explicit containment-failure outcome.
    #[must_use]
    pub fn requires_containment(&self) -> bool {
        self.failure
            .as_ref()
            .is_some_and(|failure| failure.retain_workspace)
            || self.steps.iter().any(|step| {
                step.observation.retain_workspace
                    || step.observation.outcome == StepOutcome::ContainmentFailure
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowReport {
    pub source: Commitment,
    pub graph: Commitment,
    pub limits: WorkflowLimits,
    pub jobs: Vec<JobReport>,
}
impl WorkflowReport {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        !self.jobs.is_empty()
            && self
                .jobs
                .iter()
                .all(|job| job.outcome == JobOutcome::Succeeded)
    }
    /// Deterministic JSON for a local observation artifact, NOT a canonical
    /// forge event or an independently authorized required-check result.
    #[must_use]
    pub fn to_json(&self) -> String {
        let jobs = self.jobs.iter().map(|job| {
            let steps = job.steps.iter().map(|step| {
                let o = &step.observation;
                format!("{{\"index\":{},\"name\":{},\"script\":\"{}\",\"outcome\":\"{}\",\"exit_code\":{},\"stdout_hex\":\"{}\",\"stderr_hex\":\"{}\",\"elapsed_millis\":{},\"output_complete\":{},\"workspace_retained\":{}}}",
                    step.index, step.name.as_ref().map_or_else(|| "null".to_owned(), |name| quote(name)),
                    step.script, o.outcome.token(), o.exit_code.map_or_else(|| "null".to_owned(), |code| code.to_string()),
                    hex(&o.stdout), hex(&o.stderr), o.elapsed_millis, o.output_complete, o.retain_workspace)
            }).collect::<Vec<_>>().join(",");
            let failure = job.failure.as_ref().map_or_else(|| "null".to_owned(), |failure|
                format!("{{\"detail\":{},\"workspace_retained\":{}}}", quote(&failure.detail), failure.retain_workspace));
            format!("{{\"id\":{},\"outcome\":\"{}\",\"steps\":[{steps}],\"failure\":{failure}}}", quote(&job.id), job.outcome.token())
        }).collect::<Vec<_>>().join(",");
        format!(
            "{{\"schema_version\":1,\"profile\":\"{PROFILE}\",\"authoritative_check\":false,\"workflow_source\":\"{}\",\"workflow_graph\":\"{}\",\"shell\":\"/bin/sh\",\"shell_flags\":[\"-eu\",\"-c\"],\"environment\":{{\"PATH\":\"/usr/bin:/bin\",\"LANG\":\"C\"}},\"step_timeout_millis\":{},\"run_timeout_millis\":{},\"stream_bytes\":{},\"total_output_bytes\":{},\"succeeded\":{},\"jobs\":[{jobs}]}}",
            self.source,
            self.graph,
            self.limits.step_timeout.as_millis(),
            self.limits.run_timeout.as_millis(),
            self.limits.stream_bytes,
            self.limits.total_output_bytes,
            self.succeeded()
        )
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn quote(value: &str) -> String {
    let mut result = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            c if c < '\u{20}' => {
                let _ = write!(result, "\\u{:04x}", c as u32);
            }
            c => result.push(c),
        }
    }
    result.push('"');
    result
}

#[cfg(test)]
mod settlement_tests;

#[cfg(test)]
mod deadline_tests;

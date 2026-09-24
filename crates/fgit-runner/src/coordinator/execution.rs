//! Lossless command-only execution through the existing capsule/runner boundary.
//!
//! This adapter deliberately supports one foreground argv command per job, not
//! a shell script. Shell expansion, redirection, pipelines, multiple steps and
//! step failure predicates require the job-scoped workflow executor. They are
//! refused across the entire graph before any run, slot, secret or check fact
//! is created. The trusted workflow API remains the shell/workspace profile.
use super::{
    BuildCommand, BuildInputCapsule, COMMAND_ONLY_PROFILE, CheckOutcome, CheckReceipt,
    CheckRunFact, CheckRunStatus, Commitment, Condition, ContainmentSubstrate, CoordinatorRefusal,
    DrainReason, Duration, EnvironmentBinding, Instant, JobAttemptId, JobOutcome, JobRequest,
    JobStatus, NetworkPolicy, ResourceCeilings, RunStatus, RunnerPolicy, RunnerRefusal, RunnerText,
    SandboxProfile, SourceObject, WorkflowCoordinator, WorkflowError, WorkflowRunId,
};
use crate::workflow::TRUSTED_RUNNER_LABEL;
use crate::{MAX_COMMAND_ARGUMENTS, MAX_RUNNER_TEXT_BYTES, ResourceDimension};

const MAX_COMMAND_SOURCE_BYTES: usize = 64 * 1024;

fn unsupported(job: &fgit_schema::workflow::Job, reason: &'static str) -> CoordinatorRefusal {
    CoordinatorRefusal::UnsupportedExecution {
        job_id: job.id.clone(),
        reason,
    }
}

/// Produce exact argv, preserving quoted/escaped literal bytes. No shell ever
/// reparses this result. Values outside RunnerText's atom envelope are refused,
/// not normalized, truncated, substituted, or smuggled through its private field.
pub(super) fn lower_command(
    job: &fgit_schema::workflow::Job,
) -> Result<BuildCommand, CoordinatorRefusal> {
    if job.runs_on != TRUSTED_RUNNER_LABEL {
        return Err(CoordinatorRefusal::WorkflowRefusal(
            WorkflowError::UnsupportedRunner(job.runs_on.clone()),
        ));
    }
    if job.steps.len() != 1 {
        return Err(unsupported(
            job,
            "command-only profile requires one step; use the job-scoped workflow executor for scripts",
        ));
    }
    let step = &job.steps[0];
    if step.condition == Condition::Failure {
        return Err(unsupported(
            job,
            "step failure predicates require the job-scoped workflow executor",
        ));
    }
    if step.run.len() > MAX_COMMAND_SOURCE_BYTES {
        return Err(CoordinatorRefusal::WorkflowRefusal(
            WorkflowError::ExecutionLimit,
        ));
    }
    let script = step
        .run
        .trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    if script.is_empty() || !script.is_ascii() {
        return Err(unsupported(
            job,
            "command-only profile requires a nonempty ASCII command",
        ));
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut active = false;
    let mut quote = None;
    let bytes = script.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if (byte.is_ascii_control() && byte != b'\t') || byte == 127 {
            return Err(unsupported(
                job,
                "control bytes or multiple command lines are not supported",
            ));
        }
        match quote {
            Some(b'\'') => {
                if byte == b'\'' {
                    quote = None;
                } else {
                    push_byte(&mut word, byte)?;
                }
            }
            Some(b'"') => match byte {
                b'"' => quote = None,
                b'$' | b'`' => {
                    return Err(unsupported(
                        job,
                        "shell expansion is not supported; quote literal arguments with single quotes",
                    ));
                }
                b'\\' => {
                    index += 1;
                    let Some(&next) = bytes.get(index) else {
                        return Err(unsupported(job, "trailing escape"));
                    };
                    if !matches!(next, b'"' | b'\\' | b'$' | b'`') {
                        push_byte(&mut word, b'\\')?;
                    }
                    if next.is_ascii_control() {
                        return Err(unsupported(
                            job,
                            "control bytes and line continuations are not supported",
                        ));
                    }
                    push_byte(&mut word, next)?;
                }
                _ => push_byte(&mut word, byte)?,
            },
            None => match byte {
                b' ' | b'\t' => {
                    if active {
                        push_word(&mut words, &mut word)?;
                        active = false;
                    }
                }
                b'\'' | b'"' => {
                    quote = Some(byte);
                    active = true;
                }
                b'\\' => {
                    index += 1;
                    let Some(&next) = bytes.get(index) else {
                        return Err(unsupported(job, "trailing escape"));
                    };
                    if next.is_ascii_control() {
                        return Err(unsupported(
                            job,
                            "control bytes and line continuations are not supported",
                        ));
                    }
                    push_byte(&mut word, next)?;
                    active = true;
                }
                b';' | b'|' | b'&' | b'<' | b'>' | b'(' | b')' | b'{' | b'}' | b'$' | b'`'
                | b'*' | b'?' | b'[' | b']' | b'~' | b'#' | b'!' => {
                    return Err(unsupported(
                        job,
                        "shell operators, expansion, globbing or comments require the workflow executor",
                    ));
                }
                _ => {
                    push_byte(&mut word, byte)?;
                    active = true;
                }
            },
            Some(_) => return Err(unsupported(job, "invalid quote state")),
        }
        index += 1;
    }
    if quote.is_some() {
        return Err(unsupported(job, "unclosed quote"));
    }
    if active {
        push_word(&mut words, &mut word)?;
    }
    if words.is_empty() {
        return Err(unsupported(job, "missing program"));
    }
    let program = words.remove(0);
    if program.as_str().contains('=')
        || matches!(
            program.as_str(),
            "cd" | "export"
                | "unset"
                | "set"
                | "alias"
                | "eval"
                | "exec"
                | "return"
                | "break"
                | "continue"
                | ":"
                | "."
        )
    {
        return Err(unsupported(
            job,
            "shell builtins and environment assignments require the workflow executor",
        ));
    }
    BuildCommand::new(program, words).map_err(CoordinatorRefusal::RunnerRefusal)
}

fn push_byte(word: &mut String, byte: u8) -> Result<(), CoordinatorRefusal> {
    if word.len() >= MAX_RUNNER_TEXT_BYTES {
        return Err(CoordinatorRefusal::RunnerRefusal(
            RunnerRefusal::CollectionTooLarge {
                field: "workflow_argument",
                limit: MAX_RUNNER_TEXT_BYTES,
            },
        ));
    }
    word.push(char::from(byte));
    Ok(())
}
fn push_word(words: &mut Vec<RunnerText>, word: &mut String) -> Result<(), CoordinatorRefusal> {
    if words.len() > MAX_COMMAND_ARGUMENTS {
        return Err(CoordinatorRefusal::RunnerRefusal(
            RunnerRefusal::CollectionTooLarge {
                field: "command_arguments",
                limit: MAX_COMMAND_ARGUMENTS,
            },
        ));
    }
    words.push(
        RunnerText::parse("workflow_argument", word).map_err(CoordinatorRefusal::RunnerRefusal)?,
    );
    word.clear();
    Ok(())
}

impl WorkflowCoordinator {
    /// Execute one command-only job with exact argv and a command-bound receipt.
    ///
    /// The entire graph is preflighted at enqueue. All remaining fallible input
    /// construction precedes slot reservation and state transitions. No secret
    /// is implicitly issued: this surface has no explicit secret-request input.
    /// The supplied substrate still determines actual isolation; selecting a
    /// policy or testing a fixture substrate does not establish hostile safety.
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
        self.require_ready_job(run_id, job_id)?;
        let run = self
            .active_runs
            .get(&run_id)
            .ok_or(CoordinatorRefusal::RunNotFound(run_id))?;
        let job = run
            .graph
            .jobs
            .iter()
            .find(|job| job.id == job_id)
            .ok_or_else(|| CoordinatorRefusal::JobNotFound(job_id.to_owned()))?;
        let command = lower_command(job)?;
        let toolchain = RunnerText::parse("toolchain", toolchain_name)
            .map_err(CoordinatorRefusal::RunnerRefusal)?;
        let attempt =
            run.job_attempts[job_id]
                .checked_add(1)
                .ok_or(CoordinatorRefusal::WorkflowRefusal(
                    WorkflowError::ExecutionLimit,
                ))?;
        let job_attempt = JobAttemptId::derive(run.attempt_id, job_id, attempt);
        let elapsed = run
            .started_at
            .map_or(Duration::ZERO, |start| start.elapsed());
        let remaining = self.limits.run_timeout.saturating_sub(elapsed);
        let wall_millis = u64::try_from(
            remaining
                .min(self.limits.step_timeout)
                .as_millis()
                .min(u128::from(self.ceilings.wall_clock_millis())),
        )
        .map_err(|_| CoordinatorRefusal::WorkflowRefusal(WorkflowError::InvalidLimits))?;
        if wall_millis == 0 {
            self.record_terminal_job(run_id, job_id, JobOutcome::TimedOut, None, logical_now);
            return Err(CoordinatorRefusal::WorkflowRefusal(
                WorkflowError::ExecutionLimit,
            ));
        }
        let ceilings = ResourceCeilings {
            wall_clock_millis: wall_millis,
            ..self.ceilings
        };
        let policy = RunnerPolicy::new(
            run.trigger_ctx.trust_domain.clone(),
            SandboxProfile::ProcessIsolated,
            NetworkPolicy::Denied,
            ceilings,
        )
        .map_err(CoordinatorRefusal::RunnerRefusal)?;
        let mut environment = Vec::new();
        for (name, value) in [
            ("CI", "true".to_owned()),
            ("FGIT_EXECUTION_PROFILE", COMMAND_ONLY_PROFILE.to_owned()),
            ("FGIT_RUN_ID", run_id.commitment().to_string()),
            ("FGIT_JOB_ATTEMPT", job_attempt.commitment().to_string()),
        ] {
            environment.push(
                EnvironmentBinding::new(
                    RunnerText::parse("environment_name", name)
                        .map_err(CoordinatorRefusal::RunnerRefusal)?,
                    RunnerText::parse("environment_value", &value)
                        .map_err(CoordinatorRefusal::RunnerRefusal)?,
                )
                .map_err(CoordinatorRefusal::RunnerRefusal)?,
            );
        }
        let capsule = BuildInputCapsule::new(
            run.authority_head,
            source_objects,
            dependency_lock,
            toolchain,
            command,
            environment,
        )
        .map_err(CoordinatorRefusal::RunnerRefusal)?;
        let request = JobRequest::new(run.trigger_ctx.is_fork, Vec::new(), Vec::new(), 1)
            .map_err(CoordinatorRefusal::RunnerRefusal)?;

        self.obligations.runner_slots_reserved += 1;
        let admitted = match self.control_plane.admit(
            capsule,
            policy,
            request,
            &mut self.secret_broker,
            logical_now,
        ) {
            Ok(admitted) => admitted,
            Err(error) => {
                self.obligations.runner_slots_aborted += 1;
                self.record_terminal_job(run_id, job_id, JobOutcome::Refused, None, logical_now);
                return Err(CoordinatorRefusal::RunnerRefusal(error));
            }
        };
        let run = self
            .active_runs
            .get_mut(&run_id)
            .expect("admitted run remains owned");
        run.status = RunStatus::Running;
        run.started_at.get_or_insert_with(Instant::now);
        run.job_statuses
            .insert(job_id.to_owned(), JobStatus::Running);
        run.job_attempts.insert(job_id.to_owned(), attempt);
        self.outbox_facts.push(CheckRunFact {
            run_id,
            job_id: job_id.to_owned(),
            status: CheckRunStatus::InProgress,
            conclusion: None,
            receipt_commitment: None,
            timestamp_millis: logical_now,
        });
        self.obligations.check_publications_emitted += 1;
        let receipt = match self
            .control_plane
            .execute(admitted, substrate, &mut self.secret_broker)
        {
            Ok(receipt) => receipt,
            Err(error) => {
                self.obligations.runner_slots_aborted += 1;
                self.record_terminal_job(run_id, job_id, JobOutcome::Refused, None, logical_now);
                return Err(CoordinatorRefusal::RunnerRefusal(error));
            }
        };
        self.obligations.runner_slots_committed += 1;
        self.obligations.runner_slots_acknowledged += 1;
        self.obligations.secret_leases_revoked += usize::from(receipt.revoked_secrets());
        if receipt.verify_evidence().is_err() {
            self.hold_for_containment(run_id);
            self.record_terminal_job(run_id, job_id, JobOutcome::Refused, None, logical_now);
            return Err(CoordinatorRefusal::ContainmentFailure(
                "runner receipt evidence did not verify".to_owned(),
            ));
        }
        if matches!(
            receipt.outcome(),
            CheckOutcome::ContainmentFailure { .. }
                | CheckOutcome::SubstrateRefused {
                    refusal: crate::SubstrateRefusal::ReapingUnverifiable
                }
        ) {
            self.hold_for_containment(run_id);
        }
        let outcome = match receipt.outcome() {
            CheckOutcome::Succeeded => JobOutcome::Succeeded,
            CheckOutcome::Failed => JobOutcome::Failed,
            CheckOutcome::Cancelled => JobOutcome::Cancelled,
            CheckOutcome::ResourceCeiling {
                dimension: ResourceDimension::WallClockMillis,
            } => JobOutcome::TimedOut,
            CheckOutcome::ResourceCeiling { .. } => JobOutcome::OutputLimit,
            CheckOutcome::ContainmentFailure { .. } | CheckOutcome::SubstrateRefused { .. } => {
                JobOutcome::Refused
            }
        };
        self.record_terminal_job(run_id, job_id, outcome, Some(receipt.clone()), logical_now);
        Ok(receipt)
    }

    // A containment failure blocks independent jobs too, not just immediate
    // dependents. Never let an intervening Skipped result erase the failure.
    fn hold_for_containment(&mut self, run_id: WorkflowRunId) {
        if let Some(run) = self.active_runs.get_mut(&run_id) {
            run.status = RunStatus::Draining {
                reason: DrainReason::WorkerFailure(
                    "runner containment or evidence could not be verified".to_owned(),
                ),
            };
        }
    }
}

#[cfg(test)]
mod tests;

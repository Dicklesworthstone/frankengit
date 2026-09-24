//! Durable start ownership around the existing per-job custody barriers.
use super::{
    BTreeMap, CheckDeliveryRefusal, CheckRunStatus, Commitment, CoordinatorExecutionProfile,
    CoordinatorRefusal, FileCheckJournal, MAX_BATCH_BYTES, MAX_BATCH_FACTS, ObservationBinding,
    PreparedTrustedWorkflow, WorkflowCoordinator, WorkflowExecutor, WorkflowReport, custody_error,
    field, flush_run, observation_frame,
};
use crate::coordinator::delivery::journal::CheckJournalScope;
use crate::coordinator::delivery::journal::attempt::{
    FileWorkflowAttempt, MAX_ATTEMPT_RECEIPT_BYTES, RecordedWorkflowReceipt,
    WorkflowAttemptBinding, WorkflowAttemptRefusal, WorkflowAttemptStatus,
};

impl WorkflowCoordinator {
    /// Derive the exact identity expected by FileWorkflowAttempt::create/open.
    /// The logical execution time is part of receipt identity: retain it for
    /// retries. Raw workflow source, graph, exact limits, actor and concurrency
    /// intent are bound in addition to the existing source/run/attempt identity.
    pub fn trusted_attempt_binding(
        &self,
        prepared: &PreparedTrustedWorkflow,
        scope: CheckJournalScope,
        logical_now: u64,
    ) -> Result<WorkflowAttemptBinding, CoordinatorRefusal> {
        let run = self
            .active_runs
            .get(&prepared.run_id())
            .ok_or(CoordinatorRefusal::RunNotFound(prepared.run_id()))?;
        let profile = CoordinatorExecutionProfile::TrustedWorkflow {
            source: prepared.plan.source_commitment(),
            limits: prepared.limits,
        };
        if scope.tenant != run.tenant
            || scope.repository != run.repository
            || run.execution_profile != profile
            || &run.graph != prepared.plan.graph()
            || ObservationBinding::from_run(run) != prepared.binding
        {
            return Err(custody_error(CheckDeliveryRefusal::ScopeMismatch));
        }
        let group = run.trigger_ctx.concurrency_group.as_ref();
        if run.trigger_ctx.actor.len() > 4096
            || run.trigger_ctx.trigger_name.len() > 256
            || run.idempotency_key.as_str().len() > 8192
            || group.is_some_and(|g| g.name.len() > 1024)
        {
            return Err(custody_error(CheckDeliveryRefusal::BatchTooLarge));
        }
        let empty = WorkflowReport {
            source: prepared.plan.source_commitment(),
            graph: prepared.plan.graph_commitment(),
            limits: prepared.limits,
            jobs: Vec::new(),
        };
        let mut bytes = b"frankengit/durable-trusted-execution/v1\0".to_vec();
        field(
            &mut bytes,
            &observation_frame(&prepared.binding, &empty, &BTreeMap::new(), logical_now),
        );
        for value in [&run.trigger_ctx.actor, &run.trigger_ctx.trigger_name] {
            field(&mut bytes, value.as_bytes());
        }
        field(&mut bytes, run.idempotency_key.as_str().as_bytes());
        bytes.push(u8::from(run.trigger_ctx.is_fork));
        bytes.push(u8::from(group.is_some()));
        if let Some(group) = group {
            field(&mut bytes, group.name.as_bytes());
            bytes.push(u8::from(group.cancel_in_progress));
        }
        Ok(WorkflowAttemptBinding {
            scope,
            run: run.id,
            attempt: run.attempt_id,
            request: Commitment::of_bytes(&bytes),
        })
    }

    /// Persist an exact start fence before user work, then journal each closed
    /// job and finally sync the complete local observation. A new process may
    /// retrieve a completed observation, but an unresolved Started attempt is
    /// NEVER automatically executed again. The same owner path and journal
    /// instance must be used by every retry; neither file is canonical truth.
    ///
    /// A completed replay returns archived bytes, not a reconstituted scheduler
    /// or authoritative check. It fences the new prepared handle from execution.
    /// A retained in-process receipt can finish a previously interrupted final
    /// write without rerunning jobs. An unknown process requires host/runtime
    /// reconciliation; this API cannot prove that it or its descendants exited.
    pub fn execute_trusted_workflow_durable<E: WorkflowExecutor>(
        &mut self,
        prepared: &mut PreparedTrustedWorkflow,
        executor: &mut E,
        journal: &mut FileCheckJournal,
        owner: &mut FileWorkflowAttempt,
        logical_now: u64,
        live: &dyn Fn() -> bool,
    ) -> Result<RecordedWorkflowReceipt, WorkflowAttemptRefusal> {
        let binding = self.trusted_attempt_binding(prepared, journal.scope(), logical_now)?;
        if owner.binding() != binding {
            return Err(WorkflowAttemptRefusal::IdentityMismatch);
        }
        self.check_journal_run(prepared, journal)?;
        if owner.is_failed() {
            return Err(CheckDeliveryRefusal::FailedJournal.into());
        }
        if let Some(pin) = owner.starting_journal_pin() {
            journal.verify_checkpoint(pin)?;
        }
        if let Some(receipt) = owner.completed_receipt()? {
            journal.verify_checkpoint(receipt.journal_pin())?;
            // Do not fabricate typed scheduler outcomes from opaque archived
            // bytes, but do prevent this fresh handle from rescheduling them.
            self.fence_durable_handle(prepared, receipt.requires_containment())?;
            return Ok(receipt);
        }
        match owner.status() {
            WorkflowAttemptStatus::Started if prepared.receipt().is_none() => {
                self.fence_durable_handle(prepared, true)?;
                return Err(WorkflowAttemptRefusal::ReconciliationRequired);
            }
            WorkflowAttemptStatus::Prepared => {
                if prepared.attempted || prepared.receipt().is_some() {
                    return Err(WorkflowAttemptRefusal::WrongState);
                }
                if !live() {
                    return Err(CheckDeliveryRefusal::Cancelled.into());
                }
                let batch = self
                    .prepare_check_delivery(MAX_BATCH_FACTS, MAX_BATCH_BYTES)?
                    .ok_or(CheckDeliveryRefusal::InvalidBatch)?;
                if batch.run_id() != prepared.run_id()
                    || batch.facts().len() != prepared.plan.graph().jobs.len()
                    || batch
                        .facts()
                        .iter()
                        .any(|fact| fact.status != CheckRunStatus::Queued)
                {
                    return Err(CheckDeliveryRefusal::InvalidBatch.into());
                }
                preflight_capacity(prepared, journal)?;
            }
            WorkflowAttemptStatus::Started => {} // Same-process retained receipt; never reexecute.
            WorkflowAttemptStatus::Completed => return Err(WorkflowAttemptRefusal::WrongState),
        }
        let execution = self.execute_trusted_workflow_with_custody(
            prepared,
            executor,
            logical_now,
            live,
            &mut |coordinator, fragment| {
                flush_run(coordinator, journal, fragment)?;
                if fragment.is_none() {
                    // Core admission/readiness checks have succeeded. Queue
                    // custody precedes the irreversible MAY-HAVE-EXECUTED fence.
                    owner
                        .start(journal.pin())
                        .map_err(|error| CoordinatorRefusal::ObligationLeak(error.to_string()))?;
                }
                Ok(())
            },
        );
        let receipt = match execution {
            Ok(receipt) => receipt,
            Err(error) => {
                if owner.is_failed() || owner.status() != WorkflowAttemptStatus::Prepared {
                    self.fence_durable_handle(prepared, true)?;
                }
                return Err(error.into());
            }
        };
        owner.finish(receipt, journal.pin())?;
        owner
            .completed_receipt()?
            .ok_or(WorkflowAttemptRefusal::WrongState)
    }

    fn fence_durable_handle(
        &mut self,
        prepared: &mut PreparedTrustedWorkflow,
        unresolved: bool,
    ) -> Result<(), CoordinatorRefusal> {
        if unresolved && !prepared.attempted {
            // A surviving Started record represents an accepted responsibility
            // whose old process ownership cannot be reconstructed from memory.
            self.obligations.workflow_scopes_opened = self
                .obligations
                .workflow_scopes_opened
                .checked_add(1)
                .ok_or_else(|| {
                    CoordinatorRefusal::ObligationLeak("recovered scope counter exhausted".into())
                })?;
        }
        prepared.attempted = true;
        self.hold_trusted_workflow(prepared.run_id());
        Ok(())
    }
}

// Conservative pre-allocation capacity check while the caller holds exclusive
// mutable access to the journal for the whole execution. Includes all per-job
// evidence, one batch per job, the initial queue, and downstream ack reserves.
// Physical ENOSPC/fsync failure remains possible and leaves Started unresolved.
fn preflight_capacity(
    prepared: &PreparedTrustedWorkflow,
    journal: &FileCheckJournal,
) -> Result<(), CheckDeliveryRefusal> {
    let graph = prepared.plan.graph();
    let mut evidence = 4096usize
        .checked_add(
            prepared
                .limits
                .total_output_bytes
                .checked_mul(2)
                .ok_or(CheckDeliveryRefusal::BatchTooLarge)?,
        )
        .ok_or(CheckDeliveryRefusal::BatchTooLarge)?;
    for job in &graph.jobs {
        // Up to 4096 diagnostic bytes, escaped sixfold, plus fixed framing.
        evidence = evidence
            .checked_add(30_000)
            .and_then(|n| job.id.len().checked_mul(6).and_then(|m| n.checked_add(m)))
            .ok_or(CheckDeliveryRefusal::BatchTooLarge)?;
        for step in &job.steps {
            evidence = evidence
                .checked_add(2048)
                .and_then(|n| {
                    step.name
                        .as_ref()
                        .map_or(0, String::len)
                        .checked_mul(6)
                        .and_then(|m| n.checked_add(m))
                })
                .ok_or(CheckDeliveryRefusal::BatchTooLarge)?;
        }
    }
    if evidence > MAX_ATTEMPT_RECEIPT_BYTES {
        return Err(CheckDeliveryRefusal::BatchTooLarge);
    }
    let jobs = graph.jobs.len();
    let bytes = (evidence as u64)
        + (jobs as u64) * 69
        + ((jobs + 1) as u64) * (MAX_BATCH_BYTES as u64 + 37 + 101);
    journal.preflight_execution(bytes, 3 * jobs + 2, evidence)
}

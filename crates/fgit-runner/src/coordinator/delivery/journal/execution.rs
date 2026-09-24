//! Trusted workflow launch/result barriers using the existing custody journal.
//!
//! A persisted InProgress phase is a MAY-HAVE-STARTED fence, never proof that
//! a process ran or was reaped. Reopening must not silently rerun such a run.
//! This is not canonical scheduling, producer authorization, or hostile CI.
use super::{
    BTreeMap, Binding, CheckDeliveryBatch, CheckDeliveryRefusal, CheckRunConclusion,
    CheckRunStatus, Commitment, CoordinatorRefusal, FileCheckJournal, MAX_BATCH_BYTES,
    PreparedTrustedWorkflow, TrustedWorkflowReceipt, WorkflowCoordinator, WorkflowRunId, fmt,
};
use crate::coordinator::scoped_workflow::WorkflowCustody;
use crate::workflow::{JobOutcome, MAX_JOBS, WorkflowExecutor};

/// Distinguish execution/containment refusals from local custody failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournaledWorkflowRefusal {
    Coordinator(CoordinatorRefusal),
    Custody(CheckDeliveryRefusal),
}
impl fmt::Display for JournaledWorkflowRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coordinator(error) => error.fmt(f),
            Self::Custody(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for JournaledWorkflowRefusal {}

impl WorkflowCoordinator {
    /// Persist queued facts and each launch intent before opening a job scope,
    /// then persist each cleaned-up result/evidence before the next job starts.
    /// The existing interpreter, limits, source fences and cleanup rules apply.
    ///
    /// This bounded profile requires the coordinator's pending facts to belong
    /// to this run. Flush other runs explicitly first; this call never transfers
    /// another run's custody as a hidden side effect. Exactly one fact per batch
    /// fixes retry partitions even if later cancellation facts are appended.
    ///
    /// After a result-write failure, the prepared handle retains the report. A
    /// retry using the same verified journal finishes custody without execution.
    /// After restart, a recreated handle is refused if ANY phase beyond Queued
    /// was retained, including delivered history. Inspect the journal instead of
    /// rerunning work whose outcome/containment is unknown. A torn file is never
    /// reset or repaired here. Keep the instance id and minimum pin independently.
    ///
    /// An Ok receipt means its job proposals and evidence are in local custody;
    /// it does NOT mean the workflow succeeded or a canonical check was issued.
    /// Cancellation stops user work, but bounded result settlement still runs.
    /// The runtime owns this synchronous call's blocking context and I/O budget.
    pub fn execute_journaled_trusted_workflow<'a, E: WorkflowExecutor>(
        &mut self,
        prepared: &'a mut PreparedTrustedWorkflow,
        executor: &mut E,
        journal: &mut FileCheckJournal,
        logical_now: u64,
        live: &dyn Fn() -> bool,
    ) -> Result<&'a TrustedWorkflowReceipt, JournaledWorkflowRefusal> {
        let run_id = prepared.run_id();
        let mut custody = JournalCustody {
            journal,
            run_id,
            live,
            failure: None,
        };
        // Reject wrong scopes before pinning the prepared handle's local mode.
        custody
            .check_scope(self)
            .map_err(JournaledWorkflowRefusal::Custody)?;
        let result = self.execute_trusted_workflow_with_launch_custody(
            prepared,
            executor,
            logical_now,
            live,
            &mut |_, _| Ok(()),
            Some(&mut custody),
        );
        if let Some(error) = custody.failure {
            return Err(JournaledWorkflowRefusal::Custody(error));
        }
        let receipt = result.map_err(JournaledWorkflowRefusal::Coordinator)?;
        // This also handles a complete earlier run whose final custody write
        // failed. Retained report lookup never executes commands again.
        custody
            .finish(self, receipt)
            .map_err(JournaledWorkflowRefusal::Custody)?;
        Ok(receipt)
    }
}

struct JournalCustody<'a> {
    journal: &'a mut FileCheckJournal,
    run_id: WorkflowRunId,
    live: &'a dyn Fn() -> bool,
    failure: Option<CheckDeliveryRefusal>,
}
impl JournalCustody<'_> {
    fn remember(
        &mut self,
        result: Result<(), CheckDeliveryRefusal>,
    ) -> Result<(), CheckDeliveryRefusal> {
        if let Err(error) = result {
            self.failure.get_or_insert(error);
        }
        result
    }

    fn check_scope(&self, coordinator: &WorkflowCoordinator) -> Result<(), CheckDeliveryRefusal> {
        self.journal.healthy()?;
        let run = coordinator
            .active_runs
            .get(&self.run_id)
            .ok_or(CheckDeliveryRefusal::UnknownRun)?;
        if run.tenant != self.journal.scope.tenant
            || run.repository != self.journal.scope.repository
        {
            return Err(CheckDeliveryRefusal::ScopeMismatch);
        }
        if coordinator
            .outbox_facts
            .iter()
            .any(|fact| fact.run_id != self.run_id)
        {
            return Err(CheckDeliveryRefusal::OutOfOrder);
        }
        let binding = Binding {
            attempt: run.attempt_id,
            head: run.authority_head,
            source: run.source_commit,
            graph: run.graph_id,
            trust: run.trigger_ctx.trust_domain.clone(),
            profile: run.execution_profile,
        };
        if self
            .journal
            .bindings
            .get(&self.run_id)
            .is_some_and(|known| *known != binding)
        {
            return Err(CheckDeliveryRefusal::ScopeMismatch);
        }
        Ok(())
    }

    // Fixed one-fact partitions prevent a retry of an accepted-but-unacknowledged
    // prefix from being regrouped together with subsequent cancellation facts.
    fn flush_pending(
        &mut self,
        coordinator: &mut WorkflowCoordinator,
        receipt: Option<&TrustedWorkflowReceipt>,
        cancellable: bool,
    ) -> Result<(), CheckDeliveryRefusal> {
        self.check_scope(coordinator)?;
        let live = self.live;
        for _ in 0..=MAX_JOBS * 3 {
            let keep_settling = || !cancellable || live();
            if coordinator
                .journal_check_facts(self.journal, 1, MAX_BATCH_BYTES, receipt, &keep_settling)?
                .is_none()
            {
                return Ok(());
            }
        }
        Err(CheckDeliveryRefusal::InvalidBatch)
    }

    fn start(&mut self, coordinator: &mut WorkflowCoordinator) -> Result<(), CheckDeliveryRefusal> {
        self.check_scope(coordinator)?;
        if !(self.live)() {
            return Err(CheckDeliveryRefusal::Cancelled);
        }
        // Historical phases survive downstream acknowledgement. An empty
        // pending queue must never be treated as evidence of non-execution.
        if self
            .journal
            .phases
            .iter()
            .any(|((run, _), phase)| *run == self.run_id && *phase != 1)
        {
            return Err(CheckDeliveryRefusal::StaleBatch);
        }
        // Another known in-flight job in this single-owner journal also needs
        // reconciliation; a fresh coordinator cannot forget that responsibility.
        if self
            .journal
            .phases
            .iter()
            .any(|((run, _), phase)| *run != self.run_id && *phase == 2)
        {
            return Err(CheckDeliveryRefusal::OutOfOrder);
        }
        self.flush_pending(coordinator, None, true)?;
        let run = &coordinator.active_runs[&self.run_id];
        // Catch legacy drains/missing Queued phases before acquiring any scope.
        if run
            .graph
            .jobs
            .iter()
            .any(|job| self.journal.phases.get(&(self.run_id, job.id.clone())) != Some(&1))
        {
            return Err(CheckDeliveryRefusal::EvidenceMissing);
        }
        Ok(())
    }

    fn finish(
        &mut self,
        coordinator: &mut WorkflowCoordinator,
        receipt: &TrustedWorkflowReceipt,
    ) -> Result<(), CheckDeliveryRefusal> {
        self.flush_pending(coordinator, Some(receipt), false)?;
        self.check_scope(coordinator)?;
        let run = &coordinator.active_runs[&self.run_id];
        if receipt.report().jobs.len() != run.graph.jobs.len() {
            return Err(CheckDeliveryRefusal::InvalidBatch);
        }
        // Verify physical proposal records too, not just the phase index or a
        // report retained in the caller's memory. A fresh/foreign journal cannot
        // certify a completed run merely because no in-memory facts remain.
        let mut completed = BTreeMap::new();
        let mut cursor = None;
        loop {
            let next = match cursor {
                None => self.journal.batches.iter().next(),
                Some(id) => self
                    .journal
                    .batches
                    .range((std::ops::Bound::Excluded(id), std::ops::Bound::Unbounded))
                    .next(),
            }
            .map(|(id, stored)| (*id, stored.frame));
            let Some((id, frame)) = next else {
                break;
            };
            cursor = Some(id);
            let payload = self.journal.read_frame(frame)?;
            if payload.first() != Some(&1) {
                return Err(CheckDeliveryRefusal::CorruptJournal);
            }
            let batch = CheckDeliveryBatch::decode(&payload[1..])?;
            if batch.id() != id {
                return Err(CheckDeliveryRefusal::CorruptJournal);
            }
            if batch.run_id() != self.run_id {
                continue;
            }
            for fact in batch
                .facts()
                .iter()
                .filter(|fact| fact.status == CheckRunStatus::Completed)
            {
                if completed.len() >= MAX_JOBS
                    || completed
                        .insert(fact.job_id.clone(), fact.clone())
                        .is_some()
                {
                    return Err(CheckDeliveryRefusal::InvalidBatch);
                }
            }
        }
        if completed.len() != receipt.report().jobs.len() {
            return Err(CheckDeliveryRefusal::EvidenceMissing);
        }
        for job in &receipt.report().jobs {
            let expected = receipt
                .job_commitment(&job.id)
                .ok_or(CheckDeliveryRefusal::EvidenceMissing)?;
            let fact = completed
                .get(&job.id)
                .ok_or(CheckDeliveryRefusal::EvidenceMissing)?;
            let conclusion = match job.outcome {
                JobOutcome::Succeeded | JobOutcome::Skipped => CheckRunConclusion::ActionRequired,
                JobOutcome::Failed | JobOutcome::Refused | JobOutcome::OutputLimit => {
                    CheckRunConclusion::Failure
                }
                JobOutcome::Cancelled => CheckRunConclusion::Cancelled,
                JobOutcome::TimedOut => CheckRunConclusion::TimedOut,
            };
            if fact.receipt_commitment != Some(expected) || fact.conclusion != Some(conclusion) {
                return Err(CheckDeliveryRefusal::AcknowledgementMismatch);
            }
            self.journal.read_evidence(expected)?;
        }
        Ok(())
    }
}
impl WorkflowCustody for JournalCustody<'_> {
    fn identity(&self) -> Commitment {
        Commitment::of_bytes(&self.journal.scope.bytes())
    }

    fn before_run(
        &mut self,
        coordinator: &mut WorkflowCoordinator,
        run: WorkflowRunId,
    ) -> Result<(), CheckDeliveryRefusal> {
        let result = if run == self.run_id {
            self.start(coordinator)
        } else {
            Err(CheckDeliveryRefusal::ScopeMismatch)
        };
        self.remember(result)
    }

    fn flush(
        &mut self,
        coordinator: &mut WorkflowCoordinator,
        receipt: Option<&TrustedWorkflowReceipt>,
    ) -> Result<(), CheckDeliveryRefusal> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let result = self.flush_pending(coordinator, receipt, false);
        self.remember(result)
    }
}

#[cfg(test)]
mod tests;

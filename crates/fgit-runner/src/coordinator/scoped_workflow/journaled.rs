//! Trusted execution with a durable custody barrier between job scopes.
//!
//! This uses the existing proposal journal and exact receipt encodings. It is
//! not canonical check publication, hostile isolation, or restart scheduling.
use super::*;
use crate::coordinator::delivery::{CheckDeliveryRefusal, MAX_BATCH_BYTES, MAX_BATCH_FACTS};
use crate::coordinator::delivery::journal::FileCheckJournal;

impl WorkflowCoordinator {
    /// Persist queued proposals before the first scope, then every normalized
    /// job result and its evidence after cleanup and BEFORE the next job starts.
    /// Failed persistence stops further execution; accepted prefixes survive a
    /// restart without the prepared handle. The caller must independently fence
    /// execution retries across process loss (this method alone does not).
    ///
    /// All pending facts must belong to this run. Drain other runs through their
    /// own journals first; this API never consumes an unrelated prefix. Custody
    /// after a completed job is bounded non-cancellable drain. The executor must
    /// still honor `live`, including live source and policy checks.
    pub fn execute_trusted_workflow_journaled<'a, E: WorkflowExecutor>(
        &mut self,
        prepared: &'a mut PreparedTrustedWorkflow,
        executor: &mut E,
        journal: &mut FileCheckJournal,
        logical_now: u64,
        live: &dyn Fn() -> bool,
    ) -> Result<&'a TrustedWorkflowReceipt, CoordinatorRefusal> {
        self.check_journal_run(prepared, journal)?;
        // Cancellation prevents the initial custody transfer and all execution.
        // Once execution has completed, repeated lookup may settle its output.
        if prepared.receipt().is_none() && !live() {
            return Err(custody_error(CheckDeliveryRefusal::Cancelled));
        }
        self.execute_trusted_workflow_with_custody(
            prepared, executor, logical_now, live,
            &mut |coordinator, fragment| flush_run(coordinator, journal, fragment),
        )
    }

    fn check_journal_run(
        &self, prepared: &PreparedTrustedWorkflow, journal: &FileCheckJournal,
    ) -> Result<(), CoordinatorRefusal> {
        let run = self.active_runs.get(&prepared.run_id())
            .ok_or(CoordinatorRefusal::RunNotFound(prepared.run_id()))?;
        let scope = journal.scope();
        if scope.tenant != run.tenant || scope.repository != run.repository {
            return Err(custody_error(CheckDeliveryRefusal::ScopeMismatch));
        }
        if journal.is_failed() { return Err(custody_error(CheckDeliveryRefusal::FailedJournal)); }
        if self.outbox_facts.iter().any(|fact| fact.run_id != prepared.run_id()) {
            return Err(custody_error(CheckDeliveryRefusal::OutOfOrder));
        }
        Ok(())
    }
}

fn custody_error(error: CheckDeliveryRefusal) -> CoordinatorRefusal {
    CoordinatorRefusal::ObligationLeak(format!("trusted workflow check custody: {error}"))
}
fn flush_run(
    coordinator: &mut WorkflowCoordinator,
    journal: &mut FileCheckJournal,
    fragment: Option<&TrustedWorkflowReceipt>,
) -> Result<(), CoordinatorRefusal> {
    // One initial queue prefix or one job's InProgress/Completed pair. Evidence
    // comes from the normalized private receipt, not a mutable external report.
    while coordinator.pending_check_fact_count() != 0 {
        coordinator.journal_check_facts(
            journal, MAX_BATCH_FACTS, MAX_BATCH_BYTES, fragment, &|| true,
        ).map_err(custody_error)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

//! Durable coordinator composition for the real trusted-local node executor.
//!
//! Source discovery and workspace ownership stay in the node. The existing
//! runner owns scheduling, per-job evidence custody and the execution fence.
//! Neither a local script's exit status nor a custody receipt grants a check.

mod recovery;
mod publication;

use super::{TrustedWorkflowFailure, TrustedWorkflowRun, hex};
use fgit_runner::coordinator::delivery::journal::attempt::{
    FileWorkflowAttempt, WorkflowAttemptBinding,
};
use fgit_runner::coordinator::delivery::journal::{
    CheckJournalLimits, CheckJournalScope, FileCheckJournal,
};
use fgit_runner::coordinator::{
    CoordinatorLimits, PreparedTrustedWorkflow, TriggerContext, WorkflowCoordinator,
};
use fgit_runner::workflow::{WorkflowExecutor, WorkflowPlan, WorkflowReport};
use fgit_runner::{Commitment, ResourceCeilings, RunnerText, TrustDomain};
use std::path::Path;
use std::time::Duration;

pub(super) const JOURNAL_FILE: &str = "check-proposals.journal";
pub(super) const OWNER_FILE: &str = "execution.owner";
// This is a logical local invocation, not a fabricated wall-clock timestamp.
const LOGICAL_NOW: u64 = 0;

/// Preflight does not touch the filesystem or execute any repository code.
/// An explicit local trigger includes ALL 128 nonce bits; truncating to the
/// coordinator's u64 sequence would alias distinct local invocation IDs.
pub(super) struct Prepared {
    coordinator: WorkflowCoordinator,
    workflow: PreparedTrustedWorkflow,
    binding: WorkflowAttemptBinding,
    scope: CheckJournalScope,
}

impl Prepared {
    pub(super) fn new(
        report: &TrustedWorkflowRun,
        plan: WorkflowPlan,
    ) -> Result<Self, TrustedWorkflowFailure> {
        let invalid = TrustedWorkflowFailure::InvalidInput;
        let limits = report.execution.limits;
        if !report.execution.jobs.is_empty()
            || report.execution.source != plan.source_commitment()
            || report.execution.graph != plan.graph_commitment()
            || report.run_id == [0; 16]
        {
            return Err(invalid("coordinator preflight requires the exact unexecuted plan"));
        }
        let head = report.source_head.as_internal_object_id();
        // The proposal codec has a fixed SHA-256 commitment representation.
        // Refuse other profiles rather than dropping their algorithm identity.
        if head.algorithm() != fgit_crypto::DigestAlgorithm::Sha256.id()
            || head.digest().as_bytes().len() != 32
        {
            return Err(invalid("unsupported workflow source-head commitment"));
        }
        let head = Commitment::try_from_digest(fgit_crypto::Digest::new(
            head.algorithm(), *head.digest(),
        ))
        .map_err(|_| invalid("unsupported workflow source-head commitment"))?;
        let wall_clock = u64::try_from(limits.run_timeout.as_nanos().div_ceil(1_000_000))
            .map_err(|_| invalid("workflow timeout exceeds coordinator representation"))?
            .max(1);
        // These are coordinator admission ceilings, NOT an OS resource sandbox.
        // Actual process/workspace controls remain the existing trusted profile.
        let ceilings = ResourceCeilings::new(
            100_000, 512 * 1024 * 1024, 1024 * 1024 * 1024, 0, 16, wall_clock,
        )
        .map_err(|_| invalid("workflow coordinator ceilings are invalid"))?;
        let mut coordinator = WorkflowCoordinator::new(
            CoordinatorLimits {
                max_concurrent_jobs: 1,
                max_queued_runs: 1,
                step_timeout: limits.step_timeout,
                run_timeout: limits.run_timeout,
                drain_timeout: Duration::from_secs(5),
                max_retries_per_job: 0,
            },
            ceilings,
            1,
        )
        .map_err(|_| invalid("workflow coordinator could not be admitted"))?;
        let trigger = TriggerContext {
            trigger_name: format!("trusted-local-{}", hex(&report.run_id)),
            is_fork: false,
            trust_domain: TrustDomain::new(
                RunnerText::parse("trust", "trusted-local-owner")
                    .map_err(|_| invalid("workflow trust label is invalid"))?,
            ),
            actor: "explicit-local-owner".to_owned(),
            concurrency_group: None,
        };
        let workflow = coordinator
            .enqueue_trusted_workflow(
                report.tenant,
                report.repository,
                head,
                report.executed_commit(),
                plan,
                limits,
                trigger,
                0,
                LOGICAL_NOW,
            )
            .map_err(|_| invalid("workflow coordinator preflight refused"))?;
        // Preserve the exact caller-selected budget in both representations;
        // a silently clamped coordinator cannot attest to the original report.
        if workflow.limits() != limits {
            return Err(invalid("workflow coordinator changed the selected limits"));
        }
        let scope = scope(report);
        let binding = coordinator
            .trusted_attempt_binding(&workflow, scope, LOGICAL_NOW)
            .map_err(|_| invalid("workflow attempt binding is unavailable"))?;
        Ok(Self { coordinator, workflow, binding, scope })
    }

    pub(super) fn execute<E: WorkflowExecutor>(
        mut self,
        directory: &Path,
        executor: &mut E,
        live: &dyn Fn() -> bool,
    ) -> Result<WorkflowReport, TrustedWorkflowFailure> {
        let refused = |detail| TrustedWorkflowFailure::Journal {
            directory: directory.to_path_buf(),
            detail,
        };
        // No adoption of an older or incomplete attempt. The node has already
        // synced its exclusive attempt directory and exact source marker.
        let mut journal = FileCheckJournal::create(
            &directory.join(JOURNAL_FILE), self.scope, CheckJournalLimits::default(),
        )
        .map_err(|e| refused(format!("create workflow proposal journal: {e}")))?;
        let mut owner = FileWorkflowAttempt::create(&directory.join(OWNER_FILE), self.binding)
            .map_err(|e| refused(format!("create workflow start fence: {e}")))?;
        let recorded = self.coordinator.execute_trusted_workflow_durable(
            &mut self.workflow, executor, &mut journal, &mut owner, LOGICAL_NOW, live,
        )
        .map_err(|e| refused(format!(
            "durable workflow driver failed: {e}; retain the attempt and proposal journal, do not replay"
        )))?;
        let receipt = self.workflow.receipt()
            .ok_or_else(|| refused("new workflow has no typed completed observation".to_owned()))?;
        // The durable owner and returned report must describe the SAME exact
        // observation. Do not substitute a newly rendered or partial result.
        if recorded.frame() != receipt.frame().as_slice() {
            return Err(refused("durable workflow observation mismatch".to_owned()));
        }
        if self.coordinator.pending_check_fact_count() != 0 {
            return Err(refused("workflow proposals have not all transferred custody".to_owned()));
        }
        Ok(receipt.report().clone())
    }
}

pub(super) fn scope(report: &TrustedWorkflowRun) -> CheckJournalScope {
    CheckJournalScope {
        tenant: report.tenant,
        repository: report.repository,
        // The existing immutable node marker binds the full source domain,
        // incarnation, ref, workflow blob/path, candidate/merge, input prefixes,
        // nonce and exact execution profile. It never becomes repository truth.
        journal_id: Commitment::of_bytes(report.attempt_marker().as_bytes()),
    }
}

#[cfg(test)]
mod tests;

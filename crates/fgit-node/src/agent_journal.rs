//! Native durable responsibility journals for agent effect brokers.
//!
//! The node host supplies a runtime-owned finite context, an explicitly owned
//! local directory, and the original independently authenticated Intent Run.
//! This profile performs bounded synchronous file I/O on its caller's owned
//! blocking lane; it starts no detached worker or alternate runtime. Cancellation
//! is checked before I/O and after synchronization. An in-progress OS sync is
//! drained before return, so this profile does not promise a hard syscall deadline.
//! Recovery is inspection/reconciliation only and never creates an issuing broker.

use std::path::Path;

use asupersync::Cx;
use fgit_agent::{
    AgentInstanceId, CurrentAuthorityRevocationCheckedEffectBroker, IntentRun, LogicalTime, RunId,
    RunReconciliationReport,
    effect_journal::{EffectJournalPosition, RecoveredEffectJournal},
    run_checkpoint::RunCheckpoint,
};
use fgit_authority::HeadReadReceipt;
use fgit_resource::RegionId;

mod checkpoint;
mod file;
pub use file::AgentJournalHostRefusal;

/// Opens a new single-writer journal and the existing production checked
/// broker in one call. Reusing a run's journal path refuses instead of resetting
/// its budget or forgetting already accepted effect identities.
pub fn create_checked_broker_in(
    cx: &Cx,
    directory: &Path,
    run: IntentRun,
    region: RegionId,
    instance: AgentInstanceId,
) -> Result<CurrentAuthorityRevocationCheckedEffectBroker, AgentJournalHostRefusal> {
    cx.checkpoint()
        .map_err(|_| AgentJournalHostRefusal::Cancelled)?;
    let owned = cx.clone();
    let sink = file::FileEffectJournal::create(
        directory,
        &run,
        Box::new(move || {
            owned
                .checkpoint()
                .map_err(|_| fgit_agent::effect_journal::EffectJournalPersistenceRefusal::Cancelled)
        }),
    )?;
    CurrentAuthorityRevocationCheckedEffectBroker::open_with_journal(
        run,
        region,
        instance,
        Box::new(sink),
    )
    .map_err(|_| AgentJournalHostRefusal::Binding)
}

/// Reads a journal only after obtaining exclusive custody, verifying the
/// complete frame chain, and matching the independently supplied original run.
/// Without an externally retained `expected_tail`, the result permits forensic
/// inspection but refuses to issue a complete `RunReconciliationReport`.
pub fn recover_in(
    cx: &Cx,
    directory: &Path,
    run: &IntentRun,
    expected_tail: Option<EffectJournalPosition>,
) -> Result<RecoveredEffectJournal, AgentJournalHostRefusal> {
    file::recover(directory, run, expected_tail, &|| {
        cx.checkpoint()
            .map_err(|_| AgentJournalHostRefusal::Cancelled)
    })
}

/// A recovered original run and its externally anchored responsibility history.
/// It contains no issuing broker or resumed downstream adapter.
#[derive(Clone, Debug)]
pub struct RecoveredAgentJournal {
    run: IntentRun,
    journal: RecoveredEffectJournal,
}

impl RecoveredAgentJournal {
    /// The original machine-enforced run, including its original expiry.
    #[must_use]
    pub const fn original_run(&self) -> &IntentRun {
        &self.run
    }

    /// Strictly decoded and anchored journal for forensic inspection.
    #[must_use]
    pub const fn journal(&self) -> &RecoveredEffectJournal {
        &self.journal
    }

    /// Reconstructs cleanup debt without requiring the caller to retain or
    /// manufacture the original run. Expiry never erases existing responsibility.
    pub fn reconciliation_report(
        &self,
        observed_at: LogicalTime,
    ) -> Result<RunReconciliationReport, AgentJournalHostRefusal> {
        self.journal
            .reconciliation_report(&self.run, observed_at)
            .map_err(AgentJournalHostRefusal::Codec)
    }
}

impl crate::OneNode {
    /// Persists the original authenticated run before exposing a checked
    /// journal-backed broker. Both files use create-new and explicit file and
    /// directory synchronization. An interrupted setup may leave files and
    /// refuses recreation; it never exposes an unjournaled issuing broker.
    pub async fn create_restorable_agent_broker_in(
        &self,
        request: &crate::NodeRequestContext,
        directory: &Path,
        run: IntentRun,
        original_read: &HeadReadReceipt,
        region: RegionId,
        instance: AgentInstanceId,
    ) -> Result<CurrentAuthorityRevocationCheckedEffectBroker, AgentJournalHostRefusal> {
        let check = || {
            if request.is_live() {
                Ok(())
            } else {
                Err(AgentJournalHostRefusal::Cancelled)
            }
        };
        check()?;
        if original_read.key() != self.authority_head_key() {
            return Err(AgentJournalHostRefusal::Binding);
        }
        let authenticated = self
            .authority
            .authenticate_head_receipt(request.authority(), original_read)
            .await
            .map_err(|error| {
                AgentJournalHostRefusal::RunCheckpoint(
                    fgit_agent::run_checkpoint::RunCheckpointRefusal::Authority(
                        error.into_failure(),
                    ),
                )
            })?;
        let saved = RunCheckpoint::capture(&run, &authenticated)
            .map_err(AgentJournalHostRefusal::RunCheckpoint)?;
        check()?;
        checkpoint::create(directory, &saved, &check)?;
        let owned = request.authority().clone();
        let sink = file::FileEffectJournal::create(
            directory,
            &run,
            Box::new(move || {
                if matches!(
                    crate::checkpoint_pack_context(&owned),
                    crate::PackContextCheckpoint::Live
                ) {
                    Ok(())
                } else {
                    Err(fgit_agent::effect_journal::EffectJournalPersistenceRefusal::Cancelled)
                }
            }),
        )?;
        CurrentAuthorityRevocationCheckedEffectBroker::open_with_journal(
            run,
            region,
            instance,
            Box::new(sink),
        )
        .map_err(|_| AgentJournalHostRefusal::Binding)
    }

    /// Restores a saved run through the node's REAL persistent issuance ledger,
    /// then recovers its journal. The original run object is not needed.
    ///
    /// Both expected values must be retained independently by the surrounding
    /// controller. Neither may be copied from the files being recovered. A
    /// genuine old head remains authentic after current authority advances;
    /// this does not refresh the run or authorize any new work.
    pub async fn recover_agent_journal_in(
        &self,
        request: &crate::NodeRequestContext,
        directory: &Path,
        run_id: RunId,
        expected_run: &[u8; 32],
        expected_tail: EffectJournalPosition,
    ) -> Result<RecoveredAgentJournal, AgentJournalHostRefusal> {
        let check = || {
            if request.is_live() {
                Ok(())
            } else {
                Err(AgentJournalHostRefusal::Cancelled)
            }
        };
        check()?;
        let saved = checkpoint::read(directory, run_id, expected_run, &check)?;
        let run = saved
            .restore_async(
                &self.authority,
                request.authority(),
                self.authority_head_key(),
                expected_run,
            )
            .await
            .map_err(AgentJournalHostRefusal::RunCheckpoint)?;
        check()?;
        let journal = file::recover(directory, &run, Some(expected_tail), &check)?;
        Ok(RecoveredAgentJournal { run, journal })
    }
}

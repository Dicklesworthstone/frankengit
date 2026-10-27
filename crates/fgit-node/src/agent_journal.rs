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
    AgentInstanceId, CurrentAuthorityRevocationCheckedEffectBroker, IntentRun,
    effect_journal::{EffectJournalPosition, RecoveredEffectJournal},
};
use fgit_resource::RegionId;

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

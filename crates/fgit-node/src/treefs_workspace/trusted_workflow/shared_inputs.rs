//! One workflow owns the shared source cache through its last job and drain.
//! Cache work is separate from every job's unchanged logical input budget.

use std::fs::File;

use fgit_crypto::GitHashAlgorithm;
use fgit_resource::{
    LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId, TerminalEvidence,
};
use fgit_runner::sparse_workspace::{
    HostRefusal, SharedInputCache, SharedInputCachePlan, SharedInputCacheStats, SharedInputPolicy,
    SparseWorkspacePlan,
};

pub(super) struct SharedInputs {
    cache: Option<SharedInputCache>,
    ledger: Option<ObligationLedger>,
}

impl SharedInputs {
    pub(super) fn open<A: GitHashAlgorithm>(
        source: &SparseWorkspacePlan<A>,
        parent: &File,
        live: &dyn Fn() -> bool,
    ) -> Result<Self, HostRefusal> {
        let parent = parent.try_clone().map_err(|error| HostRefusal::Io {
            operation: "retain shared workflow input parent",
            kind: error.kind(),
        })?;
        let plan = SharedInputCachePlan::for_workspace(source, SharedInputPolicy::PreferReflink);
        // Job ledgers use index + 1. This separate owner remains live across
        // jobs, including jobs whose workspaces have already been reaped.
        let ledger = ObligationLedger::root(
            RegionId::new(u64::MAX),
            LeakDisposition::RecordAndContinue,
            plan.budget(),
        );
        let reserved = ledger
            .grant(plan.budget())
            .map_err(|_| HostRefusal::ReservationMismatch)
            .and_then(|grant| {
                ledger
                    .reserve(plan.reservation(), grant)
                    .map_err(|_| HostRefusal::ReservationMismatch)
            });
        let opened = reserved
            .and_then(|reserved| SharedInputCache::create(plan, parent, reserved, &|| !live()));
        match opened {
            Ok(cache) => Ok(Self {
                cache: Some(cache),
                ledger: Some(ledger),
            }),
            Err(error) => match ledger.close() {
                RegionCloseOutcome::Quiescent(_) => Err(error),
                _ => Err(HostRefusal::SharedInputCacheUnusable),
            },
        }
    }

    pub(super) fn cache(&mut self) -> Result<&mut SharedInputCache, HostRefusal> {
        self.cache
            .as_mut()
            .ok_or(HostRefusal::SharedInputCacheUnusable)
    }

    /// Non-cancellable drain. A failed workflow still owns its cache cleanup;
    /// no success report may escape without both the receipt and quiescence.
    pub(super) fn close(&mut self) -> Result<SharedInputCacheStats, HostRefusal> {
        let cache = self
            .cache
            .take()
            .ok_or(HostRefusal::SharedInputCacheUnusable)?;
        let ledger = self
            .ledger
            .take()
            .ok_or(HostRefusal::SharedInputCacheUnusable)?;
        let closed = cache.close();
        let quiescent = matches!(ledger.close(), RegionCloseOutcome::Quiescent(_));
        let closed = closed?;
        if !quiescent {
            return Err(HostRefusal::SharedInputCacheUnusable);
        }
        match closed.into_evidence() {
            TerminalEvidence::Acknowledged(receipt, _)
                if receipt.stats.resident_bytes == 0 && receipt.stats.resident_entries == 0 =>
            {
                Ok(receipt.stats)
            }
            _ => Err(HostRefusal::SharedInputCacheUnusable),
        }
    }
}

pub(super) fn statistics_json(stats: &SharedInputCacheStats) -> String {
    format!(
        concat!(
            "{{\"profile\":\"verified-reflink-or-copy-v1\",\"cache_closed\":true,",
            "\"reflink_supported\":{},\"resident_bytes\":{},\"resident_entries\":{},",
            "\"seeded_bytes\":{},\"seeded_entries\":{},\"probe_entries\":{},",
            "\"cloned_bytes\":{},\"clone_operations\":{},\"fallback_bytes\":{},",
            "\"fallback_files\":{},\"unsupported_files\":{},\"capacity_files\":{}}}"
        ),
        stats.reflink_supported,
        stats.resident_bytes,
        stats.resident_entries,
        stats.seeded_bytes,
        stats.seeded_entries,
        stats.probe_entries,
        stats.cloned_bytes,
        stats.clone_operations,
        stats.fallback_bytes,
        stats.fallback_files,
        stats.unsupported_files,
        stats.capacity_files,
    )
}

#[cfg(test)]
mod tests;

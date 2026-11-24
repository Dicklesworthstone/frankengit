//! Bounded, disposable coordinates for already verified PR and issue histories.
//! Requests authenticate their own basis and disclosure policy before lookup;
//! the admission reader revalidates every selected payload on a warm read.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fgit_admission::merge::native::VerifiedAggregateHistory;
use fgit_authority::StoreInstanceId;
use fgit_types::{
    GitHashAlgorithm, RepositoryAuthorityHeadId, RepositoryId, RepositoryIncarnationId, TenantId,
};

use crate::OneNode;

pub(crate) const DEFAULT_CACHE_BYTES: usize = 16 * 1024 * 1024;
// Includes the entry, synchronization, Arc allocations and allocation bookkeeping.
// Actual owned path capacity and index allocations are charged separately.
const ENTRY_OVERHEAD: usize = 4096;

#[derive(Clone, Copy)]
pub(crate) enum HistoryKind {
    PullRequests,
    Issues,
}

impl HistoryKind {
    const fn slot(self) -> usize {
        match self {
            Self::PullRequests => 0,
            Self::Issues => 1,
        }
    }
}

#[derive(Debug)]
struct Entry {
    root: PathBuf,
    store: StoreInstanceId,
    tenant: TenantId,
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    format: GitHashAlgorithm,
    index: Arc<VerifiedAggregateHistory>,
}

impl Entry {
    fn matches_scope(&self, node: &OneNode) -> bool {
        self.root == node.fabric.root()
            && self.store == node.authority.instance_id()
            && self.tenant == node.tenant_id
            && self.repository == node.repository_id
            && self.incarnation == node.repository_incarnation_id
            && self.format == node.object_format
    }
}

/// Two independent slots share the configured allowance equally. PR traffic
/// cannot evict the issue reader's coordinates. Readers can temporarily retain
/// an evicted Arc; this bounds cache custody, not the entire process RSS.
/// Contention or poisoning is a miss, and no lock spans storage I/O.
#[derive(Debug)]
pub(crate) struct AggregateHistoryIndexCache {
    max_bytes: usize,
    entries: [Mutex<Option<Entry>>; 2],
    #[cfg(test)]
    builds: std::sync::atomic::AtomicUsize,
}

impl AggregateHistoryIndexCache {
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            entries: [Mutex::new(None), Mutex::new(None)],
            #[cfg(test)]
            builds: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(crate) const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    pub(crate) fn index_budget(&self, node: &OneNode) -> usize {
        ENTRY_OVERHEAD
            .checked_add(node.fabric.root().as_os_str().len())
            .and_then(|overhead| (self.max_bytes / 2).checked_sub(overhead))
            .unwrap_or(0)
    }

    pub(crate) fn lookup(
        &self,
        node: &OneNode,
        kind: HistoryKind,
        head: RepositoryAuthorityHeadId,
    ) -> Option<Arc<VerifiedAggregateHistory>> {
        if self.index_budget(node) == 0 {
            return None;
        }
        let entry = self.entries[kind.slot()].try_lock().ok()?;
        let entry = entry.as_ref()?;
        if !entry.matches_scope(node) || entry.index.source_head() != head {
            return None;
        }
        Some(Arc::clone(&entry.index))
    }

    /// Called only after the complete public page has succeeded. A partial
    /// history or a cancelled/invalid page never replaces usable coordinates.
    pub(crate) fn insert(
        &self,
        node: &OneNode,
        kind: HistoryKind,
        index: VerifiedAggregateHistory,
    ) {
        let root = node.fabric.root().to_path_buf();
        let Some(bytes) = index
            .retained_bytes()
            .checked_add(ENTRY_OVERHEAD)
            .and_then(|bytes| bytes.checked_add(root.capacity()))
        else {
            return;
        };
        if bytes > self.max_bytes / 2 {
            return;
        }
        let Ok(mut entry) = self.entries[kind.slot()].try_lock() else {
            return;
        };
        if entry.as_ref().is_some_and(|previous| {
            previous.matches_scope(node)
                && (previous.index.source_generation() > index.source_generation()
                    || (previous.index.source_generation() == index.source_generation()
                        && previous.index.source_head() != index.source_head()))
        }) {
            return;
        }
        // Different selections at the same authenticated head may replace one
        // another. Subset reads reuse the old index without constructing one.
        *entry = Some(Entry {
            root,
            store: node.authority.instance_id(),
            tenant: node.tenant_id,
            repository: node.repository_id,
            incarnation: node.repository_incarnation_id,
            format: node.object_format,
            index: Arc::new(index),
        });
        #[cfg(test)]
        self.builds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn test_builds(&self) -> usize {
        self.builds.load(std::sync::atomic::Ordering::Relaxed)
    }
}

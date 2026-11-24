//! Disposable, bounded event-history metadata shared by service children.
//!
//! Only the admission reader can construct a verified index. A hit keeps its
//! exact authenticated head binding, but does not cache payloads, credentials,
//! hidden-ref policy, or rendered pages. Every consumer selects its own current
//! authority basis and verifies the event bytes it discloses.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fgit_admission::merge::native::feed::VerifiedEventIndex;
use fgit_authority::StoreInstanceId;
use fgit_chronicle::PublicationBasis;
use fgit_types::{
    GitHashAlgorithm, RepositoryAuthorityHeadId, RepositoryId, RepositoryIncarnationId, TenantId,
};

use crate::OneNode;

// Covers the cache entry, its scope, Arc allocations, and allocator bookkeeping.
// The owned path allocation and the index's actual capacity are additional.
const ENTRY_OVERHEAD: usize = 4096;
pub(crate) const DEFAULT_CACHE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct Entry {
    root: PathBuf,
    store_instance: StoreInstanceId,
    tenant: TenantId,
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    format: GitHashAlgorithm,
    index: Arc<VerifiedEventIndex>,
}

impl Entry {
    fn matches_scope(&self, node: &OneNode) -> bool {
        self.root == node.fabric.root()
            && self.store_instance == node.authority.instance_id()
            && self.tenant == node.tenant_id
            && self.repository == node.repository_id
            && self.incarnation == node.repository_incarnation_id
            && self.format == node.object_format
    }

    fn matches(&self, node: &OneNode, head: RepositoryAuthorityHeadId) -> bool {
        self.matches_scope(node) && self.index.source_head() == head
    }
}

/// At most one immutable index is retained. An evicted index can remain alive
/// for an already-admitted reader, just like other shared immutable inputs;
/// the configured allowance bounds cache custody, not total process RSS.
/// Poisoned or contended cache locks are misses. No lock spans storage I/O.
#[derive(Debug)]
pub(crate) struct EventHistoryIndexCache {
    max_bytes: usize,
    entry: Mutex<Option<Entry>>,
    #[cfg(test)]
    builds: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    extensions: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    hits: std::sync::atomic::AtomicUsize,
}

impl EventHistoryIndexCache {
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            entry: Mutex::new(None),
            #[cfg(test)]
            builds: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            extensions: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            hits: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(crate) const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    pub(crate) fn index_budget(&self, node: &OneNode) -> usize {
        ENTRY_OVERHEAD
            .checked_add(node.fabric.root().as_os_str().len())
            .and_then(|overhead| self.max_bytes.checked_sub(overhead))
            .unwrap_or(0)
    }

    pub(crate) fn lookup(
        &self,
        node: &OneNode,
        head: RepositoryAuthorityHeadId,
    ) -> Option<Arc<VerifiedEventIndex>> {
        if self.max_bytes == 0 {
            return None;
        }
        let entry = self.entry.try_lock().ok()?;
        let entry = entry.as_ref()?;
        if !entry.matches(node, head) {
            return None;
        }
        Some(Arc::clone(&entry.index))
    }

    /// Offer a bounded older index in the same complete storage scope. The
    /// generation preflight grants no ancestry: the admission reader must
    /// verify every intervening canonical edge back to this exact source head
    /// before reusing its coordinates. Probing never records a cache hit.
    pub(crate) fn extension_candidate(
        &self,
        node: &OneNode,
        basis: &PublicationBasis,
    ) -> Option<Arc<VerifiedEventIndex>> {
        if self.max_bytes == 0 {
            return None;
        }
        let entry = self.entry.try_lock().ok()?;
        let entry = entry.as_ref()?;
        if !entry.matches_scope(node) || !entry.index.can_catch_up_at(basis) {
            return None;
        }
        Some(Arc::clone(&entry.index))
    }

    pub(crate) fn record_hit(&self) {
        #[cfg(test)]
        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn insert(&self, node: &OneNode, index: Arc<VerifiedEventIndex>) {
        self.retain(node, index, false);
    }

    pub(crate) fn insert_extended(&self, node: &OneNode, index: Arc<VerifiedEventIndex>) {
        self.retain(node, index, true);
    }

    fn retain(&self, node: &OneNode, index: Arc<VerifiedEventIndex>, extended: bool) {
        let _ = extended;
        let root = node.fabric.root().to_path_buf();
        let Some(retained) = index
            .retained_bytes()
            .checked_add(ENTRY_OVERHEAD)
            .and_then(|bytes| bytes.checked_add(root.capacity()))
        else {
            return;
        };
        if retained > self.max_bytes {
            return;
        }
        let Ok(mut entry) = self.entry.try_lock() else {
            return;
        };
        // An older request can finish after a newer reader. It may still use
        // its own pinned index, but must not evict newer metadata from the same
        // scope and force subsequent readers to rebuild it. Equal-generation
        // results also cannot establish a newer cache source.
        if entry.as_ref().is_some_and(|retained| {
            retained.matches_scope(node)
                && retained.index.source_generation() >= index.source_generation()
        }) {
            return;
        }
        *entry = Some(Entry {
            root,
            store_instance: node.authority.instance_id(),
            tenant: node.tenant_id,
            repository: node.repository_id,
            incarnation: node.repository_incarnation_id,
            format: node.object_format,
            index,
        });
        #[cfg(test)]
        if extended {
            self.extensions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.builds
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    pub(crate) fn test_counts(&self) -> (usize, usize) {
        use std::sync::atomic::Ordering;
        (
            self.builds.load(Ordering::Relaxed),
            self.hits.load(Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    pub(crate) fn test_extension_count(&self) -> usize {
        self.extensions.load(std::sync::atomic::Ordering::Relaxed)
    }
}

//! A process-local, byte-bounded cache of immutable body reads.
//!
//! # Why it exists
//!
//! Every `body.read` runs as its own autocommit read transaction in `fsqlite`.
//! Measured on a served node with 306 issues (x2mv.4.7, 2026-10-01), one issue
//! open cost about 49,000 `openat`, 352,000 `statx`, 246,000 `fcntl` and
//! 471,000 `pread` calls. That is about seven opens and fifty `statx` per body
//! read. Issue admission reads each forge and outbox body at least twice and
//! walks the decision chain five times. A long-lived server then re-reads the
//! same bodies on every request.
//!
//! # Why it is sound
//!
//! Immutable slots are write-once (`fgit_authority::ImmutableKey`). The only
//! transitions are absent to present, and present to the byte-identical
//! present value. This store has no statement that deletes or rewrites a body.
//! So the bytes of a key once read or written are its bytes for the life of the
//! store, in this process and any other.
//!
//! - An absent read is never cached, because a later write may fill the key.
//! - Heads, tokens and every other mutable row bypass this cache.
//! - The cache returns exactly the bytes the engine returned or accepted.
//!   Callers still decode them and check every digest, so the cache adds no
//!   trust.
//!
//! # Bounds
//!
//! At most [`BODY_CACHE_BYTES`] bytes are retained. A body larger than
//! [`BODY_CACHE_MAX_ENTRY`] is never cached. The least recently used bodies are
//! evicted first. A poisoned lock disables the cache (every lookup misses)
//! rather than panicking, because the cache is an acceleration and never a
//! source of truth.
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

/// Retained bytes across all cached bodies.
pub(crate) const BODY_CACHE_BYTES: usize = 64 * 1024 * 1024;
/// Largest single body worth caching. A larger one would evict too much.
pub(crate) const BODY_CACHE_MAX_ENTRY: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct BodyCache {
    budget: usize,
    max_entry: usize,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// Key bytes -> (body, recency stamp).
    bodies: HashMap<Vec<u8>, (Arc<[u8]>, u64)>,
    /// Recency stamp -> key bytes, oldest first.
    recency: BTreeMap<u64, Vec<u8>>,
    retained: usize,
    clock: u64,
    hits: u64,
    misses: u64,
}

/// Counters of one store's immutable-body cache, for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BodyCacheStats {
    /// Reads answered from memory.
    pub hits: u64,
    /// Reads that went to the engine (including absent keys).
    pub misses: u64,
    /// Bodies currently retained.
    pub entries: usize,
    /// Bytes currently retained.
    pub retained: usize,
}

impl BodyCache {
    pub(crate) fn new() -> Self {
        Self::with_bounds(BODY_CACHE_BYTES, BODY_CACHE_MAX_ENTRY)
    }

    pub(crate) fn with_bounds(budget: usize, max_entry: usize) -> Self {
        Self {
            budget,
            max_entry: max_entry.min(budget),
            state: Mutex::new(State::default()),
        }
    }

    /// The cached body for `key`, refreshing its recency, or `None`.
    pub(crate) fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let Ok(mut state) = self.state.lock() else {
            return None;
        };
        let state = &mut *state;
        state.clock = state.clock.wrapping_add(1);
        let now = state.clock;
        let Some((body, stamp)) = state.bodies.get_mut(key) else {
            state.misses = state.misses.saturating_add(1);
            return None;
        };
        let previous = std::mem::replace(stamp, now);
        let body = body.to_vec();
        if let Some(owner) = state.recency.remove(&previous) {
            state.recency.insert(now, owner);
        }
        state.hits = state.hits.saturating_add(1);
        Some(body)
    }

    /// Record `body` as the bytes of `key`. The caller has either read them
    /// from the engine or had the engine accept them for this key.
    pub(crate) fn insert(&self, key: &[u8], body: &[u8]) {
        if body.len() > self.max_entry {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let state = &mut *state;
        if state.bodies.contains_key(key) {
            return;
        }
        state.clock = state.clock.wrapping_add(1);
        let now = state.clock;
        state.bodies.insert(key.to_vec(), (Arc::from(body), now));
        state.recency.insert(now, key.to_vec());
        state.retained = state.retained.saturating_add(body.len());
        while state.retained > self.budget {
            let Some((_, oldest)) = state.recency.pop_first() else {
                break;
            };
            if let Some((evicted, _)) = state.bodies.remove(&oldest) {
                state.retained = state.retained.saturating_sub(evicted.len());
            }
        }
    }

    pub(crate) fn stats(&self) -> BodyCacheStats {
        self.state.lock().map_or_else(
            |_| BodyCacheStats::default(),
            |state| BodyCacheStats {
                hits: state.hits,
                misses: state.misses,
                entries: state.bodies.len(),
                retained: state.retained,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_read_is_a_hit_with_the_same_bytes() {
        let cache = BodyCache::new();
        assert_eq!(cache.get(b"k"), None);
        cache.insert(b"k", b"body");
        assert_eq!(cache.get(b"k").as_deref(), Some(&b"body"[..]));
        let stats = cache.stats();
        assert_eq!((stats.hits, stats.misses, stats.entries, stats.retained), (1, 1, 1, 4));
    }

    #[test]
    fn the_first_bytes_recorded_for_a_key_are_kept() {
        // Write-once slots never change, so a second insert cannot replace
        // the first; it is ignored rather than trusted.
        let cache = BodyCache::new();
        cache.insert(b"k", b"first");
        cache.insert(b"k", b"other");
        assert_eq!(cache.get(b"k").as_deref(), Some(&b"first"[..]));
        assert_eq!(cache.stats().retained, 5);
    }

    #[test]
    fn the_least_recently_used_body_is_evicted_at_the_budget() {
        let cache = BodyCache::with_bounds(10, 10);
        cache.insert(b"a", b"1234");
        cache.insert(b"b", b"5678");
        // Touch `a`, so `b` is now the oldest.
        assert!(cache.get(b"a").is_some());
        cache.insert(b"c", b"9012");
        assert!(cache.get(b"b").is_none(), "least recently used body evicted");
        assert!(cache.get(b"a").is_some());
        assert!(cache.get(b"c").is_some());
        assert!(cache.stats().retained <= 10);
    }

    #[test]
    fn a_body_over_the_entry_bound_is_never_cached_but_one_at_it_is() {
        let cache = BodyCache::with_bounds(64, 8);
        cache.insert(b"big", &[0_u8; 9]);
        assert!(cache.get(b"big").is_none());
        cache.insert(b"fits", &[0_u8; 8]);
        assert!(cache.get(b"fits").is_some());
    }

    #[test]
    fn retained_bytes_never_exceed_the_budget_under_churn() {
        let cache = BodyCache::with_bounds(1000, 100);
        for index in 0_u32..500 {
            let size = usize::try_from(index % 97).unwrap_or(0) + 1;
            cache.insert(&index.to_be_bytes(), &vec![7_u8; size]);
            assert!(cache.stats().retained <= 1000);
        }
        let stats = cache.stats();
        assert!(stats.entries > 0 && stats.retained > 900, "the budget is used, not wasted: {stats:?}");
    }
}

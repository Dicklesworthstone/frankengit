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
//! - An immutable put may compare its proposed bytes with a cached committed
//!   body and settle an identical retry or conflict without another SQL write.
//!   The caller still acquires the operation gate and observes cancellation.
//! - Heads, tokens and every other mutable row bypass this cache.
//! - The cache returns exactly the bytes the engine returned or accepted.
//!   Callers still decode them and check every digest, so the cache adds no
//!   trust.
//!
//! # Bounds
//!
//! Retained body bytes and both copies of every key share the
//! [`BODY_CACHE_BYTES`] budget. An independent [`BODY_CACHE_MAX_ENTRIES`]
//! ceiling bounds the number of map nodes and Arc allocations, including for
//! empty bodies. Container capacity and allocator overhead are additional;
//! this is not an exact process-RSS limit. The public retained-byte counter
//! continues to count payload bytes only.
//!
//! A body larger than [`BODY_CACHE_MAX_ENTRY`], or an entry whose body and
//! keys exceed the byte budget, is never cached. Eviction happens before
//! allocation and preserves least-recently-used order. A zero byte or entry
//! budget disables retention. Exhausting the recency clock discards the
//! advisory cache instead of reusing a stamp. A poisoned lock disables the
//! cache (every lookup misses) rather than panicking.
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

/// Retained payload bytes plus the bytes in both copies of every cached key.
pub const BODY_CACHE_BYTES: usize = 64 * 1024 * 1024;
/// Largest single body worth caching. A larger one would evict too much.
pub const BODY_CACHE_MAX_ENTRY: usize = 4 * 1024 * 1024;
/// Independent bound on map entries and Arc allocations, even for empty bodies.
const BODY_CACHE_MAX_ENTRIES: usize = 65_536;

#[derive(Debug)]
pub struct BodyCache {
    budget: usize,
    max_entry: usize,
    max_entries: usize,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// Key bytes -> (body, recency stamp).
    bodies: HashMap<Vec<u8>, (Arc<[u8]>, u64)>,
    /// Recency stamp -> key bytes, oldest first.
    recency: BTreeMap<u64, Vec<u8>>,
    /// Payload bytes, preserving the public diagnostics counter's meaning.
    retained: usize,
    /// Payload bytes plus the key bytes actually retained in both maps.
    accounted_bytes: usize,
    clock: u64,
    hits: u64,
    misses: u64,
    put_hits: u64,
}

/// Counters of one store's immutable-body cache, for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BodyCacheStats {
    /// Reads answered from memory.
    pub hits: u64,
    /// Reads that went to the engine (including absent keys).
    pub misses: u64,
    /// Immutable puts settled by comparison with cached committed bytes.
    pub put_hits: u64,
    /// Bodies currently retained.
    pub entries: usize,
    /// Payload bytes currently retained, excluding keys and container overhead.
    pub retained: usize,
}

impl BodyCache {
    pub(crate) fn new() -> Self {
        Self::with_bounds(BODY_CACHE_BYTES, BODY_CACHE_MAX_ENTRY)
    }

    pub(crate) fn with_bounds(budget: usize, max_entry: usize) -> Self {
        Self::with_limits(budget, max_entry, BODY_CACHE_MAX_ENTRIES)
    }

    fn with_limits(budget: usize, max_entry: usize, max_entries: usize) -> Self {
        Self {
            budget,
            max_entry: max_entry.min(budget),
            max_entries,
            state: Mutex::new(State::default()),
        }
    }

    /// The cached body for `key`, refreshing its recency, or `None`.
    pub(crate) fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let Ok(mut state) = self.state.lock() else {
            return None;
        };
        let state = &mut *state;
        let now = state.next_stamp();
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

    /// Compare against committed cached bytes without copying the body.
    ///
    /// `None` requires the ordinary store path. An absent or evicted key never
    /// proves that its durable slot is absent. Reads retain their own counters;
    /// only a settled comparison increments `put_hits`.
    pub(crate) fn matches(&self, key: &[u8], offered: &[u8]) -> Option<bool> {
        let Ok(mut state) = self.state.lock() else {
            return None;
        };
        let state = &mut *state;
        let now = state.next_stamp();
        let (body, stamp) = state.bodies.get_mut(key)?;
        let matches = body.as_ref() == offered;
        let previous = std::mem::replace(stamp, now);
        if let Some(owner) = state.recency.remove(&previous) {
            state.recency.insert(now, owner);
        }
        state.put_hits = state.put_hits.saturating_add(1);
        Some(matches)
    }

    /// Discard retained bodies before the connection leaves its live state.
    /// The store's exclusive close borrow excludes any live operation future
    /// that could insert committed bytes between eviction and shutdown.
    pub(crate) fn clear(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.discard_entries();
        }
    }

    /// Record `body` as the bytes of `key`. The caller has either read them
    /// from the engine or had the engine accept them for this key.
    pub(crate) fn insert(&self, key: &[u8], body: &[u8]) {
        if self.budget == 0 || self.max_entries == 0 || body.len() > self.max_entry {
            return;
        }
        let Some(charge) = retention_charge(key.len(), body.len()) else {
            return;
        };
        if charge > self.budget {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let state = &mut *state;
        if state.bodies.contains_key(key) {
            return;
        }
        let now = state.next_stamp();
        // Preflight the complete entry before evicting anything, and make room
        // before allocating either key copy or the body. Oversized candidates
        // therefore leave useful entries intact.
        while state.bodies.len() >= self.max_entries || state.accounted_bytes > self.budget - charge
        {
            if !state.evict_oldest() {
                // Recency is only an acceleration. If it ever disagrees with
                // the body map, discard it rather than retaining unbounded data.
                state.discard_entries();
                break;
            }
        }
        state.bodies.insert(key.to_vec(), (Arc::from(body), now));
        state.recency.insert(now, key.to_vec());
        // The preflight above proves both additions fit inside the byte budget.
        state.retained += body.len();
        state.accounted_bytes += charge;
    }

    pub(crate) fn stats(&self) -> BodyCacheStats {
        self.state.lock().map_or_else(
            |_| BodyCacheStats::default(),
            |state| BodyCacheStats {
                hits: state.hits,
                misses: state.misses,
                put_hits: state.put_hits,
                entries: state.bodies.len(),
                retained: state.retained,
            },
        )
    }
}

impl State {
    fn discard_entries(&mut self) {
        self.bodies.clear();
        self.recency.clear();
        self.retained = 0;
        self.accounted_bytes = 0;
    }

    fn next_stamp(&mut self) -> u64 {
        if let Some(next) = self.clock.checked_add(1) {
            self.clock = next;
        } else {
            // Reusing a live stamp would orphan another body's eviction entry.
            // A cold cache is always safe; its next caller reads the store.
            self.discard_entries();
            self.clock = 1;
        }
        self.clock
    }

    fn evict_oldest(&mut self) -> bool {
        let Some((_, key)) = self.recency.pop_first() else {
            return false;
        };
        let Some((body, _)) = self.bodies.remove(&key) else {
            return false;
        };
        // Every entry passed retention_charge before insertion. These are its
        // same lengths, and each charge is included in the retained totals.
        self.retained -= body.len();
        self.accounted_bytes -= body.len() + 2 * key.len();
        true
    }
}

/// Charge both owned key arrays, with overflow refused before any allocation.
fn retention_charge(key_bytes: usize, body_bytes: usize) -> Option<usize> {
    key_bytes.checked_mul(2)?.checked_add(body_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_bounded(cache: &BodyCache) {
        let state = cache.state.lock().unwrap();
        let payload_bytes: usize = state.bodies.values().map(|(body, _)| body.len()).sum();
        let body_keys: usize = state.bodies.keys().map(Vec::len).sum();
        let recency_keys: usize = state.recency.values().map(Vec::len).sum();
        assert_eq!(state.retained, payload_bytes);
        assert_eq!(
            state.accounted_bytes,
            payload_bytes + body_keys + recency_keys
        );
        assert!(state.accounted_bytes <= cache.budget);
        assert!(state.bodies.len() <= cache.max_entries);
        assert_eq!(state.bodies.len(), state.recency.len());
        for (key, (_, stamp)) in &state.bodies {
            assert_eq!(state.recency.get(stamp), Some(key));
        }
    }

    #[test]
    fn a_second_read_is_a_hit_with_the_same_bytes() {
        let cache = BodyCache::new();
        assert_eq!(cache.get(b"k"), None);
        cache.insert(b"k", b"body");
        assert_eq!(cache.get(b"k").as_deref(), Some(&b"body"[..]));
        let stats = cache.stats();
        assert_eq!(
            (stats.hits, stats.misses, stats.entries, stats.retained),
            (1, 1, 1, 4)
        );
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
        let cache = BodyCache::with_bounds(12, 10);
        cache.insert(b"a", b"1234");
        cache.insert(b"b", b"5678");
        // Touch `a`, so `b` is now the oldest.
        assert!(cache.get(b"a").is_some());
        cache.insert(b"c", b"9012");
        assert!(
            cache.get(b"b").is_none(),
            "least recently used body evicted"
        );
        assert!(cache.get(b"a").is_some());
        assert!(cache.get(b"c").is_some());
        assert_eq!(cache.stats().retained, 8);
        assert_bounded(&cache);
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
            assert_bounded(&cache);
        }
        let state = cache.state.lock().unwrap();
        assert!(
            !state.bodies.is_empty() && state.accounted_bytes > 900,
            "the body-and-key budget is used, not wasted: {state:?}"
        );
    }

    #[test]
    fn put_comparisons_preserve_bytes_and_refresh_bounded_retention() {
        let cache = BodyCache::with_bounds(12, 4);
        assert_eq!(cache.matches(b"unknown", b"1234"), None);
        cache.insert(b"a", b"1234");
        cache.insert(b"b", b"5678");
        assert_eq!(cache.matches(b"a", b"1234"), Some(true));
        assert_eq!(cache.matches(b"a", b"different"), Some(false));
        cache.insert(b"c", b"9012");
        assert_eq!(cache.matches(b"b", b"5678"), None);
        assert_eq!(cache.get(b"a").as_deref(), Some(&b"1234"[..]));
        let before = cache.stats();
        assert_eq!(before.put_hits, 2);
        assert_eq!(before.retained, 8);
        cache.clear();
        assert_eq!(cache.matches(b"a", b"1234"), None);
        assert_eq!(cache.stats().entries, 0);
        assert_eq!(cache.stats().retained, 0);
        assert_eq!(cache.stats().put_hits, before.put_hits);
    }

    #[test]
    fn empty_bodies_charge_both_copies_of_their_keys() {
        let cache = BodyCache::with_bounds(8, 8);
        cache.insert(b"aa", b"");
        cache.insert(b"bb", b"");
        assert_eq!(cache.stats().entries, 2);
        assert_eq!(cache.stats().retained, 0);
        assert_bounded(&cache);
        assert_eq!(cache.get(b"aa"), Some(Vec::new()));
        cache.insert(b"cc", b"");
        assert_eq!(cache.get(b"bb"), None, "the cold key must be evicted");
        assert_eq!(cache.get(b"aa"), Some(Vec::new()));
        assert_eq!(cache.get(b"cc"), Some(Vec::new()));
        assert_eq!(cache.stats().entries, 2);
        assert_bounded(&cache);
    }

    #[test]
    fn maximum_authority_keys_consume_the_byte_budget_even_without_payloads() {
        let key_bytes = fgit_authority::MAX_KEY_BYTES;
        let cache = BodyCache::with_bounds(4 * key_bytes, 0);
        let first = vec![1; key_bytes];
        let second = vec![2; key_bytes];
        let third = vec![3; key_bytes];
        for key in [&first, &second, &third] {
            cache.insert(key, b"");
            assert_bounded(&cache);
        }
        assert_eq!(cache.stats().entries, 2);
        assert_eq!(cache.stats().retained, 0);
        assert_eq!(cache.get(&first), None);
        assert_eq!(cache.get(&second), Some(Vec::new()));
        assert_eq!(cache.get(&third), Some(Vec::new()));
    }

    #[test]
    fn entry_limit_bounds_small_allocations_and_put_comparisons_refresh_lru() {
        let cache = BodyCache::with_limits(1024, 8, 2);
        cache.insert(b"a", b"");
        cache.insert(b"b", b"");
        assert_eq!(cache.matches(b"a", b""), Some(true));
        assert_eq!(cache.matches(b"a", b"conflict"), Some(false));
        cache.insert(b"c", b"");
        assert_eq!(cache.get(b"b"), None);
        assert_eq!(cache.get(b"a"), Some(Vec::new()));
        assert_eq!(cache.get(b"c"), Some(Vec::new()));
        assert_eq!(cache.stats().entries, 2);
        assert_bounded(&cache);
        // A repeated insertion neither overwrites the first bytes nor spends
        // another entry or key-byte charge.
        cache.insert(b"a", b"changed");
        assert_eq!(cache.get(b"a"), Some(Vec::new()));
        assert_bounded(&cache);
    }

    #[test]
    fn zero_byte_or_entry_budget_disables_empty_and_nonempty_retention() {
        for cache in [
            BodyCache::with_limits(0, 8, 8),
            BodyCache::with_limits(8, 8, 0),
        ] {
            for body in [b"".as_slice(), b"body".as_slice()] {
                cache.insert(b"k", body);
                assert_eq!(cache.get(b"k"), None);
                assert_eq!(cache.matches(b"k", body), None);
                assert_eq!(cache.stats().entries, 0);
                assert_eq!(cache.stats().retained, 0);
                assert_bounded(&cache);
            }
        }
        // Zero maximum body bytes still permits an empty value when its two
        // key copies and its entry have real capacity.
        let cache = BodyCache::with_limits(2, 0, 1);
        cache.insert(b"k", b"");
        assert_eq!(cache.get(b"k"), Some(Vec::new()));
        assert_bounded(&cache);
    }

    #[test]
    fn an_unretainable_candidate_does_not_evict_useful_entries() {
        let cache = BodyCache::with_bounds(8, 4);
        cache.insert(b"a", b"1234");
        cache.insert(b"oversized-key", b"");
        cache.insert(b"b", b"12345");
        assert_eq!(cache.stats().entries, 1);
        assert_eq!(cache.get(b"a").as_deref(), Some(b"1234".as_slice()));
        assert_eq!(cache.get(b"oversized-key"), None);
        assert_eq!(cache.get(b"b"), None);
        assert_bounded(&cache);
        cache.insert(b"b", b"");
        assert_eq!(cache.stats().entries, 2, "an exact-fit twin is retained");
        assert_bounded(&cache);
    }

    #[test]
    fn accounting_overflow_is_refused_without_wrapping() {
        assert_eq!(retention_charge(usize::MAX, 0), None);
        assert_eq!(retention_charge(usize::MAX / 2 + 1, 0), None);
        assert_eq!(retention_charge(1, usize::MAX), None);
        assert_eq!(retention_charge(usize::MAX / 2, 1), Some(usize::MAX));
        assert_eq!(retention_charge(0, 0), Some(0));
    }

    #[test]
    fn recency_exhaustion_discards_the_cache_before_reusing_a_stamp() {
        for operation in 0..3 {
            let cache = BodyCache::with_limits(64, 8, 2);
            cache.insert(b"a", b"first");
            cache.insert(b"b", b"second");
            cache.state.lock().unwrap().clock = u64::MAX - 1;
            assert_eq!(cache.matches(b"a", b"first"), Some(true));
            assert_bounded(&cache);
            match operation {
                0 => assert_eq!(cache.get(b"a"), None),
                1 => assert_eq!(cache.matches(b"a", b"first"), None),
                _ => cache.insert(b"c", b"third"),
            }
            let state = cache.state.lock().unwrap();
            assert_eq!(state.clock, 1);
            let expected_entries = if operation == 2 { 1 } else { 0 };
            assert_eq!(state.bodies.len(), expected_entries);
            drop(state);
            assert_bounded(&cache);
            cache.insert(b"d", b"fourth");
            assert_eq!(cache.get(b"d").as_deref(), Some(b"fourth".as_slice()));
            assert_bounded(&cache);
        }
    }

    #[test]
    fn mixed_empty_and_small_body_churn_stays_within_both_budgets() {
        let cache = BodyCache::with_limits(1024, 64, 7);
        for index in 0_u32..500 {
            let mut key = index.to_be_bytes().to_vec();
            key.resize(4 + (index as usize % 253), 0);
            let body = vec![7; index as usize % 65];
            cache.insert(&key, &body);
            assert_bounded(&cache);
            let before = cache.stats();
            cache.insert(&key, &body);
            assert_eq!(cache.stats().entries, before.entries);
            assert_eq!(cache.stats().retained, before.retained);
            assert_bounded(&cache);
        }
        assert!(cache.stats().entries > 0);
        cache.clear();
        assert_eq!(cache.stats().entries, 0);
        assert_eq!(cache.stats().retained, 0);
        assert_bounded(&cache);
    }
}

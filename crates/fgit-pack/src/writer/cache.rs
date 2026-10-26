//! Process-local memoization of pure pack computations. Neither a cache key
//! nor a hit grants object access: callers still select and verify source
//! objects before consulting this accelerator.

use super::*;
use std::sync::{Arc, Mutex};

// Charge fixed metadata as well as payloads, including empty delta outcomes.
// This is deliberately conservative for the map node, FIFO key, Arc and receipt.
const ENTRY_OVERHEAD: usize = 512;
const CACHE_VERSION: &[u8] = b"fgit/pack-computation-cache/v1\0";

/// Observable derived-cache counters, never authority or publication evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PackCacheStats {
    /// Retained entries, including entries pinned by an active reader.
    pub resident_bytes: usize,
    /// In-flight captures reserved before their buffers are allocated.
    /// This plus `resident_bytes` never exceeds the configured capacity.
    pub reserved_bytes: usize,
    pub entries: usize,
    pub compression_hits: u64,
    pub delta_hits: u64,
    pub misses: u64,
    pub invalidations: u64,
    pub evictions: u64,
    /// Logical DEFLATE work, including the original charges on cache hits.
    pub compression_work_units: u64,
}

/// A bounded, disposable cache shared by the node's serving children.
///
/// Capacity includes retained payloads, captures in flight, and a conservative
/// metadata charge. FIFO eviction skips entries pinned by active readers.
/// Unavailable capacity and disabled/poisoned caches change computation only,
/// never pack decisions. Entries cannot add objects to a selection and do not
/// survive process restart. Caller-owned delta programs are ordinary planning
/// output, separate from the cache's retained or captured copy.
#[derive(Debug)]
pub struct PackComputationCache {
    max_bytes: usize,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    entries: BTreeMap<[u8; 32], Retained>,
    // A tree releases nodes as entries leave; a VecDeque would retain its
    // high-water allocation after many small entries were replaced by a few
    // large ones, outside the live-entry accounting.
    order: BTreeMap<u64, [u8; 32]>,
    next: u64,
    stats: PackCacheStats,
}

impl State {
    fn reserve(&mut self, capacity: usize, additional: usize) -> bool {
        let Some(available) = capacity
            .checked_sub(self.stats.reserved_bytes)
            .and_then(|bytes| bytes.checked_sub(additional))
        else {
            return false;
        };
        while self.stats.resident_bytes > available {
            // A lookup holds its Arc through checksum verification and replay.
            // Removing such an entry would free its accounting before its bytes.
            let victim = self.order.iter().find_map(|(sequence, key)| {
                self.entries
                    .get(key)
                    .filter(|retained| Arc::strong_count(&retained.entry) == 1)
                    .map(|_| (*sequence, *key))
            });
            let Some((sequence, key)) = victim else {
                return false;
            };
            self.order.remove(&sequence);
            if let Some(removed) = self.entries.remove(&key) {
                self.stats.resident_bytes -= removed.charge;
                self.stats.evictions = self.stats.evictions.saturating_add(1);
            }
            self.stats.entries = self.entries.len();
        }
        self.stats.reserved_bytes += additional;
        true
    }
}

#[derive(Debug)]
struct Retained {
    entry: Arc<Entry>,
    charge: usize,
    sequence: u64,
}

#[derive(Debug)]
struct Entry {
    payload: Box<[u8]>,
    chunks: Box<[usize]>,
    value: Value,
    checksum: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
enum Value {
    Compressed { receipt: DeflateReceipt, work: u64 },
    Delta { present: bool },
}

impl Entry {
    fn shape_is_valid(
        &self,
        deadline: &mut (impl Deadline + ?Sized),
    ) -> Result<bool, PackWriteError> {
        match self.value {
            Value::Compressed { receipt, .. } => {
                if receipt.output_bytes != self.payload.len() {
                    return Ok(false);
                }
                let mut total = 0usize;
                for batch in self
                    .chunks
                    .chunks(ENCODER_INPUT_CHUNK_BYTES / size_of::<usize>())
                {
                    checkpoint(deadline)?;
                    for length in batch {
                        let Some(next) = total.checked_add(*length) else {
                            return Ok(false);
                        };
                        total = next;
                    }
                }
                Ok(total == self.payload.len())
            }
            Value::Delta { present } => {
                Ok(self.chunks.is_empty() && (present || self.payload.is_empty()))
            }
        }
    }

    fn checksum(
        &self,
        key: &[u8; 32],
        deadline: &mut (impl Deadline + ?Sized),
    ) -> Result<[u8; 32], PackWriteError> {
        checkpoint(deadline)?;
        let mut hash = Sha256Hasher::new();
        hash.update(CACHE_VERSION);
        hash.update(key);
        // Derived, process-local metadata only. The explicit version above
        // invalidates the computation contract; Debug includes every field.
        hash.update(format!("{:?}", self.value).as_bytes());
        hash.update(&(self.payload.len() as u64).to_be_bytes());
        for batch in self
            .chunks
            .chunks(ENCODER_INPUT_CHUNK_BYTES / size_of::<usize>())
        {
            checkpoint(deadline)?;
            for length in batch {
                hash.update(&(*length as u64).to_be_bytes());
            }
        }
        for bytes in self.payload.chunks(ENCODER_INPUT_CHUNK_BYTES) {
            checkpoint(deadline)?;
            hash.update(bytes);
        }
        checkpoint(deadline)?;
        Ok(hash.finish())
    }
}

/// Owns both the capture buffers and their shared-budget charge. Every exit,
/// including failed emission or cancellation, drops the buffers before making
/// their budget available to another worker.
struct Reservation<'cache> {
    cache: &'cache PackComputationCache,
    charge: usize,
    payload: Vec<u8>,
    chunks: Vec<usize>,
}

impl Reservation<'_> {
    fn grow(&mut self, additional: usize) -> bool {
        let Some(charge) = self.charge.checked_add(additional) else {
            return false;
        };
        let Ok(mut state) = self.cache.state.lock() else {
            return false;
        };
        if !state.reserve(self.cache.max_bytes, additional) {
            return false;
        }
        self.charge = charge;
        true
    }

    fn capture(&mut self, bytes: &[u8]) -> bool {
        let Some(additional) = bytes.len().checked_add(size_of::<usize>()) else {
            return false;
        };
        if !self.grow(additional)
            || self.payload.try_reserve_exact(bytes.len()).is_err()
            || self.chunks.try_reserve_exact(1).is_err()
        {
            return false;
        }
        self.payload.extend_from_slice(bytes);
        self.chunks.push(bytes.len());
        true
    }

    /// The complete payload charge is reserved before this copy is attempted.
    fn copy_delta(
        &mut self,
        bytes: &[u8],
        deadline: &mut (impl Deadline + ?Sized),
    ) -> Result<bool, PackWriteError> {
        if self.payload.try_reserve_exact(bytes.len()).is_err() {
            return Ok(false);
        }
        for chunk in bytes.chunks(ENCODER_INPUT_CHUNK_BYTES) {
            checkpoint(deadline)?;
            self.payload.extend_from_slice(chunk);
        }
        Ok(true)
    }

    fn insert(
        mut self,
        key: [u8; 32],
        value: Value,
        deadline: &mut (impl Deadline + ?Sized),
    ) -> Result<(), PackWriteError> {
        let mut entry = Entry {
            payload: std::mem::take(&mut self.payload).into_boxed_slice(),
            chunks: std::mem::take(&mut self.chunks).into_boxed_slice(),
            value,
            checksum: [0; 32],
        };
        // The reservation stays charged while hashing outside the mutex. On
        // failure this local entry drops before the reservation releases it.
        entry.checksum = entry.checksum(&key, deadline)?;
        let Ok(mut state) = self.cache.state.lock() else {
            return Ok(());
        };
        // A racing worker may have completed the same pure computation.
        if state.entries.contains_key(&key) {
            return Ok(());
        }
        let sequence = state.next;
        let Some(next) = sequence.checked_add(1) else {
            return Ok(());
        };
        state.entries.insert(
            key,
            Retained {
                entry: Arc::new(entry),
                charge: self.charge,
                sequence,
            },
        );
        state.order.insert(sequence, key);
        state.next = next;
        // Transfer the existing reservation atomically; insertion allocates
        // no second payload and cannot overcommit another worker's capture.
        state.stats.reserved_bytes -= self.charge;
        state.stats.resident_bytes += self.charge;
        state.stats.entries = state.entries.len();
        self.charge = 0;
        Ok(())
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.payload = Vec::new();
        self.chunks = Vec::new();
        if self.charge != 0 {
            // A poisoned cache is disabled, but still discharge a reservation
            // acquired before the poison without leaking its accounting.
            let mut state = self
                .cache
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.stats.reserved_bytes -= self.charge;
        }
    }
}

impl PackComputationCache {
    /// `0` disables retention. Oversized entries are computed without caching.
    #[must_use]
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            state: Mutex::new(State::default()),
        }
    }

    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    #[must_use]
    pub fn stats(&self) -> PackCacheStats {
        self.state
            .lock()
            .map_or_else(|_| PackCacheStats::default(), |state| state.stats)
    }

    fn reserve(&self, charge: usize) -> Option<Reservation<'_>> {
        if charge < ENTRY_OVERHEAD {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        if !state.reserve(self.max_bytes, charge) {
            return None;
        }
        Some(Reservation {
            cache: self,
            charge,
            payload: Vec::new(),
            chunks: Vec::new(),
        })
    }

    fn lookup(
        &self,
        key: &[u8; 32],
        deadline: &mut (impl Deadline + ?Sized),
    ) -> Result<Option<Arc<Entry>>, PackWriteError> {
        checkpoint(deadline)?;
        if self.max_bytes < ENTRY_OVERHEAD {
            return Ok(None);
        }
        let entry = {
            let Ok(mut state) = self.state.lock() else {
                return Ok(None);
            };
            match state
                .entries
                .get(key)
                .map(|retained| Arc::clone(&retained.entry))
            {
                Some(entry) => entry,
                None => {
                    state.stats.misses = state.stats.misses.saturating_add(1);
                    return Ok(None);
                }
            }
        };
        // Check outside the lock, in bounded cancellable steps. Cancellation
        // is not corruption: it leaves the entry and invalidation count alone.
        if !entry.shape_is_valid(deadline)? || entry.checksum != entry.checksum(key, deadline)? {
            if let Ok(mut state) = self.state.lock() {
                let same = state
                    .entries
                    .get(key)
                    .is_some_and(|stored| Arc::ptr_eq(&stored.entry, &entry));
                drop(entry);
                // Other validators may still pin a corrupt entry. Keep its
                // charge until their Arcs also leave; every lookup rechecks it.
                if same
                    && state
                        .entries
                        .get(key)
                        .is_some_and(|stored| Arc::strong_count(&stored.entry) == 1)
                {
                    if let Some(removed) = state.entries.remove(key) {
                        state.order.remove(&removed.sequence);
                        state.stats.resident_bytes -= removed.charge;
                    }
                    state.stats.entries = state.entries.len();
                }
                state.stats.invalidations = state.stats.invalidations.saturating_add(1);
                state.stats.misses = state.stats.misses.saturating_add(1);
            }
            return Ok(None);
        }
        if let Ok(mut state) = self.state.lock() {
            match entry.value {
                Value::Compressed { .. } => {
                    state.stats.compression_hits = state.stats.compression_hits.saturating_add(1)
                }
                Value::Delta { .. } => {
                    state.stats.delta_hits = state.stats.delta_hits.saturating_add(1)
                }
            }
        }
        Ok(Some(entry))
    }

    fn charge_compression(&self, work: u64) {
        if let Ok(mut state) = self.state.lock() {
            state.stats.compression_work_units =
                state.stats.compression_work_units.saturating_add(work);
        }
    }

    pub(super) fn delta<D: Deadline + ?Sized>(
        &self,
        fingerprint: &[u8; 32],
        base: ObjectId,
        target: ObjectId,
        bound: usize,
        deadline: &mut D,
        compute: impl FnOnce(&mut D) -> Result<Option<Vec<u8>>, PackWriteError>,
    ) -> Result<Option<Vec<u8>>, PackWriteError> {
        if self.max_bytes < ENTRY_OVERHEAD {
            return compute(deadline);
        }
        let mut hash = Sha256Hasher::new();
        hash.update(CACHE_VERSION);
        hash.update(b"delta\0");
        hash.update(fingerprint);
        hash.update(&[base.as_bytes().len() as u8]);
        hash.update(base.as_bytes());
        hash.update(target.as_bytes());
        // Keep the EXACT scan bound. A negative result from a tighter scan
        // must never suppress a useful program at a larger bound.
        hash.update(&(bound as u64).to_be_bytes());
        let key = hash.finish();
        if let Some(entry) = self.lookup(&key, deadline)?
            && let Value::Delta { present } = entry.value
        {
            if !present {
                return Ok(None);
            }
            // This copy becomes the caller's ordinary planned delta, not a
            // second cache entry. Allocation trouble falls back to computation.
            let mut program = Vec::new();
            if program.try_reserve_exact(entry.payload.len()).is_err() {
                drop(entry);
                return compute(deadline);
            }
            for bytes in entry.payload.chunks(ENCODER_INPUT_CHUNK_BYTES) {
                checkpoint(deadline)?;
                program.extend_from_slice(bytes);
            }
            return Ok(Some(program));
        }
        let program = compute(deadline)?;
        let payload = program.as_deref().unwrap_or_default();
        if let Some(charge) = payload.len().checked_add(ENTRY_OVERHEAD)
            && let Some(mut reservation) = self.reserve(charge)
            && reservation.copy_delta(payload, deadline)?
        {
            reservation.insert(
                key,
                Value::Delta {
                    present: program.is_some(),
                },
                deadline,
            )?;
        }
        Ok(program)
    }
}

pub(super) fn delta_fingerprint(profile: PackWriteProfile, limits: &PackLimits) -> [u8; 32] {
    // The complete profile and limits include the indexed-search stride and
    // candidate budget inputs, not merely the human-readable profile name.
    let mut hash = Sha256Hasher::new();
    hash.update(CACHE_VERSION);
    hash.update(format!("{profile:?}/{limits:?}").as_bytes());
    hash.update(&(DELTA_INDEX_BLOCK_BYTES as u64).to_be_bytes());
    hash.update(&(DELTA_MAX_MATCH_CHAIN as u64).to_be_bytes());
    hash.finish()
}

/// The ordinary deterministic encoder with bounded per-entry memoization.
///
/// Keys bind the verified native identity (when called by the pack writer),
/// the EXACT payload bytes, full frozen profile, and every encoder limit.
/// A changed work ceiling is therefore a miss and runs the original encoder,
/// preserving its refusal code and observed count. Successful hits retain
/// the original work charge and check cancellation between output chunks.
#[derive(Debug)]
pub struct MemoizedPackEncoder {
    encoder: DeterministicPackEncoder,
    profile: PackWriteProfile,
    cache: Arc<PackComputationCache>,
    work_units: u64,
}

impl MemoizedPackEncoder {
    #[must_use]
    pub fn for_profile(profile: PackWriteProfile, cache: Arc<PackComputationCache>) -> Self {
        Self::new(DeflateLimits::GIT_OBJECT, profile, cache)
    }

    #[must_use]
    pub fn new(
        limits: DeflateLimits,
        profile: PackWriteProfile,
        cache: Arc<PackComputationCache>,
    ) -> Self {
        Self {
            encoder: DeterministicPackEncoder::new(limits, profile.compression),
            profile,
            cache,
            work_units: 0,
        }
    }

    /// Logical work for finalized members, including cached computations.
    #[must_use]
    pub const fn work_units(&self) -> u64 {
        self.work_units
    }

    fn encode(
        &mut self,
        identity: Option<ObjectId>,
        input: &[u8],
        deadline: &mut dyn Deadline,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), PackWriteError>,
    ) -> Result<DeflateReceipt, PackWriteError> {
        checkpoint(deadline)?;
        let capacity = self.cache.max_bytes.saturating_sub(ENTRY_OVERHEAD);
        let key = if capacity == 0 {
            None
        } else {
            let mut hash = Sha256Hasher::new();
            hash.update(CACHE_VERSION);
            hash.update(b"deflate\0");
            hash.update(format!("{:?}/{:?}", self.profile, self.encoder.limits).as_bytes());
            hash.update(&(ENCODER_INPUT_CHUNK_BYTES as u64).to_be_bytes());
            match identity {
                Some(id) => {
                    hash.update(&[id.as_bytes().len() as u8]);
                    hash.update(id.as_bytes());
                }
                None => hash.update(&[0]),
            }
            // Delta payloads are distinct from their target's full object
            // body, and from programs against another base. Bind the bytes.
            let mut payload_hash = Sha256Hasher::new();
            for chunk in input.chunks(ENCODER_INPUT_CHUNK_BYTES) {
                checkpoint(deadline)?;
                payload_hash.update(chunk);
            }
            hash.update(&payload_hash.finish());
            Some(hash.finish())
        };
        if let Some(key) = key
            && let Some(entry) = self.cache.lookup(&key, deadline)?
            && let Value::Compressed { receipt, work } = entry.value
        {
            let mut position = 0;
            for length in &entry.chunks {
                checkpoint(deadline)?;
                let end = position + length;
                emit(&entry.payload[position..end])?;
                position = end;
            }
            checkpoint(deadline)?;
            self.work_units = self.work_units.saturating_add(work);
            self.cache.charge_compression(work);
            return Ok(receipt);
        }
        let mut reservation = key.and_then(|_| self.cache.reserve(ENTRY_OVERHEAD));
        let (receipt, work) = self
            .encoder
            .encode_with_work(input, deadline, &mut |bytes| {
                emit(bytes)?;
                if let Some(capture) = reservation.as_mut()
                    && !capture.capture(bytes)
                {
                    // Release buffers and their reservation together; the
                    // original encoder continues with identical output.
                    reservation = None;
                }
                Ok(())
            })?;
        self.work_units = self.work_units.saturating_add(work);
        self.cache.charge_compression(work);
        if let Some(reservation) = reservation
            && let Some(key) = key
        {
            reservation.insert(key, Value::Compressed { receipt, work }, deadline)?;
        }
        Ok(receipt)
    }
}

impl PackEntryEncoder for MemoizedPackEncoder {
    fn encode_entry(
        &mut self,
        input: &[u8],
        deadline: &mut dyn Deadline,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), PackWriteError>,
    ) -> Result<DeflateReceipt, PackWriteError> {
        self.encode(None, input, deadline, emit)
    }

    fn encode_object_entry(
        &mut self,
        id: ObjectId,
        input: &[u8],
        deadline: &mut dyn Deadline,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), PackWriteError>,
    ) -> Result<DeflateReceipt, PackWriteError> {
        self.encode(Some(id), input, deadline, emit)
    }
}

#[cfg(test)]
mod tests;

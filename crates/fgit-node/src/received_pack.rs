//! Bounded process-local custody of native-verified received packs.
//!
//! This accelerator is not object authority and is never persisted. The receive
//! validator supplies every reconstructed native identity only after its normal
//! graph validation succeeds. A serving caller must independently authorize an
//! exact visible selection before asking for reuse. A hit contains precisely
//! that selection, with all delta bases inside it; it cannot disclose a hidden
//! extra object or turn physical presence into reachability.
//!
//! The received-pack-v1 profile preserves the sender's verified representation,
//! rather than claiming the native writer's ordering or compression receipts.

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};

use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_git_object::ObjectType;
use fgit_pack::{
    Deadline, EntryKind, NativeChecksumVerifier, PackError, PackLimits, PackOrderKey,
    PackWriteError, ParsedDeltaBase, QuarantinedPack, RetainedPackBytes, validate_pack_trailer,
};
use fgit_types::GitOid;

const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 8;
const HASH_CHUNK_BYTES: usize = 64 * 1024;
// Includes the entry, Arc headers, bounded FIFO and receipt. The per-object
// charge also covers temporary dependency/depth/visit arrays during capture.
const ENTRY_OVERHEAD: usize = 1024;
const OBJECT_OVERHEAD: usize = 512;

/// Metadata established by the native validator for EVERY raw pack entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedReceivedObject {
    pub(crate) id: GitOid,
    pub(crate) kind: ObjectType,
    pub(crate) bytes: usize,
}

/// Evidence for an exact native-verified sender representation. No native
/// encoder, deterministic ordering or delta-search work is claimed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedPackReceipt {
    checksum: GitOid,
    sha256: [u8; 32],
    object_count: u32,
    ofs_delta_count: usize,
    ref_delta_count: usize,
    total_object_bytes: usize,
    output_bytes: usize,
    maximum_delta_depth: usize,
}

impl ReceivedPackReceipt {
    #[must_use]
    pub const fn profile(&self) -> &'static str {
        "received-pack-v1"
    }
    #[must_use]
    pub const fn checksum(&self) -> GitOid {
        self.checksum
    }
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    #[must_use]
    pub const fn object_count(&self) -> u32 {
        self.object_count
    }
    #[must_use]
    pub const fn ofs_delta_count(&self) -> usize {
        self.ofs_delta_count
    }
    #[must_use]
    pub const fn ref_delta_count(&self) -> usize {
        self.ref_delta_count
    }
    #[must_use]
    pub const fn total_object_bytes(&self) -> usize {
        self.total_object_bytes
    }
    #[must_use]
    pub const fn output_bytes(&self) -> usize {
        self.output_bytes
    }
    #[must_use]
    pub const fn maximum_delta_depth(&self) -> usize {
        self.maximum_delta_depth
    }
}

#[derive(Debug)]
struct Entry {
    bytes: RetainedPackBytes,
    objects: Vec<VerifiedReceivedObject>,
    receipt: ReceivedPackReceipt,
    // Includes both native body sizes and inflated delta-program sizes.
    maximum_object_bytes: usize,
    // Raw entry inflation is separate from reconstructed native-object bytes.
    total_entry_bytes: usize,
    maximum_delta_fanout: usize,
    binding: [u8; 32],
    charge: usize,
}

#[derive(Debug, Default)]
struct State {
    // At most eight entries. The first unpinned entry is the FIFO victim.
    entries: Vec<Arc<Entry>>,
    resident_bytes: usize,
    reserved_bytes: usize,
    reservations: usize,
}

/// Shared by serving children. Pinned readers remain charged and cannot be
/// evicted while their payloads still hold the immutable allocation.
#[derive(Debug)]
pub struct ReceivedPackCache {
    max_bytes: usize,
    state: Arc<Mutex<State>>,
}

impl ReceivedPackCache {
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    pub(crate) const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    pub(crate) fn capture_limit(&self) -> usize {
        self.max_bytes
            .saturating_sub(ENTRY_OVERHEAD)
            .min(MAX_CAPTURE_BYTES)
    }

    fn reserve(&self, charge: usize) -> Option<Reservation> {
        if charge > self.max_bytes {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        while state.reservations + state.entries.len() >= MAX_ENTRIES
            || state.resident_bytes.checked_add(state.reserved_bytes)?
                > self.max_bytes.checked_sub(charge)?
        {
            let index = state
                .entries
                .iter()
                .position(|entry| Arc::strong_count(entry) == 1)?;
            let removed = state.entries.remove(index);
            state.resident_bytes -= removed.charge;
            drop(removed);
        }
        if state.entries.capacity() < MAX_ENTRIES
            && state.entries.try_reserve_exact(MAX_ENTRIES).is_err()
        {
            return None;
        }
        state.reserved_bytes += charge;
        state.reservations += 1;
        Some(Reservation {
            state: Arc::clone(&self.state),
            charge,
        })
    }

    /// Prepare optional custody after native identity and closure validation.
    /// Allocation, shape and capacity failures are misses; cancellation remains
    /// the original receive's authoritative stop condition.
    pub(crate) fn prepare_verified(
        &self,
        pack: &QuarantinedPack,
        objects: impl ExactSizeIterator<Item = VerifiedReceivedObject>,
        ids_at_offset: &BTreeMap<u64, GitOid>,
        limits: &PackLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Option<PendingReceivedPack>, PackError> {
        check(deadline)?;
        let Some(bytes) = pack.retained_bytes() else {
            return Ok(None);
        };
        let count = objects.len();
        if count == 0
            || count > limits.max_entries as usize
            || count != pack.entries().len()
            || count != ids_at_offset.len()
            || usize::try_from(bytes.object_count()).ok() != Some(count)
            || pack.header.object_count != bytes.object_count()
            || pack.format != bytes.format()
            || pack.trailer != bytes.checksum()
            || bytes.bytes().len() > self.capture_limit()
            || bytes.retained_capacity() > self.capture_limit()
        {
            return Ok(None);
        }
        let Some(charge) = count
            .checked_mul(OBJECT_OVERHEAD)
            .and_then(|metadata| metadata.checked_add(ENTRY_OVERHEAD))
            .and_then(|metadata| metadata.checked_add(bytes.retained_capacity()))
        else {
            return Ok(None);
        };
        let Some(reservation) = self.reserve(charge) else {
            return Ok(None);
        };
        // The public parser accepts a verifier trait, so independently require
        // the native checksum before establishing reusable custody.
        if validate_pack_trailer(
            bytes.bytes(),
            bytes.format(),
            limits,
            &NativeChecksumVerifier,
        )
        .is_err()
        {
            check(deadline)?;
            return Ok(None);
        }
        check(deadline)?;
        let mut metadata = Vec::new();
        if metadata.try_reserve_exact(count).is_err() {
            return Ok(None);
        }
        let mut total_object_bytes = 0usize;
        let mut maximum_object_bytes = 0usize;
        for object in objects {
            check(deadline)?;
            if object.id.algorithm() != bytes.format()
                || object.id.is_zero()
                || object.bytes > limits.max_object_bytes
                || metadata
                    .last()
                    .is_some_and(|previous: &VerifiedReceivedObject| previous.id >= object.id)
            {
                return Ok(None);
            }
            let Some(total) = total_object_bytes.checked_add(object.bytes) else {
                return Ok(None);
            };
            if total > limits.max_total_expanded_bytes {
                return Ok(None);
            }
            total_object_bytes = total;
            maximum_object_bytes = maximum_object_bytes.max(object.bytes);
            metadata.push(object);
        }
        let Some(dependencies) = dependencies(pack, &metadata, ids_at_offset, limits, deadline)?
        else {
            return Ok(None);
        };
        // The native writer applies the object ceiling to delta programs too.
        maximum_object_bytes = maximum_object_bytes.max(dependencies.maximum_entry_bytes);
        let sha256 = strong_hash(bytes.bytes(), deadline)?;
        let receipt = ReceivedPackReceipt {
            checksum: bytes.checksum(),
            sha256,
            object_count: bytes.object_count(),
            ofs_delta_count: dependencies.ofs,
            ref_delta_count: dependencies.reference,
            total_object_bytes,
            output_bytes: bytes.bytes().len(),
            maximum_delta_depth: dependencies.depth,
        };
        let binding = metadata_binding(
            &metadata,
            &receipt,
            maximum_object_bytes,
            dependencies.total_entry_bytes,
            dependencies.fanout,
            deadline,
        )?;
        check(deadline)?;
        Ok(Some(PendingReceivedPack {
            entry: Entry {
                bytes: bytes.clone(),
                objects: metadata,
                receipt,
                maximum_object_bytes,
                total_entry_bytes: dependencies.total_entry_bytes,
                maximum_delta_fanout: dependencies.fanout,
                binding,
                charge,
            },
            reservation,
        }))
    }

    #[cfg(test)]
    fn retain_verified(
        &self,
        pack: &QuarantinedPack,
        objects: impl ExactSizeIterator<Item = VerifiedReceivedObject>,
        ids_at_offset: &BTreeMap<u64, GitOid>,
        limits: &PackLimits,
        deadline: &mut impl Deadline,
    ) -> Result<(), PackError> {
        if let Some(pending) =
            self.prepare_verified(pack, objects, ids_at_offset, limits, deadline)?
        {
            pending.commit();
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn retained_entries(&self) -> usize {
        self.state
            .lock()
            .expect("unpoisoned test cache")
            .entries
            .len()
    }

    /// Match a complete, current caller-authorized selection. Ordering hints
    /// do not change the sender's representation under this explicit profile.
    pub(crate) fn try_reuse(
        &self,
        keys: &[PackOrderKey],
        limits: &PackLimits,
        allow_ofs_delta: bool,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Option<ReceivedPackPayload>, PackWriteError> {
        check(live)?;
        if keys.is_empty() || keys.len() > limits.max_entries as usize {
            return Ok(None);
        }
        for pair in keys.windows(2) {
            check(live)?;
            if pair[0].id >= pair[1].id {
                return Ok(None);
            }
        }
        let selected = {
            let Ok(state) = self.state.lock() else {
                return Ok(None);
            };
            let mut selected = None;
            for entry in &state.entries {
                check(live)?;
                if entry.objects.len() != keys.len()
                    || entry.receipt.output_bytes > limits.max_input_bytes
                    || entry.maximum_object_bytes > limits.max_object_bytes
                    || entry.receipt.total_object_bytes > limits.max_total_expanded_bytes
                    || entry.total_entry_bytes > limits.max_total_expanded_bytes
                    || entry.receipt.maximum_delta_depth > limits.max_delta_depth
                    || entry.maximum_delta_fanout > limits.max_delta_fanout
                    || (!allow_ofs_delta && entry.receipt.ofs_delta_count != 0)
                {
                    continue;
                }
                let mut matches = true;
                for (object, key) in entry.objects.iter().zip(keys) {
                    check(live)?;
                    if object.id != key.id || object.kind != key.object_type {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    selected = Some(Arc::clone(entry));
                    break;
                }
            }
            selected
        };
        let Some(entry) = selected else {
            check(live)?;
            return Ok(None);
        };
        if strong_hash(entry.bytes.bytes(), live)? != entry.receipt.sha256
            || metadata_binding(
                &entry.objects,
                &entry.receipt,
                entry.maximum_object_bytes,
                entry.total_entry_bytes,
                entry.maximum_delta_fanout,
                live,
            )? != entry.binding
        {
            check(live)?;
            return Ok(None);
        }
        check(live)?;
        Ok(Some(ReceivedPackPayload { entry, offset: 0 }))
    }
}

#[derive(Debug)]
struct Reservation {
    state: Arc<Mutex<State>>,
    charge: usize,
}

impl Reservation {
    fn commit(mut self, entry: Entry) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state
            .entries
            .iter()
            .any(|existing| existing.receipt == entry.receipt && existing.objects == entry.objects)
        {
            return;
        }
        state.entries.push(Arc::new(entry));
        state.reserved_bytes -= self.charge;
        state.resident_bytes += self.charge;
        state.reservations -= 1;
        self.charge = 0;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.charge != 0
            && let Ok(mut state) = self.state.lock()
        {
            state.reserved_bytes -= self.charge;
            state.reservations -= 1;
        }
    }
}

/// Native-verified bytes awaiting the fabric's final collision check.
/// Drop releases the entry before its reservation; no lookup can see it.
#[derive(Debug)]
pub struct PendingReceivedPack {
    entry: Entry,
    reservation: Reservation,
}

impl PendingReceivedPack {
    pub(crate) fn commit(self) {
        let Self { entry, reservation } = self;
        reservation.commit(entry);
    }
}

/// Each active reader has its own cursor and pins the accounted bytes.
#[derive(Debug)]
pub struct ReceivedPackPayload {
    entry: Arc<Entry>,
    offset: usize,
}

impl ReceivedPackPayload {
    pub(crate) fn receipt(&self) -> &ReceivedPackReceipt {
        &self.entry.receipt
    }

    pub(crate) fn next_chunk(&mut self, maximum: usize) -> io::Result<Option<Vec<u8>>> {
        if maximum == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let bytes = self.entry.bytes.bytes();
        if self.offset == bytes.len() {
            return Ok(None);
        }
        let end = self.offset + maximum.min(bytes.len() - self.offset);
        let chunk = copy_bytes(&bytes[self.offset..end])?;
        self.offset = end;
        Ok(Some(chunk))
    }

    pub(crate) fn into_bytes(self) -> io::Result<Vec<u8>> {
        copy_bytes(self.entry.bytes.bytes())
    }
}

fn copy_bytes(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    output.extend_from_slice(bytes);
    Ok(output)
}

fn check(deadline: &mut impl Deadline) -> Result<(), PackError> {
    if deadline.checkpoint() {
        Ok(())
    } else {
        Err(PackError::DeadlineExceeded)
    }
}

fn strong_hash(bytes: &[u8], deadline: &mut impl Deadline) -> Result<[u8; 32], PackError> {
    let mut hash = Sha256Hasher::new();
    for chunk in bytes.chunks(HASH_CHUNK_BYTES) {
        check(deadline)?;
        hash.update(chunk);
    }
    check(deadline)?;
    Ok(hash.finish())
}

fn metadata_binding(
    objects: &[VerifiedReceivedObject],
    receipt: &ReceivedPackReceipt,
    maximum_object_bytes: usize,
    total_entry_bytes: usize,
    maximum_delta_fanout: usize,
    deadline: &mut impl Deadline,
) -> Result<[u8; 32], PackError> {
    check(deadline)?;
    let mut hash = Sha256Hasher::new();
    hash.update(b"frankengit/received-pack-v1/verified-association\0");
    hash.update(&receipt.sha256);
    hash.update(&[receipt.checksum.as_bytes().len() as u8]);
    hash.update(receipt.checksum.as_bytes());
    hash.update(&receipt.object_count.to_be_bytes());
    for value in [
        receipt.ofs_delta_count,
        receipt.ref_delta_count,
        receipt.total_object_bytes,
        receipt.output_bytes,
        receipt.maximum_delta_depth,
        maximum_object_bytes,
        total_entry_bytes,
        maximum_delta_fanout,
        objects.len(),
    ] {
        hash.update(&(value as u64).to_be_bytes());
    }
    for object in objects {
        check(deadline)?;
        hash.update(&[object.id.as_bytes().len() as u8]);
        hash.update(object.id.as_bytes());
        hash.update(&[match object.kind {
            ObjectType::Commit => 1,
            ObjectType::Tree => 2,
            ObjectType::Blob => 3,
            ObjectType::Tag => 4,
        }]);
        hash.update(&(object.bytes as u64).to_be_bytes());
    }
    check(deadline)?;
    Ok(hash.finish())
}

struct Dependencies {
    ofs: usize,
    reference: usize,
    depth: usize,
    fanout: usize,
    maximum_entry_bytes: usize,
    total_entry_bytes: usize,
}

/// Validate the pack-local graph. Forward REF bases are supported; external
/// bases, cycles and malformed joins cannot establish self-contained custody.
fn dependencies(
    pack: &QuarantinedPack,
    metadata: &[VerifiedReceivedObject],
    ids: &BTreeMap<u64, GitOid>,
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<Option<Dependencies>, PackError> {
    let count = metadata.len();
    let mut parents = Vec::new();
    let mut fanout = Vec::new();
    let mut depths = Vec::new();
    let mut seen = Vec::new();
    let mut chain = Vec::new();
    if parents.try_reserve_exact(count).is_err()
        || fanout.try_reserve_exact(count).is_err()
        || depths.try_reserve_exact(count).is_err()
        || seen.try_reserve_exact(count).is_err()
        || chain.try_reserve_exact(count).is_err()
    {
        return Ok(None);
    }
    parents.resize(count, None::<usize>);
    fanout.resize(count, 0usize);
    depths.resize(count, usize::MAX);
    seen.resize(count, 0u8);
    let mut result = Dependencies {
        ofs: 0,
        reference: 0,
        depth: 0,
        fanout: 0,
        maximum_entry_bytes: 0,
        total_entry_bytes: 0,
    };
    for entry in pack.entries() {
        check(deadline)?;
        if entry.header.declared_size > limits.max_object_bytes {
            return Ok(None);
        }
        let Some(total) = result
            .total_entry_bytes
            .checked_add(entry.header.declared_size)
        else {
            return Ok(None);
        };
        if total > limits.max_total_expanded_bytes {
            return Ok(None);
        }
        result.total_entry_bytes = total;
        result.maximum_entry_bytes = result.maximum_entry_bytes.max(entry.header.declared_size);
        let Some(id) = ids.get(&entry.offset) else {
            return Ok(None);
        };
        let Ok(index) = metadata.binary_search_by_key(id, |object| object.id) else {
            return Ok(None);
        };
        if seen[index] != 0 {
            return Ok(None);
        }
        seen[index] = 1;
        let base = match (&entry.delta_base, entry.header.kind) {
            (Some(ParsedDeltaBase::Ofs { base_offset, .. }), EntryKind::OfsDelta) => {
                if *base_offset >= entry.offset {
                    return Ok(None);
                }
                result.ofs += 1;
                ids.get(base_offset)
            }
            (Some(ParsedDeltaBase::Ref { base, .. }), EntryKind::RefDelta) => {
                result.reference += 1;
                Some(base)
            }
            (None, kind) => {
                let native = match kind {
                    EntryKind::Commit => ObjectType::Commit,
                    EntryKind::Tree => ObjectType::Tree,
                    EntryKind::Blob => ObjectType::Blob,
                    EntryKind::Tag => ObjectType::Tag,
                    EntryKind::OfsDelta | EntryKind::RefDelta => return Ok(None),
                };
                if native != metadata[index].kind
                    || entry.header.declared_size != metadata[index].bytes
                {
                    return Ok(None);
                }
                continue;
            }
            _ => return Ok(None),
        };
        let Some(base) = base else {
            return Ok(None);
        };
        let Ok(parent) = metadata.binary_search_by_key(base, |object| object.id) else {
            return Ok(None);
        };
        if metadata[parent].kind != metadata[index].kind {
            return Ok(None);
        }
        parents[index] = Some(parent);
        fanout[parent] += 1;
        result.fanout = result.fanout.max(fanout[parent]);
        if result.fanout > limits.max_delta_fanout {
            return Ok(None);
        }
    }
    if seen.contains(&0) {
        return Ok(None);
    }
    seen.fill(0);
    for start in 0..count {
        check(deadline)?;
        if depths[start] != usize::MAX {
            continue;
        }
        chain.clear();
        let mut at = start;
        loop {
            check(deadline)?;
            if depths[at] != usize::MAX {
                break;
            }
            if seen[at] == 1 || chain.len() > limits.max_delta_depth {
                return Ok(None);
            }
            seen[at] = 1;
            chain.push(at);
            let Some(parent) = parents[at] else {
                break;
            };
            at = parent;
        }
        while let Some(index) = chain.pop() {
            check(deadline)?;
            let depth = match parents[index] {
                Some(parent) => match depths[parent].checked_add(1) {
                    Some(depth) => depth,
                    None => return Ok(None),
                },
                None => 0,
            };
            if depth > limits.max_delta_depth {
                return Ok(None);
            }
            depths[index] = depth;
            seen[index] = 2;
            result.depth = result.depth.max(depth);
        }
    }
    Ok(Some(result))
}

#[cfg(test)]
mod tests;

//! Reframe complete verified entry runs without reconstructing their objects.
//!
//! There are at most eight retained sources. Membership is checked once per
//! candidate, and pairwise overlap masks make the at-most-255 cover choices
//! independent of repository size. Only exact, disjoint covers reach graph
//! verification. OFS distances remain valid because no source run is split.

use super::{
    Entry, MAX_ENTRIES, ReceivedPackCache, ReceivedPackPayload, ReceivedPackReceipt, check,
    metadata_binding, strong_hash,
};
use fgit_crypto::{DigestHasher, Sha1Hasher, Sha256Hasher};
use fgit_pack::{Deadline, PackError, PackLimits, PackOrderKey};
use fgit_types::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256};
use std::sync::Arc;

struct Candidate {
    entry: Arc<Entry>,
    // Sorted positions in the freshly authorized selection.
    positions: Vec<usize>,
}

pub(super) fn select(
    cache: &ReceivedPackCache,
    keys: &[PackOrderKey],
    limits: &PackLimits,
    allow_ofs_delta: bool,
    live: &mut impl Deadline,
) -> Result<Option<ReceivedPackPayload>, PackError> {
    check(live)?;
    let Some(first) = keys.first() else {
        return Ok(None);
    };
    if keys.len() > limits.max_entries as usize {
        return Ok(None);
    }
    let format = first.id.algorithm();
    for (index, key) in keys.iter().enumerate() {
        check(live)?;
        if key.id.algorithm() != format
            || key.id.is_zero()
            || (index != 0 && keys[index - 1].id >= key.id)
        {
            return Ok(None);
        }
    }
    // Pin custody under the lock, then release it before any large scan/hash.
    // A concurrent receive cannot evict bytes being inspected or served.
    let mut snapshot = Vec::new();
    if snapshot.try_reserve_exact(MAX_ENTRIES).is_err() {
        return Ok(None);
    }
    {
        let Ok(state) = cache.state.lock() else {
            return Ok(None);
        };
        if state.entries.len() > MAX_ENTRIES {
            return Ok(None);
        }
        snapshot.extend(state.entries.iter().map(Arc::clone));
    }
    let mut candidates = Vec::new();
    if candidates.try_reserve_exact(snapshot.len()).is_err() {
        return Ok(None);
    }
    for entry in snapshot {
        check(live)?;
        let receipt = &entry.receipt;
        if entry.objects.is_empty()
            || entry.objects.len() > keys.len()
            || entry.objects.len() != receipt.object_count as usize
            || entry.parents.len() != entry.objects.len()
            || receipt.source_pack_count != 1
            || receipt.checksum.algorithm() != format
            || entry.bytes.format() != format
            || entry.bytes.checksum() != receipt.checksum
            || entry.bytes.bytes().len() != receipt.output_bytes
            || receipt.output_bytes < 12 + format.digest_len()
            || receipt.output_bytes > limits.max_input_bytes
            || entry.maximum_object_bytes > limits.max_object_bytes
            || receipt.total_object_bytes > limits.max_total_expanded_bytes
            || entry.total_entry_bytes > limits.max_total_expanded_bytes
            || receipt.maximum_delta_depth > limits.max_delta_depth
            || entry.maximum_delta_fanout > limits.max_delta_fanout
            || (!allow_ofs_delta && receipt.ofs_delta_count != 0)
        {
            continue;
        }
        let mut positions = Vec::new();
        if positions.try_reserve_exact(entry.objects.len()).is_err() {
            return Ok(None);
        }
        for object in &entry.objects {
            check(live)?;
            let Ok(index) = keys.binary_search_by_key(&object.id, |key| key.id) else {
                break;
            };
            if object.kind != keys[index].object_type
                || positions.last().is_some_and(|previous| *previous >= index)
            {
                break;
            }
            positions.push(index);
        }
        if positions.len() != entry.objects.len() {
            continue;
        }
        candidates.push(Candidate { entry, positions });
    }
    let mut overlaps = [0u16; MAX_ENTRIES];
    for left in 0..candidates.len() {
        for right in left + 1..candidates.len() {
            check(live)?;
            if intersects(
                &candidates[left].positions,
                &candidates[right].positions,
                live,
            )? {
                overlaps[left] |= 1 << right;
                overlaps[right] |= 1 << left;
            }
        }
    }
    // Prefer the existing exact sender representation, then fewer sources,
    // then FIFO source order. A bad graph in one cover does not poison a
    // later, independently valid representation of the same authorized set.
    // Verify bytes only for actual cover candidates, and at most once per
    // source. An unrelated/overlapping representation must not make a warm
    // exact hit hash the whole retained cache.
    let mut integrity = [None; MAX_ENTRIES];
    for source_count in 1..=candidates.len() {
        for mask in 1u16..1u16 << candidates.len() {
            check(live)?;
            if mask.count_ones() as usize != source_count {
                continue;
            }
            let mut count = 0usize;
            let mut disjoint = true;
            for (index, candidate) in candidates.iter().enumerate() {
                if mask & (1 << index) != 0 {
                    if mask & overlaps[index] != 0 {
                        disjoint = false;
                        break;
                    }
                    count = count.saturating_add(candidate.positions.len());
                }
            }
            if !disjoint || count != keys.len() {
                continue;
            }
            let Some(mut receipt) = totals(&candidates, mask, format, limits, live)? else {
                continue;
            };
            let mut intact = true;
            for (index, candidate) in candidates.iter().enumerate() {
                if mask & (1 << index) == 0 {
                    continue;
                }
                let valid = if let Some(valid) = integrity[index] {
                    valid
                } else {
                    let entry = &candidate.entry;
                    let valid = strong_hash(entry.bytes.bytes(), live)? == entry.receipt.sha256
                        && metadata_binding(
                            &entry.objects,
                            &entry.parents,
                            &entry.receipt,
                            entry.maximum_object_bytes,
                            entry.total_entry_bytes,
                            entry.maximum_delta_fanout,
                            live,
                        )? == entry.binding;
                    integrity[index] = Some(valid);
                    valid
                };
                if !valid {
                    intact = false;
                    break;
                }
            }
            if !intact {
                continue;
            }
            let Some(depth) = graph_depth(&candidates, mask, keys, limits, live)? else {
                continue;
            };
            receipt.maximum_delta_depth = depth;
            let mut entries = Vec::new();
            if entries.try_reserve_exact(source_count).is_err() {
                return Ok(None);
            }
            for (index, candidate) in candidates.iter().enumerate() {
                if mask & (1 << index) != 0 {
                    entries.push(Arc::clone(&candidate.entry));
                }
            }
            check(live)?;
            let header = if source_count == 1 {
                receipt = entries[0].receipt.clone();
                None
            } else {
                Some(reframe(&entries, &mut receipt, format, live)?)
            };
            return Ok(Some(ReceivedPackPayload {
                entries,
                receipt,
                header,
                part: 0,
                offset: 0,
            }));
        }
    }
    check(live)?;
    Ok(None)
}

fn intersects(
    left: &[usize],
    right: &[usize],
    live: &mut impl Deadline,
) -> Result<bool, PackError> {
    let (mut a, mut b) = (0, 0);
    while a < left.len() && b < right.len() {
        check(live)?;
        match left[a].cmp(&right[b]) {
            std::cmp::Ordering::Less => a += 1,
            std::cmp::Ordering::Greater => b += 1,
            std::cmp::Ordering::Equal => return Ok(true),
        }
    }
    Ok(false)
}

fn totals(
    candidates: &[Candidate],
    mask: u16,
    format: GitHashAlgorithm,
    limits: &PackLimits,
    live: &mut impl Deadline,
) -> Result<Option<ReceivedPackReceipt>, PackError> {
    let mut receipt = ReceivedPackReceipt {
        checksum: candidates[0].entry.receipt.checksum,
        sha256: [0; 32],
        object_count: 0,
        ofs_delta_count: 0,
        ref_delta_count: 0,
        total_object_bytes: 0,
        output_bytes: 12 + format.digest_len(),
        maximum_delta_depth: 0,
        source_pack_count: 0,
    };
    let mut entry_bytes = 0usize;
    for (index, candidate) in candidates.iter().enumerate() {
        check(live)?;
        if mask & (1 << index) == 0 {
            continue;
        }
        let entry = &candidate.entry;
        let source = &entry.receipt;
        let Some(count) = receipt.object_count.checked_add(source.object_count) else {
            return Ok(None);
        };
        let Some(objects) = receipt
            .total_object_bytes
            .checked_add(source.total_object_bytes)
        else {
            return Ok(None);
        };
        let Some(expanded) = entry_bytes.checked_add(entry.total_entry_bytes) else {
            return Ok(None);
        };
        let Some(output) = receipt
            .output_bytes
            .checked_add(source.output_bytes - 12 - format.digest_len())
        else {
            return Ok(None);
        };
        if count > limits.max_entries
            || objects > limits.max_total_expanded_bytes
            || expanded > limits.max_total_expanded_bytes
            || output > limits.max_input_bytes
        {
            return Ok(None);
        }
        receipt.object_count = count;
        receipt.total_object_bytes = objects;
        receipt.output_bytes = output;
        receipt.ofs_delta_count += source.ofs_delta_count;
        receipt.ref_delta_count += source.ref_delta_count;
        receipt.source_pack_count += 1;
        entry_bytes = expanded;
    }
    Ok(Some(receipt))
}

fn filled<T: Clone>(count: usize, value: T) -> Option<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).ok()?;
    values.resize(count, value);
    Some(values)
}

/// Revalidate the assembled representation, not just each source's local
/// lower bounds. This admits no client-side/external base dependency.
fn graph_depth(
    candidates: &[Candidate],
    mask: u16,
    keys: &[PackOrderKey],
    limits: &PackLimits,
    live: &mut impl Deadline,
) -> Result<Option<usize>, PackError> {
    check(live)?;
    let Some(mut parents) = filled(keys.len(), None::<usize>) else {
        return Ok(None);
    };
    let Some(mut fanout) = filled(keys.len(), 0usize) else {
        return Ok(None);
    };
    let Some(mut depths) = filled(keys.len(), usize::MAX) else {
        return Ok(None);
    };
    let Some(mut visits) = filled(keys.len(), 0u8) else {
        return Ok(None);
    };
    let mut chain = Vec::new();
    // Depth, not repository size, bounds the live ancestor stack.
    if chain
        .try_reserve_exact(keys.len().min(limits.max_delta_depth.saturating_add(1)))
        .is_err()
    {
        return Ok(None);
    }
    for (index, candidate) in candidates.iter().enumerate() {
        if mask & (1 << index) == 0 {
            continue;
        }
        for (local, position) in candidate.positions.iter().copied().enumerate() {
            check(live)?;
            let Some(base) = candidate.entry.parents[local] else {
                continue;
            };
            let Ok(parent) = keys.binary_search_by_key(&base, |key| key.id) else {
                return Ok(None);
            };
            if keys[parent].object_type != keys[position].object_type {
                return Ok(None);
            }
            parents[position] = Some(parent);
            fanout[parent] += 1;
            if fanout[parent] > limits.max_delta_fanout {
                return Ok(None);
            }
        }
    }
    let mut maximum = 0;
    for start in 0..keys.len() {
        check(live)?;
        if depths[start] != usize::MAX {
            continue;
        }
        chain.clear();
        let mut at = start;
        loop {
            check(live)?;
            if depths[at] != usize::MAX {
                break;
            }
            if visits[at] == 1 || chain.len() > limits.max_delta_depth {
                return Ok(None);
            }
            visits[at] = 1;
            chain.push(at);
            let Some(parent) = parents[at] else {
                break;
            };
            at = parent;
        }
        while let Some(index) = chain.pop() {
            check(live)?;
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
            visits[index] = 2;
            maximum = maximum.max(depth);
        }
    }
    Ok(Some(maximum))
}

enum NativeHasher {
    Sha1(Sha1Hasher),
    Sha256(Sha256Hasher),
}

impl NativeHasher {
    fn new(format: GitHashAlgorithm) -> Self {
        match format {
            GitHashAlgorithm::Sha1 => Self::Sha1(Sha1Hasher::new()),
            GitHashAlgorithm::Sha256 => Self::Sha256(Sha256Hasher::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(hash) => hash.update(bytes),
            Self::Sha256(hash) => hash.update(bytes),
        }
    }

    fn finish(self) -> GitOid {
        match self {
            Self::Sha1(hash) => GitOid::Sha1(GitOidSha1::from_bytes(hash.finish())),
            Self::Sha256(hash) => GitOid::Sha256(GitOidSha256::from_bytes(hash.finish())),
        }
    }
}

fn reframe(
    entries: &[Arc<Entry>],
    receipt: &mut ReceivedPackReceipt,
    format: GitHashAlgorithm,
    live: &mut impl Deadline,
) -> Result<[u8; 12], PackError> {
    let mut header = [0u8; 12];
    header[..4].copy_from_slice(b"PACK");
    header[4..8].copy_from_slice(&2u32.to_be_bytes());
    header[8..].copy_from_slice(&receipt.object_count.to_be_bytes());
    let mut native = NativeHasher::new(format);
    let mut strong = Sha256Hasher::new();
    native.update(&header);
    strong.update(&header);
    for entry in entries {
        let bytes = entry.bytes.bytes();
        let run = &bytes[12..bytes.len() - format.digest_len()];
        for chunk in run.chunks(super::HASH_CHUNK_BYTES) {
            check(live)?;
            native.update(chunk);
            strong.update(chunk);
        }
    }
    check(live)?;
    receipt.checksum = native.finish();
    strong.update(receipt.checksum.as_bytes());
    receipt.sha256 = strong.finish();
    check(live)?;
    Ok(header)
}

//! Reframe complete verified entry runs without reconstructing their objects.
//!
//! Up to 64 retained sources share one byte budget. Exact FIFO singletons are
//! tried first; larger selections propagate uniquely owned objects before
//! enumerating at most eight remaining ambiguous sources. Forced selections
//! with a whole residual-base candidate also get a bounded FIFO singleton
//! pass. Only exact, disjoint covers reach graph verification. OFS distances
//! remain valid because no source run is split.
//! An external REF base additionally needs a same-basis, typed client-have
//! proof; its bytes never enter the emitted selection or its resource totals.

use super::{
    Entry, MAX_ENTRIES, ReceivedPackCache, ReceivedPackPayload, ReceivedPackReceipt, check, intact,
};
use fgit_crypto::{DigestHasher, Sha1Hasher, Sha256Hasher};
use fgit_git_object::ObjectType;
use fgit_pack::{Deadline, PackError, PackLimits, PackOrderKey};
use fgit_types::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256};
use std::collections::BTreeMap;
use std::sync::Arc;

mod cover;

struct Candidate {
    entry: Arc<Entry>,
    // Sorted positions in the freshly authorized selection.
    positions: Vec<usize>,
}

pub(super) fn valid_request(
    keys: &[PackOrderKey],
    held: &[(GitOid, ObjectType)],
    limits: &PackLimits,
    live: &mut impl Deadline,
) -> Result<bool, PackError> {
    check(live)?;
    let Some(first) = keys.first() else {
        return Ok(false);
    };
    if keys.len() > limits.max_entries as usize {
        return Ok(false);
    }
    let format = first.id.algorithm();
    for (index, key) in keys.iter().enumerate() {
        check(live)?;
        if key.id.algorithm() != format
            || key.id.is_zero()
            || (index != 0 && keys[index - 1].id >= key.id)
        {
            return Ok(false);
        }
    }
    if held.len() > limits.max_entries as usize {
        return Ok(false);
    }
    for (index, (id, _)) in held.iter().enumerate() {
        check(live)?;
        if id.algorithm() != format || id.is_zero() || (index != 0 && held[index - 1].0 >= *id) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn select(
    cache: &ReceivedPackCache,
    keys: &[PackOrderKey],
    limits: &PackLimits,
    allow_ofs_delta: bool,
    held: &[(GitOid, ObjectType)],
    live: &mut impl Deadline,
) -> Result<Option<ReceivedPackPayload>, PackError> {
    if !valid_request(keys, held, limits, live)? {
        return Ok(None);
    }
    let format = keys[0].id.algorithm();
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
            || entry.wire.len() != entry.objects.len()
            || receipt.selective
            || receipt.source_pack_count != 1
            || receipt.external_base_count > receipt.ref_delta_count
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
    // Prefer the existing exact sender representation, then fewer sources,
    // then FIFO mask order. A warm exact hit does not allocate ownership or
    // queue metadata for the larger cover search. Verify bytes only for real
    // covers, lazily and at most once per source across every attempted cover.
    let mut integrity = [None; MAX_ENTRIES];
    for (index, candidate) in candidates.iter().enumerate() {
        check(live)?;
        if candidate.positions.len() != keys.len() {
            continue;
        }
        if let Some(pack) = materialize_cover(
            &candidates,
            1u64 << index,
            keys,
            held,
            limits,
            &mut integrity,
            live,
        )? {
            return Ok(Some(pack));
        }
    }
    let Some(choices) = cover::choices(&candidates, keys.len(), live)? else {
        return Ok(None);
    };
    for mask in choices {
        check(live)?;
        if let Some(pack) =
            materialize_cover(&candidates, mask, keys, held, limits, &mut integrity, live)?
        {
            return Ok(Some(pack));
        }
    }
    check(live)?;
    Ok(None)
}

/// A metadata-exact cover still needs every source integrity, graph and
/// envelope check. Failure leaves later choices available under the same
/// per-request integrity cache.
fn materialize_cover(
    candidates: &[Candidate],
    mask: u64,
    keys: &[PackOrderKey],
    held: &[(GitOid, ObjectType)],
    limits: &PackLimits,
    integrity: &mut [Option<bool>; MAX_ENTRIES],
    live: &mut impl Deadline,
) -> Result<Option<ReceivedPackPayload>, PackError> {
    let format = keys[0].id.algorithm();
    let source_count = mask.count_ones() as usize;
    let Some(mut receipt) = totals(candidates, mask, format, limits, live)? else {
        return Ok(None);
    };
    for (index, candidate) in candidates.iter().enumerate() {
        check(live)?;
        if mask & (1u64 << index) == 0 {
            continue;
        }
        let valid = if let Some(valid) = integrity[index] {
            valid
        } else {
            let valid = intact(&candidate.entry, live)?;
            integrity[index] = Some(valid);
            valid
        };
        if !valid {
            return Ok(None);
        }
    }
    let Some(graph) = graph_shape(candidates, mask, keys, held, limits, live)? else {
        return Ok(None);
    };
    receipt.maximum_delta_depth = graph.maximum_delta_depth;
    receipt.external_base_count = graph.external_base_count;
    let mut entries = Vec::new();
    if entries.try_reserve_exact(source_count).is_err() {
        return Ok(None);
    }
    for (index, candidate) in candidates.iter().enumerate() {
        if mask & (1u64 << index) != 0 {
            entries.push(Arc::clone(&candidate.entry));
        }
    }
    check(live)?;
    let header = if source_count == 1 {
        // Preserve the sender bytes/checksums without replacing the graph
        // accounting recomputed for this exact output and held-base proof.
        receipt.checksum = entries[0].receipt.checksum;
        receipt.sha256 = entries[0].receipt.sha256;
        None
    } else {
        Some(reframe(&entries, &mut receipt, format, live)?)
    };
    Ok(Some(ReceivedPackPayload {
        entries,
        receipt,
        header,
        selected: None,
        part: 0,
        offset: 0,
    }))
}

fn totals(
    candidates: &[Candidate],
    mask: u64,
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
        external_base_count: 0,
        selective: false,
    };
    let mut entry_bytes = 0usize;
    for (index, candidate) in candidates.iter().enumerate() {
        check(live)?;
        if mask & (1u64 << index) == 0 {
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

pub(super) fn filled<T: Clone>(count: usize, value: T) -> Option<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).ok()?;
    values.resize(count, value);
    Some(values)
}

pub(super) struct GraphShape {
    pub(super) maximum_delta_depth: usize,
    pub(super) external_base_count: usize,
}

/// Revalidate the complete output graph. An emitted base always takes
/// precedence over client-have membership, so a held ID cannot hide a cycle
/// or a wrong kind in the actual pack. Only unresolved REF parents may use
/// the caller's typed held proof; capture kept every OFS parent in its run.
fn graph_shape(
    candidates: &[Candidate],
    mask: u64,
    keys: &[PackOrderKey],
    held: &[(GitOid, ObjectType)],
    limits: &PackLimits,
    live: &mut impl Deadline,
) -> Result<Option<GraphShape>, PackError> {
    let edges = candidates
        .iter()
        .enumerate()
        .filter(|(index, _)| mask & (1u64 << index) != 0)
        .flat_map(|(_, candidate)| {
            candidate
                .positions
                .iter()
                .copied()
                .enumerate()
                .map(move |(local, position)| (position, candidate.entry.parents[local]))
        });
    selected_graph(keys, held, limits, edges, live)
}

/// Verify exactly one parent association for every freshly authorized key.
/// Complete-run and selective representations share this final graph check.
pub(super) fn selected_graph(
    keys: &[PackOrderKey],
    held: &[(GitOid, ObjectType)],
    limits: &PackLimits,
    edges: impl IntoIterator<Item = (usize, Option<GitOid>)>,
    live: &mut impl Deadline,
) -> Result<Option<GraphShape>, PackError> {
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
    let Some(mut external_roots) = filled(keys.len(), false) else {
        return Ok(None);
    };
    // At most one external-parent edge per emitted object. This map counts
    // fanout across every selected source, not each received pack separately.
    let mut external_fanout = BTreeMap::<GitOid, usize>::new();
    let mut chain = Vec::new();
    // Depth, not repository size, bounds the live ancestor stack.
    if chain
        .try_reserve_exact(keys.len().min(limits.max_delta_depth.saturating_add(1)))
        .is_err()
    {
        return Ok(None);
    }
    for (position, base) in edges {
        check(live)?;
        if position >= keys.len() || visits[position] != 0 {
            return Ok(None);
        }
        visits[position] = 1;
        let Some(base) = base else {
            continue;
        };
        match keys.binary_search_by_key(&base, |key| key.id) {
            Ok(parent) => {
                if keys[parent].object_type != keys[position].object_type {
                    return Ok(None);
                }
                parents[position] = Some(parent);
                fanout[parent] += 1;
                if fanout[parent] > limits.max_delta_fanout {
                    return Ok(None);
                }
            }
            Err(_) => {
                let Ok(parent) = held.binary_search_by_key(&base, |(id, _)| *id) else {
                    return Ok(None);
                };
                if held[parent].1 != keys[position].object_type {
                    return Ok(None);
                }
                external_roots[position] = true;
                let fanout = external_fanout.entry(base).or_default();
                *fanout += 1;
                if *fanout > limits.max_delta_fanout {
                    return Ok(None);
                }
            }
        }
    }
    if visits.iter().any(|seen| *seen != 1) {
        return Ok(None);
    }
    visits.fill(0);
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
                // Client-held objects are native roots: their private storage
                // encoding is neither known nor part of this emitted graph.
                None => usize::from(external_roots[index]),
            };
            if depth > limits.max_delta_depth {
                return Ok(None);
            }
            depths[index] = depth;
            visits[index] = 2;
            maximum = maximum.max(depth);
        }
    }
    Ok(Some(GraphShape {
        maximum_delta_depth: maximum,
        external_base_count: external_fanout.len(),
    }))
}

pub(super) enum NativeHasher {
    Sha1(Sha1Hasher),
    Sha256(Sha256Hasher),
}

impl NativeHasher {
    pub(super) fn new(format: GitHashAlgorithm) -> Self {
        match format {
            GitHashAlgorithm::Sha1 => Self::Sha1(Sha1Hasher::new()),
            GitHashAlgorithm::Sha256 => Self::Sha256(Sha256Hasher::new()),
        }
    }

    pub(super) fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(hash) => hash.update(bytes),
            Self::Sha256(hash) => hash.update(bytes),
        }
    }

    pub(super) fn finish(self) -> GitOid {
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

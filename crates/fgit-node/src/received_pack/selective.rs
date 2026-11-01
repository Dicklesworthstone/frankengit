//! Exact entry reuse from overlapping verified sender packs.
//!
//! Resolve representations outward from native or authorized held roots. Each
//! variant is queued at most once; its selected parent is fixed before it, so
//! chosen cycles are impossible. Depth, target identity and source FIFO order
//! close every tie. Fanout-constrained greedy misses use the native writer.

use super::composition::{NativeHasher, filled, selected_graph, valid_request};
use super::{
    Entry, HASH_CHUNK_BYTES, MAX_ENTRIES, ReceivedPackCache, ReceivedPackPayload,
    ReceivedPackReceipt, check, intact,
};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_git_object::ObjectType;
use fgit_pack::{Deadline, EntryKind, PackError, PackLimits, PackOrderKey};
use fgit_types::{GitHashAlgorithm, GitOid};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::Arc;

#[derive(Clone, Copy)]
enum Parent {
    Whole,
    Selected(usize),
    Held(usize),
}

struct Variant {
    target: usize,
    source: usize,
    local: usize,
    parent: Parent,
    next: usize,
}

#[derive(Clone, Copy)]
struct Choice {
    source: usize,
    local: usize,
}

// A native pack header needs at most ten bytes; a SHA-256 REF base needs32.
// Compressed data remains borrowed from the accounted sender allocation.
#[derive(Debug)]
pub(super) struct Piece {
    source: usize,
    local: usize,
    prefix: [u8; 42],
    prefix_len: u8,
}

impl Piece {
    fn new(source: usize, local: usize, entry: &Entry) -> Option<Self> {
        let span = &entry.wire[local];
        let mut piece = Self {
            source,
            local,
            prefix: [0; 42],
            prefix_len: 0,
        };
        if span.kind == EntryKind::OfsDelta {
            let parent = entry.parents[local]?;
            let original = entry.bytes.bytes().get(span.start..span.header_end)?;
            let length = original.len().checked_add(parent.as_bytes().len())?;
            if original.is_empty() || length > piece.prefix.len() {
                return None;
            }
            piece.prefix[..original.len()].copy_from_slice(original);
            piece.prefix[0] = (piece.prefix[0] & 0x8f) | 0x70;
            piece.prefix[original.len()..length].copy_from_slice(parent.as_bytes());
            piece.prefix_len = u8::try_from(length).ok()?;
        }
        Some(piece)
    }

    pub(super) fn part_bytes<'a>(&'a self, entries: &'a [Arc<Entry>], part: usize) -> &'a [u8] {
        if part == 0 {
            return &self.prefix[..usize::from(self.prefix_len)];
        }
        let entry = &entries[self.source];
        let span = &entry.wire[self.local];
        let start = if self.prefix_len == 0 {
            span.start
        } else {
            span.payload
        };
        &entry.bytes.bytes()[start..span.end]
    }
}

fn source_shape(entry: &Entry, format: GitHashAlgorithm) -> bool {
    let receipt = &entry.receipt;
    !entry.objects.is_empty()
        && entry.objects.len() == receipt.object_count as usize
        && entry.parents.len() == entry.objects.len()
        && entry.wire.len() == entry.objects.len()
        && !receipt.selective
        && receipt.source_pack_count == 1
        && receipt.external_base_count <= receipt.ref_delta_count
        && receipt.checksum.algorithm() == format
        && entry.bytes.format() == format
        && entry.bytes.checksum() == receipt.checksum
        && entry.bytes.bytes().len() == receipt.output_bytes
        && receipt.output_bytes >= 12 + format.digest_len()
}

fn wire_size(entry: &Entry, local: usize) -> Option<usize> {
    let span = &entry.wire[local];
    if span.kind == EntryKind::OfsDelta {
        span.header_end
            .checked_sub(span.start)?
            .checked_add(entry.parents[local]?.as_bytes().len())?
            .checked_add(span.end.checked_sub(span.payload)?)
    } else {
        span.end.checked_sub(span.start)
    }
}

fn variant(
    entry: &Entry,
    source: usize,
    local: usize,
    target: usize,
    keys: &[PackOrderKey],
    held: &[(GitOid, ObjectType)],
    limits: &PackLimits,
) -> Option<Variant> {
    let object = &entry.objects[local];
    let span = &entry.wire[local];
    if object.id != keys[target].id
        || object.kind != keys[target].object_type
        || object.bytes > limits.max_object_bytes
        || span.declared_size > limits.max_object_bytes
        || wire_size(entry, local)? > limits.max_input_bytes
    {
        return None;
    }
    let parent = match entry.parents[local] {
        None => Parent::Whole,
        Some(id) => match keys.binary_search_by_key(&id, |key| key.id) {
            // The actual emitted graph takes precedence over redundant haves.
            Ok(position) => {
                if keys[position].object_type != object.kind {
                    return None;
                }
                Parent::Selected(position)
            }
            Err(_) => {
                let position = held.binary_search_by_key(&id, |(id, _)| *id).ok()?;
                if held[position].1 != object.kind {
                    return None;
                }
                Parent::Held(position)
            }
        },
    };
    Some(Variant {
        target,
        source,
        local,
        parent,
        next: usize::MAX,
    })
}

/// Scratch is proportional to retained matching memberships and is dropped
/// before the output descriptors are allocated.
fn resolve(
    entries: &[Arc<Entry>],
    keys: &[PackOrderKey],
    held: &[(GitOid, ObjectType)],
    limits: &PackLimits,
    live: &mut impl Deadline,
) -> Result<Option<Vec<Choice>>, PackError> {
    let mut variants = Vec::new();
    for (source, entry) in entries.iter().enumerate() {
        check(live)?;
        if variants
            .try_reserve_exact(keys.len().min(entry.objects.len()))
            .is_err()
        {
            return Ok(None);
        }
        if keys.len() < entry.objects.len() {
            for (target, key) in keys.iter().enumerate() {
                check(live)?;
                if let Ok(local) = entry
                    .objects
                    .binary_search_by_key(&key.id, |object| object.id)
                    && let Some(candidate) =
                        variant(entry, source, local, target, keys, held, limits)
                {
                    variants.push(candidate);
                }
            }
        } else {
            for (local, object) in entry.objects.iter().enumerate() {
                check(live)?;
                if let Ok(target) = keys.binary_search_by_key(&object.id, |key| key.id)
                    && let Some(candidate) =
                        variant(entry, source, local, target, keys, held, limits)
                {
                    variants.push(candidate);
                }
            }
        }
    }
    // Retained eligible membership must cover every selected-object row before
    // per-key scratch is allocated. Final selection still checks exact coverage.
    if variants.len() < keys.len() {
        return Ok(None);
    }
    let Some(mut heads) = filled(keys.len(), usize::MAX) else {
        return Ok(None);
    };
    let Some(mut chosen) = filled(keys.len(), None::<Choice>) else {
        return Ok(None);
    };
    let Some(mut fanout) = filled(keys.len(), 0usize) else {
        return Ok(None);
    };
    let mut external = Vec::new();
    if external.try_reserve_exact(variants.len()).is_err() {
        return Ok(None);
    }
    for candidate in &variants {
        check(live)?;
        if let Parent::Held(parent) = candidate.parent {
            external.push(parent);
        }
    }
    external.sort_unstable();
    external.dedup();
    check(live)?;
    let Some(mut external_fanout) = filled(external.len(), 0usize) else {
        return Ok(None);
    };
    let mut ready = BinaryHeap::new();
    if ready.try_reserve_exact(variants.len()).is_err() {
        return Ok(None);
    }
    for (index, candidate) in variants.iter_mut().enumerate() {
        check(live)?;
        let depth = match candidate.parent {
            Parent::Whole => 0,
            Parent::Held(_) => 1,
            Parent::Selected(parent) => {
                candidate.next = heads[parent];
                heads[parent] = index;
                continue;
            }
        };
        ready.push(Reverse((
            depth,
            candidate.target,
            candidate.source,
            candidate.local,
            index,
        )));
    }
    let mut integrity = [None; MAX_ENTRIES];
    let mut count = 0usize;
    while let Some(Reverse((depth, target, source, local, index))) = ready.pop() {
        check(live)?;
        if chosen[target].is_some() || depth > limits.max_delta_depth {
            continue;
        }
        let external_slot = match variants[index].parent {
            Parent::Whole => None,
            Parent::Selected(parent) => {
                if fanout[parent] >= limits.max_delta_fanout {
                    continue;
                }
                None
            }
            Parent::Held(parent) => {
                let Ok(slot) = external.binary_search(&parent) else {
                    return Ok(None);
                };
                if external_fanout[slot] >= limits.max_delta_fanout {
                    continue;
                }
                Some(slot)
            }
        };
        // Establish full-source byte/association integrity before fixing a
        // target or releasing dependent variants; corrupt sources lose only
        // their own choices, leaving independently valid alternatives available.
        let valid = if let Some(valid) = integrity[source] {
            valid
        } else {
            let valid = intact(&entries[source], live)?;
            integrity[source] = Some(valid);
            valid
        };
        if !valid {
            continue;
        }
        chosen[target] = Some(Choice { source, local });
        match variants[index].parent {
            Parent::Selected(parent) => fanout[parent] += 1,
            Parent::Held(_) => {
                let Some(slot) = external_slot else {
                    return Ok(None);
                };
                external_fanout[slot] += 1;
            }
            Parent::Whole => {}
        }
        count += 1;
        if count == keys.len() {
            break;
        }
        let Some(next_depth) = depth.checked_add(1) else {
            return Ok(None);
        };
        let mut dependent = heads[target];
        while dependent != usize::MAX {
            check(live)?;
            let candidate = &variants[dependent];
            if chosen[candidate.target].is_none() && next_depth <= limits.max_delta_depth {
                ready.push(Reverse((
                    next_depth,
                    candidate.target,
                    candidate.source,
                    candidate.local,
                    dependent,
                )));
            }
            dependent = candidate.next;
        }
    }
    if count != keys.len() {
        return Ok(None);
    }
    let mut result = Vec::new();
    if result.try_reserve_exact(keys.len()).is_err() {
        return Ok(None);
    }
    for choice in chosen {
        check(live)?;
        let Some(choice) = choice else {
            return Ok(None);
        };
        result.push(choice);
    }
    check(live)?;
    Ok(Some(result))
}

pub(super) fn select(
    cache: &ReceivedPackCache,
    keys: &[PackOrderKey],
    limits: &PackLimits,
    held: &[(GitOid, ObjectType)],
    live: &mut impl Deadline,
) -> Result<Option<ReceivedPackPayload>, PackError> {
    if !valid_request(keys, held, limits, live)? {
        return Ok(None);
    }
    let format = keys[0].id.algorithm();
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
        snapshot.extend(
            state
                .entries
                .iter()
                .filter(|entry| source_shape(entry, format))
                .map(Arc::clone),
        );
    }
    let Some(mut choices) = resolve(&snapshot, keys, held, limits, live)? else {
        return Ok(None);
    };
    let edges = choices
        .iter()
        .enumerate()
        .map(|(position, choice)| (position, snapshot[choice.source].parents[choice.local]));
    let Some(graph) = selected_graph(keys, held, limits, edges, live)? else {
        return Ok(None);
    };
    let mut receipt = ReceivedPackReceipt {
        checksum: snapshot[choices[0].source].receipt.checksum,
        sha256: [0; 32],
        object_count: u32::try_from(keys.len()).map_err(|_| PackError::IntegerOverflow {
            context: "selected pack count",
        })?,
        ofs_delta_count: 0,
        ref_delta_count: 0,
        total_object_bytes: 0,
        output_bytes: 12 + format.digest_len(),
        maximum_delta_depth: graph.maximum_delta_depth,
        source_pack_count: 0,
        external_base_count: graph.external_base_count,
        selective: true,
    };
    let mut used = [false; MAX_ENTRIES];
    let mut expanded = 0usize;
    for choice in &choices {
        check(live)?;
        let entry = &snapshot[choice.source];
        let Some(objects) = receipt
            .total_object_bytes
            .checked_add(entry.objects[choice.local].bytes)
        else {
            return Ok(None);
        };
        let Some(programs) = expanded.checked_add(entry.wire[choice.local].declared_size) else {
            return Ok(None);
        };
        let Some(output) =
            wire_size(entry, choice.local).and_then(|size| receipt.output_bytes.checked_add(size))
        else {
            return Ok(None);
        };
        if objects > limits.max_total_expanded_bytes
            || programs > limits.max_total_expanded_bytes
            || output > limits.max_input_bytes
        {
            return Ok(None);
        }
        receipt.total_object_bytes = objects;
        receipt.output_bytes = output;
        expanded = programs;
        receipt.ref_delta_count += usize::from(entry.parents[choice.local].is_some());
        used[choice.source] = true;
    }
    receipt.source_pack_count = used.iter().filter(|used| **used).count();
    let mut entries = Vec::new();
    if entries
        .try_reserve_exact(receipt.source_pack_count)
        .is_err()
    {
        return Ok(None);
    }
    let mut remap = [usize::MAX; MAX_ENTRIES];
    for (source, entry) in snapshot.iter().enumerate() {
        check(live)?;
        if used[source] {
            remap[source] = entries.len();
            entries.push(Arc::clone(entry));
        }
    }
    choices.sort_unstable_by_key(|choice| {
        (
            choice.source,
            snapshot[choice.source].wire[choice.local].start,
        )
    });
    check(live)?;
    let Some(parts) = choices
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
    else {
        return Ok(None);
    };
    let mut pieces = Vec::new();
    if pieces.try_reserve_exact(choices.len()).is_err() {
        return Ok(None);
    }
    for choice in choices {
        check(live)?;
        let Some(piece) = Piece::new(remap[choice.source], choice.local, &snapshot[choice.source])
        else {
            return Ok(None);
        };
        pieces.push(piece);
    }
    let mut header = [0; 12];
    header[..4].copy_from_slice(b"PACK");
    header[4..8].copy_from_slice(&2u32.to_be_bytes());
    header[8..].copy_from_slice(&receipt.object_count.to_be_bytes());
    let mut payload = ReceivedPackPayload {
        entries,
        receipt,
        header: Some(header),
        selected: Some(pieces),
        part: 0,
        offset: 0,
    };
    let mut native = NativeHasher::new(format);
    let mut strong = Sha256Hasher::new();
    for part in 0..parts {
        check(live)?;
        let Some(bytes) = payload.part_bytes(part) else {
            return Ok(None);
        };
        for chunk in bytes.chunks(HASH_CHUNK_BYTES) {
            check(live)?;
            native.update(chunk);
            strong.update(chunk);
        }
    }
    payload.receipt.checksum = native.finish();
    strong.update(payload.receipt.checksum.as_bytes());
    payload.receipt.sha256 = strong.finish();
    check(live)?;
    Ok(Some(payload))
}

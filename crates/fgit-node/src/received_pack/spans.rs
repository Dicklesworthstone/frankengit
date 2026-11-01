//! Bind per-entry wire spans to the original, natively verified allocation.

use super::{VerifiedReceivedObject, check};
use fgit_pack::{
    Deadline, EntryKind, PackError, PackLimits, ParsedDeltaBase, QuarantinedPack,
    decode_entry_header, parse_delta_base,
};
use fgit_types::GitOid;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug)]
pub(super) struct WireEntry {
    pub(super) start: usize,
    pub(super) header_end: usize,
    pub(super) payload: usize,
    pub(super) end: usize,
    pub(super) declared_size: usize,
    pub(super) kind: EntryKind,
}

pub(super) fn kind_code(kind: EntryKind) -> u8 {
    match kind {
        EntryKind::Commit => 1,
        EntryKind::Tree => 2,
        EntryKind::Blob => 3,
        EntryKind::Tag => 4,
        EntryKind::OfsDelta => 6,
        EntryKind::RefDelta => 7,
    }
}

fn optional<T>(result: Result<T, PackError>) -> Result<Option<T>, PackError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(PackError::DeadlineExceeded) => Err(PackError::DeadlineExceeded),
        Err(_) => Ok(None),
    }
}

pub(super) fn capture(
    pack: &QuarantinedPack,
    objects: &[VerifiedReceivedObject],
    ids: &BTreeMap<u64, GitOid>,
    limits: &PackLimits,
    live: &mut impl Deadline,
) -> Result<Option<Vec<WireEntry>>, PackError> {
    check(live)?;
    let Some(retained) = pack.retained_bytes() else {
        return Ok(None);
    };
    let raw = retained.bytes();
    let Some(trailer) = raw.len().checked_sub(pack.format.digest_len()) else {
        return Ok(None);
    };
    let empty = WireEntry {
        start: 0,
        header_end: 0,
        payload: 0,
        end: 0,
        declared_size: 0,
        kind: EntryKind::Blob,
    };
    let mut wire = Vec::new();
    if wire.try_reserve_exact(objects.len()).is_err() {
        return Ok(None);
    }
    wire.resize(objects.len(), empty);
    let mut previous_end = 12;
    for (ordinal, entry) in pack.entries().iter().enumerate() {
        check(live)?;
        let Ok(start) = usize::try_from(entry.offset) else {
            return Ok(None);
        };
        let end = match pack.entries().get(ordinal + 1) {
            Some(next) => match usize::try_from(next.offset) {
                Ok(offset) => offset,
                Err(_) => return Ok(None),
            },
            None => trailer,
        };
        if start != previous_end || start >= end || end > trailer {
            return Ok(None);
        }
        let Some(bytes) = raw.get(start..end) else {
            return Ok(None);
        };
        let Some((header, length)) = optional(decode_entry_header(bytes, limits, live))? else {
            return Ok(None);
        };
        if header != entry.header {
            return Ok(None);
        }
        let Some(header_end) = start.checked_add(length) else {
            return Ok(None);
        };
        let parsed = match header.kind {
            EntryKind::OfsDelta | EntryKind::RefDelta => {
                let Some(parsed) = optional(parse_delta_base(
                    header.kind,
                    entry.offset,
                    &raw[header_end..end],
                    pack.format,
                    live,
                ))?
                else {
                    return Ok(None);
                };
                Some(parsed)
            }
            _ => None,
        };
        if parsed != entry.delta_base {
            return Ok(None);
        }
        let base_bytes = match parsed {
            Some(ParsedDeltaBase::Ofs { consumed, .. } | ParsedDeltaBase::Ref { consumed, .. }) => {
                consumed
            }
            None => 0,
        };
        let Some(payload) = header_end.checked_add(base_bytes) else {
            return Ok(None);
        };
        if payload >= end {
            return Ok(None);
        }
        let Some(id) = ids.get(&entry.offset) else {
            return Ok(None);
        };
        let Ok(local) = objects.binary_search_by_key(id, |object| object.id) else {
            return Ok(None);
        };
        if wire[local].end != 0 {
            return Ok(None);
        }
        wire[local] = WireEntry {
            start,
            header_end,
            payload,
            end,
            declared_size: header.declared_size,
            kind: header.kind,
        };
        previous_end = end;
    }
    if previous_end != trailer || wire.iter().any(|span| span.end == 0) {
        return Ok(None);
    }
    check(live)?;
    Ok(Some(wire))
}

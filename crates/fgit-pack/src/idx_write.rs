//! Standard idx-v2 construction over exact pack byte ranges and resolved IDs.
//! This is an interchange writer, not a substitute for native object/graph
//! validation. Callers must obtain the complete location table from their
//! bounded pack resolver; CRCs and trailers alone do not authenticate that map.
use crate::{
    Deadline, IdxEntry, IdxV2, NativeChecksumVerifier, ObjectFormat, ObjectId, PackError,
    PackLimits, checkpoint, parse_pack_header, split_pack_trailer, validate_idx_checksum,
    validate_object_count, validate_pack_trailer,
};
use fgit_crypto::DigestHasher;

/// A native-validated identity joined to the exact range and CRC delivered by
/// the streaming pack reader. The association between ID and decoded body is
/// established by the caller's object/delta verifier, never inferred from CRC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamPackIndexEntry {
    pub oid: ObjectId,
    pub pack_offset: u64,
    pub end_offset: u64,
    pub crc32: u32,
}

/// Build the same deterministic idx-v2 bytes from a verified streaming receipt
/// and native-validated object rows, without re-reading or retaining the pack.
///
/// Rows may arrive in any order. Besides count/domain/range/duplicate checks,
/// their exact offsets, ends and CRCs must reproduce the reader's private
/// framing commitment. Mixing metadata from another stream fails closed.
pub fn build_streamed_pack_index_v2(
    receipt: &crate::StreamPackReceipt,
    locations: &[StreamPackIndexEntry],
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<Vec<u8>, PackError> {
    checkpoint(deadline)?;
    let maximum = limits.max_index_entries.min(limits.max_entries as usize);
    if locations.len() > maximum {
        return Err(PackError::EntryCountLimit {
            actual: u32::try_from(locations.len()).unwrap_or(u32::MAX),
            limit: u32::try_from(maximum).unwrap_or(u32::MAX),
        });
    }
    limits.input(
        usize::try_from(receipt.pack_bytes()).map_err(|_| PackError::InputLimit {
            actual: usize::MAX,
            limit: limits.max_input_bytes,
        })?,
    )?;
    validate_object_count(
        receipt.header(),
        u32::try_from(locations.len()).map_err(|_| PackError::IntegerOverflow {
            context: "streamed index count",
        })?,
    )?;
    let body_end = receipt
        .pack_bytes()
        .checked_sub(receipt.format().digest_len() as u64)
        .ok_or(PackError::Truncated {
            context: "streamed pack trailer",
        })?;
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(locations.len())
        .map_err(|_| PackError::AllocationFailed {
            requested: locations.len(),
        })?;
    ordered.extend_from_slice(locations);
    ordered.sort_unstable_by_key(|row| row.pack_offset);
    checkpoint(deadline)?;
    let mut expected = 12;
    let mut framing = crate::stream::framing_hasher();
    let mut rows = Vec::new();
    rows.try_reserve_exact(ordered.len())
        .map_err(|_| PackError::AllocationFailed {
            requested: ordered.len(),
        })?;
    for row in ordered {
        checkpoint(deadline)?;
        if row.oid.algorithm() != receipt.format() {
            return Err(PackError::ObjectFormatMismatch {
                expected: receipt.format(),
                actual: row.oid.algorithm(),
            });
        }
        if row.oid.is_zero() {
            return Err(PackError::NativeObjectIdMismatch);
        }
        if row.pack_offset != expected
            || row.end_offset <= row.pack_offset
            || row.end_offset > body_end
        {
            return Err(PackError::InvalidIndexOrdering);
        }
        expected = row.end_offset;
        crate::stream::framing_row(&mut framing, row.pack_offset, row.end_offset, row.crc32);
        rows.push(IdxEntry {
            oid: row.oid,
            crc32: row.crc32,
            pack_offset: row.pack_offset,
        });
    }
    if expected != body_end {
        return Err(PackError::TrailingPackData);
    }
    if framing.finish() != receipt.framing_sha256 {
        return Err(PackError::IndexChecksumMismatch);
    }
    encode_rows(
        receipt.format(),
        rows,
        receipt.trailer().as_bytes(),
        limits,
        deadline,
    )
}

/// Build a deterministic idx-v2 for an already resolved pack without repacking.
///
/// Rows may arrive in any order. Duplicate IDs/offsets, wrong native domains,
/// incomplete counts and invalid ranges refuse. The first range must start at
/// the pack's first entry; the last ends before its native trailer. CRCs cover
/// exact encoded entries, including delta headers. Large offsets use the idx-v2
/// indirection table. Output and scratch counts are bounded before allocation.
///
/// This validates framing coordinates and checksums, NOT the caller's claim
/// that an ID resolves at an offset. The native quarantine/graph boundary must
/// establish that association before this derived index is used for recovery.
pub fn build_pack_index_v2(
    pack: &[u8],
    format: ObjectFormat,
    locations: &[(ObjectId, u64)],
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<Vec<u8>, PackError> {
    checkpoint(deadline)?;
    let maximum = limits.max_index_entries.min(limits.max_entries as usize);
    if locations.len() > maximum {
        return Err(PackError::EntryCountLimit {
            actual: u32::try_from(locations.len()).unwrap_or(u32::MAX),
            limit: u32::try_from(maximum).unwrap_or(u32::MAX),
        });
    }
    validate_pack_trailer(pack, format, limits, &NativeChecksumVerifier)?;
    checkpoint(deadline)?;
    let (body, trailer) = split_pack_trailer(pack, format, limits)?;
    let header = parse_pack_header(body, limits)?;
    validate_object_count(
        header,
        u32::try_from(locations.len()).map_err(|_| PackError::IntegerOverflow {
            context: "recovery index count",
        })?,
    )?;
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(locations.len())
        .map_err(|_| PackError::AllocationFailed {
            requested: locations.len(),
        })?;
    ordered.extend_from_slice(locations);
    ordered.sort_unstable_by_key(|row| row.1);
    checkpoint(deadline)?;
    if ordered.first().is_some_and(|row| row.1 != 12) || (ordered.is_empty() && body.len() != 12) {
        return Err(PackError::TrailingPackData);
    }
    let table = crate::stream::CRC_TABLE;
    let mut rows = Vec::new();
    rows.try_reserve_exact(ordered.len())
        .map_err(|_| PackError::AllocationFailed {
            requested: ordered.len(),
        })?;
    for (i, &(id, offset)) in ordered.iter().enumerate() {
        checkpoint(deadline)?;
        if id.algorithm() != format {
            return Err(PackError::ObjectFormatMismatch {
                expected: format,
                actual: id.algorithm(),
            });
        }
        if id.is_zero() {
            return Err(PackError::NativeObjectIdMismatch);
        }
        let end = ordered.get(i + 1).map_or(body.len() as u64, |row| row.1);
        if end == offset {
            return Err(PackError::DuplicateObjectOffset(offset));
        }
        let start = usize::try_from(offset).map_err(|_| PackError::InvalidOfsDelta)?;
        let end = usize::try_from(end).map_err(|_| PackError::InvalidOfsDelta)?;
        let entry = body
            .get(start..end)
            .filter(|bytes| !bytes.is_empty())
            .ok_or(PackError::InvalidOfsDelta)?;
        let mut crc = u32::MAX;
        for chunk in entry.chunks(65_536) {
            checkpoint(deadline)?;
            for &byte in chunk {
                crc = table[((crc ^ u32::from(byte)) & 255) as usize] ^ (crc >> 8);
            }
        }
        rows.push(IdxEntry {
            oid: id,
            crc32: !crc,
            pack_offset: offset,
        });
    }
    encode_rows(format, rows, trailer, limits, deadline)
}

fn encode_rows(
    format: ObjectFormat,
    mut rows: Vec<IdxEntry>,
    trailer: &[u8],
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<Vec<u8>, PackError> {
    let width = format.digest_len();
    let large_count = rows
        .iter()
        .filter(|row| row.pack_offset >= 0x8000_0000)
        .count();
    let size = rows
        .len()
        .checked_mul(width + 8)
        .and_then(|n| n.checked_add(1032 + width * 2))
        .and_then(|n| n.checked_add(large_count.checked_mul(8)?))
        .ok_or(PackError::IntegerOverflow {
            context: "recovery index bytes",
        })?;
    limits.input(size)?;
    rows.sort_unstable_by(|a, b| a.oid.as_bytes().cmp(b.oid.as_bytes()));
    checkpoint(deadline)?;
    if rows.windows(2).any(|pair| pair[0].oid == pair[1].oid) {
        return Err(PackError::DuplicateObjectId);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(size)
        .map_err(|_| PackError::AllocationFailed { requested: size })?;
    output.extend_from_slice(b"\xfftOc\0\0\0\x02");
    let mut fanout = [0_u32; 256];
    for row in &rows {
        checkpoint(deadline)?;
        fanout[usize::from(row.oid.as_bytes()[0])] += 1;
    }
    let mut cumulative = 0_u32;
    for count in fanout {
        cumulative += count;
        output.extend_from_slice(&cumulative.to_be_bytes());
    }
    for row in &rows {
        checkpoint(deadline)?;
        output.extend_from_slice(row.oid.as_bytes());
    }
    for row in &rows {
        checkpoint(deadline)?;
        output.extend_from_slice(&row.crc32.to_be_bytes());
    }
    let mut large_ordinal = 0_u32;
    for row in &rows {
        checkpoint(deadline)?;
        let word = if row.pack_offset < 0x8000_0000 {
            u32::try_from(row.pack_offset).map_err(|_| PackError::InvalidOfsDelta)?
        } else {
            if large_ordinal >= 0x8000_0000 {
                return Err(PackError::InvalidOfsDelta);
            }
            let word = large_ordinal | 0x8000_0000;
            large_ordinal += 1;
            word
        };
        output.extend_from_slice(&word.to_be_bytes());
    }
    for row in &rows {
        checkpoint(deadline)?;
        if row.pack_offset >= 0x8000_0000 {
            output.extend_from_slice(&row.pack_offset.to_be_bytes());
        }
    }
    output.extend_from_slice(trailer);
    checkpoint(deadline)?;
    match format {
        ObjectFormat::Sha1 => {
            let sum = fgit_crypto::sha1_digest(&output);
            output.extend_from_slice(&sum);
        }
        ObjectFormat::Sha256 => {
            let sum = fgit_crypto::sha256_digest(&output);
            output.extend_from_slice(&sum);
        }
    }
    checkpoint(deadline)?;
    // Cross-check with the existing native reader, not a second decoder.
    IdxV2::parse(&output, format, limits, deadline)?;
    validate_idx_checksum(&output, format, limits, &NativeChecksumVerifier)?;
    checkpoint(deadline)?;
    Ok(output)
}

#[cfg(test)]
mod tests;

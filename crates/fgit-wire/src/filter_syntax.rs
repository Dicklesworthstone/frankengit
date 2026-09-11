//! Bounded Git filter grammar, including percent-encoded compound filters.
use super::*;

const MAX_FILTER_NESTING: usize = 32;

pub(super) fn parse(
    text: &[u8],
    format: GitObjectFormat,
    limits: &WireLimits,
) -> Result<ObjectFilter, WireError> {
    if text.len() > limits.max_packet_bytes {
        return Err(WireError::PacketTooLarge {
            declared: text.len(),
            limit: limits.max_packet_bytes,
        });
    }
    let mut remaining = limits.max_filter_parts;
    parse_part(text, format, limits, 0, &mut remaining)
}

fn invalid(text: &[u8]) -> WireError {
    WireError::InvalidFilter {
        filter: text.to_vec(),
    }
}
fn parts_limit(limits: &WireLimits) -> WireError {
    WireError::TooManyFilterParts {
        limit: limits.max_filter_parts,
    }
}

fn parse_part(
    text: &[u8],
    format: GitObjectFormat,
    limits: &WireLimits,
    depth: usize,
    remaining: &mut usize,
) -> Result<ObjectFilter, WireError> {
    if depth > MAX_FILTER_NESTING || depth > limits.max_filter_parts {
        return Err(parts_limit(limits));
    }
    if let Some(compound) = text.strip_prefix(b"combine:") {
        if compound.is_empty() {
            return Err(invalid(text));
        }
        let mut parts = Vec::new();
        for encoded in compound.split(|byte| *byte == b'+') {
            if encoded.is_empty() {
                return Err(invalid(text));
            }
            if *remaining == 0 {
                return Err(parts_limit(limits));
            }
            let decoded = decode_part(encoded)?;
            let part = parse_part(&decoded, format, limits, depth + 1, remaining)?;
            parts
                .try_reserve(1)
                .map_err(|_| WireError::AllocationFailure)?;
            parts.push(part);
        }
        return Ok(ObjectFilter::Combine(parts));
    }
    *remaining = remaining
        .checked_sub(1)
        .ok_or_else(|| parts_limit(limits))?;
    if text == b"blob:none" {
        return Ok(ObjectFilter::BlobNone);
    }
    if let Some(value) = text.strip_prefix(b"blob:limit=") {
        return scaled_size(value)
            .map(ObjectFilter::BlobLimit)
            .ok_or_else(|| invalid(text));
    }
    if let Some(value) = text.strip_prefix(b"tree:") {
        return parse_unsigned(value)
            .ok()
            .and_then(|value| u32::try_from(value).ok())
            .map(ObjectFilter::TreeDepth)
            .ok_or_else(|| invalid(text));
    }
    if let Some(value) = text.strip_prefix(b"sparse:oid=") {
        return parse_object_id(value, format).map(ObjectFilter::SparseObject);
    }
    if let Some(value) = text.strip_prefix(b"sparse:path=") {
        validate_opaque_path(value, limits)?;
        return Ok(ObjectFilter::SparsePath(value.to_vec()));
    }
    Err(invalid(text))
}

fn scaled_size(value: &[u8]) -> Option<u64> {
    let (&last, prefix) = value.split_last()?;
    let (digits, scale) = match last {
        b'k' | b'K' => (prefix, 1024_u64),
        b'm' | b'M' => (prefix, 1024_u64.pow(2)),
        b'g' | b'G' => (prefix, 1024_u64.pow(3)),
        _ => (value, 1),
    };
    parse_unsigned(digits).ok()?.checked_mul(scale)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
fn decode_part(encoded: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(encoded.len())
        .map_err(|_| WireError::AllocationFailure)?;
    let mut offset = 0;
    while offset < encoded.len() {
        let byte = encoded[offset];
        if byte == b'%' {
            let high = encoded.get(offset + 1).and_then(|byte| hex(*byte));
            let low = encoded.get(offset + 2).and_then(|byte| hex(*byte));
            let (Some(high), Some(low)) = (high, low) else {
                return Err(invalid(encoded));
            };
            decoded.push((high << 4) | low);
            offset += 3;
        } else {
            if byte <= b' ' || b"~!@#$^&*()[]{}\\;\",<>?'`".contains(&byte) {
                return Err(invalid(encoded));
            }
            decoded.push(byte);
            offset += 1;
        }
    }
    Ok(decoded)
}

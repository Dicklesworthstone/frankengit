//! Bounded shallow-update framing for adapters that opt into resolved updates.
use std::collections::BTreeSet;
use super::*;

pub(super) fn has_controls(request: &PackRequest) -> bool {
    !request.shallows.is_empty() || changes_boundary(request)
}

pub(super) fn changes_boundary(request: &PackRequest) -> bool {
    request.deepen.is_some() || request.deepen_since.is_some() || !request.deepen_not.is_empty()
}

pub(super) fn response(
    repository: &impl UploadPackRepository,
    request: &PackRequest,
    limits: &WireLimits,
) -> Result<Vec<Packet>, WireError> {
    if !repository.supports_shallow() { return Err(WireError::PackSourceRefused); }
    if request.shallows.len() > limits.max_shallows {
        return Err(WireError::TooManyObjectIds { field: "shallow", limit: limits.max_shallows });
    }
    let update = repository.shallow_update(request)?;
    if update.shallow.len() > limits.max_shallows || update.unshallow.len() > limits.max_shallows {
        return Err(WireError::TooManyObjectIds { field: "shallow update", limit: limits.max_shallows });
    }
    let old: BTreeSet<_> = request.shallows.iter().copied().collect();
    let mut shallow = BTreeSet::new();
    for (values, removing) in [(&update.shallow, false), (&update.unshallow, true)] {
        let mut previous = None;
        for &id in values {
            if id.algorithm() != repository.object_format() {
                return Err(WireError::ObjectFormatMismatch {
                    expected: repository.object_format(), observed: id.algorithm(),
                });
            }
            if previous.is_some_and(|prior| prior >= id) || !repository.contains_want(id) {
                return Err(WireError::PackSourceRefused);
            }
            if removing {
                if !old.contains(&id) || shallow.contains(&id) { return Err(WireError::PackSourceRefused); }
            } else {
                shallow.insert(id);
            }
            previous = Some(id);
        }
    }
    if !changes_boundary(request) && (!update.shallow.is_empty() || !update.unshallow.is_empty()) {
        return Err(WireError::PackSourceRefused);
    }
    let legacy = request.version != UploadPackVersion::V2;
    if legacy && !changes_boundary(request) { return Ok(Vec::new()); }
    let mut output = Vec::new();
    let mut used = 0;
    if !legacy {
        let line = b"shallow-info\n";
        add_output_packet(&mut output, line_packet(line), line.len() + 4, &mut used, limits)?;
    }
    for (keyword, values) in [("shallow", &update.shallow), ("unshallow", &update.unshallow)] {
        for &id in values {
            let line = format!("{keyword} {}\n", oid_hex(id));
            let bytes = line.len() + 4;
            if bytes > limits.max_packet_bytes {
                return Err(WireError::PacketTooLarge { declared: bytes, limit: limits.max_packet_bytes });
            }
            add_output_packet(&mut output, line_packet(line.into_bytes()), bytes, &mut used, limits)?;
        }
    }
    add_output_packet(
        &mut output,
        if legacy { Packet::Flush } else { Packet::Delimiter },
        4,
        &mut used,
        limits,
    )?;
    Ok(output)
}

//! Bounded protocol-v2 object-info size queries (Git 2.54 profile).
//!
//! Native object metadata is read only after disclosure authorization. Missing
//! and hidden objects have the same empty value, and every response is assembled
//! completely before its first packet can escape the command machine.

use crate::{
    AnyGitOid, GitObjectFormat, Packet, Transition, UploadPackRepository, WireError, WireEvent,
    WireLimits, add_output_packet, oid_hex, parse_object_id,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct ObjectInfoRequest {
    // Unlike want/have sets, object-info echoes every OID in request order.
    // Repeated IDs count against both the input and output resource ceilings.
    objects: Vec<AnyGitOid>,
    size: bool,
}

impl ObjectInfoRequest {
    pub(crate) fn accept(
        &mut self,
        line: &[u8],
        format: GitObjectFormat,
        limits: &WireLimits,
    ) -> Result<(), WireError> {
        if line == b"size" {
            self.size = true;
            return Ok(());
        }
        let Some(value) = line.strip_prefix(b"oid ") else {
            return Err(WireError::MalformedRequestLine {
                line: line.to_vec(),
            });
        };
        let oid = parse_object_id(value, format)?;
        if self.objects.len() >= limits.max_wants {
            return Err(WireError::TooManyObjectIds {
                field: "object-info oid",
                limit: limits.max_wants,
            });
        }
        self.objects
            .try_reserve(1)
            .map_err(|_| WireError::AllocationFailure)?;
        self.objects.push(oid);
        Ok(())
    }

    pub(crate) fn finish(
        &self,
        repository: &impl UploadPackRepository,
        limits: &WireLimits,
    ) -> Result<Transition, WireError> {
        if !repository.supports_object_info() {
            return Err(WireError::PackSourceRefused);
        }
        repository.object_info_checkpoint()?;
        let mut output = Vec::new();
        let mut used_bytes = 0;
        if self.size && !self.objects.is_empty() {
            // Git 2.54's protocol-caps.c writes these textual payloads without
            // a trailing LF; pkt-line framing supplies their exact boundaries.
            append(&mut output, b"size".to_vec(), &mut used_bytes, limits)?;
        }
        for &oid in &self.objects {
            repository.object_info_checkpoint()?;
            let mut line = oid_hex(oid).into_bytes();
            if self.size {
                line.push(b' ');
                // Do not look up a hidden object, even when the storage layer
                // happens to contain it. Unknown and hidden rows are identical.
                if repository.contains_want(oid)
                    && let Some(size) = repository.object_info_size(oid)?
                {
                    line.extend_from_slice(size.to_string().as_bytes());
                }
            }
            append(&mut output, line, &mut used_bytes, limits)?;
        }
        repository.object_info_checkpoint()?;
        add_output_packet(&mut output, Packet::Flush, 4, &mut used_bytes, limits)?;
        Ok(Transition {
            output,
            events: vec![WireEvent::ObjectInfo {
                object_count: self.objects.len(),
                size: self.size,
            }],
        })
    }
}

fn append(
    output: &mut Vec<Packet>,
    line: Vec<u8>,
    used_bytes: &mut usize,
    limits: &WireLimits,
) -> Result<(), WireError> {
    let bytes = line.len() + 4;
    if bytes > limits.max_packet_bytes {
        return Err(WireError::PacketTooLarge {
            declared: bytes,
            limit: limits.max_packet_bytes,
        });
    }
    add_output_packet(output, Packet::Data(line), bytes, used_bytes, limits)
}

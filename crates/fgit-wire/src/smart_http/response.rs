//! Pull-driven native Git response bodies for an authenticated HTTP gateway.
//!
//! The caller writes each returned chunk before asking for another. The pack
//! producer is borrowed: a gateway still owns its runtime region, cancellation,
//! deadlines and drain obligations. A transport write failure must call `abort`
//! and close the HTTP stream; it must never append a successful HTTP terminator.

use super::ProtocolVersion;
use super::rpc::{RpcError, UploadReply};
use crate::receive::ReceiveCancellation;
use crate::{PackPayloadSource, Packet, WireError, WireLimits, encode_packet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Prefix,
    Pack,
    Flush,
    Complete,
    Failed,
}

/// A bounded Git body, not an HTTP encoder or canonical publication receipt.
/// Feed its chunks to `super::ResponseEncoder` and finish that encoder only
/// after this producer returns `Ok(None)`. Prefix, sideband headers, payloads
/// and the final Git flush all consume one aggregate body-byte budget.
pub struct UploadResponse<'source, Source: PackPayloadSource + ?Sized> {
    prefix: Vec<u8>,
    prefix_offset: usize,
    source: Option<&'source mut Source>,
    phase: Phase,
    limits: WireLimits,
    maximum_chunk_bytes: usize,
    maximum_response_bytes: u64,
    emitted_bytes: u64,
    sideband: bool,
    wants_pack: bool,
    saw_pack_bytes: bool,
}

impl UploadReply {
    /// Bind exactly the pack requested by this complete HTTP RPC. The source
    /// must be selected from the same authorized immutable repository view.
    /// It retains responsibility for pack identity, checksums and closure.
    pub fn into_response<'source, Source: PackPayloadSource + ?Sized>(
        self,
        source: Option<&'source mut Source>,
        limits: WireLimits,
        maximum_response_bytes: u64,
    ) -> Result<UploadResponse<'source, Source>, RpcError> {
        limits.validate()?;
        let wants_pack = self.pack_request.is_some();
        match (wants_pack, source.is_some()) {
            (true, false) => return Err(RpcError::MissingPack),
            (false, true) => return Err(RpcError::UnexpectedPack),
            _ => {}
        }
        let sideband = self.pack_request.as_ref().is_some_and(|request| {
            self.version == ProtocolVersion::V2 || request.options.sideband_64k()
        });
        // A producer sees at most one packet's worth of native bytes per poll.
        let maximum_chunk_bytes = limits
            .max_packet_bytes
            .checked_sub(5)
            .filter(|count| *count != 0)
            .ok_or(WireError::InvalidLimit {
                field: "max_packet_bytes for HTTP pack response",
            })?;
        if self.prefix.len() > limits.max_outbound_bytes {
            return Err(RpcError::OutputLimit);
        }
        let minimum = (self.prefix.len() as u64)
            .checked_add(if sideband { 4 } else { 0 })
            .ok_or(RpcError::OutputLimit)?;
        if minimum > maximum_response_bytes {
            return Err(RpcError::OutputLimit);
        }
        Ok(UploadResponse {
            prefix: self.prefix,
            prefix_offset: 0,
            source,
            phase: Phase::Prefix,
            limits,
            maximum_chunk_bytes,
            maximum_response_bytes,
            emitted_bytes: 0,
            sideband,
            wants_pack,
            saw_pack_bytes: false,
        })
    }
}

impl<Source: PackPayloadSource + ?Sized> UploadResponse<'_, Source> {
    /// Bytes released for the host to write, not a socket delivery receipt.
    #[must_use]
    pub const fn emitted_bytes(&self) -> u64 {
        self.emitted_bytes
    }

    /// Explicitly poison the response after a transport write failure. This
    /// releases the source borrow but does not discharge its owner's runtime
    /// obligations. No later poll can produce a successful Git trailer.
    pub fn abort(&mut self) {
        self.phase = Phase::Failed;
        self.prefix = Vec::new();
        self.source = None;
    }

    /// Pull one bounded body chunk with cooperative cancellation. The pack
    /// source is never polled while prefix bytes are still pending and is not
    /// polled again until the caller requests another chunk.
    pub fn next_chunk<C: ReceiveCancellation>(
        &mut self,
        cancellation: &mut C,
    ) -> Result<Option<Vec<u8>>, RpcError> {
        let previously_emitted = self.emitted_bytes;
        let result = self.next_inner(cancellation);
        if result.is_err() {
            self.emitted_bytes = previously_emitted;
            self.abort();
        }
        result
    }

    fn next_inner<C: ReceiveCancellation>(
        &mut self,
        cancellation: &mut C,
    ) -> Result<Option<Vec<u8>>, RpcError> {
        if self.phase == Phase::Failed {
            return Err(RpcError::FailedRequest);
        }
        if self.phase == Phase::Complete {
            return Ok(None);
        }
        if !cancellation.checkpoint() {
            return Err(RpcError::Cancelled);
        }
        if self.phase == Phase::Prefix {
            if self.prefix_offset < self.prefix.len() {
                let count =
                    (self.prefix.len() - self.prefix_offset).min(self.limits.max_packet_bytes);
                self.charge(count, self.sideband)?;
                let end = self.prefix_offset + count;
                let mut output = Vec::new();
                output
                    .try_reserve_exact(count)
                    .map_err(|_| WireError::AllocationFailure)?;
                output.extend_from_slice(&self.prefix[self.prefix_offset..end]);
                self.prefix_offset = end;
                if end == self.prefix.len() {
                    self.prefix = Vec::new();
                }
                return Ok(Some(output));
            }
            self.prefix = Vec::new();
            self.phase = if self.wants_pack {
                Phase::Pack
            } else {
                Phase::Complete
            };
        }
        if self.phase == Phase::Pack {
            let source = self.source.as_mut().ok_or(RpcError::MissingPack)?;
            let next = source.next_chunk(self.maximum_chunk_bytes)?;
            if !cancellation.checkpoint() {
                return Err(RpcError::Cancelled);
            }
            if let Some(chunk) = next {
                if chunk.is_empty() {
                    return Err(RpcError::EmptyPackChunk);
                }
                if chunk.len() > self.maximum_chunk_bytes {
                    return Err(WireError::PackChunkTooLarge {
                        observed: chunk.len(),
                        limit: self.maximum_chunk_bytes,
                    }
                    .into());
                }
                self.saw_pack_bytes = true;
                if self.sideband {
                    let count = chunk.len().checked_add(5).ok_or(RpcError::OutputLimit)?;
                    self.charge(count, true)?;
                    let mut payload = Vec::new();
                    payload
                        .try_reserve_exact(chunk.len() + 1)
                        .map_err(|_| WireError::AllocationFailure)?;
                    payload.push(1);
                    payload.extend(chunk);
                    return Ok(Some(encode_packet(&Packet::Data(payload), &self.limits)?));
                }
                self.charge(chunk.len(), false)?;
                return Ok(Some(chunk));
            }
            self.source = None;
            if !self.saw_pack_bytes {
                return Err(RpcError::MissingPack);
            }
            self.phase = if self.sideband {
                Phase::Flush
            } else {
                Phase::Complete
            };
        }
        if self.phase == Phase::Flush {
            self.charge(4, false)?;
            self.phase = Phase::Complete;
            // HTTP carries the native flush. The 0002 marker belongs to the
            // remote helper's IPC boundary, not this HTTP response body.
            return Ok(Some(encode_packet(&Packet::Flush, &self.limits)?));
        }
        Ok(None)
    }

    fn charge(&mut self, count: usize, reserve_flush: bool) -> Result<(), RpcError> {
        let next = self
            .emitted_bytes
            .checked_add(count as u64)
            .ok_or(RpcError::OutputLimit)?;
        let required = next
            .checked_add(if reserve_flush { 4 } else { 0 })
            .ok_or(RpcError::OutputLimit)?;
        if required > self.maximum_response_bytes {
            return Err(RpcError::OutputLimit);
        }
        self.emitted_bytes = next;
        Ok(())
    }
}

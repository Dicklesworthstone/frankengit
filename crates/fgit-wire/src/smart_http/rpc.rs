//! Native Git services over bounded, decoded HTTP request bodies.
//!
//! The gateway authenticates and resolves an immutable repository view BEFORE
//! constructing either adapter. These types do not own a listener, credentials,
//! route authority or runtime. Every RPC gets a new machine; no Git protocol
//! state leaks between HTTP requests. Pack construction and receive admission
//! are withheld until both HTTP framing and Git request grammar are complete.

use std::fmt::{self, Display, Formatter};

use super::{BodyDecoder, BodyFraming, HttpError, HttpLimits, Operation, ProtocolVersion,
    RequestHead, Service, discovery_prefix};
use crate::{AdvertisedRef, Capabilities, LegacyUploadPack, PackRequest, Packet, PktLineDecoder,
    Transition, UploadPackRepository, UploadPackVersion, V1Advertisement, V2UploadPack,
    WireError, WireEvent, WireLimits, encode_packet};
use crate::receive::{ReceiveCancellation, ReceiveCompletion, ReceiveContext, ReceiveError,
    ReceivePack, ReceiveQuarantineHandoff, advertise_receive_pack};

/// The structured error retains its owning protocol's refusal. HTTP-facing
/// diagnostics must not reflect the nested client text before authorization.
#[derive(Debug)]
pub enum RpcError {
    Http(HttpError),
    Wire(WireError),
    Receive(ReceiveError),
    WrongOperation,
    IncompleteRequest,
    MultipleCommands,
    FailedRequest,
    Cancelled,
    OutputLimit,
    MissingPack,
    UnexpectedPack,
    EmptyPackChunk,
}
impl Display for RpcError {
    fn fmt(&self, out: &mut Formatter<'_>) -> fmt::Result {
        out.write_str("smart HTTP Git service refused the operation")
    }
}
impl std::error::Error for RpcError {}
impl From<HttpError> for RpcError { fn from(e: HttpError) -> Self { Self::Http(e) } }
impl From<WireError> for RpcError { fn from(e: WireError) -> Self { Self::Wire(e) } }
impl From<ReceiveError> for RpcError { fn from(e: ReceiveError) -> Self { Self::Receive(e) } }

/// Only framing progress escapes a still-unvalidated request. `consumed` stops
/// at this HTTP message's boundary; any pipelined suffix remains the host's.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcProgress {
    pub consumed: usize,
    pub body_complete: bool,
    pub decoded_body_bytes: u64,
}

fn checkpoint<C: ReceiveCancellation>(cancellation: &mut C) -> Result<(), RpcError> {
    if cancellation.checkpoint() { Ok(()) } else { Err(RpcError::Cancelled) }
}
fn body_for(
    request: &RequestHead<'_>, service: Service, limits: HttpLimits,
) -> Result<BodyDecoder, RpcError> {
    if request.operation != Operation::Rpc(service) { return Err(RpcError::WrongOperation); }
    if request.body == BodyFraming::Empty { return Err(HttpError::LengthRequired.into()); }
    Ok(BodyDecoder::new(request.body, limits)?)
}
fn append_packets(
    output: &mut Vec<u8>, packets: &[Packet], limits: &WireLimits,
) -> Result<(), RpcError> {
    for packet in packets {
        let count = match packet { Packet::Data(data) => data.len().checked_add(4), _ => Some(4) }
            .ok_or(RpcError::OutputLimit)?;
        let next = output.len().checked_add(count).ok_or(RpcError::OutputLimit)?;
        if next > limits.max_outbound_bytes { return Err(RpcError::OutputLimit); }
        output.try_reserve(count).map_err(|_| WireError::AllocationFailure)?;
        output.extend_from_slice(&encode_packet(packet, limits)?);
    }
    Ok(())
}

enum UploadMachine { Legacy(LegacyUploadPack), V2(V2UploadPack), Failed }

/// One HTTP upload-pack request over one immutable, pre-authorized view.
/// No outer fetch-pack IPC envelope is parsed here: HTTP carries raw Git
/// pkt-lines. The returned reply contains no pack until the caller builds it.
pub struct UploadRpc<'repo, R: UploadPackRepository> {
    repository: &'repo R,
    body: BodyDecoder,
    decoder: PktLineDecoder,
    machine: UploadMachine,
    version: ProtocolVersion,
    limits: WireLimits,
    output: Vec<u8>,
    pack_request: Option<PackRequest>,
    command_complete: bool,
}
impl<'repo, R: UploadPackRepository> UploadRpc<'repo, R> {
    /// `selected_version` is the host's negotiated version. Capabilities must
    /// match its discovery response and the exact repository profile.
    pub fn new(
        request: &RequestHead<'_>, selected_version: ProtocolVersion,
        capabilities: Capabilities, repository: &'repo R,
        wire_limits: WireLimits, http_limits: HttpLimits,
    ) -> Result<Self, RpcError> {
        let body = body_for(request, Service::UploadPack, http_limits)?;
        let decoder = PktLineDecoder::new(wire_limits.clone())?;
        let machine = match selected_version {
            ProtocolVersion::V0 | ProtocolVersion::V1 => {
                let version = if selected_version == ProtocolVersion::V0 {
                    UploadPackVersion::V0
                } else { UploadPackVersion::V1 };
                UploadMachine::Legacy(LegacyUploadPack::new(version, capabilities, wire_limits.clone())?
                    .with_stateless_http_rounds().with_shallow_updates())
            }
            ProtocolVersion::V2 => UploadMachine::V2(
                V2UploadPack::new(capabilities, wire_limits.clone())?
                    .with_stateless_http_rounds().with_shallow_updates()),
        };
        Ok(Self { repository, body, decoder, machine, version: selected_version,
            limits: wire_limits, output: Vec::new(), pack_request: None, command_complete: false })
    }

    /// Feed HTTP body bytes, including chunk framing when selected. No pack
    /// request, ref response, or mutation handoff escapes this method.
    pub fn push<C: ReceiveCancellation>(
        &mut self, input: &[u8], cancellation: &mut C,
    ) -> Result<RpcProgress, RpcError> {
        let result = self.push_inner(input, cancellation);
        if result.is_err() {
            self.machine = UploadMachine::Failed;
            self.output = Vec::new();
            self.pack_request = None;
        }
        result
    }

    fn push_inner<C: ReceiveCancellation>(
        &mut self, input: &[u8], cancellation: &mut C,
    ) -> Result<RpcProgress, RpcError> {
        if matches!(self.machine, UploadMachine::Failed) { return Err(RpcError::FailedRequest); }
        checkpoint(cancellation)?;
        let mut consumed = 0;
        while consumed < input.len() && !self.body.is_complete() {
            checkpoint(cancellation)?;
            let step = self.body.push(&input[consumed..])?;
            consumed += step.consumed;
            if !step.data.is_empty() {
                self.accept_payload(step.data, cancellation)?;
            }
        }
        checkpoint(cancellation)?;
        Ok(RpcProgress { consumed, body_complete: self.body.is_complete(),
            decoded_body_bytes: self.body.decoded_bytes() })
    }

    fn accept_payload<C: ReceiveCancellation>(
        &mut self, payload: &[u8], cancellation: &mut C,
    ) -> Result<(), RpcError> {
        if self.command_complete { return Err(RpcError::MultipleCommands); }
        // Bound each decoder push regardless of the HTTP framework's chunk size.
        // A many-megabyte HTTP chunk never becomes one packet-decoder allocation.
        let decoder_chunk_bytes = self.limits.max_packet_bytes
            .min(self.limits.max_packets_per_push.saturating_mul(4));
        for fragment in payload.chunks(decoder_chunk_bytes) {
            checkpoint(cancellation)?;
            let packets = self.decoder.push(fragment)?;
            for packet in packets {
                checkpoint(cancellation)?;
                if self.command_complete { return Err(RpcError::MultipleCommands); }
                let transition = match &mut self.machine {
                    UploadMachine::Legacy(machine) => machine.push_packet(&packet, self.repository)?,
                    UploadMachine::V2(machine) => machine.push_packet(&packet, self.repository)?,
                    UploadMachine::Failed => return Err(RpcError::FailedRequest),
                };
                self.accept_transition(transition)?;
                let negotiation_complete = match &self.machine {
                    UploadMachine::Legacy(machine) => machine.is_http_negotiation_complete(),
                    UploadMachine::V2(machine) => machine.is_http_negotiation_complete(),
                    UploadMachine::Failed => false,
                };
                self.command_complete |= negotiation_complete;
            }
            // Reject even a partial second command following a complete first
            // one. A successful first command cannot hide a trailing bad frame.
            if self.command_complete { self.decoder.finish()?; }
        }
        Ok(())
    }

    fn accept_transition(&mut self, transition: Transition) -> Result<(), RpcError> {
        let sideband_all = matches!(&self.machine, UploadMachine::V2(machine)
            if machine.options.sideband_all());
        if sideband_all {
            for packet in transition.output {
                let packet = match packet {
                    Packet::Data(data) => {
                        let count = data.len().checked_add(1).ok_or(RpcError::OutputLimit)?;
                        let mut framed = Vec::new();
                        framed.try_reserve_exact(count).map_err(|_| WireError::AllocationFailure)?;
                        framed.push(1); framed.extend_from_slice(&data);
                        Packet::Data(framed)
                    }
                    control => control,
                };
                append_packets(&mut self.output, &[packet], &self.limits)?;
            }
        } else {
            append_packets(&mut self.output, &transition.output, &self.limits)?;
        }
        for event in transition.events {
            match event {
                WireEvent::PackRequested(request) => {
                    if self.command_complete { return Err(RpcError::MultipleCommands); }
                    self.pack_request = Some(request);
                    self.command_complete = true;
                }
                WireEvent::LsRefs { .. } => {
                    if self.command_complete { return Err(RpcError::MultipleCommands); }
                    self.command_complete = true;
                }
                WireEvent::Common(_) => {}
            }
        }
        Ok(())
    }

    /// Consume the request exactly once. HTTP termination is checked before
    /// producing a pack request or making any response bytes available.
    pub fn finish<C: ReceiveCancellation>(
        mut self, cancellation: &mut C,
    ) -> Result<UploadReply, RpcError> {
        if matches!(self.machine, UploadMachine::Failed) { return Err(RpcError::FailedRequest); }
        checkpoint(cancellation)?;
        self.body.finish()?;
        self.decoder.finish()?;
        match &self.machine {
            UploadMachine::Legacy(machine) => machine.finish_stateless_http_round()?,
            UploadMachine::V2(_) if self.command_complete => {}
            UploadMachine::V2(_) => return Err(RpcError::IncompleteRequest),
            UploadMachine::Failed => return Err(RpcError::FailedRequest),
        }
        checkpoint(cancellation)?;
        Ok(UploadReply { version: self.version, prefix: self.output, pack_request: self.pack_request })
    }
}

/// A complete, bounded request. A successful reply is not repository authority;
/// the caller must build any requested pack from the same authorized snapshot.
#[derive(Debug)]
pub struct UploadReply {
    pub(super) version: ProtocolVersion,
    pub(super) prefix: Vec<u8>,
    pub(super) pack_request: Option<PackRequest>,
}
impl UploadReply {
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion { self.version }
    #[must_use]
    pub fn prefix(&self) -> &[u8] { &self.prefix }
    #[must_use]
    pub fn pack_request(&self) -> Option<&PackRequest> { self.pack_request.as_ref() }
}

/// HTTP receive-pack body decoder composed with the real native quarantine.
/// Parsing may stage only the native transaction-local quarantine; the caller's
/// handoff is unavailable until `finish_with_handoff` validates HTTP EOF.
pub struct ReceiveRpc {
    body: BodyDecoder,
    machine: Option<ReceivePack>,
    chunk_bytes: usize,
}
impl ReceiveRpc {
    pub fn new(
        request: &RequestHead<'_>, selected_version: ProtocolVersion,
        context: ReceiveContext, http_limits: HttpLimits,
    ) -> Result<Self, RpcError> {
        if selected_version == ProtocolVersion::V2 { return Err(HttpError::UnsupportedVersion.into()); }
        let body = body_for(request, Service::ReceivePack, http_limits)?;
        let chunk_bytes = context.limits.wire.max_packet_bytes
            .min(context.limits.wire.max_packets_per_push.saturating_mul(4));
        let machine = Some(ReceivePack::new(context)?);
        Ok(Self { body, machine, chunk_bytes })
    }
    pub fn push<C: ReceiveCancellation>(
        &mut self, input: &[u8], cancellation: &mut C,
    ) -> Result<RpcProgress, RpcError> {
        let result = self.push_inner(input, cancellation);
        if result.is_err() { self.machine = None; }
        result
    }
    fn push_inner<C: ReceiveCancellation>(
        &mut self, input: &[u8], cancellation: &mut C,
    ) -> Result<RpcProgress, RpcError> {
        let machine = self.machine.as_mut().ok_or(RpcError::FailedRequest)?;
        checkpoint(cancellation)?;
        let mut consumed = 0;
        while consumed < input.len() && !self.body.is_complete() {
            checkpoint(cancellation)?;
            let step = self.body.push(&input[consumed..])?;
            consumed += step.consumed;
            for fragment in step.data.chunks(self.chunk_bytes) {
                checkpoint(cancellation)?;
                // RequestParsed remains private until HTTP and pack validation.
                let _ = machine.push_bytes(fragment)?;
            }
        }
        checkpoint(cancellation)?;
        Ok(RpcProgress { consumed, body_complete: self.body.is_complete(),
            decoded_body_bytes: self.body.decoded_bytes() })
    }
    /// The original handoff's outcome is returned unchanged. In particular,
    /// cancellation after a publishing handoff is not rewritten as non-commit.
    pub fn finish_with_handoff<H: ReceiveQuarantineHandoff, C: ReceiveCancellation>(
        mut self, handoff: &mut H, cancellation: &mut C,
    ) -> Result<ReceiveCompletion, RpcError> {
        let machine = self.machine.as_mut().ok_or(RpcError::FailedRequest)?;
        checkpoint(cancellation)?;
        self.body.finish()?;
        checkpoint(cancellation)?;
        Ok(machine.finish_with_handoff(handoff, cancellation)?)
    }
}

/// Generate discovery through the native advertisement encoders. The complete
/// body, including service/version preludes, shares one outbound byte ceiling.
pub fn upload_discovery(
    repository: &impl UploadPackRepository, capabilities: Capabilities,
    version: ProtocolVersion, limits: &WireLimits,
) -> Result<Vec<u8>, RpcError> {
    let _ = PktLineDecoder::new(limits.clone())?;
    let packets = if version == ProtocolVersion::V2 {
        capabilities.encode_v2_advertisement(limits)?
    } else {
        // Validate count/identity/order before cloning potentially large refs.
        crate::validate_advertised_refs(repository.advertised_refs(), repository.object_format(), limits)?;
        let mut refs = Vec::new();
        refs.try_reserve_exact(repository.advertised_refs().len()).map_err(|_| WireError::AllocationFailure)?;
        refs.extend_from_slice(repository.advertised_refs());
        let mut advertisement = V1Advertisement::new(refs, capabilities, repository.object_format(), limits)?;
        advertisement.version_one_prelude = version == ProtocolVersion::V1;
        advertisement.encode(limits)?
    };
    discovery_body(Service::UploadPack, version, &packets, limits)
}

pub fn receive_discovery(
    refs: Vec<AdvertisedRef>, context: &ReceiveContext, version: ProtocolVersion,
) -> Result<Vec<u8>, RpcError> {
    if version == ProtocolVersion::V2 { return Err(HttpError::UnsupportedVersion.into()); }
    let mut packets = Vec::new();
    if version == ProtocolVersion::V1 { packets.push(Packet::Data(b"version 1\n".to_vec())); }
    packets.extend(advertise_receive_pack(refs, context)?);
    discovery_body(Service::ReceivePack, version, &packets, &context.limits.wire)
}
fn discovery_body(
    service: Service, version: ProtocolVersion, packets: &[Packet], limits: &WireLimits,
) -> Result<Vec<u8>, RpcError> {
    let prefix = discovery_prefix(service, version)?;
    if prefix.len() > limits.max_outbound_bytes { return Err(RpcError::OutputLimit); }
    let mut output = Vec::new();
    output.try_reserve(prefix.len()).map_err(|_| WireError::AllocationFailure)?;
    output.extend_from_slice(prefix);
    append_packets(&mut output, packets, limits)?;
    Ok(output)
}

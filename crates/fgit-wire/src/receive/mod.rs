//! Bounded SANS-I/O `git-receive-pack` request parsing and quarantine handoff.
//!
//! This module accepts the v0/v1 receive-pack request grammar, preserves the
//! command order supplied by the client, and holds incoming pack bytes only in
//! a transaction-local buffer. It validates pkt-line framing, command syntax,
//! negotiated capabilities, certificate nonce syntax, and the native pack
//! trailer/structural envelope before calling a caller-owned admission handoff.
//! It neither authorizes a ref update nor publishes objects or refs.
//!
//! The remaining admission checks are intentionally not guessed here. A
//! [`ReceiveQuarantineHandoff`] receives the structural quarantine result while
//! it is still transaction-local, and FG-019b supplies the authoritative
//! expected-old, reachability, object-identity, signature, and ref-policy
//! decisions. Returning from that handoff drops both raw bytes and the
//! [`fgit_pack::QuarantinedPack`] unless the handoff's own transactional owner
//! has consumed them.

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

use fgit_pack::{
    NativeChecksumVerifier, PackError, PackLimits, QuarantinedPack, read_verified_pack,
};
use fgit_types::RefName;

use crate::{
    AdvertisedRef, AnyGitOid, Capabilities, Capability, GitObjectFormat, Packet, PktLineDecoder,
    SidebandBand, V1Advertisement, WireError, WireLimits, add_output_packet, encode_sideband_64k,
    line_without_lf, packet_name, parse_object_id,
};

const EMPTY_REPOSITORY_CAPABILITY_REF: &[u8] = b"capabilities^{}";
const ATOMIC_FAILURE_MESSAGE: &[u8] = b"atomic push failed";

/// Bounds applied in addition to the shared pkt-line and pack-reader bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveLimits {
    /// Shared pkt-line, capability, ref, and response bounds.
    pub wire: WireLimits,
    /// Pack-reader limits applied before decompression and entry allocation.
    pub pack: PackLimits,
    /// Maximum ref commands retained from one request.
    pub max_commands: usize,
    /// Maximum client push options retained from one request.
    pub max_push_options: usize,
    /// Maximum bytes in one client push option.
    pub max_push_option_bytes: usize,
    /// Maximum certificate lines before the terminating `push-cert-end` line.
    pub max_certificate_lines: usize,
    /// Maximum certificate bytes retained while parsing a signed push.
    pub max_certificate_bytes: usize,
    /// Maximum raw pack bytes retained by this transaction-local state machine.
    pub max_quarantine_bytes: usize,
    /// Maximum bytes in a report-status diagnostic supplied by the caller.
    pub max_status_message_bytes: usize,
}

impl Default for ReceiveLimits {
    fn default() -> Self {
        let pack = PackLimits::default();
        Self {
            wire: WireLimits::default(),
            max_quarantine_bytes: pack.max_input_bytes,
            pack,
            max_commands: 16_384,
            max_push_options: 256,
            max_push_option_bytes: 4_096,
            max_certificate_lines: 16_384,
            max_certificate_bytes: 4 * 1024 * 1024,
            max_status_message_bytes: 4_096,
        }
    }
}

impl ReceiveLimits {
    fn validate(&self) -> Result<(), ReceiveError> {
        PktLineDecoder::new(self.wire.clone()).map_err(ReceiveError::Wire)?;
        if self.max_commands == 0
            || self.max_push_options == 0
            || self.max_push_option_bytes == 0
            || self.max_certificate_lines == 0
            || self.max_certificate_bytes == 0
            || self.max_status_message_bytes == 0
            || self.max_quarantine_bytes > self.pack.max_input_bytes
        {
            return Err(ReceiveError::InvalidLimit {
                field: "receive limits",
            });
        }
        Ok(())
    }
}

/// The receive-pack capabilities implemented by this state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveCapability {
    /// Per-ref `ok` and `ng` outcome records.
    ReportStatus,
    /// Extended report-status grammar; v1 records remain valid within it.
    ReportStatusV2,
    /// Multiplex report-status packets as sideband band 1.
    SideBand64k,
    /// Suppress progress output; this machine emits no progress packets.
    Quiet,
    /// Treat one rejected ref command as a rejection for every command.
    Atomic,
    /// Permit offset-delta notation in the incoming pack.
    OfsDelta,
    /// Accept the second, bounded push-options section.
    PushOptions,
    /// Accept a bounded `agent=<value>` client identification.
    Agent,
    /// Permit a command whose new object ID is all zeroes.
    DeleteRefs,
    /// Parse a signed push-certificate profile and its nonce.
    PushCert,
}

impl ReceiveCapability {
    fn parse(name: &[u8]) -> Option<Self> {
        match name {
            b"report-status" => Some(Self::ReportStatus),
            b"report-status-v2" => Some(Self::ReportStatusV2),
            b"side-band-64k" => Some(Self::SideBand64k),
            b"quiet" => Some(Self::Quiet),
            b"atomic" => Some(Self::Atomic),
            b"ofs-delta" => Some(Self::OfsDelta),
            b"push-options" => Some(Self::PushOptions),
            b"agent" => Some(Self::Agent),
            b"delete-refs" => Some(Self::DeleteRefs),
            b"push-cert" => Some(Self::PushCert),
            _ => None,
        }
    }
}

/// The enabled signed-push parsing profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignedPushProfile {
    /// Signed push certificates are refused before their body is retained.
    Refuse,
    /// Parse the v0.1 certificate envelope and require its exact advertised nonce.
    ParseV1 { expected_nonce: Vec<u8> },
}

impl SignedPushProfile {
    fn expected_nonce(&self) -> Option<&[u8]> {
        match self {
            Self::Refuse => None,
            Self::ParseV1 { expected_nonce } => Some(expected_nonce),
        }
    }
}

/// Immutable receive-pack facts selected before request bytes arrive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveContext {
    /// Repository-native object identity domain.
    pub object_format: GitObjectFormat,
    /// Capabilities attached to the server's first advertised ref.
    pub server_capabilities: Capabilities,
    /// Bounded parsing and validation limits.
    pub limits: ReceiveLimits,
    /// Signed-push parsing and nonce policy.
    pub signed_push: SignedPushProfile,
}

impl ReceiveContext {
    /// Validates limits, receive capability support, and signed-push coherence.
    pub fn new(
        object_format: GitObjectFormat,
        server_capabilities: Capabilities,
        limits: ReceiveLimits,
        signed_push: SignedPushProfile,
    ) -> Result<Self, ReceiveError> {
        limits.validate()?;
        validate_server_capabilities(&server_capabilities, &signed_push)?;
        Ok(Self {
            object_format,
            server_capabilities,
            limits,
            signed_push,
        })
    }
}

/// One parsed ref update. Its `old` value is an expected-old assertion, not a
/// proof that an authority head has changed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveCommand {
    /// Expected old native object ID, or all-zero for a create request.
    pub old: AnyGitOid,
    /// Requested new native object ID, or all-zero for a delete request.
    pub new: AnyGitOid,
    /// Validated full Git ref name.
    pub ref_name: Vec<u8>,
}

impl ReceiveCommand {
    /// Classifies the command from its two native zero-ID sentinels.
    #[must_use]
    pub fn kind(&self) -> ReceiveCommandKind {
        match (self.old.is_zero(), self.new.is_zero()) {
            (true, false) => ReceiveCommandKind::Create,
            (false, true) => ReceiveCommandKind::Delete,
            (false, false) => ReceiveCommandKind::Update,
            (true, true) => ReceiveCommandKind::InvalidZeroPair,
        }
    }

    /// Returns the exact expected-old assertion that FG-019b must check.
    #[must_use]
    pub fn expected_old(&self) -> Option<AnyGitOid> {
        (!self.old.is_zero()).then_some(self.old)
    }
}

/// Ref-command classification. No force/fast-forward decision is made here;
/// an update preserves its expected old ID for authority-backed admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveCommandKind {
    /// All-zero old ID followed by a non-zero new ID.
    Create,
    /// Non-zero old ID followed by an all-zero new ID.
    Delete,
    /// Two non-zero IDs; admission decides fast-forward/force policy.
    Update,
    /// Two zero IDs, which receive-pack refuses.
    InvalidZeroPair,
}

/// Versioned signed-push evidence retained only for the admission handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushCertificate {
    /// The required protocol envelope version.
    pub version: Vec<u8>,
    /// The certificate's pusher identity line value.
    pub pusher: Vec<u8>,
    /// The requested receiver URL line value.
    pub pushee: Vec<u8>,
    /// The nonce that matched this context's expected nonce exactly.
    pub nonce: Vec<u8>,
    /// Push options embedded in the signed certificate.
    pub push_options: Vec<Vec<u8>>,
    /// Exact signature-armour packet payloads. Cryptographic verification is an
    /// admission responsibility and is never implied by syntactic parsing.
    pub signature_lines: Vec<Vec<u8>>,
}

/// A parsed request, still only a non-authoritative proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveRequest {
    /// Client commands in the exact first-seen wire order.
    pub commands: Vec<ReceiveCommand>,
    /// Negotiated capabilities in the exact first-command order.
    pub capabilities: Vec<Capability>,
    /// Bounded post-command push options in packet order.
    pub push_options: Vec<Vec<u8>>,
    /// Parsed certificate evidence, if the client selected signed-push.
    pub certificate: Option<PushCertificate>,
}

impl ReceiveRequest {
    /// Returns whether the client negotiated one capability by its exact name.
    #[must_use]
    pub fn has_capability(&self, name: &[u8]) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability.name == name)
    }

    /// True only when all commands are deletes, so no pack bytes are required.
    #[must_use]
    pub fn deletes_only(&self) -> bool {
        self.commands
            .iter()
            .all(|command| command.kind() == ReceiveCommandKind::Delete)
    }

    /// True when any command requires a pack, including an update.
    #[must_use]
    pub fn requires_pack(&self) -> bool {
        !self.deletes_only()
    }

    fn report_status_mode(&self) -> ReportStatusMode {
        if self.has_capability(b"report-status-v2") {
            ReportStatusMode::V2
        } else if self.has_capability(b"report-status") {
            ReportStatusMode::V1
        } else {
            ReportStatusMode::Disabled
        }
    }
}

/// A public completion receipt that intentionally carries no raw pack bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveCompletion {
    /// The parsed, non-authoritative request passed to admission.
    pub request: ReceiveRequest,
    /// Structural quarantine facts observed before handoff.
    pub quarantine: QuarantineReceipt,
}

/// Structural facts from the bounded pack reader, safe to carry after pack
/// bytes and entries have been dropped by this state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineReceipt {
    /// The repository-native pack object domain.
    pub object_format: GitObjectFormat,
    /// Number of pack entries structurally decoded in quarantine.
    pub object_count: u32,
    /// Number of raw pack bytes fed to the structural reader.
    pub pack_bytes: usize,
    /// Whether the command list required no pack because every command deletes.
    pub delete_only: bool,
}

/// The synchronous boundary from structural quarantine to authoritative
/// admission. Implementations may inspect entries but must not infer a ref
/// commit from this call alone.
pub trait ReceiveQuarantineHandoff {
    /// Receives bounded structural facts while the quarantined pack is local.
    fn handoff(
        &mut self,
        request: &ReceiveRequest,
        pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt,
    ) -> Result<(), ReceiveError>;
}

/// Cooperative cancellation boundary for the synchronous receive core.
pub trait ReceiveCancellation {
    /// Returns true when parsing/validation may continue.
    fn checkpoint(&mut self) -> bool;
}

impl<Probe> ReceiveCancellation for Probe
where
    Probe: FnMut() -> bool,
{
    fn checkpoint(&mut self) -> bool {
        self()
    }
}

/// Wire events emitted before any authority-backed admission decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveEvent {
    /// The command and optional push-options sections are complete.
    RequestReady(ReceiveRequest),
    /// A refused state discarded its transaction-local quarantine buffer.
    QuarantineDiscarded,
}

/// Output and observations from one packet or byte transition.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReceiveTransition {
    /// Receive-pack does not emit a response until a caller supplies outcomes.
    pub output: Vec<Packet>,
    /// Parser observations in deterministic transition order.
    pub events: Vec<ReceiveEvent>,
}

/// Receive-pack state after each accepted transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceivePhase {
    /// Reading the command list or an optional signed-push envelope.
    Commands,
    /// Reading a negotiated push-options list.
    PushOptions,
    /// Receiving raw, transaction-local pack bytes.
    Pack,
    /// A delete-only request is ready for structural handoff.
    Ready,
    /// Handoff completed; the session cannot accept more input.
    Complete,
    /// A typed refusal occurred and the local quarantine was discarded.
    Refused,
}

/// A bounded, deterministic receive-pack state machine.
#[derive(Clone, Debug)]
pub struct ReceivePack {
    context: ReceiveContext,
    decoder: PktLineDecoder,
    phase: ReceivePhase,
    commands: Vec<ReceiveCommand>,
    client_capabilities: Vec<Capability>,
    push_options: Vec<Vec<u8>>,
    certificate: Option<PushCertificate>,
    certificate_builder: Option<CertificateBuilder>,
    quarantine: Vec<u8>,
}

impl ReceivePack {
    /// Creates a receive-pack request machine before any bytes are retained.
    pub fn new(context: ReceiveContext) -> Result<Self, ReceiveError> {
        let decoder =
            PktLineDecoder::new(context.limits.wire.clone()).map_err(ReceiveError::Wire)?;
        Ok(Self {
            context,
            decoder,
            phase: ReceivePhase::Commands,
            commands: Vec::new(),
            client_capabilities: Vec::new(),
            push_options: Vec::new(),
            certificate: None,
            certificate_builder: None,
            quarantine: Vec::new(),
        })
    }

    /// Returns the current receive state.
    #[must_use]
    pub const fn phase(&self) -> ReceivePhase {
        self.phase
    }

    /// Returns the bytes still retained in the transaction-local quarantine.
    #[must_use]
    pub const fn quarantine_len(&self) -> usize {
        self.quarantine.len()
    }

    /// Accepts one already-decoded protocol packet. Raw pack bytes must use
    /// [`Self::push_bytes`] after the command-list flush.
    pub fn push_packet(&mut self, packet: Packet) -> Result<ReceiveTransition, ReceiveError> {
        let result = self.push_packet_inner(packet);
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Accepts a network fragment. Packet framing stops at the first command
    /// flush, so a same-read raw `PACK` suffix enters only the quarantine buffer.
    pub fn push_bytes(&mut self, input: &[u8]) -> Result<ReceiveTransition, ReceiveError> {
        let result = self.push_bytes_inner(input);
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Validates a complete transport input and synchronously hands the local
    /// quarantine to admission. It never returns pack bytes or entries.
    pub fn finish_with_handoff<Handoff, Cancellation>(
        &mut self,
        handoff: &mut Handoff,
        cancellation: &mut Cancellation,
    ) -> Result<ReceiveCompletion, ReceiveError>
    where
        Handoff: ReceiveQuarantineHandoff,
        Cancellation: ReceiveCancellation,
    {
        let result = self.finish_with_handoff_inner(handoff, cancellation);
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn push_bytes_inner(&mut self, input: &[u8]) -> Result<ReceiveTransition, ReceiveError> {
        if self.phase == ReceivePhase::Pack {
            self.append_pack_bytes(input)?;
            return Ok(ReceiveTransition::default());
        }
        let boundary = self
            .decoder
            .push_until_flush(input)
            .map_err(ReceiveError::Wire)?;
        let mut transition = ReceiveTransition::default();
        for packet in boundary.packets {
            transition.append(self.push_packet_inner(packet)?)?;
        }
        if boundary.found_flush && boundary.consumed < input.len() {
            if self.phase != ReceivePhase::Pack {
                return Err(ReceiveError::UnexpectedPackBytes { state: self.phase });
            }
            self.append_pack_bytes(&input[boundary.consumed..])?;
        }
        Ok(transition)
    }

    fn push_packet_inner(&mut self, packet: Packet) -> Result<ReceiveTransition, ReceiveError> {
        match self.phase {
            ReceivePhase::Commands => self.push_command_packet(packet),
            ReceivePhase::PushOptions => self.push_push_option_packet(packet),
            ReceivePhase::Pack => Err(ReceiveError::UnexpectedPacket {
                state: self.phase,
                packet: packet_name(&packet),
            }),
            ReceivePhase::Ready | ReceivePhase::Complete | ReceivePhase::Refused => {
                Err(ReceiveError::TerminalState { state: self.phase })
            }
        }
    }

    fn push_command_packet(&mut self, packet: Packet) -> Result<ReceiveTransition, ReceiveError> {
        match packet {
            Packet::Data(line) => self.push_command_line(line),
            Packet::Flush => self.finish_command_list(),
            Packet::Delimiter | Packet::ResponseEnd => Err(ReceiveError::UnexpectedPacket {
                state: self.phase,
                packet: packet_name(&packet),
            }),
        }
    }

    fn push_command_line(&mut self, line: Vec<u8>) -> Result<ReceiveTransition, ReceiveError> {
        if self.certificate_builder.is_some() {
            self.push_certificate_line(line)?;
            return Ok(ReceiveTransition::default());
        }
        if self.commands.is_empty()
            && self.client_capabilities.is_empty()
            && line.starts_with(b"push-cert\0")
        {
            self.start_certificate(line)?;
            return Ok(ReceiveTransition::default());
        }
        let line = line_without_lf(&line).map_err(ReceiveError::Wire)?;
        let (command, capabilities) =
            parse_command_line(line, self.context.object_format, &self.context.limits)?;
        if let Some(capabilities) = capabilities {
            if !self.commands.is_empty() || !self.client_capabilities.is_empty() {
                return Err(ReceiveError::CapabilitiesNotFirstCommand);
            }
            self.client_capabilities = negotiate_capabilities(
                capabilities,
                &self.context.server_capabilities,
                &self.context.limits.wire,
            )?;
        }
        self.push_command(command)?;
        Ok(ReceiveTransition::default())
    }

    fn finish_command_list(&mut self) -> Result<ReceiveTransition, ReceiveError> {
        if self.certificate_builder.is_some() {
            return Err(ReceiveError::CertificateTruncated);
        }
        if self.commands.is_empty() {
            return Err(ReceiveError::MissingCommands);
        }
        self.validate_command_capabilities()?;
        let request = self.request()?;
        if request.has_capability(b"push-options") {
            self.phase = ReceivePhase::PushOptions;
            return Ok(ReceiveTransition::default());
        }
        self.phase = if request.requires_pack() {
            ReceivePhase::Pack
        } else {
            ReceivePhase::Ready
        };
        Ok(ReceiveTransition {
            output: Vec::new(),
            events: vec![ReceiveEvent::RequestReady(request)],
        })
    }

    fn push_push_option_packet(
        &mut self,
        packet: Packet,
    ) -> Result<ReceiveTransition, ReceiveError> {
        match packet {
            Packet::Data(line) => {
                let option = line_without_lf(&line).map_err(ReceiveError::Wire)?;
                validate_push_option(option, &self.context.limits)?;
                if self.push_options.len() == self.context.limits.max_push_options {
                    return Err(ReceiveError::TooManyPushOptions {
                        limit: self.context.limits.max_push_options,
                    });
                }
                self.push_options
                    .try_reserve(1)
                    .map_err(|_| ReceiveError::AllocationFailure)?;
                self.push_options.push(option.to_vec());
                Ok(ReceiveTransition::default())
            }
            Packet::Flush => {
                let request = self.request()?;
                self.phase = if request.requires_pack() {
                    ReceivePhase::Pack
                } else {
                    ReceivePhase::Ready
                };
                Ok(ReceiveTransition {
                    output: Vec::new(),
                    events: vec![ReceiveEvent::RequestReady(request)],
                })
            }
            Packet::Delimiter | Packet::ResponseEnd => Err(ReceiveError::UnexpectedPacket {
                state: self.phase,
                packet: packet_name(&packet),
            }),
        }
    }

    fn start_certificate(&mut self, line: Vec<u8>) -> Result<(), ReceiveError> {
        let Some(line) = line.strip_suffix(b"\n") else {
            return Err(ReceiveError::Wire(WireError::MissingLineFeed));
        };
        let Some(raw_capabilities) = line.strip_prefix(b"push-cert\0") else {
            return Err(ReceiveError::MalformedCertificate);
        };
        let expected_nonce = self
            .context
            .signed_push
            .expected_nonce()
            .ok_or(ReceiveError::SignedPushUnsupported)?;
        self.client_capabilities = negotiate_capabilities(
            raw_capabilities,
            &self.context.server_capabilities,
            &self.context.limits.wire,
        )?;
        if !self.has_client_capability(b"push-cert") {
            return Err(ReceiveError::SignedPushCapabilityMissing);
        }
        if expected_nonce.is_empty() {
            return Err(ReceiveError::InvalidLimit {
                field: "signed push expected nonce",
            });
        }
        self.certificate_builder = Some(CertificateBuilder::new(expected_nonce.to_vec()));
        Ok(())
    }

    fn push_certificate_line(&mut self, line: Vec<u8>) -> Result<(), ReceiveError> {
        let progress = {
            let builder = self
                .certificate_builder
                .as_mut()
                .ok_or(ReceiveError::MalformedCertificate)?;
            builder.push_line(line, &self.context)?
        };
        match progress {
            CertificateProgress::Continue => Ok(()),
            CertificateProgress::Command(command) => self.push_command(command),
            CertificateProgress::Complete(certificate) => {
                self.certificate = Some(certificate);
                self.certificate_builder = None;
                Ok(())
            }
        }
    }

    fn push_command(&mut self, command: ReceiveCommand) -> Result<(), ReceiveError> {
        if command.kind() == ReceiveCommandKind::InvalidZeroPair {
            return Err(ReceiveError::BothObjectIdsZero);
        }
        if self.commands.len() == self.context.limits.max_commands {
            return Err(ReceiveError::TooManyCommands {
                limit: self.context.limits.max_commands,
            });
        }
        if self
            .commands
            .iter()
            .any(|existing| existing.ref_name == command.ref_name)
        {
            return Err(ReceiveError::DuplicateRefCommand {
                ref_name: command.ref_name,
            });
        }
        self.commands
            .try_reserve(1)
            .map_err(|_| ReceiveError::AllocationFailure)?;
        self.commands.push(command);
        Ok(())
    }

    fn validate_command_capabilities(&self) -> Result<(), ReceiveError> {
        if self.commands.iter().any(|command| command.new.is_zero())
            && !self.has_client_capability(b"delete-refs")
        {
            return Err(ReceiveError::DeleteRefsNotNegotiated);
        }
        Ok(())
    }

    fn append_pack_bytes(&mut self, bytes: &[u8]) -> Result<(), ReceiveError> {
        let new_len = self.quarantine.len().checked_add(bytes.len()).ok_or(
            ReceiveError::QuarantineBytesExceeded {
                limit: self.context.limits.max_quarantine_bytes,
            },
        )?;
        if new_len > self.context.limits.max_quarantine_bytes {
            return Err(ReceiveError::QuarantineBytesExceeded {
                limit: self.context.limits.max_quarantine_bytes,
            });
        }
        self.quarantine
            .try_reserve(bytes.len())
            .map_err(|_| ReceiveError::AllocationFailure)?;
        self.quarantine.extend_from_slice(bytes);
        Ok(())
    }

    fn finish_with_handoff_inner<Handoff, Cancellation>(
        &mut self,
        handoff: &mut Handoff,
        cancellation: &mut Cancellation,
    ) -> Result<ReceiveCompletion, ReceiveError>
    where
        Handoff: ReceiveQuarantineHandoff,
        Cancellation: ReceiveCancellation,
    {
        self.decoder.finish().map_err(ReceiveError::Wire)?;
        let request = match self.phase {
            ReceivePhase::Ready | ReceivePhase::Pack => self.request()?,
            ReceivePhase::Commands | ReceivePhase::PushOptions => {
                return Err(ReceiveError::IncompleteRequest { state: self.phase });
            }
            ReceivePhase::Complete | ReceivePhase::Refused => {
                return Err(ReceiveError::TerminalState { state: self.phase });
            }
        };
        if !cancellation.checkpoint() {
            return Err(ReceiveError::Cancelled);
        }
        let raw_pack = std::mem::take(&mut self.quarantine);
        let receipt = QuarantineReceipt {
            object_format: self.context.object_format,
            object_count: 0,
            pack_bytes: raw_pack.len(),
            delete_only: request.deletes_only(),
        };
        if request.requires_pack() && raw_pack.is_empty() {
            return Err(ReceiveError::PackRequired);
        }
        if !request.requires_pack() && !raw_pack.is_empty() {
            return Err(ReceiveError::UnexpectedPackBytes {
                state: ReceivePhase::Ready,
            });
        }
        if request.deletes_only() {
            handoff.handoff(&request, None, &receipt)?;
            self.phase = ReceivePhase::Complete;
            return Ok(ReceiveCompletion {
                request,
                quarantine: receipt,
            });
        }
        let mut deadline = PackDeadline { cancellation };
        let pack = read_verified_pack(
            &raw_pack,
            self.context.object_format,
            &self.context.limits.pack,
            &mut deadline,
            &NativeChecksumVerifier,
        )
        .map_err(ReceiveError::Pack)?;
        let receipt = QuarantineReceipt {
            object_count: pack.header.object_count,
            ..receipt
        };
        handoff.handoff(&request, Some(&pack), &receipt)?;
        self.phase = ReceivePhase::Complete;
        Ok(ReceiveCompletion {
            request,
            quarantine: receipt,
        })
    }

    fn request(&self) -> Result<ReceiveRequest, ReceiveError> {
        if self.commands.is_empty() {
            return Err(ReceiveError::MissingCommands);
        }
        Ok(ReceiveRequest {
            commands: self.commands.clone(),
            capabilities: self.client_capabilities.clone(),
            push_options: self.push_options.clone(),
            certificate: self.certificate.clone(),
        })
    }

    fn has_client_capability(&self, name: &[u8]) -> bool {
        self.client_capabilities
            .iter()
            .any(|capability| capability.name == name)
    }

    fn refuse(&mut self) {
        self.quarantine = Vec::new();
        self.phase = ReceivePhase::Refused;
    }
}

impl ReceiveTransition {
    fn append(&mut self, other: Self) -> Result<(), ReceiveError> {
        self.output
            .try_reserve(other.output.len())
            .map_err(|_| ReceiveError::AllocationFailure)?;
        self.events
            .try_reserve(other.events.len())
            .map_err(|_| ReceiveError::AllocationFailure)?;
        self.output.extend(other.output);
        self.events.extend(other.events);
        Ok(())
    }
}

struct PackDeadline<'a, Cancellation> {
    cancellation: &'a mut Cancellation,
}

impl<Cancellation> fgit_pack::Deadline for PackDeadline<'_, Cancellation>
where
    Cancellation: ReceiveCancellation,
{
    fn checkpoint(&mut self) -> bool {
        self.cancellation.checkpoint()
    }
}

#[derive(Clone, Debug)]
struct CertificateBuilder {
    expected_nonce: Vec<u8>,
    stage: CertificateStage,
    line_count: usize,
    byte_count: usize,
    version: Option<Vec<u8>>,
    pusher: Option<Vec<u8>>,
    pushee: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    push_options: Vec<Vec<u8>>,
    signature_lines: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CertificateStage {
    Headers,
    Commands,
    Signature,
}

enum CertificateProgress {
    Continue,
    Command(ReceiveCommand),
    Complete(PushCertificate),
}

impl CertificateBuilder {
    fn new(expected_nonce: Vec<u8>) -> Self {
        Self {
            expected_nonce,
            stage: CertificateStage::Headers,
            line_count: 0,
            byte_count: 0,
            version: None,
            pusher: None,
            pushee: None,
            nonce: None,
            push_options: Vec::new(),
            signature_lines: Vec::new(),
        }
    }

    fn push_line(
        &mut self,
        line: Vec<u8>,
        context: &ReceiveContext,
    ) -> Result<CertificateProgress, ReceiveError> {
        self.line_count =
            self.line_count
                .checked_add(1)
                .ok_or(ReceiveError::CertificateTooLarge {
                    limit: context.limits.max_certificate_lines,
                })?;
        if self.line_count > context.limits.max_certificate_lines {
            return Err(ReceiveError::CertificateTooLarge {
                limit: context.limits.max_certificate_lines,
            });
        }
        self.byte_count =
            self.byte_count
                .checked_add(line.len())
                .ok_or(ReceiveError::CertificateTooLarge {
                    limit: context.limits.max_certificate_bytes,
                })?;
        if self.byte_count > context.limits.max_certificate_bytes {
            return Err(ReceiveError::CertificateTooLarge {
                limit: context.limits.max_certificate_bytes,
            });
        }
        match self.stage {
            CertificateStage::Headers => self.push_header(line, context),
            CertificateStage::Commands => self.push_command_or_signature(line, context),
            CertificateStage::Signature => self.push_signature(line, context),
        }
    }

    fn push_header(
        &mut self,
        line: Vec<u8>,
        context: &ReceiveContext,
    ) -> Result<CertificateProgress, ReceiveError> {
        if line == b"\n" {
            if self.version.as_deref() != Some(b"0.1".as_slice())
                || self.pusher.is_none()
                || self.pushee.is_none()
                || self.nonce.is_none()
            {
                return Err(ReceiveError::MalformedCertificate);
            }
            self.stage = CertificateStage::Commands;
            return Ok(CertificateProgress::Continue);
        }
        let line = line_without_lf(&line).map_err(ReceiveError::Wire)?;
        if let Some(value) = line.strip_prefix(b"certificate version ") {
            Self::set_once(&mut self.version, value, context)?;
        } else if let Some(value) = line.strip_prefix(b"pusher ") {
            if self.version.is_none() {
                return Err(ReceiveError::MalformedCertificate);
            }
            Self::set_once(&mut self.pusher, value, context)?;
        } else if let Some(value) = line.strip_prefix(b"pushee ") {
            if self.pusher.is_none() {
                return Err(ReceiveError::MalformedCertificate);
            }
            Self::set_once(&mut self.pushee, value, context)?;
        } else if let Some(value) = line.strip_prefix(b"nonce ") {
            if self.pushee.is_none() {
                return Err(ReceiveError::MalformedCertificate);
            }
            if value != self.expected_nonce {
                return Err(ReceiveError::CertificateNonceMismatch);
            }
            Self::set_once(&mut self.nonce, value, context)?;
        } else if let Some(value) = line.strip_prefix(b"push-option ") {
            if self.nonce.is_none() {
                return Err(ReceiveError::MalformedCertificate);
            }
            validate_push_option(value, &context.limits)?;
            self.push_option(value, context)?;
        } else {
            return Err(ReceiveError::MalformedCertificate);
        }
        Ok(CertificateProgress::Continue)
    }

    fn push_command_or_signature(
        &mut self,
        line: Vec<u8>,
        context: &ReceiveContext,
    ) -> Result<CertificateProgress, ReceiveError> {
        if line == b"-----BEGIN PGP SIGNATURE-----\n" {
            self.signature_lines.push(line);
            self.stage = CertificateStage::Signature;
            return Ok(CertificateProgress::Continue);
        }
        let line = line_without_lf(&line).map_err(ReceiveError::Wire)?;
        let (command, capabilities) =
            parse_command_line(line, context.object_format, &context.limits)?;
        if capabilities.is_some() {
            return Err(ReceiveError::CapabilitiesNotFirstCommand);
        }
        Ok(CertificateProgress::Command(command))
    }

    fn push_signature(
        &mut self,
        line: Vec<u8>,
        _context: &ReceiveContext,
    ) -> Result<CertificateProgress, ReceiveError> {
        if line == b"push-cert-end\n" {
            if self.signature_lines.len() < 2
                || self
                    .signature_lines
                    .last()
                    .is_none_or(|line| line.as_slice() != b"-----END PGP SIGNATURE-----\n")
            {
                return Err(ReceiveError::MalformedCertificate);
            }
            let certificate = PushCertificate {
                version: self
                    .version
                    .take()
                    .ok_or(ReceiveError::MalformedCertificate)?,
                pusher: self
                    .pusher
                    .take()
                    .ok_or(ReceiveError::MalformedCertificate)?,
                pushee: self
                    .pushee
                    .take()
                    .ok_or(ReceiveError::MalformedCertificate)?,
                nonce: self
                    .nonce
                    .take()
                    .ok_or(ReceiveError::MalformedCertificate)?,
                push_options: std::mem::take(&mut self.push_options),
                signature_lines: std::mem::take(&mut self.signature_lines),
            };
            return Ok(CertificateProgress::Complete(certificate));
        }
        line_without_lf(&line).map_err(ReceiveError::Wire)?;
        self.signature_lines
            .try_reserve(1)
            .map_err(|_| ReceiveError::AllocationFailure)?;
        self.signature_lines.push(line);
        Ok(CertificateProgress::Continue)
    }

    fn set_once(
        field: &mut Option<Vec<u8>>,
        value: &[u8],
        context: &ReceiveContext,
    ) -> Result<(), ReceiveError> {
        if value.is_empty()
            || value.len() > context.limits.max_certificate_bytes
            || value.iter().any(|byte| !(0x20..=0x7e).contains(byte))
            || field.is_some()
        {
            return Err(ReceiveError::MalformedCertificate);
        }
        *field = Some(value.to_vec());
        Ok(())
    }

    fn push_option(&mut self, value: &[u8], context: &ReceiveContext) -> Result<(), ReceiveError> {
        if self.push_options.len() == context.limits.max_push_options {
            return Err(ReceiveError::TooManyPushOptions {
                limit: context.limits.max_push_options,
            });
        }
        self.push_options
            .try_reserve(1)
            .map_err(|_| ReceiveError::AllocationFailure)?;
        self.push_options.push(value.to_vec());
        Ok(())
    }
}

fn parse_command_line<'line>(
    line: &'line [u8],
    format: GitObjectFormat,
    limits: &ReceiveLimits,
) -> Result<(ReceiveCommand, Option<&'line [u8]>), ReceiveError> {
    let (command, capabilities) = match line.iter().position(|byte| *byte == 0) {
        Some(index) => (&line[..index], Some(&line[index + 1..])),
        None => (line, None),
    };
    if command.contains(&0) || capabilities.is_some_and(|value| value.contains(&0)) {
        return Err(ReceiveError::MalformedCommand {
            line: line.to_vec(),
        });
    }
    let mut fields = command.split(|byte| *byte == b' ');
    let old = fields
        .next()
        .ok_or_else(|| ReceiveError::MalformedCommand {
            line: line.to_vec(),
        })?;
    let new = fields
        .next()
        .ok_or_else(|| ReceiveError::MalformedCommand {
            line: line.to_vec(),
        })?;
    let ref_name = fields
        .next()
        .ok_or_else(|| ReceiveError::MalformedCommand {
            line: line.to_vec(),
        })?;
    if old.is_empty()
        || new.is_empty()
        || ref_name.is_empty()
        || fields.next().is_some()
        || command.starts_with(b" ")
        || command.ends_with(b" ")
    {
        return Err(ReceiveError::MalformedCommand {
            line: line.to_vec(),
        });
    }
    let old = parse_object_id(old, format).map_err(ReceiveError::Wire)?;
    let new = parse_object_id(new, format).map_err(ReceiveError::Wire)?;
    let ref_name = parse_update_ref_name(ref_name, limits)?;
    Ok((ReceiveCommand { old, new, ref_name }, capabilities))
}

fn parse_update_ref_name(value: &[u8], limits: &ReceiveLimits) -> Result<Vec<u8>, ReceiveError> {
    if value.len() > limits.wire.max_ref_name_bytes {
        return Err(ReceiveError::Wire(WireError::RefNameTooLarge {
            limit: limits.wire.max_ref_name_bytes,
        }));
    }
    RefName::try_new(value)
        .map(|name| name.as_bytes().to_vec())
        .map_err(|_| ReceiveError::Wire(WireError::InvalidRefName))
}

fn negotiate_capabilities(
    raw: &[u8],
    server: &Capabilities,
    limits: &WireLimits,
) -> Result<Vec<Capability>, ReceiveError> {
    if raw.is_empty() {
        return Err(ReceiveError::Wire(WireError::EmptyCapability));
    }
    let parsed = Capabilities::parse_v1(raw, limits).map_err(ReceiveError::Wire)?;
    let mut result = Vec::new();
    result
        .try_reserve(parsed.entries().len())
        .map_err(|_| ReceiveError::AllocationFailure)?;
    for capability in parsed.entries() {
        let kind = ReceiveCapability::parse(&capability.name).ok_or_else(|| {
            ReceiveError::UnsupportedCapability {
                capability: capability.name.clone(),
            }
        })?;
        if !server.contains(&capability.name) {
            return Err(ReceiveError::CapabilityNotAdvertised {
                capability: capability.name.clone(),
            });
        }
        validate_capability_value(kind, capability)?;
        result.push(capability.clone());
    }
    Ok(result)
}

fn validate_server_capabilities(
    capabilities: &Capabilities,
    signed_push: &SignedPushProfile,
) -> Result<(), ReceiveError> {
    for capability in capabilities.entries() {
        let kind = ReceiveCapability::parse(&capability.name).ok_or_else(|| {
            ReceiveError::UnsupportedCapability {
                capability: capability.name.clone(),
            }
        })?;
        if kind == ReceiveCapability::PushCert {
            let expected_nonce = signed_push
                .expected_nonce()
                .ok_or(ReceiveError::SignedPushUnsupported)?;
            if capability.value.as_deref() != Some(expected_nonce) {
                return Err(ReceiveError::InvalidLimit {
                    field: "advertised signed push nonce",
                });
            }
        }
        validate_capability_value(kind, capability)?;
    }
    Ok(())
}

fn validate_capability_value(
    kind: ReceiveCapability,
    capability: &Capability,
) -> Result<(), ReceiveError> {
    match kind {
        ReceiveCapability::Agent => {
            if capability.value.as_ref().is_none_or(Vec::is_empty) {
                return Err(ReceiveError::CapabilityValueRequired {
                    capability: capability.name.clone(),
                });
            }
        }
        ReceiveCapability::PushCert => {}
        _ if capability.value.is_some() => {
            return Err(ReceiveError::CapabilityValueForbidden {
                capability: capability.name.clone(),
            });
        }
        _ => {}
    }
    Ok(())
}

fn validate_push_option(value: &[u8], limits: &ReceiveLimits) -> Result<(), ReceiveError> {
    if value.is_empty()
        || value.len() > limits.max_push_option_bytes
        || value
            .iter()
            .any(|byte| *byte == 0 || *byte == b'\r' || *byte == b'\n')
    {
        return Err(ReceiveError::InvalidPushOption);
    }
    Ok(())
}

/// Deterministically emits the v0/v1 receive-pack ref advertisement.
///
/// For an empty repository, Git's `capabilities^{}` pseudo-ref carries the
/// first-ref capability NUL section without inventing a mutable branch.
pub fn advertise_receive_pack(
    refs: Vec<AdvertisedRef>,
    context: &ReceiveContext,
) -> Result<Vec<Packet>, ReceiveError> {
    validate_server_capabilities(&context.server_capabilities, &context.signed_push)?;
    if !refs.is_empty() {
        return V1Advertisement::new(
            refs,
            context.server_capabilities.clone(),
            context.object_format,
            &context.limits.wire,
        )
        .and_then(|advertisement| advertisement.encode(&context.limits.wire))
        .map_err(ReceiveError::Wire);
    }
    let mut line = Vec::new();
    let oid_width = context.object_format.digest_len() * 2;
    line.try_reserve(oid_width.saturating_add(EMPTY_REPOSITORY_CAPABILITY_REF.len() + 2))
        .map_err(|_| ReceiveError::AllocationFailure)?;
    line.resize(oid_width, b'0');
    line.push(b' ');
    line.extend_from_slice(EMPTY_REPOSITORY_CAPABILITY_REF);
    if !context.server_capabilities.entries().is_empty() {
        line.push(0);
        for (index, capability) in context.server_capabilities.entries().iter().enumerate() {
            if index != 0 {
                line.push(b' ');
            }
            line.extend_from_slice(&capability_bytes(capability)?);
        }
    }
    line.push(b'\n');
    let encoded_len = line
        .len()
        .checked_add(4)
        .ok_or(ReceiveError::AllocationFailure)?;
    if encoded_len > context.limits.wire.max_packet_bytes {
        return Err(ReceiveError::Wire(WireError::PacketTooLarge {
            declared: encoded_len,
            limit: context.limits.wire.max_packet_bytes,
        }));
    }
    let mut output = Vec::new();
    let mut used = 0_usize;
    add_output_packet(
        &mut output,
        Packet::Data(line),
        encoded_len,
        &mut used,
        &context.limits.wire,
    )
    .map_err(ReceiveError::Wire)?;
    add_output_packet(
        &mut output,
        Packet::Flush,
        4,
        &mut used,
        &context.limits.wire,
    )
    .map_err(ReceiveError::Wire)?;
    Ok(output)
}

fn capability_bytes(capability: &Capability) -> Result<Vec<u8>, ReceiveError> {
    let value_len = capability.value.as_ref().map_or(0, Vec::len);
    let total = capability
        .name
        .len()
        .checked_add(usize::from(capability.value.is_some()))
        .and_then(|size| size.checked_add(value_len))
        .ok_or(ReceiveError::AllocationFailure)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(total)
        .map_err(|_| ReceiveError::AllocationFailure)?;
    output.extend_from_slice(&capability.name);
    if let Some(value) = &capability.value {
        output.push(b'=');
        output.extend_from_slice(value);
    }
    Ok(output)
}

/// Report-status protocol version selected by client capability negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportStatusMode {
    /// No report-status capability was selected.
    Disabled,
    /// Original `unpack`/`ok`/`ng` records.
    V1,
    /// `report-status-v2`; this implementation emits its compatible v1 core.
    V2,
}

/// Pack-level status recorded before individual ref results.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnpackStatus {
    /// Quarantine structural validation succeeded.
    Ok,
    /// Quarantine or admission rejected the pack before a ref outcome.
    Rejected { message: Vec<u8> },
}

/// One command outcome in the same order as [`ReceiveRequest::commands`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveCommandStatus {
    /// The authority-backed layer accepted this one command.
    Ok,
    /// The authority-backed layer rejected this one command.
    Rejected { message: Vec<u8> },
}

/// Generates deterministic report-status packets without publishing any ref.
pub fn report_status(
    request: &ReceiveRequest,
    unpack: UnpackStatus,
    statuses: &[ReceiveCommandStatus],
    limits: &ReceiveLimits,
) -> Result<Vec<Packet>, ReceiveError> {
    if request.report_status_mode() == ReportStatusMode::Disabled {
        return Ok(Vec::new());
    }
    if statuses.len() != request.commands.len() {
        return Err(ReceiveError::StatusCountMismatch {
            expected: request.commands.len(),
            actual: statuses.len(),
        });
    }
    let statuses = apply_atomic_status(request, statuses);
    let sideband = request.has_capability(b"side-band-64k");
    let mut output = Vec::new();
    let mut used = 0_usize;
    append_report_packet(
        &mut output,
        unpack_record(&unpack, limits)?,
        sideband,
        &mut used,
        limits,
    )?;
    for (command, status) in request.commands.iter().zip(&statuses) {
        append_report_packet(
            &mut output,
            command_record(command, status, limits)?,
            sideband,
            &mut used,
            limits,
        )?;
    }
    add_output_packet(&mut output, Packet::Flush, 4, &mut used, &limits.wire)
        .map_err(ReceiveError::Wire)?;
    Ok(output)
}

fn apply_atomic_status(
    request: &ReceiveRequest,
    statuses: &[ReceiveCommandStatus],
) -> Vec<ReceiveCommandStatus> {
    if request.has_capability(b"atomic")
        && statuses
            .iter()
            .any(|status| matches!(status, ReceiveCommandStatus::Rejected { .. }))
    {
        return vec![
            ReceiveCommandStatus::Rejected {
                message: ATOMIC_FAILURE_MESSAGE.to_vec(),
            };
            statuses.len()
        ];
    }
    statuses.to_vec()
}

fn unpack_record(status: &UnpackStatus, limits: &ReceiveLimits) -> Result<Packet, ReceiveError> {
    let line = match status {
        UnpackStatus::Ok => b"unpack ok\n".to_vec(),
        UnpackStatus::Rejected { message } => status_line(b"unpack ", message, limits)?,
    };
    ensure_outbound_line(&line, limits)?;
    Ok(Packet::Data(line))
}

fn command_record(
    command: &ReceiveCommand,
    status: &ReceiveCommandStatus,
    limits: &ReceiveLimits,
) -> Result<Packet, ReceiveError> {
    let mut line = Vec::new();
    match status {
        ReceiveCommandStatus::Ok => {
            line.extend_from_slice(b"ok ");
            line.extend_from_slice(&command.ref_name);
            line.push(b'\n');
        }
        ReceiveCommandStatus::Rejected { message } => {
            line.extend_from_slice(b"ng ");
            line.extend_from_slice(&command.ref_name);
            line.push(b' ');
            validate_status_message(message, limits)?;
            line.extend_from_slice(message);
            line.push(b'\n');
        }
    }
    ensure_outbound_line(&line, limits)?;
    Ok(Packet::Data(line))
}

fn status_line(
    prefix: &[u8],
    message: &[u8],
    limits: &ReceiveLimits,
) -> Result<Vec<u8>, ReceiveError> {
    validate_status_message(message, limits)?;
    let mut line = Vec::new();
    line.try_reserve(prefix.len().saturating_add(message.len() + 1))
        .map_err(|_| ReceiveError::AllocationFailure)?;
    line.extend_from_slice(prefix);
    line.extend_from_slice(message);
    line.push(b'\n');
    Ok(line)
}

fn validate_status_message(message: &[u8], limits: &ReceiveLimits) -> Result<(), ReceiveError> {
    if message.is_empty()
        || message.len() > limits.max_status_message_bytes
        || message
            .iter()
            .any(|byte| *byte == 0 || *byte == b'\r' || *byte == b'\n')
    {
        return Err(ReceiveError::InvalidStatusMessage);
    }
    Ok(())
}

fn ensure_outbound_line(line: &[u8], limits: &ReceiveLimits) -> Result<(), ReceiveError> {
    let encoded = line
        .len()
        .checked_add(4)
        .ok_or(ReceiveError::AllocationFailure)?;
    if encoded > limits.wire.max_packet_bytes {
        return Err(ReceiveError::Wire(WireError::PacketTooLarge {
            declared: encoded,
            limit: limits.wire.max_packet_bytes,
        }));
    }
    Ok(())
}

fn append_report_packet(
    output: &mut Vec<Packet>,
    packet: Packet,
    sideband: bool,
    used: &mut usize,
    limits: &ReceiveLimits,
) -> Result<(), ReceiveError> {
    let Packet::Data(line) = packet else {
        return Err(ReceiveError::UnexpectedPacket {
            state: ReceivePhase::Complete,
            packet: packet_name(&packet),
        });
    };
    if sideband {
        for packet in encode_sideband_64k(SidebandBand::PackData, &line, &limits.wire)
            .map_err(ReceiveError::Wire)?
        {
            let Packet::Data(data) = packet else {
                return Err(ReceiveError::UnexpectedPacket {
                    state: ReceivePhase::Complete,
                    packet: packet_name(&packet),
                });
            };
            let encoded = data
                .len()
                .checked_add(4)
                .ok_or(ReceiveError::AllocationFailure)?;
            add_output_packet(output, Packet::Data(data), encoded, used, &limits.wire)
                .map_err(ReceiveError::Wire)?;
        }
        return Ok(());
    }
    let encoded = line
        .len()
        .checked_add(4)
        .ok_or(ReceiveError::AllocationFailure)?;
    add_output_packet(output, Packet::Data(line), encoded, used, &limits.wire)
        .map_err(ReceiveError::Wire)
}

/// Typed receive-pack refusal. No variant represents a successful ref update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveError {
    /// Shared pkt-line/capability/ref framing refusal.
    Wire(WireError),
    /// Bounded pack-reader refusal before quarantine handoff.
    Pack(PackError),
    /// Receive-specific bounds are inconsistent.
    InvalidLimit { field: &'static str },
    /// A requested capability has no receive-pack implementation.
    UnsupportedCapability { capability: Vec<u8> },
    /// A known receive capability was not advertised by this server.
    CapabilityNotAdvertised { capability: Vec<u8> },
    /// A capability that requires a value omitted it.
    CapabilityValueRequired { capability: Vec<u8> },
    /// A capability that has no value grammar carried one.
    CapabilityValueForbidden { capability: Vec<u8> },
    /// The client placed capabilities after the first command.
    CapabilitiesNotFirstCommand,
    /// No update command was supplied before flush.
    MissingCommands,
    /// The bounded command ceiling was exceeded.
    TooManyCommands { limit: usize },
    /// Two commands targeted one ref, which is ambiguous under atomic semantics.
    DuplicateRefCommand { ref_name: Vec<u8> },
    /// One command used all-zero old and all-zero new IDs.
    BothObjectIdsZero,
    /// A command did not have exactly old/new/ref fields.
    MalformedCommand { line: Vec<u8> },
    /// A delete command was supplied without negotiated `delete-refs`.
    DeleteRefsNotNegotiated,
    /// A packet/control marker is invalid in the current state.
    UnexpectedPacket {
        state: ReceivePhase,
        packet: &'static str,
    },
    /// A raw-pack suffix arrived before the state entered pack reception.
    UnexpectedPackBytes { state: ReceivePhase },
    /// The caller used a terminal state machine again.
    TerminalState { state: ReceivePhase },
    /// Input ended before the command/push-options flush.
    IncompleteRequest { state: ReceivePhase },
    /// A command requires pack bytes but the transport ended without them.
    PackRequired,
    /// Appending bytes would exceed the local quarantine ceiling.
    QuarantineBytesExceeded { limit: usize },
    /// Push options exceeded their bounded count.
    TooManyPushOptions { limit: usize },
    /// A push option is empty, oversized, or carries a line/control byte.
    InvalidPushOption,
    /// Signed push certificates are disabled in this context.
    SignedPushUnsupported,
    /// A signed push did not negotiate `push-cert`.
    SignedPushCapabilityMissing,
    /// Certificate syntax, ordering, or required fields are invalid.
    MalformedCertificate,
    /// Certificate input ended before its terminating packet.
    CertificateTruncated,
    /// Certificate nonce differs from the profile's exact expected nonce.
    CertificateNonceMismatch,
    /// Certificate line or byte bounds were exceeded.
    CertificateTooLarge { limit: usize },
    /// Cancellation occurred before pack validation/handoff completed.
    Cancelled,
    /// Ref status count does not match command count.
    StatusCountMismatch { expected: usize, actual: usize },
    /// A status diagnostic is empty, oversized, or contains control bytes.
    InvalidStatusMessage,
    /// A bounded allocation failed.
    AllocationFailure,
}

impl Display for ReceiveError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => Display::fmt(error, formatter),
            Self::Pack(error) => Display::fmt(error, formatter),
            Self::InvalidLimit { field } => write!(formatter, "invalid receive limit {field}"),
            Self::UnsupportedCapability { capability } => {
                write!(formatter, "unsupported receive capability {capability:?}")
            }
            Self::CapabilityNotAdvertised { capability } => write!(
                formatter,
                "receive capability was not advertised {capability:?}"
            ),
            Self::CapabilityValueRequired { capability } => {
                write!(formatter, "receive capability needs a value {capability:?}")
            }
            Self::CapabilityValueForbidden { capability } => write!(
                formatter,
                "receive capability forbids a value {capability:?}"
            ),
            Self::CapabilitiesNotFirstCommand => {
                formatter.write_str("receive capabilities occur after the first command")
            }
            Self::MissingCommands => formatter.write_str("receive request has no commands"),
            Self::TooManyCommands { limit } => {
                write!(formatter, "receive command limit {limit} exceeded")
            }
            Self::DuplicateRefCommand { ref_name } => {
                write!(formatter, "duplicate receive command ref {ref_name:?}")
            }
            Self::BothObjectIdsZero => {
                formatter.write_str("receive command cannot use two zero object IDs")
            }
            Self::MalformedCommand { line } => {
                write!(formatter, "malformed receive command {line:?}")
            }
            Self::DeleteRefsNotNegotiated => {
                formatter.write_str("delete command lacks delete-refs capability")
            }
            Self::UnexpectedPacket { state, packet } => write!(
                formatter,
                "packet {packet} is invalid in receive state {state:?}"
            ),
            Self::UnexpectedPackBytes { state } => write!(
                formatter,
                "pack bytes are invalid in receive state {state:?}"
            ),
            Self::TerminalState { state } => {
                write!(formatter, "receive machine is terminal in state {state:?}")
            }
            Self::IncompleteRequest { state } => {
                write!(formatter, "receive request ended in state {state:?}")
            }
            Self::PackRequired => formatter.write_str("receive command list requires a pack"),
            Self::QuarantineBytesExceeded { limit } => {
                write!(formatter, "receive quarantine exceeds {limit} bytes")
            }
            Self::TooManyPushOptions { limit } => {
                write!(formatter, "receive push option limit {limit} exceeded")
            }
            Self::InvalidPushOption => formatter.write_str("invalid receive push option"),
            Self::SignedPushUnsupported => {
                formatter.write_str("signed push certificate is unsupported by this profile")
            }
            Self::SignedPushCapabilityMissing => {
                formatter.write_str("signed push lacks negotiated push-cert capability")
            }
            Self::MalformedCertificate => formatter.write_str("malformed signed push certificate"),
            Self::CertificateTruncated => {
                formatter.write_str("signed push certificate ended before push-cert-end")
            }
            Self::CertificateNonceMismatch => {
                formatter.write_str("signed push certificate nonce mismatch")
            }
            Self::CertificateTooLarge { limit } => write!(
                formatter,
                "signed push certificate exceeds {limit} bytes or lines"
            ),
            Self::Cancelled => formatter.write_str("receive validation cancelled"),
            Self::StatusCountMismatch { expected, actual } => write!(
                formatter,
                "receive status count {actual} differs from command count {expected}"
            ),
            Self::InvalidStatusMessage => formatter.write_str("invalid receive status message"),
            Self::AllocationFailure => formatter.write_str("bounded receive allocation failed"),
        }
    }
}

impl Error for ReceiveError {}

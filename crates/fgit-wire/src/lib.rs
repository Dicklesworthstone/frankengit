#![forbid(unsafe_code)]
//! Bounded, SANS-I/O Git wire-protocol primitives and upload-pack state machines.
//!
//! The crate owns packet framing, capability syntax, fetch request parsing, and
//! the protocol decisions that turn a complete request into an explicit pack
//! request.  It does not own sockets, tasks, repositories, or pack generation.
//! An adapter supplies [`UploadPackRepository`] and later satisfies
//! [`PackPayloadSource`]; this keeps all protocol transitions deterministic and
//! testable over bytes alone.
//!
//! # Compatibility boundary
//!
//! Matched here: Git pkt-line framing (including flush, delimiter, and
//! response-end), bounded v0/v1 advertisements and fetch negotiation,
//! `multi_ack` / `multi_ack_detailed`, v2 `ls-refs` and `fetch` command
//! sections, native SHA-1/SHA-256 object-ID widths, shallow/deepen and the
//! documented object-filter forms, and side-band-64k packet multiplexing.
//! V0/v1 wants are required to have appeared in the advertised refs; v2 wants
//! are instead checked against the repository's canonical permitted closure,
//! matching the protocol-v2 distinction.
//!
//! The [`receive`] module separately implements bounded v0/v1 receive-pack
//! request parsing and structural pack quarantine; authoritative ref admission
//! and publication remain outside this crate. Explicitly unsupported, and
//! refused rather than delegated, are unknown v2 commands/capabilities,
//! unbounded negotiation sets, malformed `deepen` and filter grammar,
//! object-info/bundle-uri/server-option commands, and transport/service-
//! discovery framing. A runtime adapter owns socket cancellation, while a pack
//! implementation owns pack bytes and the eventual thin-pack or delta
//! construction; neither can change these parsed request commitments.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub use fgit_crypto::{AnyGitOid, GitObjectFormat};
pub use fgit_git_object::ObjectType;

use fgit_types::RefName;

/// Bounded shallow-history and partial-clone closure computation.
pub mod closure;
/// Bounded SANS-I/O receive-pack parsing and structural pack quarantine.
pub mod receive;

/// The largest pkt-line frame permitted by Git's common protocol.
pub const MAX_PKT_LINE_BYTES: usize = 65_520;
/// The largest data payload after a pkt-line's four-byte header.
pub const MAX_PKT_LINE_DATA_BYTES: usize = MAX_PKT_LINE_BYTES - 4;
/// The largest sideband payload after its one-byte band designator.
pub const MAX_SIDEBAND_DATA_BYTES: usize = MAX_PKT_LINE_DATA_BYTES - 1;

/// Limits applied before bytes are accumulated or protocol collections grow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireLimits {
    /// Maximum complete pkt-line frame, including its four-byte header.
    pub max_packet_bytes: usize,
    /// Maximum undecoded bytes held by one incremental packet decoder.
    pub max_pending_bytes: usize,
    /// Maximum packets yielded by a single decoder call.
    pub max_packets_per_push: usize,
    /// Maximum serialized bytes in one generated advertisement or response.
    pub max_outbound_bytes: usize,
    /// Maximum capability entries in one advertisement or request.
    pub max_capabilities: usize,
    /// Maximum bytes in one capability token.
    pub max_capability_bytes: usize,
    /// Maximum `want` object IDs in one fetch request.
    pub max_wants: usize,
    /// Maximum `have` object IDs in one fetch request.
    pub max_haves: usize,
    /// Maximum shallow object IDs in one fetch request.
    pub max_shallows: usize,
    /// Maximum ref-prefix arguments in a v2 `ls-refs` request.
    pub max_ref_prefixes: usize,
    /// Maximum refs accepted from or emitted by one advertisement.
    pub max_advertised_refs: usize,
    /// Maximum parts in a `combine:` object filter.
    pub max_filter_parts: usize,
    /// Maximum byte length of an opaque ref name or ref prefix.
    pub max_ref_name_bytes: usize,
}

impl Default for WireLimits {
    fn default() -> Self {
        Self {
            max_packet_bytes: MAX_PKT_LINE_BYTES,
            max_pending_bytes: MAX_PKT_LINE_BYTES * 2,
            max_packets_per_push: 4_096,
            max_outbound_bytes: 64 * 1024 * 1024,
            max_capabilities: 256,
            max_capability_bytes: 4_096,
            max_wants: 16_384,
            max_haves: 65_536,
            max_shallows: 8_192,
            max_ref_prefixes: 1_024,
            max_advertised_refs: 1_000_000,
            max_filter_parts: 32,
            max_ref_name_bytes: 4_096,
        }
    }
}

impl WireLimits {
    fn validate(&self) -> Result<(), WireError> {
        if !(4..=MAX_PKT_LINE_BYTES).contains(&self.max_packet_bytes) {
            return Err(WireError::InvalidLimit {
                field: "max_packet_bytes",
            });
        }
        if self.max_pending_bytes < self.max_packet_bytes {
            return Err(WireError::InvalidLimit {
                field: "max_pending_bytes",
            });
        }
        if self.max_packets_per_push == 0
            || self.max_capabilities == 0
            || self.max_outbound_bytes == 0
            || self.max_capability_bytes == 0
            || self.max_wants == 0
            || self.max_haves == 0
            || self.max_shallows == 0
            || self.max_ref_prefixes == 0
            || self.max_advertised_refs == 0
            || self.max_filter_parts == 0
            || self.max_ref_name_bytes == 0
        {
            return Err(WireError::InvalidLimit {
                field: "non-zero protocol limit",
            });
        }
        Ok(())
    }
}

/// A decoded pkt-line control or data packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    /// A data packet.  An empty vector represents Git's valid `0004` packet.
    Data(Vec<u8>),
    /// `0000`, a message flush.
    Flush,
    /// `0001`, a v2 section delimiter.
    Delimiter,
    /// `0002`, a v2 response end marker.
    ResponseEnd,
}

/// Packets decoded while searching for a receive-pack request flush.
///
/// When `found_flush` is true, `consumed` identifies the first byte after the
/// marker in the supplied input. Callers can pass `&input[consumed..]` to a
/// different protocol parser without copying it into [`PktLineDecoder`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PktLineFlushBoundary {
    /// Complete decoded packets, including the terminating marker when found.
    pub packets: Vec<Packet>,
    /// Bytes consumed from this invocation's input slice.
    pub consumed: usize,
    /// Whether a `0000` flush occurred in this invocation.
    pub found_flush: bool,
}

/// Typed refusal from packet syntax, bounded collection growth, or protocol state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    /// A configured bound is internally inconsistent.
    InvalidLimit { field: &'static str },
    /// The four-byte pkt-line length did not contain hexadecimal ASCII.
    InvalidPacketLengthHex { offset: usize, byte: u8 },
    /// `0003` is reserved and is not a valid pkt-line.
    ReservedPacketLength,
    /// A frame exceeds the declared packet bound.
    PacketTooLarge { declared: usize, limit: usize },
    /// More undecoded bytes would be retained than the declared bound permits.
    PendingBytesExceeded { limit: usize },
    /// A single call would return too many decoded packets.
    PacketCountExceeded { limit: usize },
    /// A generated response would exceed its configured byte budget.
    OutboundBytesExceeded { limit: usize },
    /// Input ended with a partial pkt-line frame.
    TruncatedPacket { pending: usize },
    /// A bounded allocation failed.
    AllocationFailure,
    /// A line was required to end with LF.
    MissingLineFeed,
    /// A protocol token contained a forbidden byte.
    InvalidToken {
        field: &'static str,
        offset: usize,
        byte: u8,
    },
    /// A capability token had no valid name.
    EmptyCapability,
    /// A capability exceeded its configured byte limit.
    CapabilityTooLarge { limit: usize },
    /// A capability set exceeded its configured entry count.
    TooManyCapabilities { limit: usize },
    /// A capability was listed more than once where Git requires one meaning.
    DuplicateCapability { name: Vec<u8> },
    /// The protocol version declaration was absent or malformed.
    InvalidVersionAdvertisement,
    /// A request command was not supported by this machine.
    UnsupportedCommand { command: Vec<u8> },
    /// A command phase received an illegal packet/control marker.
    IllegalTransition {
        state: &'static str,
        packet: &'static str,
    },
    /// A command line was malformed.
    MalformedRequestLine { line: Vec<u8> },
    /// An object ID did not have the repository format's lowercase hex shape.
    InvalidObjectId { algorithm: GitObjectFormat },
    /// A request used an object identity from a different repository format.
    ObjectFormatMismatch {
        expected: GitObjectFormat,
        observed: GitObjectFormat,
    },
    /// A v0/v1 `want` did not occur in the advertised ref set.
    WantNotAdvertised { oid: AnyGitOid },
    /// A v2 `want` was neither advertised nor permitted by the repository closure.
    WantNotReachable { oid: AnyGitOid },
    /// A request repeated a `want`, `have`, or shallow identity.
    DuplicateObjectId { field: &'static str, oid: AnyGitOid },
    /// A bounded request collection has reached its limit.
    TooManyObjectIds { field: &'static str, limit: usize },
    /// A request attempted `have` or `done` before any `want`.
    MissingWant,
    /// A requested capability is not advertised by this server.
    UnknownCapability { capability: Vec<u8> },
    /// A deepen depth used a negative sign.
    NegativeDepth,
    /// A deepen depth was not decimal ASCII or overflowed its target width.
    InvalidDepth,
    /// A `deepen-since` timestamp was not a non-negative decimal Unix time.
    InvalidTimestamp,
    /// A `deepen-not` ref was not available from the canonical advertisement.
    UnknownDeepenNotRef { name: Vec<u8> },
    /// A filter grammar was unsupported or malformed.
    InvalidFilter { filter: Vec<u8> },
    /// A filter contained more parts than the configured ceiling.
    TooManyFilterParts { limit: usize },
    /// A ref name/prefix exceeded its bounded opaque-byte limit.
    RefNameTooLarge { limit: usize },
    /// A ref name contains a NUL or line terminator and cannot appear on wire.
    InvalidRefName,
    /// A ref advertisement exceeded its configured count limit.
    TooManyAdvertisedRefs { limit: usize },
    /// Advertisement refs must be deterministic and duplicate-free.
    UnsortedOrDuplicateAdvertisement,
    /// A sideband frame did not contain its one-byte band designator.
    MissingSidebandBand,
    /// A sideband frame used a band other than 1, 2, or 3.
    InvalidSidebandBand { band: u8 },
    /// A pack source returned a chunk larger than its requested ceiling.
    PackChunkTooLarge { observed: usize, limit: usize },
    /// The deferred pack source reported a typed refusal.
    PackSourceRefused,
}

impl Display for WireError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "invalid wire limit {field}"),
            Self::InvalidPacketLengthHex { offset, byte } => {
                write!(
                    formatter,
                    "pkt-line length byte {byte:#x} at offset {offset} is not hex"
                )
            }
            Self::ReservedPacketLength => formatter.write_str("pkt-line length 0003 is reserved"),
            Self::PacketTooLarge { declared, limit } => {
                write!(
                    formatter,
                    "pkt-line length {declared} exceeds {limit}-byte limit"
                )
            }
            Self::PendingBytesExceeded { limit } => {
                write!(
                    formatter,
                    "pkt-line pending bytes exceed {limit}-byte limit"
                )
            }
            Self::PacketCountExceeded { limit } => {
                write!(formatter, "pkt-line count exceeds {limit}-packet limit")
            }
            Self::OutboundBytesExceeded { limit } => {
                write!(formatter, "wire response exceeds {limit}-byte limit")
            }
            Self::TruncatedPacket { pending } => {
                write!(
                    formatter,
                    "input ended with {pending} pending pkt-line bytes"
                )
            }
            Self::AllocationFailure => formatter.write_str("bounded wire allocation failed"),
            Self::MissingLineFeed => formatter.write_str("protocol line lacks trailing LF"),
            Self::InvalidToken {
                field,
                offset,
                byte,
            } => {
                write!(
                    formatter,
                    "invalid {field} byte {byte:#x} at offset {offset}"
                )
            }
            Self::EmptyCapability => formatter.write_str("capability name is empty"),
            Self::CapabilityTooLarge { limit } => {
                write!(formatter, "capability exceeds {limit} bytes")
            }
            Self::TooManyCapabilities { limit } => {
                write!(formatter, "too many capabilities; limit {limit}")
            }
            Self::DuplicateCapability { name } => {
                write!(formatter, "duplicate capability {name:?}")
            }
            Self::InvalidVersionAdvertisement => {
                formatter.write_str("invalid protocol-v2 advertisement")
            }
            Self::UnsupportedCommand { command } => {
                write!(formatter, "unsupported v2 command {command:?}")
            }
            Self::IllegalTransition { state, packet } => {
                write!(formatter, "cannot accept {packet} in {state}")
            }
            Self::MalformedRequestLine { line } => {
                write!(formatter, "malformed request line {line:?}")
            }
            Self::InvalidObjectId { algorithm } => {
                write!(formatter, "invalid {algorithm} object ID")
            }
            Self::ObjectFormatMismatch { expected, observed } => {
                write!(
                    formatter,
                    "object format mismatch: expected {expected}, observed {observed}"
                )
            }
            Self::WantNotAdvertised { oid } => write!(formatter, "want {oid:?} was not advertised"),
            Self::WantNotReachable { oid } => write!(formatter, "want {oid:?} is not reachable"),
            Self::DuplicateObjectId { field, oid } => {
                write!(formatter, "duplicate {field} object ID {oid:?}")
            }
            Self::TooManyObjectIds { field, limit } => {
                write!(formatter, "too many {field} IDs; limit {limit}")
            }
            Self::MissingWant => formatter.write_str("request needs a want before have or done"),
            Self::UnknownCapability { capability } => {
                write!(formatter, "unknown capability {capability:?}")
            }
            Self::NegativeDepth => formatter.write_str("deepen depth cannot be negative"),
            Self::InvalidDepth => formatter.write_str("invalid deepen depth"),
            Self::InvalidTimestamp => formatter.write_str("invalid deepen-since timestamp"),
            Self::UnknownDeepenNotRef { name } => {
                write!(formatter, "unknown deepen-not ref {name:?}")
            }
            Self::InvalidFilter { filter } => write!(formatter, "invalid object filter {filter:?}"),
            Self::TooManyFilterParts { limit } => {
                write!(formatter, "too many filter parts; limit {limit}")
            }
            Self::RefNameTooLarge { limit } => write!(formatter, "ref name exceeds {limit} bytes"),
            Self::InvalidRefName => formatter.write_str("invalid ref name bytes"),
            Self::TooManyAdvertisedRefs { limit } => {
                write!(formatter, "too many advertised refs; limit {limit}")
            }
            Self::UnsortedOrDuplicateAdvertisement => {
                formatter.write_str("advertisement refs are unsorted or duplicate")
            }
            Self::MissingSidebandBand => formatter.write_str("sideband packet lacks a band byte"),
            Self::InvalidSidebandBand { band } => write!(formatter, "invalid sideband band {band}"),
            Self::PackChunkTooLarge { observed, limit } => {
                write!(formatter, "pack chunk {observed} exceeds {limit}")
            }
            Self::PackSourceRefused => formatter.write_str("pack source refused to yield a chunk"),
        }
    }
}

impl Error for WireError {}

/// Incremental, bounded pkt-line decoder.
#[derive(Clone, Debug)]
pub struct PktLineDecoder {
    limits: WireLimits,
    pending: Vec<u8>,
}

impl PktLineDecoder {
    /// Creates an incremental decoder after checking its bounds.
    pub fn new(limits: WireLimits) -> Result<Self, WireError> {
        limits.validate()?;
        Ok(Self {
            limits,
            pending: Vec::new(),
        })
    }

    /// Appends bytes and returns every complete packet now available.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Packet>, WireError> {
        self.append(bytes)?;

        let mut packets = Vec::new();
        loop {
            if self.pending.len() >= 4 {
                self.check_packet_count(packets.len())?;
            }
            let Some((packet, consumed)) = self.decode_complete_packet()? else {
                break;
            };
            self.pending.drain(..consumed);
            packets.push(packet);
        }
        Ok(packets)
    }

    /// Decodes only through the first flush, leaving any later input outside
    /// this decoder for the caller to process as another protocol phase.
    ///
    /// Unlike [`Self::push`], this method appends only bytes necessary to
    /// complete the next pkt-line. This lets a receive-pack adapter retain a
    /// borrowed `PACK` suffix rather than allocating or misparsing it as a
    /// pkt-line. Partial pkt-lines still remain subject to
    /// [`WireLimits::max_pending_bytes`].
    pub fn push_until_flush(&mut self, bytes: &[u8]) -> Result<PktLineFlushBoundary, WireError> {
        let mut consumed = 0_usize;
        let mut packets = Vec::new();

        loop {
            self.fill_to_frame_boundary(bytes, &mut consumed)?;
            if self.pending.len() >= 4 {
                self.check_packet_count(packets.len())?;
            }
            let Some((packet, frame_len)) = self.decode_complete_packet()? else {
                return Ok(PktLineFlushBoundary {
                    packets,
                    consumed,
                    found_flush: false,
                });
            };
            self.pending.drain(..frame_len);
            let found_flush = matches!(packet, Packet::Flush);
            packets.push(packet);
            if found_flush {
                return Ok(PktLineFlushBoundary {
                    packets,
                    consumed,
                    found_flush: true,
                });
            }
        }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        let available = self
            .limits
            .max_pending_bytes
            .saturating_sub(self.pending.len());
        if bytes.len() > available {
            return Err(WireError::PendingBytesExceeded {
                limit: self.limits.max_pending_bytes,
            });
        }
        self.pending
            .try_reserve(bytes.len())
            .map_err(|_| WireError::AllocationFailure)?;
        self.pending.extend_from_slice(bytes);
        Ok(())
    }

    fn fill_to_frame_boundary(
        &mut self,
        bytes: &[u8],
        consumed: &mut usize,
    ) -> Result<(), WireError> {
        loop {
            let target_len = if self.pending.len() < 4 {
                4
            } else {
                let length = parse_packet_length(&self.pending[..4])?;
                match length {
                    0..=2 => 4,
                    3 => return Err(WireError::ReservedPacketLength),
                    _ if length > self.limits.max_packet_bytes => {
                        return Err(WireError::PacketTooLarge {
                            declared: length,
                            limit: self.limits.max_packet_bytes,
                        });
                    }
                    _ => length,
                }
            };

            if self.pending.len() >= target_len || *consumed == bytes.len() {
                return Ok(());
            }

            let needed = target_len - self.pending.len();
            let available = bytes.len() - *consumed;
            let take = needed.min(available);
            self.append(&bytes[*consumed..*consumed + take])?;
            *consumed += take;
        }
    }

    fn decode_complete_packet(&self) -> Result<Option<(Packet, usize)>, WireError> {
        if self.pending.len() < 4 {
            return Ok(None);
        }
        let length = parse_packet_length(&self.pending[..4])?;
        let (packet, consumed) = match length {
            0 => (Packet::Flush, 4),
            1 => (Packet::Delimiter, 4),
            2 => (Packet::ResponseEnd, 4),
            3 => return Err(WireError::ReservedPacketLength),
            _ => {
                if length > self.limits.max_packet_bytes {
                    return Err(WireError::PacketTooLarge {
                        declared: length,
                        limit: self.limits.max_packet_bytes,
                    });
                }
                if self.pending.len() < length {
                    return Ok(None);
                }
                let payload_len = length - 4;
                let mut payload = Vec::new();
                payload
                    .try_reserve_exact(payload_len)
                    .map_err(|_| WireError::AllocationFailure)?;
                payload.extend_from_slice(&self.pending[4..length]);
                (Packet::Data(payload), length)
            }
        };
        Ok(Some((packet, consumed)))
    }

    const fn check_packet_count(&self, decoded_count: usize) -> Result<(), WireError> {
        if decoded_count == self.limits.max_packets_per_push {
            return Err(WireError::PacketCountExceeded {
                limit: self.limits.max_packets_per_push,
            });
        }
        Ok(())
    }

    /// Refuses a byte stream that ends between packet boundaries.
    pub const fn finish(&self) -> Result<(), WireError> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(WireError::TruncatedPacket {
                pending: self.pending.len(),
            })
        }
    }

    /// Returns the number of bytes waiting for a complete frame.
    #[must_use]
    pub const fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

fn parse_packet_length(header: &[u8]) -> Result<usize, WireError> {
    let mut output = 0_usize;
    for (offset, byte) in header.iter().copied().enumerate() {
        let digit = match byte {
            b'0'..=b'9' => usize::from(byte - b'0'),
            b'a'..=b'f' => usize::from(byte - b'a' + 10),
            b'A'..=b'F' => usize::from(byte - b'A' + 10),
            _ => return Err(WireError::InvalidPacketLengthHex { offset, byte }),
        };
        output = output
            .checked_mul(16)
            .and_then(|value| value.checked_add(digit))
            .ok_or(WireError::PacketTooLarge {
                declared: usize::MAX,
                limit: MAX_PKT_LINE_BYTES,
            })?;
    }
    Ok(output)
}

/// Encodes one packet with Git's lowercase four-hex-digit length prefix.
pub fn encode_packet(packet: &Packet, limits: &WireLimits) -> Result<Vec<u8>, WireError> {
    limits.validate()?;
    let payload = match packet {
        Packet::Data(payload) => Some(payload.as_slice()),
        Packet::Flush | Packet::Delimiter | Packet::ResponseEnd => None,
    };
    let special = match packet {
        Packet::Flush => Some(*b"0000"),
        Packet::Delimiter => Some(*b"0001"),
        Packet::ResponseEnd => Some(*b"0002"),
        Packet::Data(_) => None,
    };
    if let Some(header) = special {
        return Ok(header.to_vec());
    }
    let payload = payload.ok_or(WireError::IllegalTransition {
        state: "packet encoding",
        packet: "absent payload",
    })?;
    let total = payload
        .len()
        .checked_add(4)
        .ok_or(WireError::PacketTooLarge {
            declared: usize::MAX,
            limit: limits.max_packet_bytes,
        })?;
    if total > limits.max_packet_bytes {
        return Err(WireError::PacketTooLarge {
            declared: total,
            limit: limits.max_packet_bytes,
        });
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(total)
        .map_err(|_| WireError::AllocationFailure)?;
    let header = format_packet_length(total);
    output.extend_from_slice(&header);
    output.extend_from_slice(payload);
    Ok(output)
}

/// Encodes a finite packet sequence without invoking I/O.
pub fn encode_packets(packets: &[Packet], limits: &WireLimits) -> Result<Vec<u8>, WireError> {
    let mut output = Vec::new();
    for packet in packets {
        let encoded = encode_packet(packet, limits)?;
        if encoded.len() > limits.max_outbound_bytes.saturating_sub(output.len()) {
            return Err(WireError::OutboundBytesExceeded {
                limit: limits.max_outbound_bytes,
            });
        }
        output
            .try_reserve(encoded.len())
            .map_err(|_| WireError::AllocationFailure)?;
        output.extend_from_slice(&encoded);
    }
    Ok(output)
}

fn add_output_packet(
    output: &mut Vec<Packet>,
    packet: Packet,
    encoded_bytes: usize,
    used_bytes: &mut usize,
    limits: &WireLimits,
) -> Result<(), WireError> {
    let available = limits.max_outbound_bytes.saturating_sub(*used_bytes);
    if encoded_bytes > available {
        return Err(WireError::OutboundBytesExceeded {
            limit: limits.max_outbound_bytes,
        });
    }
    output
        .try_reserve(1)
        .map_err(|_| WireError::AllocationFailure)?;
    output.push(packet);
    *used_bytes += encoded_bytes;
    Ok(())
}

const fn format_packet_length(length: usize) -> [u8; 4] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    [
        HEX[(length >> 12) & 0xf],
        HEX[(length >> 8) & 0xf],
        HEX[(length >> 4) & 0xf],
        HEX[length & 0xf],
    ]
}

/// One capability with an ASCII name and an optional opaque ASCII value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capability {
    /// Capability key as supplied on wire.
    pub name: Vec<u8>,
    /// Optional value after the first equals sign.
    pub value: Option<Vec<u8>>,
}

impl Capability {
    /// Parses an ASCII `name` or `name=value` capability without accepting controls.
    pub fn parse(token: &[u8], limits: &WireLimits) -> Result<Self, WireError> {
        Self::parse_with_spaces(token, limits, false)
    }

    /// Parses a v2 capability, whose value may contain printable spaces.
    pub fn parse_v2(token: &[u8], limits: &WireLimits) -> Result<Self, WireError> {
        Self::parse_with_spaces(token, limits, true)
    }

    fn parse_with_spaces(
        token: &[u8],
        limits: &WireLimits,
        allow_value_spaces: bool,
    ) -> Result<Self, WireError> {
        if token.is_empty() {
            return Err(WireError::EmptyCapability);
        }
        if token.len() > limits.max_capability_bytes {
            return Err(WireError::CapabilityTooLarge {
                limit: limits.max_capability_bytes,
            });
        }
        let split = token.iter().position(|byte| *byte == b'=');
        let (name, value) = split.map_or((token, None), |index| {
            (&token[..index], Some(&token[index + 1..]))
        });
        if name.is_empty() {
            return Err(WireError::EmptyCapability);
        }
        for (offset, byte) in name.iter().copied().enumerate() {
            if !(0x21..=0x7e).contains(&byte) || byte == b'=' {
                return Err(WireError::InvalidToken {
                    field: "capability",
                    offset,
                    byte,
                });
            }
        }
        if let Some(value) = value {
            for (offset, byte) in value.iter().copied().enumerate() {
                let permitted = if allow_value_spaces {
                    (0x20..=0x7e).contains(&byte)
                } else {
                    (0x21..=0x7e).contains(&byte)
                };
                if !permitted {
                    return Err(WireError::InvalidToken {
                        field: "capability value",
                        offset,
                        byte,
                    });
                }
            }
        }
        Ok(Self {
            name: name.to_vec(),
            value: value.map(ToOwned::to_owned),
        })
    }

    fn encoded(&self) -> Result<Vec<u8>, WireError> {
        let value_len = self.value.as_ref().map_or(0, Vec::len);
        let separator = usize::from(self.value.is_some());
        let total = self
            .name
            .len()
            .checked_add(separator)
            .and_then(|length| length.checked_add(value_len))
            .ok_or(WireError::AllocationFailure)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(total)
            .map_err(|_| WireError::AllocationFailure)?;
        output.extend_from_slice(&self.name);
        if let Some(value) = &self.value {
            output.push(b'=');
            output.extend_from_slice(value);
        }
        Ok(output)
    }
}

/// Order-preserving, duplicate-free capability set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Capabilities {
    entries: Vec<Capability>,
}

impl Capabilities {
    /// Parses whitespace-separated v0/v1 capability tokens.
    pub fn parse_v1(tokens: &[u8], limits: &WireLimits) -> Result<Self, WireError> {
        let mut capabilities = Self::default();
        for token in tokens.split(|byte| *byte == b' ') {
            if token.is_empty() {
                return Err(WireError::EmptyCapability);
            }
            capabilities.insert(Capability::parse(token, limits)?, limits)?;
        }
        Ok(capabilities)
    }

    /// Parses v2 capability advertisement packets, beginning with `version 2`.
    pub fn parse_v2_advertisement(
        packets: &[Packet],
        limits: &WireLimits,
    ) -> Result<Self, WireError> {
        let Some(Packet::Data(version)) = packets.first() else {
            return Err(WireError::InvalidVersionAdvertisement);
        };
        if version.as_slice() != b"version 2\n" {
            return Err(WireError::InvalidVersionAdvertisement);
        }
        let mut capabilities = Self::default();
        let mut saw_flush = false;
        for (index, packet) in packets[1..].iter().enumerate() {
            match packet {
                Packet::Data(line) => {
                    let token = line_without_lf(line)?;
                    capabilities.insert(Capability::parse_v2(token, limits)?, limits)?;
                }
                Packet::Flush => {
                    if index + 2 != packets.len() {
                        return Err(WireError::IllegalTransition {
                            state: "v2 advertisement after flush",
                            packet: packet_name(&packets[index + 2]),
                        });
                    }
                    saw_flush = true;
                    break;
                }
                Packet::Delimiter | Packet::ResponseEnd => {
                    return Err(WireError::IllegalTransition {
                        state: "v2 advertisement",
                        packet: packet_name(packet),
                    });
                }
            }
        }
        if !saw_flush {
            return Err(WireError::InvalidVersionAdvertisement);
        }
        Ok(capabilities)
    }

    /// Returns whether an advertised capability key is present.
    #[must_use]
    pub fn contains(&self, name: &[u8]) -> bool {
        self.entries.iter().any(|entry| entry.name == name)
    }

    /// Preserves original wire order for deterministic re-emission.
    #[must_use]
    pub fn entries(&self) -> &[Capability] {
        &self.entries
    }

    /// Encodes a v2 advertisement beginning with `version 2` and ending flush.
    pub fn encode_v2_advertisement(&self, limits: &WireLimits) -> Result<Vec<Packet>, WireError> {
        let mut output = Vec::new();
        let mut used_bytes = 0_usize;
        output
            .try_reserve(self.entries.len().saturating_add(2))
            .map_err(|_| WireError::AllocationFailure)?;
        add_output_packet(
            &mut output,
            Packet::Data(b"version 2\n".to_vec()),
            b"version 2\n".len() + 4,
            &mut used_bytes,
            limits,
        )?;
        for capability in &self.entries {
            let mut line = capability.encoded()?;
            line.try_reserve(1)
                .map_err(|_| WireError::AllocationFailure)?;
            line.push(b'\n');
            if line.len() + 4 > limits.max_packet_bytes {
                return Err(WireError::PacketTooLarge {
                    declared: line.len() + 4,
                    limit: limits.max_packet_bytes,
                });
            }
            let encoded_bytes = line.len() + 4;
            add_output_packet(
                &mut output,
                Packet::Data(line),
                encoded_bytes,
                &mut used_bytes,
                limits,
            )?;
        }
        add_output_packet(&mut output, Packet::Flush, 4, &mut used_bytes, limits)?;
        Ok(output)
    }

    fn insert(&mut self, capability: Capability, limits: &WireLimits) -> Result<(), WireError> {
        if self.entries.len() == limits.max_capabilities {
            return Err(WireError::TooManyCapabilities {
                limit: limits.max_capabilities,
            });
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.name == capability.name)
        {
            return Err(WireError::DuplicateCapability {
                name: capability.name,
            });
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| WireError::AllocationFailure)?;
        self.entries.push(capability);
        Ok(())
    }
}

fn line_without_lf(line: &[u8]) -> Result<&[u8], WireError> {
    let Some((&b'\n', text)) = line.split_last() else {
        return Err(WireError::MissingLineFeed);
    };
    if text.contains(&b'\n') || text.contains(&b'\r') || text.contains(&0) {
        return Err(WireError::MalformedRequestLine {
            line: line.to_vec(),
        });
    }
    Ok(text)
}

const fn packet_name(packet: &Packet) -> &'static str {
    match packet {
        Packet::Data(_) => "data",
        Packet::Flush => "flush",
        Packet::Delimiter => "delimiter",
        Packet::ResponseEnd => "response end",
    }
}

/// Sideband stream class in `side-band` and `side-band-64k` modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SidebandBand {
    /// Pack bytes.
    PackData,
    /// Informational progress bytes.
    Progress,
    /// Fatal remote error bytes.
    Fatal,
}

impl SidebandBand {
    const fn byte(self) -> u8 {
        match self {
            Self::PackData => 1,
            Self::Progress => 2,
            Self::Fatal => 3,
        }
    }

    const fn parse(byte: u8) -> Result<Self, WireError> {
        match byte {
            1 => Ok(Self::PackData),
            2 => Ok(Self::Progress),
            3 => Ok(Self::Fatal),
            _ => Err(WireError::InvalidSidebandBand { band: byte }),
        }
    }
}

/// One decoded sideband payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SidebandFrame {
    /// The stream class selected by the leading byte.
    pub band: SidebandBand,
    /// Opaque bytes after the band designator.
    pub data: Vec<u8>,
}

/// Decodes a pkt-line data packet as a sideband frame.
pub fn parse_sideband(packet: &Packet) -> Result<SidebandFrame, WireError> {
    let Packet::Data(payload) = packet else {
        return Err(WireError::IllegalTransition {
            state: "sideband",
            packet: packet_name(packet),
        });
    };
    let Some((band, data)) = payload.split_first() else {
        return Err(WireError::MissingSidebandBand);
    };
    Ok(SidebandFrame {
        band: SidebandBand::parse(*band)?,
        data: data.to_vec(),
    })
}

/// Encodes a sideband payload into bounded pkt-line data packets.
pub fn encode_sideband_64k(
    band: SidebandBand,
    data: &[u8],
    limits: &WireLimits,
) -> Result<Vec<Packet>, WireError> {
    limits.validate()?;
    let payload_limit = limits
        .max_packet_bytes
        .checked_sub(5)
        .ok_or(WireError::InvalidLimit {
            field: "max_packet_bytes for sideband",
        })?;
    if payload_limit == 0 {
        return Err(WireError::InvalidLimit {
            field: "max_packet_bytes for sideband",
        });
    }
    let mut output = Vec::new();
    let chunks = data.chunks(payload_limit);
    output
        .try_reserve(chunks.len().max(1))
        .map_err(|_| WireError::AllocationFailure)?;
    if data.is_empty() {
        output.push(Packet::Data(vec![band.byte()]));
        return Ok(output);
    }
    for chunk in chunks {
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(chunk.len() + 1)
            .map_err(|_| WireError::AllocationFailure)?;
        payload.push(band.byte());
        payload.extend_from_slice(chunk);
        output.push(Packet::Data(payload));
    }
    Ok(output)
}

/// Parsed Git partial-clone filter grammar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectFilter {
    /// Omit all blobs.
    BlobNone,
    /// Include blobs no larger than this byte count.
    BlobLimit(u64),
    /// Include trees no deeper than this depth.
    TreeDepth(u32),
    /// Request a sparse path expression.
    SparsePath(Vec<u8>),
    /// Request a sparse specification object.
    SparseObject(AnyGitOid),
    /// Conjunction of filter terms.
    Combine(Vec<Self>),
}

/// Parses one bounded upload-pack `filter` value.
pub fn parse_filter(
    text: &[u8],
    object_format: GitObjectFormat,
    limits: &WireLimits,
) -> Result<ObjectFilter, WireError> {
    parse_filter_at_depth(text, object_format, limits, 0)
}

fn parse_filter_at_depth(
    text: &[u8],
    object_format: GitObjectFormat,
    limits: &WireLimits,
    depth: usize,
) -> Result<ObjectFilter, WireError> {
    if text == b"blob:none" {
        return Ok(ObjectFilter::BlobNone);
    }
    if let Some(value) = text.strip_prefix(b"blob:limit=") {
        return parse_unsigned(value)
            .map(ObjectFilter::BlobLimit)
            .map_err(|()| WireError::InvalidFilter {
                filter: text.to_vec(),
            });
    }
    if let Some(value) = text.strip_prefix(b"tree:") {
        let depth = parse_unsigned(value).map_err(|()| WireError::InvalidFilter {
            filter: text.to_vec(),
        })?;
        return u32::try_from(depth)
            .map(ObjectFilter::TreeDepth)
            .map_err(|_| WireError::InvalidFilter {
                filter: text.to_vec(),
            });
    }
    if let Some(value) = text.strip_prefix(b"sparse:oid=") {
        return parse_object_id(value, object_format).map(ObjectFilter::SparseObject);
    }
    if let Some(value) = text.strip_prefix(b"sparse:path=") {
        validate_opaque_path(value, limits)?;
        return Ok(ObjectFilter::SparsePath(value.to_vec()));
    }
    if let Some(value) = text.strip_prefix(b"combine:") {
        if depth == limits.max_filter_parts {
            return Err(WireError::TooManyFilterParts {
                limit: limits.max_filter_parts,
            });
        }
        let mut parts = Vec::new();
        for part in value.split(|byte| *byte == b'+') {
            if part.is_empty() {
                return Err(WireError::InvalidFilter {
                    filter: text.to_vec(),
                });
            }
            if parts.len() == limits.max_filter_parts {
                return Err(WireError::TooManyFilterParts {
                    limit: limits.max_filter_parts,
                });
            }
            parts
                .try_reserve(1)
                .map_err(|_| WireError::AllocationFailure)?;
            parts.push(parse_filter_at_depth(
                part,
                object_format,
                limits,
                depth + 1,
            )?);
        }
        if parts.is_empty() {
            return Err(WireError::InvalidFilter {
                filter: text.to_vec(),
            });
        }
        return Ok(ObjectFilter::Combine(parts));
    }
    Err(WireError::InvalidFilter {
        filter: text.to_vec(),
    })
}

fn validate_opaque_path(path: &[u8], limits: &WireLimits) -> Result<(), WireError> {
    if path.is_empty() || path.len() > limits.max_ref_name_bytes {
        return Err(WireError::InvalidFilter {
            filter: path.to_vec(),
        });
    }
    if path
        .iter()
        .any(|byte| *byte == 0 || *byte == b'\n' || *byte == b'\r')
    {
        return Err(WireError::InvalidFilter {
            filter: path.to_vec(),
        });
    }
    Ok(())
}

fn parse_unsigned(text: &[u8]) -> Result<u64, ()> {
    if text.is_empty() {
        return Err(());
    }
    let mut value = 0_u64;
    for byte in text {
        if !byte.is_ascii_digit() {
            return Err(());
        }
        value = value
            .checked_mul(10)
            .and_then(|number| number.checked_add(u64::from(*byte - b'0')))
            .ok_or(())?;
    }
    Ok(value)
}

fn parse_depth(text: &[u8]) -> Result<u32, WireError> {
    if text.starts_with(b"-") {
        return Err(WireError::NegativeDepth);
    }
    let depth = parse_unsigned(text).map_err(|()| WireError::InvalidDepth)?;
    let depth = u32::try_from(depth).map_err(|_| WireError::InvalidDepth)?;
    if depth == 0 {
        return Err(WireError::InvalidDepth);
    }
    Ok(depth)
}

fn parse_timestamp(text: &[u8]) -> Result<i64, WireError> {
    let timestamp = parse_unsigned(text).map_err(|()| WireError::InvalidTimestamp)?;
    i64::try_from(timestamp).map_err(|_| WireError::InvalidTimestamp)
}

fn parse_object_id(text: &[u8], algorithm: GitObjectFormat) -> Result<AnyGitOid, WireError> {
    let expected = algorithm.digest_len() * 2;
    if text.len() != expected || !text.iter().all(u8::is_ascii_lowercase_or_digit) {
        return Err(WireError::InvalidObjectId { algorithm });
    }
    let string = std::str::from_utf8(text).map_err(|_| WireError::InvalidObjectId { algorithm })?;
    AnyGitOid::from_hex(algorithm, string).map_err(|_| WireError::InvalidObjectId { algorithm })
}

trait AsciiLowercaseOrDigit {
    fn is_ascii_lowercase_or_digit(&self) -> bool;
}

impl AsciiLowercaseOrDigit for u8 {
    fn is_ascii_lowercase_or_digit(&self) -> bool {
        self.is_ascii_digit() || self.is_ascii_lowercase()
    }
}

fn parse_ref_name(text: &[u8], limits: &WireLimits) -> Result<Vec<u8>, WireError> {
    if text.len() > limits.max_ref_name_bytes {
        return Err(WireError::RefNameTooLarge {
            limit: limits.max_ref_name_bytes,
        });
    }
    RefName::try_new_one_level(text)
        .map(|name| name.as_bytes().to_vec())
        .map_err(|_| WireError::InvalidRefName)
}

fn parse_ref_prefix(text: &[u8], limits: &WireLimits) -> Result<Vec<u8>, WireError> {
    if text.is_empty() || text.len() > limits.max_ref_name_bytes {
        return Err(WireError::RefNameTooLarge {
            limit: limits.max_ref_name_bytes,
        });
    }
    if text
        .iter()
        .any(|byte| *byte == 0 || *byte == b'\n' || *byte == b'\r')
    {
        return Err(WireError::InvalidRefName);
    }
    Ok(text.to_vec())
}

/// Upload-pack generation used by the request state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadPackVersion {
    /// The original protocol without a version declaration.
    V0,
    /// Protocol v1, which uses the v0 packet grammar after its declaration.
    V1,
    /// Protocol v2 command sections.
    V2,
}

/// Multi-ack behavior chosen by the client's advertised request capabilities.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AckMode {
    /// Only the final common object is acknowledged.
    #[default]
    None,
    /// Each common object is reported with `continue`.
    MultiAck,
    /// Each common object is reported with `common`, then `ready` when done.
    MultiAckDetailed,
}

/// A repository ref exposed by upload-pack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvertisedRef {
    /// Canonical native object identity.
    pub oid: AnyGitOid,
    /// Opaque Git ref name, excluding LF and NUL.
    pub name: Vec<u8>,
}

impl AdvertisedRef {
    /// Constructs a bounded wire-safe ref record.
    pub fn new(oid: AnyGitOid, name: &[u8], limits: &WireLimits) -> Result<Self, WireError> {
        Ok(Self {
            oid,
            name: parse_ref_name(name, limits)?,
        })
    }
}

/// Canonical repository facts needed by the SANS-I/O state machines.
///
/// The implementation is intentionally not given an object database or a pack
/// writer.  `contains_want` is the authority/closure check that decides a v2
/// non-advertised object request; it must not be satisfied by a cache alone.
pub trait UploadPackRepository {
    /// The native object format of this repository.
    fn object_format(&self) -> GitObjectFormat;
    /// Deterministically ordered advertised refs, with no duplicate name or OID.
    fn advertised_refs(&self) -> &[AdvertisedRef];
    /// Whether a v2 non-advertised want is in the canonical permitted closure.
    fn contains_want(&self, oid: AnyGitOid) -> bool;
    /// Whether a client `have` is already common with the advertised closure.
    fn is_common(&self, oid: AnyGitOid) -> bool;
    /// Resolves one canonical advertised ref for a `deepen-not` control.
    fn resolve_ref(&self, name: &[u8]) -> Option<AnyGitOid> {
        self.advertised_refs()
            .iter()
            .find(|reference| reference.name == name)
            .map(|reference| reference.oid)
    }
    /// Canonical symbolic-ref target, if the supplied ref is symbolic.
    fn symref_target(&self, _name: &[u8]) -> Option<&[u8]> {
        None
    }
    /// Canonical peeled target for an annotated-tag ref, if one exists.
    fn peeled(&self, _oid: AnyGitOid) -> Option<AnyGitOid> {
        None
    }
}

/// Minimal deferred request passed from wire parsing to a future pack writer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PackOptions(u8);

impl PackOptions {
    /// No optional pack features were requested.
    pub const NONE: Self = Self(0);
    /// Pack payload uses `side-band-64k` framing.
    pub const SIDE_BAND_64K: Self = Self(1);
    const THIN_PACK: u8 = 1 << 1;
    const INCLUDE_TAG: u8 = 1 << 2;
    const OFS_DELTA: u8 = 1 << 3;
    const NO_PROGRESS: u8 = 1 << 4;
    const SIDEBAND_ALL: u8 = 1 << 5;

    const fn with(self, option: u8) -> Self {
        Self(self.0 | option)
    }
    const fn contains(self, option: u8) -> bool {
        self.0 & option != 0
    }
    /// Whether pack data uses `side-band-64k` framing.
    #[must_use]
    pub const fn sideband_64k(self) -> bool {
        self.contains(Self::SIDE_BAND_64K.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackRequest {
    /// Protocol version that selected this request.
    pub version: UploadPackVersion,
    /// Requested tips, in first-seen packet order.
    pub wants: Vec<AnyGitOid>,
    /// Client common-object candidates, in first-seen packet order.
    pub haves: Vec<AnyGitOid>,
    /// Existing shallow roots supplied by the client.
    pub shallows: Vec<AnyGitOid>,
    /// Optional depth boundary requested by the client.
    pub deepen: Option<u32>,
    /// Optional lower committer-time boundary requested by the client.
    pub deepen_since: Option<i64>,
    /// Ref tips whose reachable history is excluded from deepening.
    pub deepen_not: Vec<AnyGitOid>,
    /// Optional parsed partial-clone filter.
    pub filter: Option<ObjectFilter>,
    /// Typed optional pack behaviors negotiated for this request.
    pub options: PackOptions,
}

/// A protocol observation or required external action from a transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireEvent {
    /// The server has parsed a complete fetch and needs pack construction.
    PackRequested(PackRequest),
    /// A v2 `ls-refs` request was accepted.
    LsRefs {
        /// Prefixes supplied by the client, retained in packet order.
        prefixes: Vec<Vec<u8>>,
        /// Whether the client requested symbolic-ref attributes.
        symrefs: bool,
        /// Whether the client requested peeled tag attributes.
        peel: bool,
        /// Whether the client requested unborn-head attributes.
        unborn: bool,
    },
    /// A common object was observed during negotiation.
    Common(AnyGitOid),
}

/// Wire bytes or deferred actions emitted by a pure transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transition {
    /// Packets the adapter may serialize and write in order.
    pub output: Vec<Packet>,
    /// Observations and external work requests in deterministic order.
    pub events: Vec<WireEvent>,
}

impl Transition {
    const fn empty() -> Self {
        Self {
            output: Vec::new(),
            events: Vec::new(),
        }
    }

    fn append(&mut self, other: Self) -> Result<(), WireError> {
        self.output
            .try_reserve(other.output.len())
            .map_err(|_| WireError::AllocationFailure)?;
        self.events
            .try_reserve(other.events.len())
            .map_err(|_| WireError::AllocationFailure)?;
        self.output.extend(other.output);
        self.events.extend(other.events);
        Ok(())
    }
}

/// The sole pack-generation seam required by this crate.
///
/// Implementors must either return a chunk no larger than `maximum_chunk_bytes`,
/// return `None` at end-of-pack, or return a typed refusal.  The wire layer
/// never asks a pack writer for a complete pack in one allocation.
pub trait PackPayloadSource {
    /// Produces the next bounded pack chunk.
    fn next_chunk(&mut self, maximum_chunk_bytes: usize) -> Result<Option<Vec<u8>>, WireError>;
}

/// Frames one bounded pack chunk through sideband-64k without performing I/O.
///
/// The adapter calls [`PackPayloadSource::next_chunk`] and this function in a
/// loop, writing each returned packet group before requesting another chunk.
/// That order prevents the wire layer from collecting an entire pack in memory.
pub fn sideband_pack_chunk(chunk: &[u8], limits: &WireLimits) -> Result<Vec<Packet>, WireError> {
    let maximum_chunk_bytes =
        limits
            .max_packet_bytes
            .checked_sub(5)
            .ok_or(WireError::InvalidLimit {
                field: "max_packet_bytes for pack source",
            })?;
    if chunk.len() > maximum_chunk_bytes {
        return Err(WireError::PackChunkTooLarge {
            observed: chunk.len(),
            limit: maximum_chunk_bytes,
        });
    }
    encode_sideband_64k(SidebandBand::PackData, chunk, limits)
}

/// Encodes a deterministic v0/v1 ref advertisement and parses its inverse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V1Advertisement {
    /// Whether the server emitted the protocol-v1 `version 1` prelude.
    pub version_one_prelude: bool,
    /// Advertised refs in Git's required wire order.
    pub refs: Vec<AdvertisedRef>,
    /// Server capability list, attached to the first ref after NUL.
    pub capabilities: Capabilities,
}

impl V1Advertisement {
    /// Builds an advertisement after checking ref order and object-format consistency.
    pub fn new(
        refs: Vec<AdvertisedRef>,
        capabilities: Capabilities,
        object_format: GitObjectFormat,
        limits: &WireLimits,
    ) -> Result<Self, WireError> {
        validate_advertised_refs(&refs, object_format, limits)?;
        Ok(Self {
            version_one_prelude: false,
            refs,
            capabilities,
        })
    }

    /// Emits the v0/v1 ref records and their terminating flush.
    pub fn encode(&self, limits: &WireLimits) -> Result<Vec<Packet>, WireError> {
        let mut output = Vec::new();
        let mut used_bytes = 0_usize;
        output
            .try_reserve(
                self.refs
                    .len()
                    .saturating_add(1)
                    .saturating_add(usize::from(self.version_one_prelude)),
            )
            .map_err(|_| WireError::AllocationFailure)?;
        if self.version_one_prelude {
            add_output_packet(
                &mut output,
                Packet::Data(b"version 1\n".to_vec()),
                b"version 1\n".len() + 4,
                &mut used_bytes,
                limits,
            )?;
        }
        for (index, reference) in self.refs.iter().enumerate() {
            let mut line = oid_hex(reference.oid).into_bytes();
            line.try_reserve(reference.name.len().saturating_add(2))
                .map_err(|_| WireError::AllocationFailure)?;
            line.push(b' ');
            line.extend_from_slice(&reference.name);
            if index == 0 && !self.capabilities.entries.is_empty() {
                line.push(0);
                for (capability_index, capability) in self.capabilities.entries.iter().enumerate() {
                    if capability_index != 0 {
                        line.push(b' ');
                    }
                    line.extend_from_slice(&capability.encoded()?);
                }
            }
            line.push(b'\n');
            if line.len() + 4 > limits.max_packet_bytes {
                return Err(WireError::PacketTooLarge {
                    declared: line.len() + 4,
                    limit: limits.max_packet_bytes,
                });
            }
            let encoded_bytes = line.len() + 4;
            add_output_packet(
                &mut output,
                Packet::Data(line),
                encoded_bytes,
                &mut used_bytes,
                limits,
            )?;
        }
        add_output_packet(&mut output, Packet::Flush, 4, &mut used_bytes, limits)?;
        Ok(output)
    }

    /// Parses a complete v0/v1 ref advertisement packet sequence.
    pub fn parse(
        packets: &[Packet],
        object_format: GitObjectFormat,
        limits: &WireLimits,
    ) -> Result<Self, WireError> {
        let mut refs = Vec::new();
        let mut capabilities = Capabilities::default();
        let mut saw_flush = false;
        let mut version_one_prelude = false;
        for (index, packet) in packets.iter().enumerate() {
            match packet {
                Packet::Data(line) => {
                    if refs.is_empty() && line.as_slice() == b"version 1\n" {
                        if version_one_prelude {
                            return Err(WireError::InvalidVersionAdvertisement);
                        }
                        version_one_prelude = true;
                        continue;
                    }
                    let line = line_without_lf(line)?;
                    let (reference, trailing_capabilities) =
                        parse_v1_ref_line(line, object_format, limits)?;
                    if trailing_capabilities.is_some() && !refs.is_empty() {
                        return Err(WireError::MalformedRequestLine {
                            line: line.to_vec(),
                        });
                    }
                    if let Some(raw) = trailing_capabilities {
                        capabilities = Capabilities::parse_v1(raw, limits)?;
                    }
                    refs.try_reserve(1)
                        .map_err(|_| WireError::AllocationFailure)?;
                    refs.push(reference);
                }
                Packet::Flush => {
                    if index + 1 != packets.len() {
                        return Err(WireError::IllegalTransition {
                            state: "v0/v1 advertisement after flush",
                            packet: packet_name(&packets[index + 1]),
                        });
                    }
                    saw_flush = true;
                    break;
                }
                Packet::Delimiter | Packet::ResponseEnd => {
                    return Err(WireError::IllegalTransition {
                        state: "v0/v1 advertisement",
                        packet: packet_name(packet),
                    });
                }
            }
        }
        if !saw_flush {
            return Err(WireError::IllegalTransition {
                state: "v0/v1 advertisement",
                packet: "end of input",
            });
        }
        let mut advertisement = Self::new(refs, capabilities, object_format, limits)?;
        advertisement.version_one_prelude = version_one_prelude;
        Ok(advertisement)
    }
}

fn parse_v1_ref_line<'a>(
    line: &'a [u8],
    object_format: GitObjectFormat,
    limits: &WireLimits,
) -> Result<(AdvertisedRef, Option<&'a [u8]>), WireError> {
    let (body, capabilities) = line
        .iter()
        .position(|byte| *byte == 0)
        .map_or((line, None), |offset| {
            (&line[..offset], Some(&line[offset + 1..]))
        });
    let Some(space) = body.iter().position(|byte| *byte == b' ') else {
        return Err(WireError::MalformedRequestLine {
            line: line.to_vec(),
        });
    };
    if body[space + 1..].contains(&b' ') {
        return Err(WireError::MalformedRequestLine {
            line: line.to_vec(),
        });
    }
    let oid = parse_object_id(&body[..space], object_format)?;
    let reference = AdvertisedRef::new(oid, &body[space + 1..], limits)?;
    Ok((reference, capabilities))
}

fn validate_advertised_refs(
    refs: &[AdvertisedRef],
    object_format: GitObjectFormat,
    limits: &WireLimits,
) -> Result<(), WireError> {
    if refs.len() > limits.max_advertised_refs {
        return Err(WireError::TooManyAdvertisedRefs {
            limit: limits.max_advertised_refs,
        });
    }
    let mut previous: Option<&[u8]> = None;
    for reference in refs {
        if reference.oid.algorithm() != object_format {
            return Err(WireError::ObjectFormatMismatch {
                expected: object_format,
                observed: reference.oid.algorithm(),
            });
        }
        parse_ref_name(&reference.name, limits)?;
        if let Some(previous_name) = previous
            && previous_name >= reference.name.as_slice()
        {
            return Err(WireError::UnsortedOrDuplicateAdvertisement);
        }
        previous = Some(&reference.name);
    }
    Ok(())
}

fn oid_hex(oid: AnyGitOid) -> String {
    match oid {
        AnyGitOid::Sha1(value) => value.to_string(),
        AnyGitOid::Sha256(value) => value.to_string(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LegacyState {
    AwaitWant,
    AwaitHave,
    Complete,
}

/// SANS-I/O v0/v1 upload-pack fetch request machine.
#[derive(Clone, Debug)]
pub struct LegacyUploadPack {
    version: UploadPackVersion,
    limits: WireLimits,
    decoder: PktLineDecoder,
    server_capabilities: Capabilities,
    state: LegacyState,
    wants: Vec<AnyGitOid>,
    haves: Vec<AnyGitOid>,
    shallows: Vec<AnyGitOid>,
    deepen: Option<u32>,
    deepen_since: Option<i64>,
    deepen_not: Vec<AnyGitOid>,
    filter: Option<ObjectFilter>,
    ack_mode: AckMode,
    options: PackOptions,
    last_common: Option<AnyGitOid>,
    saw_want_capabilities: bool,
}

impl LegacyUploadPack {
    /// Creates a v0 or v1 request machine.  V2 has a distinct command grammar.
    pub fn new(
        version: UploadPackVersion,
        server_capabilities: Capabilities,
        limits: WireLimits,
    ) -> Result<Self, WireError> {
        if matches!(version, UploadPackVersion::V2) {
            return Err(WireError::IllegalTransition {
                state: "legacy constructor",
                packet: "v2",
            });
        }
        let decoder = PktLineDecoder::new(limits.clone())?;
        Ok(Self {
            version,
            limits,
            decoder,
            server_capabilities,
            state: LegacyState::AwaitWant,
            wants: Vec::new(),
            haves: Vec::new(),
            shallows: Vec::new(),
            deepen: None,
            deepen_since: None,
            deepen_not: Vec::new(),
            filter: None,
            ack_mode: AckMode::None,
            options: PackOptions::NONE,
            last_common: None,
            saw_want_capabilities: false,
        })
    }

    /// Feeds arbitrary byte fragments and returns all deterministic outputs/events.
    pub fn push_bytes(
        &mut self,
        bytes: &[u8],
        repository: &impl UploadPackRepository,
    ) -> Result<Transition, WireError> {
        let packets = self.decoder.push(bytes)?;
        let mut transition = Transition::empty();
        for packet in packets {
            transition.append(self.push_packet(&packet, repository)?)?;
        }
        Ok(transition)
    }

    /// Refuses a transport that ended inside a pkt-line frame.
    pub const fn finish(&self) -> Result<(), WireError> {
        self.decoder.finish()
    }

    /// Feeds one already-decoded packet.
    pub fn push_packet(
        &mut self,
        packet: &Packet,
        repository: &impl UploadPackRepository,
    ) -> Result<Transition, WireError> {
        match self.state {
            LegacyState::AwaitWant => self.accept_want_phase(packet, repository),
            LegacyState::AwaitHave => self.accept_have_phase(packet, repository),
            LegacyState::Complete => Err(WireError::IllegalTransition {
                state: "completed legacy upload-pack request",
                packet: packet_name(packet),
            }),
        }
    }

    fn accept_want_phase(
        &mut self,
        packet: &Packet,
        repository: &impl UploadPackRepository,
    ) -> Result<Transition, WireError> {
        match packet {
            Packet::Flush => {
                if self.wants.is_empty() {
                    return Err(WireError::MissingWant);
                }
                self.state = LegacyState::AwaitHave;
                Ok(Transition {
                    output: vec![line_packet(b"NAK\n")],
                    events: Vec::new(),
                })
            }
            Packet::Data(line) => self.accept_want_line(line, repository),
            Packet::Delimiter | Packet::ResponseEnd => Err(WireError::IllegalTransition {
                state: "legacy want phase",
                packet: packet_name(packet),
            }),
        }
    }

    fn accept_want_line(
        &mut self,
        line: &[u8],
        repository: &impl UploadPackRepository,
    ) -> Result<Transition, WireError> {
        let line = line_without_lf(line)?;
        if let Some(rest) = line.strip_prefix(b"want ") {
            return self.accept_want(rest, repository);
        }
        if let Some(rest) = line.strip_prefix(b"shallow ") {
            self.require_capability(b"shallow")?;
            let oid = parse_object_id(rest, repository.object_format())?;
            push_unique_oid("shallow", oid, &mut self.shallows, self.limits.max_shallows)?;
            return Ok(Transition::empty());
        }
        if let Some(rest) = line.strip_prefix(b"deepen ") {
            self.require_capability(b"shallow")?;
            if self.deepen.is_some() || self.deepen_since.is_some() {
                return Err(WireError::MalformedRequestLine {
                    line: line.to_vec(),
                });
            }
            self.deepen = Some(parse_depth(rest)?);
            return Ok(Transition::empty());
        }
        if let Some(rest) = line.strip_prefix(b"deepen-since ") {
            self.require_capability(b"shallow")?;
            if self.deepen.is_some() || self.deepen_since.is_some() {
                return Err(WireError::MalformedRequestLine {
                    line: line.to_vec(),
                });
            }
            self.deepen_since = Some(parse_timestamp(rest)?);
            return Ok(Transition::empty());
        }
        if let Some(rest) = line.strip_prefix(b"deepen-not ") {
            self.require_capability(b"shallow")?;
            let name = parse_ref_name(rest, &self.limits)?;
            let oid = repository
                .resolve_ref(&name)
                .ok_or(WireError::UnknownDeepenNotRef { name })?;
            push_unique_oid(
                "deepen-not",
                oid,
                &mut self.deepen_not,
                self.limits.max_shallows,
            )?;
            return Ok(Transition::empty());
        }
        if let Some(rest) = line.strip_prefix(b"filter ") {
            self.require_capability(b"filter")?;
            if self.filter.is_some() {
                return Err(WireError::MalformedRequestLine {
                    line: line.to_vec(),
                });
            }
            self.filter = Some(parse_filter(
                rest,
                repository.object_format(),
                &self.limits,
            )?);
            return Ok(Transition::empty());
        }
        Err(WireError::MalformedRequestLine {
            line: line.to_vec(),
        })
    }

    fn accept_want(
        &mut self,
        rest: &[u8],
        repository: &impl UploadPackRepository,
    ) -> Result<Transition, WireError> {
        let (oid_text, capability_text) = rest
            .iter()
            .position(|byte| *byte == b' ')
            .map_or((rest, None), |offset| {
                (&rest[..offset], Some(&rest[offset + 1..]))
            });
        let oid = parse_object_id(oid_text, repository.object_format())?;
        if !repository
            .advertised_refs()
            .iter()
            .any(|reference| reference.oid == oid)
        {
            return Err(WireError::WantNotAdvertised { oid });
        }
        if capability_text.is_some() && self.saw_want_capabilities {
            return Err(WireError::MalformedRequestLine {
                line: rest.to_vec(),
            });
        }
        if let Some(raw) = capability_text {
            let requested = Capabilities::parse_v1(raw, &self.limits)?;
            self.accept_request_capabilities(&requested)?;
            self.saw_want_capabilities = true;
        }
        push_unique_oid("want", oid, &mut self.wants, self.limits.max_wants)?;
        Ok(Transition::empty())
    }

    fn accept_have_phase(
        &mut self,
        packet: &Packet,
        repository: &impl UploadPackRepository,
    ) -> Result<Transition, WireError> {
        let Packet::Data(line) = packet else {
            return Err(WireError::IllegalTransition {
                state: "legacy have phase",
                packet: packet_name(packet),
            });
        };
        let line = line_without_lf(line)?;
        if let Some(rest) = line.strip_prefix(b"have ") {
            let oid = parse_object_id(rest, repository.object_format())?;
            push_unique_oid("have", oid, &mut self.haves, self.limits.max_haves)?;
            if repository.is_common(oid) {
                self.last_common = Some(oid);
                return Ok(self.common_ack_transition(oid));
            }
            return Ok(Transition::empty());
        }
        if line == b"done" {
            if self.wants.is_empty() {
                return Err(WireError::MissingWant);
            }
            self.state = LegacyState::Complete;
            let mut transition = self.final_ack_transition();
            transition
                .events
                .push(WireEvent::PackRequested(self.pack_request()));
            return Ok(transition);
        }
        Err(WireError::MalformedRequestLine {
            line: line.to_vec(),
        })
    }

    fn accept_request_capabilities(&mut self, requested: &Capabilities) -> Result<(), WireError> {
        for capability in requested.entries() {
            if !self.server_capabilities.contains(&capability.name) {
                return Err(WireError::UnknownCapability {
                    capability: capability.name.clone(),
                });
            }
            match capability.name.as_slice() {
                b"multi_ack" => {
                    if self.ack_mode != AckMode::MultiAckDetailed {
                        self.ack_mode = AckMode::MultiAck;
                    }
                }
                b"multi_ack_detailed" => self.ack_mode = AckMode::MultiAckDetailed,
                b"side-band-64k" => self.options = self.options.with(PackOptions::SIDE_BAND_64K.0),
                b"thin-pack" => self.options = self.options.with(PackOptions::THIN_PACK),
                b"include-tag" => self.options = self.options.with(PackOptions::INCLUDE_TAG),
                b"ofs-delta" => self.options = self.options.with(PackOptions::OFS_DELTA),
                b"no-progress" => self.options = self.options.with(PackOptions::NO_PROGRESS),
                _ => {}
            }
        }
        Ok(())
    }

    fn require_capability(&self, capability: &[u8]) -> Result<(), WireError> {
        if self.server_capabilities.contains(capability) {
            Ok(())
        } else {
            Err(WireError::UnknownCapability {
                capability: capability.to_vec(),
            })
        }
    }

    fn common_ack_transition(&self, oid: AnyGitOid) -> Transition {
        let output = match self.ack_mode {
            AckMode::None => Vec::new(),
            AckMode::MultiAck => vec![line_packet(
                format!("ACK {oid_hex} continue\n", oid_hex = oid_hex(oid)).into_bytes(),
            )],
            AckMode::MultiAckDetailed => vec![line_packet(
                format!("ACK {oid_hex} common\n", oid_hex = oid_hex(oid)).into_bytes(),
            )],
        };
        Transition {
            output,
            events: vec![WireEvent::Common(oid)],
        }
    }

    fn final_ack_transition(&self) -> Transition {
        let output = self.last_common.map_or_else(
            || vec![line_packet(b"NAK\n")],
            |oid| match self.ack_mode {
                AckMode::MultiAckDetailed => vec![line_packet(
                    format!("ACK {oid_hex} ready\n", oid_hex = oid_hex(oid)).into_bytes(),
                )],
                AckMode::None | AckMode::MultiAck => vec![line_packet(
                    format!("ACK {oid_hex}\n", oid_hex = oid_hex(oid)).into_bytes(),
                )],
            },
        );
        Transition {
            output,
            events: Vec::new(),
        }
    }

    fn pack_request(&self) -> PackRequest {
        PackRequest {
            version: self.version,
            wants: self.wants.clone(),
            haves: self.haves.clone(),
            shallows: self.shallows.clone(),
            deepen: self.deepen,
            deepen_since: self.deepen_since,
            deepen_not: self.deepen_not.clone(),
            filter: self.filter.clone(),
            options: self.options,
        }
    }
}

fn line_packet(line: impl Into<Vec<u8>>) -> Packet {
    Packet::Data(line.into())
}

fn push_unique_oid(
    field: &'static str,
    oid: AnyGitOid,
    target: &mut Vec<AnyGitOid>,
    limit: usize,
) -> Result<(), WireError> {
    if target.contains(&oid) {
        return Err(WireError::DuplicateObjectId { field, oid });
    }
    if target.len() == limit {
        return Err(WireError::TooManyObjectIds { field, limit });
    }
    target
        .try_reserve(1)
        .map_err(|_| WireError::AllocationFailure)?;
    target.push(oid);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum V2Command {
    LsRefs,
    Fetch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum V2State {
    AwaitCommand,
    AwaitCapabilities(V2Command),
    AwaitArguments(V2Command),
    Complete,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LsRefsOptions(u8);

impl LsRefsOptions {
    const SYMREFS: u8 = 1;
    const PEEL: u8 = 1 << 1;
    const UNBORN: u8 = 1 << 2;

    const fn with(self, option: u8) -> Self {
        Self(self.0 | option)
    }
    const fn contains(self, option: u8) -> bool {
        self.0 & option != 0
    }
}

/// SANS-I/O protocol-v2 upload-pack command machine for `ls-refs` and `fetch`.
#[derive(Clone, Debug)]
pub struct V2UploadPack {
    limits: WireLimits,
    decoder: PktLineDecoder,
    server_capabilities: Capabilities,
    state: V2State,
    request_capabilities: Capabilities,
    wants: Vec<AnyGitOid>,
    haves: Vec<AnyGitOid>,
    shallows: Vec<AnyGitOid>,
    deepen: Option<u32>,
    deepen_since: Option<i64>,
    deepen_not: Vec<AnyGitOid>,
    filter: Option<ObjectFilter>,
    options: PackOptions,
    done: bool,
    ref_prefixes: Vec<Vec<u8>>,
    ls_refs: LsRefsOptions,
}

impl V2UploadPack {
    /// Creates a v2 command machine that accepts exactly one complete request.
    pub fn new(server_capabilities: Capabilities, limits: WireLimits) -> Result<Self, WireError> {
        let decoder = PktLineDecoder::new(limits.clone())?;
        Ok(Self {
            limits,
            decoder,
            server_capabilities,
            state: V2State::AwaitCommand,
            request_capabilities: Capabilities::default(),
            wants: Vec::new(),
            haves: Vec::new(),
            shallows: Vec::new(),
            deepen: None,
            deepen_since: None,
            deepen_not: Vec::new(),
            filter: None,
            options: PackOptions::NONE,
            done: false,
            ref_prefixes: Vec::new(),
            ls_refs: LsRefsOptions::default(),
        })
    }

    /// Feeds arbitrary pkt-line fragments and produces pure outputs/events.
    pub fn push_bytes(
        &mut self,
        bytes: &[u8],
        repository: &impl UploadPackRepository,
    ) -> Result<Transition, WireError> {
        let packets = self.decoder.push(bytes)?;
        let mut transition = Transition::empty();
        for packet in packets {
            transition.append(self.push_packet(&packet, repository)?)?;
        }
        Ok(transition)
    }

    /// Refuses a transport that ended inside a pkt-line frame.
    pub const fn finish(&self) -> Result<(), WireError> {
        self.decoder.finish()
    }

    /// Feeds one decoded v2 request packet.
    pub fn push_packet(
        &mut self,
        packet: &Packet,
        repository: &impl UploadPackRepository,
    ) -> Result<Transition, WireError> {
        match self.state {
            V2State::AwaitCommand => self.accept_command(packet),
            V2State::AwaitCapabilities(command) => self.accept_capability(packet, command),
            V2State::AwaitArguments(command) => self.accept_argument(packet, command, repository),
            V2State::Complete => Err(WireError::IllegalTransition {
                state: "completed v2 upload-pack request",
                packet: packet_name(packet),
            }),
        }
    }

    fn accept_command(&mut self, packet: &Packet) -> Result<Transition, WireError> {
        let Packet::Data(line) = packet else {
            return Err(WireError::IllegalTransition {
                state: "v2 command phase",
                packet: packet_name(packet),
            });
        };
        let line = line_without_lf(line)?;
        let Some(command) = line.strip_prefix(b"command=") else {
            return Err(WireError::MalformedRequestLine {
                line: line.to_vec(),
            });
        };
        let command = match command {
            b"ls-refs" => V2Command::LsRefs,
            b"fetch" => V2Command::Fetch,
            _ => {
                return Err(WireError::UnsupportedCommand {
                    command: command.to_vec(),
                });
            }
        };
        let capability: &[u8] = match command {
            V2Command::LsRefs => b"ls-refs",
            V2Command::Fetch => b"fetch",
        };
        if !self.server_capabilities.contains(capability) {
            return Err(WireError::UnsupportedCommand {
                command: command_name(command).to_vec(),
            });
        }
        self.state = V2State::AwaitCapabilities(command);
        Ok(Transition::empty())
    }

    fn accept_capability(
        &mut self,
        packet: &Packet,
        command: V2Command,
    ) -> Result<Transition, WireError> {
        match packet {
            Packet::Data(line) => {
                let token = line_without_lf(line)?;
                let capability = Capability::parse_v2(token, &self.limits)?;
                if !self.server_capabilities.contains(&capability.name) {
                    return Err(WireError::UnknownCapability {
                        capability: capability.name,
                    });
                }
                self.request_capabilities.insert(capability, &self.limits)?;
                Ok(Transition::empty())
            }
            Packet::Delimiter => {
                self.state = V2State::AwaitArguments(command);
                Ok(Transition::empty())
            }
            Packet::Flush | Packet::ResponseEnd => Err(WireError::IllegalTransition {
                state: "v2 capability phase",
                packet: packet_name(packet),
            }),
        }
    }

    fn accept_argument(
        &mut self,
        packet: &Packet,
        command: V2Command,
        repository: &impl UploadPackRepository,
    ) -> Result<Transition, WireError> {
        match packet {
            Packet::Data(line) => {
                let line = line_without_lf(line)?;
                match command {
                    V2Command::LsRefs => self.accept_ls_refs_argument(line),
                    V2Command::Fetch => self.accept_fetch_argument(line, repository),
                }
            }
            Packet::Flush => match command {
                V2Command::LsRefs => self.finish_ls_refs(repository),
                V2Command::Fetch => self.finish_fetch(repository),
            },
            Packet::Delimiter | Packet::ResponseEnd => Err(WireError::IllegalTransition {
                state: "v2 argument phase",
                packet: packet_name(packet),
            }),
        }
    }

    fn accept_ls_refs_argument(&mut self, line: &[u8]) -> Result<Transition, WireError> {
        match line {
            b"symrefs" => self.ls_refs = self.ls_refs.with(LsRefsOptions::SYMREFS),
            b"peel" => self.ls_refs = self.ls_refs.with(LsRefsOptions::PEEL),
            b"unborn" => self.ls_refs = self.ls_refs.with(LsRefsOptions::UNBORN),
            _ => {
                let Some(prefix) = line.strip_prefix(b"ref-prefix ") else {
                    return Err(WireError::MalformedRequestLine {
                        line: line.to_vec(),
                    });
                };
                let prefix = parse_ref_prefix(prefix, &self.limits)?;
                if self.ref_prefixes.contains(&prefix) {
                    return Err(WireError::MalformedRequestLine {
                        line: line.to_vec(),
                    });
                }
                if self.ref_prefixes.len() == self.limits.max_ref_prefixes {
                    return Err(WireError::TooManyObjectIds {
                        field: "ref-prefix",
                        limit: self.limits.max_ref_prefixes,
                    });
                }
                self.ref_prefixes
                    .try_reserve(1)
                    .map_err(|_| WireError::AllocationFailure)?;
                self.ref_prefixes.push(prefix);
            }
        }
        Ok(Transition::empty())
    }

    fn accept_fetch_argument(
        &mut self,
        line: &[u8],
        repository: &impl UploadPackRepository,
    ) -> Result<Transition, WireError> {
        if let Some(rest) = line.strip_prefix(b"want ") {
            let oid = parse_object_id(rest, repository.object_format())?;
            if !repository.contains_want(oid) {
                return Err(WireError::WantNotReachable { oid });
            }
            push_unique_oid("want", oid, &mut self.wants, self.limits.max_wants)?;
            return Ok(Transition::empty());
        }
        if let Some(rest) = line.strip_prefix(b"have ") {
            if self.wants.is_empty() {
                return Err(WireError::MissingWant);
            }
            let oid = parse_object_id(rest, repository.object_format())?;
            push_unique_oid("have", oid, &mut self.haves, self.limits.max_haves)?;
            return Ok(Transition::empty());
        }
        if let Some(rest) = line.strip_prefix(b"shallow ") {
            self.require_fetch_feature(b"shallow")?;
            let oid = parse_object_id(rest, repository.object_format())?;
            push_unique_oid("shallow", oid, &mut self.shallows, self.limits.max_shallows)?;
            return Ok(Transition::empty());
        }
        if let Some(rest) = line.strip_prefix(b"deepen ") {
            self.require_fetch_feature(b"shallow")?;
            if self.deepen.is_some() || self.deepen_since.is_some() {
                return Err(WireError::MalformedRequestLine {
                    line: line.to_vec(),
                });
            }
            self.deepen = Some(parse_depth(rest)?);
            return Ok(Transition::empty());
        }
        if let Some(rest) = line.strip_prefix(b"deepen-since ") {
            self.require_fetch_feature(b"shallow")?;
            if self.deepen.is_some() || self.deepen_since.is_some() {
                return Err(WireError::MalformedRequestLine {
                    line: line.to_vec(),
                });
            }
            self.deepen_since = Some(parse_timestamp(rest)?);
            return Ok(Transition::empty());
        }
        if let Some(rest) = line.strip_prefix(b"deepen-not ") {
            self.require_fetch_feature(b"shallow")?;
            let name = parse_ref_name(rest, &self.limits)?;
            let oid = repository
                .resolve_ref(&name)
                .ok_or(WireError::UnknownDeepenNotRef { name })?;
            push_unique_oid(
                "deepen-not",
                oid,
                &mut self.deepen_not,
                self.limits.max_shallows,
            )?;
            return Ok(Transition::empty());
        }
        if let Some(rest) = line.strip_prefix(b"filter ") {
            self.require_fetch_feature(b"filter")?;
            if self.filter.is_some() {
                return Err(WireError::MalformedRequestLine {
                    line: line.to_vec(),
                });
            }
            self.filter = Some(parse_filter(
                rest,
                repository.object_format(),
                &self.limits,
            )?);
            return Ok(Transition::empty());
        }
        if line == b"sideband-all" {
            if !self.server_capabilities.contains(b"sideband-all") {
                return Err(WireError::UnknownCapability {
                    capability: b"sideband-all".to_vec(),
                });
            }
            self.options = self.options.with(PackOptions::SIDEBAND_ALL);
            return Ok(Transition::empty());
        }
        match line {
            b"thin-pack" => self.options = self.options.with(PackOptions::THIN_PACK),
            b"include-tag" => self.options = self.options.with(PackOptions::INCLUDE_TAG),
            b"ofs-delta" => self.options = self.options.with(PackOptions::OFS_DELTA),
            b"no-progress" => self.options = self.options.with(PackOptions::NO_PROGRESS),
            _ => {}
        }
        if matches!(
            line,
            b"thin-pack" | b"include-tag" | b"ofs-delta" | b"no-progress"
        ) {
            return Ok(Transition::empty());
        }
        if line == b"done" {
            if self.wants.is_empty() {
                return Err(WireError::MissingWant);
            }
            if self.done {
                return Err(WireError::MalformedRequestLine {
                    line: line.to_vec(),
                });
            }
            self.done = true;
            return Ok(Transition::empty());
        }
        Err(WireError::MalformedRequestLine {
            line: line.to_vec(),
        })
    }

    fn finish_ls_refs(
        &mut self,
        repository: &impl UploadPackRepository,
    ) -> Result<Transition, WireError> {
        validate_advertised_refs(
            repository.advertised_refs(),
            repository.object_format(),
            &self.limits,
        )?;
        let mut output = Vec::new();
        let mut used_bytes = 0_usize;
        for reference in repository.advertised_refs() {
            if !self.ref_prefixes.is_empty()
                && !self
                    .ref_prefixes
                    .iter()
                    .any(|prefix| reference.name.starts_with(prefix))
            {
                continue;
            }
            let mut line = oid_hex(reference.oid).into_bytes();
            line.try_reserve(reference.name.len().saturating_add(2))
                .map_err(|_| WireError::AllocationFailure)?;
            line.push(b' ');
            line.extend_from_slice(&reference.name);
            if self.ls_refs.contains(LsRefsOptions::SYMREFS)
                && let Some(target) = repository.symref_target(&reference.name)
            {
                parse_ref_name(target, &self.limits)?;
                line.try_reserve(target.len().saturating_add(16))
                    .map_err(|_| WireError::AllocationFailure)?;
                line.extend_from_slice(b" symref-target:");
                line.extend_from_slice(target);
            }
            if self.ls_refs.contains(LsRefsOptions::PEEL)
                && let Some(peeled) = repository.peeled(reference.oid)
            {
                if peeled.algorithm() != repository.object_format() {
                    return Err(WireError::ObjectFormatMismatch {
                        expected: repository.object_format(),
                        observed: peeled.algorithm(),
                    });
                }
                let peeled = oid_hex(peeled);
                line.try_reserve(peeled.len().saturating_add(8))
                    .map_err(|_| WireError::AllocationFailure)?;
                line.extend_from_slice(b" peeled:");
                line.extend_from_slice(peeled.as_bytes());
            }
            line.push(b'\n');
            if line.len() + 4 > self.limits.max_packet_bytes {
                return Err(WireError::PacketTooLarge {
                    declared: line.len() + 4,
                    limit: self.limits.max_packet_bytes,
                });
            }
            let encoded_bytes = line.len() + 4;
            add_output_packet(
                &mut output,
                Packet::Data(line),
                encoded_bytes,
                &mut used_bytes,
                &self.limits,
            )?;
        }
        add_output_packet(&mut output, Packet::Flush, 4, &mut used_bytes, &self.limits)?;
        self.state = V2State::Complete;
        Ok(Transition {
            output,
            events: vec![WireEvent::LsRefs {
                prefixes: self.ref_prefixes.clone(),
                symrefs: self.ls_refs.contains(LsRefsOptions::SYMREFS),
                peel: self.ls_refs.contains(LsRefsOptions::PEEL),
                unborn: self.ls_refs.contains(LsRefsOptions::UNBORN),
            }],
        })
    }

    fn require_fetch_feature(&self, feature: &[u8]) -> Result<(), WireError> {
        let supported = self.server_capabilities.entries().iter().any(|capability| {
            capability.name == b"fetch"
                && capability.value.as_ref().is_some_and(|value| {
                    value
                        .split(|byte| *byte == b' ')
                        .any(|item| item == feature)
                })
        });
        if supported {
            Ok(())
        } else {
            Err(WireError::UnknownCapability {
                capability: feature.to_vec(),
            })
        }
    }

    fn finish_fetch(
        &mut self,
        repository: &impl UploadPackRepository,
    ) -> Result<Transition, WireError> {
        if self.wants.is_empty() {
            return Err(WireError::MissingWant);
        }
        if !self.done {
            return Err(WireError::IllegalTransition {
                state: "v2 fetch without done",
                packet: "flush",
            });
        }
        let last_common = self
            .haves
            .iter()
            .copied()
            .rev()
            .find(|oid| repository.is_common(*oid));
        let mut output = Vec::new();
        output
            .try_reserve(5)
            .map_err(|_| WireError::AllocationFailure)?;
        output.push(line_packet(b"acknowledgments\n"));
        match last_common {
            Some(oid) => output.push(line_packet(
                format!("ACK {oid_hex}\n", oid_hex = oid_hex(oid)).into_bytes(),
            )),
            None => output.push(line_packet(b"NAK\n")),
        }
        output.push(Packet::Delimiter);
        output.push(line_packet(b"packfile\n"));
        self.state = V2State::Complete;
        Ok(Transition {
            output,
            events: vec![WireEvent::PackRequested(PackRequest {
                version: UploadPackVersion::V2,
                wants: self.wants.clone(),
                haves: self.haves.clone(),
                shallows: self.shallows.clone(),
                deepen: self.deepen,
                deepen_since: self.deepen_since,
                deepen_not: self.deepen_not.clone(),
                filter: self.filter.clone(),
                options: self.options.with(PackOptions::SIDE_BAND_64K.0),
            })],
        })
    }
}

const fn command_name(command: V2Command) -> &'static [u8] {
    match command {
        V2Command::LsRefs => b"ls-refs",
        V2Command::Fetch => b"fetch",
    }
}

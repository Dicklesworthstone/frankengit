//! Bounded SSH wire encoding and decoding primitives (RFC 4251 / RFC 4253).
//!
//! All operations enforce explicit allocation and length bounds to prevent OOM
//! and parsing desynchronization attacks.

use core::fmt::{self, Display, Formatter};

/// Maximum admitted string length on the SSH control wire (64 KiB).
pub const MAX_WIRE_STRING_BYTES: usize = 65_536;

/// Maximum packet payload size admitted during negotiation (35,000 bytes).
pub const MAX_PACKET_BYTES: usize = 35_000;

/// Minimum padding required by RFC 4253 section 6.
pub const MIN_PADDING_BYTES: usize = 4;

/// Packet block alignment (8 bytes for unencrypted/3DES/AES, 8 for ChaCha20).
pub const PACKET_BLOCK_ALIGN: usize = 8;

/// Wire decoding errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    UnexpectedEof { expected: usize, available: usize },
    StringTooLarge { observed: usize, limit: usize },
    PacketTooLarge { observed: usize, limit: usize },
    PacketTooSmall { observed: usize, min: usize },
    InvalidPadding { padding: usize, packet_len: usize },
    InvalidBoolean { observed: u8 },
    InvalidUtf8,
    Overflow,
}

impl Display for WireError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { expected, available } => {
                write!(formatter, "unexpected EOF: expected {expected} bytes, available {available}")
            }
            Self::StringTooLarge { observed, limit } => {
                write!(formatter, "string length {observed} exceeds wire limit {limit}")
            }
            Self::PacketTooLarge { observed, limit } => {
                write!(formatter, "packet length {observed} exceeds wire limit {limit}")
            }
            Self::PacketTooSmall { observed, min } => {
                write!(formatter, "packet length {observed} below minimum {min}")
            }
            Self::InvalidPadding { padding, packet_len } => {
                write!(formatter, "invalid padding length {padding} for packet length {packet_len}")
            }
            Self::InvalidBoolean { observed } => {
                write!(formatter, "invalid boolean wire byte {observed}")
            }
            Self::InvalidUtf8 => formatter.write_str("wire string contains invalid UTF-8"),
            Self::Overflow => formatter.write_str("integer overflow during wire decoding"),
        }
    }
}

impl core::error::Error for WireError {}

/// Reader over a borrowed slice of wire bytes.
#[derive(Clone, Debug)]
pub struct WireReader<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    /// Creates a new reader over `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    /// Bytes remaining to be read.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.offset
    }

    /// The current byte offset into the buffer.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Reads a single byte.
    pub const fn read_u8(&mut self) -> Result<u8, WireError> {
        if self.offset >= self.buf.len() {
            return Err(WireError::UnexpectedEof {
                expected: 1,
                available: 0,
            });
        }
        let b = self.buf[self.offset];
        self.offset += 1;
        Ok(b)
    }

    /// Reads a boolean (RFC 4251: 0 = false, 1 = true).
    pub fn read_bool(&mut self) -> Result<bool, WireError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            observed => Err(WireError::InvalidBoolean { observed }),
        }
    }

    /// Reads a big-endian uint32.
    pub fn read_u32(&mut self) -> Result<u32, WireError> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a big-endian uint64.
    pub fn read_u64(&mut self) -> Result<u64, WireError> {
        let bytes = self.read_exact(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Reads exact slice of `n` bytes.
    pub fn read_exact(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let remaining = self.remaining();
        if remaining < n {
            return Err(WireError::UnexpectedEof {
                expected: n,
                available: remaining,
            });
        }
        let start = self.offset;
        let end = start + n;
        self.offset = end;
        Ok(&self.buf[start..end])
    }

    /// Reads a length-prefixed byte string, bounded by `max_len`.
    pub fn read_string_bounded(&mut self, max_len: usize) -> Result<&'a [u8], WireError> {
        let len = self.read_u32()? as usize;
        if len > max_len {
            return Err(WireError::StringTooLarge {
                observed: len,
                limit: max_len,
            });
        }
        self.read_exact(len)
    }

    /// Reads a standard bounded wire string (limit 64 KiB).
    pub fn read_string(&mut self) -> Result<&'a [u8], WireError> {
        self.read_string_bounded(MAX_WIRE_STRING_BYTES)
    }

    /// Reads a UTF-8 wire string.
    pub fn read_utf8(&mut self) -> Result<&'a str, WireError> {
        let bytes = self.read_string()?;
        core::str::from_utf8(bytes).map_err(|_| WireError::InvalidUtf8)
    }

    /// Reads an RFC 4251 multiple precision integer (mpint).
    pub fn read_mpint(&mut self) -> Result<&'a [u8], WireError> {
        self.read_string_bounded(1024)
    }

    /// Reads a name-list (comma-separated names).
    pub fn read_name_list(&mut self) -> Result<Vec<&'a str>, WireError> {
        let raw = self.read_utf8()?;
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        Ok(raw.split(',').collect())
    }
}

/// Buffer writer for SSH wire encoding.
#[derive(Clone, Debug, Default)]
pub struct WireWriter {
    buf: Vec<u8>,
}

impl WireWriter {
    /// Creates a new empty writer.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Creates a new writer with reserved capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Consumes the writer and returns the encoded buffer.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Borrows the current encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Writes a single byte.
    pub fn write_u8(&mut self, b: u8) {
        self.buf.push(b);
    }

    /// Writes a boolean.
    pub fn write_bool(&mut self, b: bool) {
        self.buf.push(u8::from(b));
    }

    /// Writes a big-endian uint32.
    pub fn write_u32(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    /// Writes a big-endian uint64.
    pub fn write_u64(&mut self, val: u64) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    /// Writes raw slice.
    pub fn write_raw(&mut self, slice: &[u8]) {
        self.buf.extend_from_slice(slice);
    }

    /// Writes a length-prefixed string.
    pub fn write_string(&mut self, s: &[u8]) {
        self.write_u32(s.len() as u32);
        self.buf.extend_from_slice(s);
    }

    /// Writes a UTF-8 string.
    pub fn write_utf8(&mut self, s: &str) {
        self.write_string(s.as_bytes());
    }

    /// Writes a comma-separated name list.
    pub fn write_name_list(&mut self, names: &[&str]) {
        let joined = names.join(",");
        self.write_utf8(&joined);
    }

    /// Encodes an RFC 4251 multiple precision integer (mpint) from big-endian bytes.
    pub fn write_mpint(&mut self, bytes: &[u8]) {
        let mut start = 0;
        while start < bytes.len() && bytes[start] == 0 {
            start += 1;
        }
        if start == bytes.len() {
            // value 0 is encoded with length 0
            self.write_u32(0);
            return;
        }
        let non_zero = &bytes[start..];
        let need_pad = (non_zero[0] & 0x80) != 0;
        let len = (non_zero.len() + usize::from(need_pad)) as u32;
        self.write_u32(len);
        if need_pad {
            self.write_u8(0);
        }
        self.write_raw(non_zero);
    }
}

/// Encodes an unencrypted SSH binary packet (RFC 4253 §6).
///
/// Format:
/// uint32    packet_length
/// byte      padding_length
/// byte[n1]  payload
/// byte[n2]  random_padding
#[must_use]
pub fn encode_cleartext_packet(payload: &[u8], random_pad: &[u8]) -> Vec<u8> {
    // Determine padding length to satisfy block alignment (multiple of 8) and MIN_PADDING_BYTES
    let unpadded_len = 1 + payload.len(); // 1 byte padding_len + payload
    let mut padding_len = MIN_PADDING_BYTES;
    while !(4 + unpadded_len + padding_len).is_multiple_of(PACKET_BLOCK_ALIGN) {
        padding_len += 1;
    }

    let packet_length = (1 + payload.len() + padding_len) as u32;
    let mut out = Vec::with_capacity(4 + packet_length as usize);
    out.extend_from_slice(&packet_length.to_be_bytes());
    out.push(padding_len as u8);
    out.extend_from_slice(payload);

    // Append padding bytes
    for i in 0..padding_len {
        let b = if i < random_pad.len() { random_pad[i] } else { 0 };
        out.push(b);
    }

    out
}

/// Decodes an unencrypted SSH binary packet.
pub fn decode_cleartext_packet(packet_bytes: &[u8]) -> Result<&[u8], WireError> {
    if packet_bytes.len() < 5 {
        return Err(WireError::UnexpectedEof {
            expected: 5,
            available: packet_bytes.len(),
        });
    }

    let packet_length = u32::from_be_bytes([
        packet_bytes[0],
        packet_bytes[1],
        packet_bytes[2],
        packet_bytes[3],
    ]) as usize;

    if packet_length > MAX_PACKET_BYTES {
        return Err(WireError::PacketTooLarge {
            observed: packet_length,
            limit: MAX_PACKET_BYTES,
        });
    }

    if packet_length < 5 {
        return Err(WireError::PacketTooSmall {
            observed: packet_length,
            min: 5,
        });
    }

    let expected_total = 4 + packet_length;
    if packet_bytes.len() < expected_total {
        return Err(WireError::UnexpectedEof {
            expected: expected_total,
            available: packet_bytes.len(),
        });
    }

    let padding_length = packet_bytes[4] as usize;
    if padding_length < MIN_PADDING_BYTES || padding_length >= packet_length {
        return Err(WireError::InvalidPadding {
            padding: padding_length,
            packet_len: packet_length,
        });
    }

    let payload_len = packet_length - 1 - padding_length;
    let payload = &packet_bytes[5..5 + payload_len];
    Ok(payload)
}

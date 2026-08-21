#![forbid(unsafe_code)]
//! Bounded, streaming RFC 1950/RFC 1951 decompression for FrankenGit.
//!
//! The decoder owns no ambient I/O, clock, task, or cancellation authority.
//! Callers feed bytes through [`Inflater::push`], can drain tentative output
//! between chunks, and must call [`Inflater::finish`] before accepting those
//! bytes. A caller that needs deadline cancellation supplies a
//! [`CancellationProbe`] to [`Inflater::push_with_control`].

use std::collections::VecDeque;
use std::fmt;

/// The RFC 1951 maximum backwards-copy distance.
pub const RFC1951_MAX_WINDOW_BYTES: usize = 32_768;
const MAX_HUFFMAN_BITS: u8 = 15;
const HUFFMAN_LENGTH_SLOTS: usize = 16;
const ZLIB_MAGIC_ERROR: &str = "invalid RFC 1950 zlib header";

/// Explicit resource ceilings for one zlib member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InflateLimits {
    /// Maximum compressed bytes accepted over the whole member.
    pub max_input_bytes: usize,
    /// Maximum undecoded compressed bytes retained between `push` calls.
    pub max_pending_input_bytes: usize,
    /// Maximum bytes emitted by one member.
    pub max_output_bytes: usize,
    /// Maximum output bytes per compressed byte consumed. A nonzero value is
    /// mandatory for every admitted member; `None` is rejected as an invalid
    /// configuration rather than silently disabling bomb resistance.
    pub max_expansion_ratio: Option<u32>,
    /// Maximum RFC 1951 history window bytes that this profile permits.
    pub max_window_bytes: usize,
    /// Maximum number of symbols retained by one Huffman table.
    pub max_huffman_symbols: usize,
    /// Maximum list or dynamic-code-length element count.
    pub max_collection_elements: usize,
    /// Deterministic decode work units. This is a work/time budget, not a wall
    /// clock read; runtime-owned deadline cancellation is supplied separately.
    pub max_work_units: u64,
}

impl InflateLimits {
    /// A conservative profile suitable for bounded Git object/pack admission.
    pub const GIT_OBJECT: Self = Self {
        max_input_bytes: 64 * 1024 * 1024,
        max_pending_input_bytes: 1024 * 1024,
        max_output_bytes: 256 * 1024 * 1024,
        max_expansion_ratio: Some(256),
        max_window_bytes: RFC1951_MAX_WINDOW_BYTES,
        max_huffman_symbols: 320,
        max_collection_elements: 320,
        max_work_units: 512 * 1024 * 1024,
    };

    fn validate(self) -> Result<(), InflateRefusal> {
        if self.max_input_bytes == 0
            || self.max_pending_input_bytes == 0
            || self.max_output_bytes == 0
            || self.max_window_bytes == 0
            || self.max_window_bytes > RFC1951_MAX_WINDOW_BYTES
            || self.max_huffman_symbols == 0
            || self.max_collection_elements == 0
            || self.max_work_units == 0
            || self.max_expansion_ratio.is_none_or(|ratio| ratio == 0)
        {
            return Err(InflateRefusal::ResourceLimit {
                resource: Resource::Configuration,
                limit: 1,
                observed: 0,
            });
        }
        Ok(())
    }
}

/// A bounded resource whose ceiling was reached before additional work/allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resource {
    Configuration,
    InputBytes,
    PendingInputBytes,
    OutputBytes,
    ExpansionRatio,
    WindowBytes,
    HuffmanSymbols,
    CollectionElements,
    WorkUnits,
    Allocation,
}

/// A precise non-success result from zlib/DEFLATE admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InflateRefusal {
    ResourceLimit {
        resource: Resource,
        limit: u64,
        observed: u64,
    },
    Cancelled,
    InvalidZlibHeader,
    PresetDictionaryUnsupported,
    UnexpectedEnd,
    TrailingGarbage,
    Adler32Mismatch {
        expected: u32,
        actual: u32,
    },
    ReservedBlockType,
    StoredLengthMismatch {
        length: u16,
        complement: u16,
    },
    InvalidHuffmanCode,
    IncompleteHuffmanSet,
    OversubscribedHuffmanSet,
    InvalidCodeLength,
    InvalidLengthOrDistanceCode,
    DistanceTooFar {
        distance: usize,
        available: usize,
    },
}

impl fmt::Display for InflateRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceLimit {
                resource,
                limit,
                observed,
            } => write!(
                formatter,
                "resource limit {resource:?} exceeded: {observed} > {limit}"
            ),
            Self::Cancelled => formatter.write_str("inflate cancelled by caller control"),
            Self::InvalidZlibHeader => formatter.write_str(ZLIB_MAGIC_ERROR),
            Self::PresetDictionaryUnsupported => {
                formatter.write_str("zlib preset dictionaries are unsupported")
            }
            Self::UnexpectedEnd => formatter.write_str("truncated zlib/DEFLATE member"),
            Self::TrailingGarbage => formatter.write_str("trailing bytes after zlib member"),
            Self::Adler32Mismatch { expected, actual } => write!(
                formatter,
                "zlib Adler-32 mismatch: expected {expected:08x}, actual {actual:08x}"
            ),
            Self::ReservedBlockType => formatter.write_str("reserved DEFLATE block type"),
            Self::StoredLengthMismatch { length, complement } => write!(
                formatter,
                "stored DEFLATE block length {length} does not complement {complement}"
            ),
            Self::InvalidHuffmanCode => formatter.write_str("invalid DEFLATE Huffman code"),
            Self::IncompleteHuffmanSet => {
                formatter.write_str("incomplete DEFLATE Huffman code set")
            }
            Self::OversubscribedHuffmanSet => {
                formatter.write_str("oversubscribed DEFLATE Huffman code set")
            }
            Self::InvalidCodeLength => formatter.write_str("invalid DEFLATE dynamic code length"),
            Self::InvalidLengthOrDistanceCode => {
                formatter.write_str("invalid DEFLATE length or distance code")
            }
            Self::DistanceTooFar {
                distance,
                available,
            } => write!(
                formatter,
                "DEFLATE distance {distance} exceeds available history {available}"
            ),
        }
    }
}

impl std::error::Error for InflateRefusal {}

/// Cooperative cancellation for the synchronous decoder.
pub trait CancellationProbe {
    /// Returns true when the caller requires a typed cancellation result.
    fn is_cancelled(&mut self) -> bool;
}

/// A control that never cancels, used by [`Inflater::push`].
#[derive(Default)]
pub struct NeverCancel;

impl CancellationProbe for NeverCancel {
    fn is_cancelled(&mut self) -> bool {
        false
    }
}

/// Decoder progress after accepting a chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamProgress {
    /// More compressed bytes are required before progress can continue.
    NeedInput,
    /// The member trailer verified; further input is trailing garbage.
    Finished,
}

#[derive(Clone, Debug)]
struct BitReader {
    bytes: Vec<u8>,
    bit_position: usize,
    discarded_bytes: u64,
}

impl BitReader {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit_position: 0,
            discarded_bytes: 0,
        }
    }

    fn append(&mut self, input: &[u8], limit: usize) -> Result<(), InflateRefusal> {
        self.compact();
        let required =
            self.bytes
                .len()
                .checked_add(input.len())
                .ok_or(InflateRefusal::ResourceLimit {
                    resource: Resource::PendingInputBytes,
                    limit: u64::try_from(limit).unwrap_or(u64::MAX),
                    observed: u64::MAX,
                })?;
        if required > limit {
            return Err(InflateRefusal::ResourceLimit {
                resource: Resource::PendingInputBytes,
                limit: u64::try_from(limit).unwrap_or(u64::MAX),
                observed: u64::try_from(required).unwrap_or(u64::MAX),
            });
        }
        self.bytes
            .try_reserve(input.len())
            .map_err(|_| InflateRefusal::ResourceLimit {
                resource: Resource::Allocation,
                limit: u64::try_from(limit).unwrap_or(u64::MAX),
                observed: u64::try_from(required).unwrap_or(u64::MAX),
            })?;
        self.bytes.extend_from_slice(input);
        Ok(())
    }

    fn available_bits(&self) -> usize {
        self.bytes
            .len()
            .saturating_mul(8)
            .saturating_sub(self.bit_position)
    }

    const fn checkpoint(&self) -> usize {
        self.bit_position
    }

    fn restore(&mut self, checkpoint: usize) {
        self.bit_position = checkpoint;
    }

    fn read_bits(&mut self, count: u8) -> Option<u16> {
        if self.available_bits() < usize::from(count) {
            return None;
        }
        let mut value = 0_u16;
        for offset in 0..count {
            let absolute = self.bit_position + usize::from(offset);
            let bit = (self.bytes[absolute / 8] >> (absolute % 8)) & 1;
            value |= u16::from(bit) << offset;
        }
        self.bit_position += usize::from(count);
        Some(value)
    }

    fn align_to_byte(&mut self) -> bool {
        let skipped = (8 - (self.bit_position % 8)) % 8;
        if self.available_bits() < skipped {
            return false;
        }
        self.bit_position += skipped;
        true
    }

    fn compact(&mut self) {
        let consumed_whole_bytes = self.bit_position / 8;
        if consumed_whole_bytes == 0 {
            return;
        }
        self.bytes.drain(..consumed_whole_bytes);
        self.bit_position -= consumed_whole_bytes * 8;
        self.discarded_bytes += u64::try_from(consumed_whole_bytes).unwrap_or(u64::MAX);
    }

    fn has_remaining_bytes(&self) -> bool {
        self.available_bits() != 0
    }

    fn consumed_bytes(&self) -> usize {
        usize::try_from(
            self.discarded_bytes
                .saturating_add(u64::try_from(self.bit_position / 8).unwrap_or(u64::MAX)),
        )
        .unwrap_or(usize::MAX)
    }
}

#[derive(Clone, Debug)]
struct HuffmanCode {
    reversed_bits: u16,
    bit_len: u8,
    symbol: u16,
}

#[derive(Clone, Debug)]
struct HuffmanTable {
    codes: Vec<HuffmanCode>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HuffmanSetPolicy {
    Complete,
    LiteralLengthMayBeIncomplete,
    DistanceMayUseSingleBitCode,
}

impl HuffmanTable {
    fn build(
        lengths: &[u8],
        limits: InflateLimits,
        policy: HuffmanSetPolicy,
    ) -> Result<Self, InflateRefusal> {
        if lengths.len() > limits.max_huffman_symbols {
            return Err(InflateRefusal::ResourceLimit {
                resource: Resource::HuffmanSymbols,
                limit: u64::try_from(limits.max_huffman_symbols).unwrap_or(u64::MAX),
                observed: u64::try_from(lengths.len()).unwrap_or(u64::MAX),
            });
        }
        let mut counts = [0_u16; HUFFMAN_LENGTH_SLOTS];
        let mut non_zero = 0_usize;
        for &length in lengths {
            if length > MAX_HUFFMAN_BITS {
                return Err(InflateRefusal::InvalidCodeLength);
            }
            if length != 0 {
                counts[usize::from(length)] += 1;
                non_zero += 1;
            }
        }
        if non_zero == 0 {
            return Err(InflateRefusal::IncompleteHuffmanSet);
        }

        let mut available = 1_i32;
        for bit_len in 1..=usize::from(MAX_HUFFMAN_BITS) {
            available = (available * 2) - i32::from(counts[bit_len]);
            if available < 0 {
                return Err(InflateRefusal::OversubscribedHuffmanSet);
            }
        }
        if available != 0 {
            let single_one_bit_symbol = non_zero == 1 && counts[1] == 1;
            let is_permitted = match policy {
                HuffmanSetPolicy::Complete => false,
                HuffmanSetPolicy::LiteralLengthMayBeIncomplete => true,
                HuffmanSetPolicy::DistanceMayUseSingleBitCode => single_one_bit_symbol,
            };
            if !is_permitted {
                return Err(InflateRefusal::IncompleteHuffmanSet);
            }
        }

        let mut next = [0_u16; HUFFMAN_LENGTH_SLOTS];
        let mut code = 0_u16;
        for bit_len in 1..=usize::from(MAX_HUFFMAN_BITS) {
            code = (code + counts[bit_len - 1]) << 1;
            next[bit_len] = code;
        }

        let mut codes = Vec::new();
        codes
            .try_reserve(non_zero)
            .map_err(|_| InflateRefusal::ResourceLimit {
                resource: Resource::Allocation,
                limit: u64::try_from(limits.max_huffman_symbols).unwrap_or(u64::MAX),
                observed: u64::try_from(non_zero).unwrap_or(u64::MAX),
            })?;
        for (symbol, &bit_len) in lengths.iter().enumerate() {
            if bit_len == 0 {
                continue;
            }
            let index = usize::from(bit_len);
            let canonical = next[index];
            next[index] += 1;
            codes.push(HuffmanCode {
                reversed_bits: reverse_low_bits(canonical, bit_len),
                bit_len,
                symbol: u16::try_from(symbol).map_err(|_| InflateRefusal::InvalidCodeLength)?,
            });
        }
        Ok(Self { codes })
    }

    fn fixed_literal_length(limits: InflateLimits) -> Result<Self, InflateRefusal> {
        let mut lengths = [0_u8; 288];
        lengths[..144].fill(8);
        lengths[144..256].fill(9);
        lengths[256..280].fill(7);
        lengths[280..].fill(8);
        Self::build(&lengths, limits, HuffmanSetPolicy::Complete)
    }

    fn fixed_distance(limits: InflateLimits) -> Result<Self, InflateRefusal> {
        Self::build(&[5_u8; 32], limits, HuffmanSetPolicy::Complete)
    }
}

const fn reverse_low_bits(value: u16, bit_len: u8) -> u16 {
    let mut reversed = 0_u16;
    let mut offset = 0_u8;
    while offset < bit_len {
        reversed = (reversed << 1) | ((value >> offset) & 1);
        offset += 1;
    }
    reversed
}

const LENGTH_BASE: [usize; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASE: [usize; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12_289, 16_385, 24_577,
];
const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

#[derive(Clone, Debug)]
enum PendingSymbol {
    Symbol,
    Length {
        base: usize,
        extra_bits: u8,
    },
    Distance {
        length: usize,
    },
    DistanceExtra {
        length: usize,
        base: usize,
        extra_bits: u8,
    },
}

#[derive(Clone, Debug)]
enum State {
    ZlibHeader,
    BlockHeader,
    StoredHeader {
        final_block: bool,
    },
    StoredData {
        final_block: bool,
        remaining: u16,
    },
    Compressed {
        final_block: bool,
        literal_length: HuffmanTable,
        distance: HuffmanTable,
        pending: PendingSymbol,
    },
    Adler32,
    Finished,
}

/// A stateful zlib member decoder with bounded tentative streaming output.
#[derive(Clone, Debug)]
pub struct Inflater {
    limits: InflateLimits,
    reader: BitReader,
    state: State,
    received_input_bytes: usize,
    emitted_output_bytes: usize,
    work_units: u64,
    window_limit: usize,
    window: VecDeque<u8>,
    pending_output: Vec<u8>,
    adler32: Adler32,
}

impl Inflater {
    /// Creates a decoder whose configured resource ceilings are validated first.
    pub fn new(limits: InflateLimits) -> Result<Self, InflateRefusal> {
        limits.validate()?;
        Ok(Self {
            limits,
            reader: BitReader::new(),
            state: State::ZlibHeader,
            received_input_bytes: 0,
            emitted_output_bytes: 0,
            work_units: 0,
            window_limit: 0,
            window: VecDeque::new(),
            pending_output: Vec::new(),
            adler32: Adler32::new(),
        })
    }

    /// Supplies compressed bytes using a control that never cancels.
    pub fn push(&mut self, input: &[u8]) -> Result<StreamProgress, InflateRefusal> {
        let mut control = NeverCancel;
        self.push_with_control(input, &mut control)
    }

    /// Supplies compressed bytes and checks caller-owned cancellation between
    /// bounded decode steps. A cancellation result leaves any already exposed
    /// bytes tentative; callers must discard them unless `finish` succeeds.
    pub fn push_with_control(
        &mut self,
        input: &[u8],
        control: &mut impl CancellationProbe,
    ) -> Result<StreamProgress, InflateRefusal> {
        if matches!(self.state, State::Finished) && !input.is_empty() {
            return Err(InflateRefusal::TrailingGarbage);
        }
        let received = self.received_input_bytes.checked_add(input.len()).ok_or(
            InflateRefusal::ResourceLimit {
                resource: Resource::InputBytes,
                limit: u64::try_from(self.limits.max_input_bytes).unwrap_or(u64::MAX),
                observed: u64::MAX,
            },
        )?;
        if received > self.limits.max_input_bytes {
            return Err(InflateRefusal::ResourceLimit {
                resource: Resource::InputBytes,
                limit: u64::try_from(self.limits.max_input_bytes).unwrap_or(u64::MAX),
                observed: u64::try_from(received).unwrap_or(u64::MAX),
            });
        }
        self.reader
            .append(input, self.limits.max_pending_input_bytes)?;
        self.received_input_bytes = received;
        let progress = self.drive(control)?;
        self.reader.compact();
        Ok(progress)
    }

    /// Verifies that the member is complete and returns a typed truncation
    /// refusal when more compressed bytes are still necessary.
    pub fn finish(&mut self) -> Result<(), InflateRefusal> {
        let mut control = NeverCancel;
        match self.drive(&mut control)? {
            StreamProgress::Finished => Ok(()),
            StreamProgress::NeedInput => Err(InflateRefusal::UnexpectedEnd),
        }
    }

    /// Drains output made available since the last call. It is tentative until
    /// [`Self::finish`] succeeds.
    #[must_use]
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending_output)
    }

    /// Returns whether the zlib trailer has verified successfully.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(self.state, State::Finished)
    }

    fn drive(
        &mut self,
        control: &mut impl CancellationProbe,
    ) -> Result<StreamProgress, InflateRefusal> {
        loop {
            self.charge_work(control)?;
            match self.state.clone() {
                State::ZlibHeader => {
                    let checkpoint = self.reader.checkpoint();
                    let Some(cmf) = self.reader.read_bits(8) else {
                        self.reader.restore(checkpoint);
                        return Ok(StreamProgress::NeedInput);
                    };
                    let Some(flg) = self.reader.read_bits(8) else {
                        self.reader.restore(checkpoint);
                        return Ok(StreamProgress::NeedInput);
                    };
                    let cmf = u8::try_from(cmf).map_err(|_| InflateRefusal::InvalidZlibHeader)?;
                    let flg = u8::try_from(flg).map_err(|_| InflateRefusal::InvalidZlibHeader)?;
                    let header = (u16::from(cmf) << 8) | u16::from(flg);
                    if (cmf & 0x0f) != 8 || (cmf >> 4) > 7 || header % 31 != 0 {
                        return Err(InflateRefusal::InvalidZlibHeader);
                    }
                    if (flg & 0x20) != 0 {
                        return Err(InflateRefusal::PresetDictionaryUnsupported);
                    }
                    let advertised_window = 1_usize << (usize::from(cmf >> 4) + 8);
                    if advertised_window > self.limits.max_window_bytes {
                        return Err(InflateRefusal::ResourceLimit {
                            resource: Resource::WindowBytes,
                            limit: u64::try_from(self.limits.max_window_bytes).unwrap_or(u64::MAX),
                            observed: u64::try_from(advertised_window).unwrap_or(u64::MAX),
                        });
                    }
                    self.window
                        .try_reserve_exact(advertised_window)
                        .map_err(|_| InflateRefusal::ResourceLimit {
                            resource: Resource::Allocation,
                            limit: u64::try_from(advertised_window).unwrap_or(u64::MAX),
                            observed: u64::try_from(advertised_window).unwrap_or(u64::MAX),
                        })?;
                    self.window_limit = advertised_window;
                    self.state = State::BlockHeader;
                }
                State::BlockHeader => {
                    let checkpoint = self.reader.checkpoint();
                    let Some(final_block) = self.reader.read_bits(1) else {
                        self.reader.restore(checkpoint);
                        return Ok(StreamProgress::NeedInput);
                    };
                    let Some(block_type) = self.reader.read_bits(2) else {
                        self.reader.restore(checkpoint);
                        return Ok(StreamProgress::NeedInput);
                    };
                    let final_block = final_block != 0;
                    self.state = match block_type {
                        0 => State::StoredHeader { final_block },
                        1 => State::Compressed {
                            final_block,
                            literal_length: HuffmanTable::fixed_literal_length(self.limits)?,
                            distance: HuffmanTable::fixed_distance(self.limits)?,
                            pending: PendingSymbol::Symbol,
                        },
                        2 => {
                            let dynamic_checkpoint = self.reader.checkpoint();
                            let Some((literal_length, distance)) =
                                self.read_dynamic_tables(control)?
                            else {
                                self.reader.restore(dynamic_checkpoint);
                                self.reader.restore(checkpoint);
                                return Ok(StreamProgress::NeedInput);
                            };
                            State::Compressed {
                                final_block,
                                literal_length,
                                distance,
                                pending: PendingSymbol::Symbol,
                            }
                        }
                        3 => return Err(InflateRefusal::ReservedBlockType),
                        _ => return Err(InflateRefusal::ReservedBlockType),
                    };
                }
                State::StoredHeader { final_block } => {
                    let checkpoint = self.reader.checkpoint();
                    if !self.reader.align_to_byte() {
                        self.reader.restore(checkpoint);
                        return Ok(StreamProgress::NeedInput);
                    }
                    let Some(length) = self.reader.read_bits(16) else {
                        self.reader.restore(checkpoint);
                        return Ok(StreamProgress::NeedInput);
                    };
                    let Some(complement) = self.reader.read_bits(16) else {
                        self.reader.restore(checkpoint);
                        return Ok(StreamProgress::NeedInput);
                    };
                    if length != !complement {
                        return Err(InflateRefusal::StoredLengthMismatch { length, complement });
                    }
                    self.state = State::StoredData {
                        final_block,
                        remaining: length,
                    };
                }
                State::StoredData {
                    final_block,
                    remaining,
                } => {
                    if remaining == 0 {
                        self.state = if final_block {
                            State::Adler32
                        } else {
                            State::BlockHeader
                        };
                        continue;
                    }
                    let checkpoint = self.reader.checkpoint();
                    let Some(byte) = self.reader.read_bits(8) else {
                        self.reader.restore(checkpoint);
                        return Ok(StreamProgress::NeedInput);
                    };
                    self.emit_byte_checked(
                        u8::try_from(byte).map_err(|_| InflateRefusal::InvalidHuffmanCode)?,
                    )?;
                    self.state = State::StoredData {
                        final_block,
                        remaining: remaining - 1,
                    };
                }
                State::Compressed {
                    final_block,
                    literal_length,
                    distance,
                    pending,
                } => {
                    if !self.advance_compressed(
                        final_block,
                        &literal_length,
                        &distance,
                        pending,
                        control,
                    )? {
                        return Ok(StreamProgress::NeedInput);
                    }
                }
                State::Adler32 => {
                    let checkpoint = self.reader.checkpoint();
                    if !self.reader.align_to_byte() {
                        self.reader.restore(checkpoint);
                        return Ok(StreamProgress::NeedInput);
                    }
                    let mut expected = 0_u32;
                    for _ in 0..4 {
                        let Some(byte) = self.reader.read_bits(8) else {
                            self.reader.restore(checkpoint);
                            return Ok(StreamProgress::NeedInput);
                        };
                        expected = (expected << 8) | u32::from(byte);
                    }
                    let actual = self.adler32.value();
                    if expected != actual {
                        return Err(InflateRefusal::Adler32Mismatch { expected, actual });
                    }
                    if self.reader.has_remaining_bytes() {
                        return Err(InflateRefusal::TrailingGarbage);
                    }
                    self.state = State::Finished;
                    return Ok(StreamProgress::Finished);
                }
                State::Finished => return Ok(StreamProgress::Finished),
            }
        }
    }

    fn advance_compressed(
        &mut self,
        final_block: bool,
        literal_length: &HuffmanTable,
        distance: &HuffmanTable,
        pending: PendingSymbol,
        control: &mut impl CancellationProbe,
    ) -> Result<bool, InflateRefusal> {
        match pending {
            PendingSymbol::Symbol => {
                let Some(symbol) = self.decode_symbol(literal_length, control)? else {
                    return Ok(false);
                };
                match symbol {
                    0..=255 => {
                        self.emit_byte_checked(
                            u8::try_from(symbol)
                                .map_err(|_| InflateRefusal::InvalidLengthOrDistanceCode)?,
                        )?;
                        self.state = State::Compressed {
                            final_block,
                            literal_length: literal_length.clone(),
                            distance: distance.clone(),
                            pending: PendingSymbol::Symbol,
                        };
                    }
                    256 => {
                        self.state = if final_block {
                            State::Adler32
                        } else {
                            State::BlockHeader
                        };
                    }
                    257..=285 => {
                        let index = usize::from(symbol - 257);
                        self.state = State::Compressed {
                            final_block,
                            literal_length: literal_length.clone(),
                            distance: distance.clone(),
                            pending: PendingSymbol::Length {
                                base: LENGTH_BASE[index],
                                extra_bits: LENGTH_EXTRA[index],
                            },
                        };
                    }
                    _ => return Err(InflateRefusal::InvalidLengthOrDistanceCode),
                }
            }
            PendingSymbol::Length { base, extra_bits } => {
                let checkpoint = self.reader.checkpoint();
                let Some(extra) = self.reader.read_bits(extra_bits) else {
                    self.reader.restore(checkpoint);
                    return Ok(false);
                };
                let length =
                    base.checked_add(usize::from(extra))
                        .ok_or(InflateRefusal::ResourceLimit {
                            resource: Resource::OutputBytes,
                            limit: u64::try_from(self.limits.max_output_bytes).unwrap_or(u64::MAX),
                            observed: u64::MAX,
                        })?;
                self.state = State::Compressed {
                    final_block,
                    literal_length: literal_length.clone(),
                    distance: distance.clone(),
                    pending: PendingSymbol::Distance { length },
                };
            }
            PendingSymbol::Distance { length } => {
                let Some(symbol) = self.decode_symbol(distance, control)? else {
                    return Ok(false);
                };
                let index = usize::from(symbol);
                if index >= DISTANCE_BASE.len() {
                    return Err(InflateRefusal::InvalidLengthOrDistanceCode);
                }
                self.state = State::Compressed {
                    final_block,
                    literal_length: literal_length.clone(),
                    distance: distance.clone(),
                    pending: PendingSymbol::DistanceExtra {
                        length,
                        base: DISTANCE_BASE[index],
                        extra_bits: DISTANCE_EXTRA[index],
                    },
                };
            }
            PendingSymbol::DistanceExtra {
                length,
                base,
                extra_bits,
            } => {
                let checkpoint = self.reader.checkpoint();
                let Some(extra) = self.reader.read_bits(extra_bits) else {
                    self.reader.restore(checkpoint);
                    return Ok(false);
                };
                let match_distance = base
                    .checked_add(usize::from(extra))
                    .ok_or(InflateRefusal::InvalidLengthOrDistanceCode)?;
                self.copy_match(match_distance, length)?;
                self.state = State::Compressed {
                    final_block,
                    literal_length: literal_length.clone(),
                    distance: distance.clone(),
                    pending: PendingSymbol::Symbol,
                };
            }
        }
        Ok(true)
    }

    fn decode_symbol(
        &mut self,
        table: &HuffmanTable,
        control: &mut impl CancellationProbe,
    ) -> Result<Option<u16>, InflateRefusal> {
        let checkpoint = self.reader.checkpoint();
        let mut bits = 0_u16;
        for bit_len in 1..=MAX_HUFFMAN_BITS {
            self.charge_work(control)?;
            let Some(next_bit) = self.reader.read_bits(1) else {
                self.reader.restore(checkpoint);
                return Ok(None);
            };
            bits |= next_bit << (bit_len - 1);
            if let Some(code) = table
                .codes
                .iter()
                .find(|code| code.bit_len == bit_len && code.reversed_bits == bits)
            {
                return Ok(Some(code.symbol));
            }
        }
        Err(InflateRefusal::InvalidHuffmanCode)
    }

    fn read_dynamic_tables(
        &mut self,
        control: &mut impl CancellationProbe,
    ) -> Result<Option<(HuffmanTable, HuffmanTable)>, InflateRefusal> {
        let checkpoint = self.reader.checkpoint();
        let Some(hlit) = self.reader.read_bits(5) else {
            self.reader.restore(checkpoint);
            return Ok(None);
        };
        let Some(hdist) = self.reader.read_bits(5) else {
            self.reader.restore(checkpoint);
            return Ok(None);
        };
        let Some(hclen) = self.reader.read_bits(4) else {
            self.reader.restore(checkpoint);
            return Ok(None);
        };
        let literal_count = usize::from(hlit) + 257;
        let distance_count = usize::from(hdist) + 1;
        let code_length_count = usize::from(hclen) + 4;
        let total = literal_count + distance_count;
        if total > self.limits.max_collection_elements {
            return Err(InflateRefusal::ResourceLimit {
                resource: Resource::CollectionElements,
                limit: u64::try_from(self.limits.max_collection_elements).unwrap_or(u64::MAX),
                observed: u64::try_from(total).unwrap_or(u64::MAX),
            });
        }
        let mut code_lengths = [0_u8; 19];
        for index in CODE_LENGTH_ORDER.iter().take(code_length_count) {
            let Some(length) = self.reader.read_bits(3) else {
                self.reader.restore(checkpoint);
                return Ok(None);
            };
            code_lengths[*index] =
                u8::try_from(length).map_err(|_| InflateRefusal::InvalidCodeLength)?;
        }
        let code_length_table =
            HuffmanTable::build(&code_lengths, self.limits, HuffmanSetPolicy::Complete)?;
        let mut lengths = [0_u8; 320];
        let mut position = 0_usize;
        while position < total {
            let Some(symbol) = self.decode_symbol(&code_length_table, control)? else {
                self.reader.restore(checkpoint);
                return Ok(None);
            };
            match symbol {
                0..=15 => {
                    lengths[position] =
                        u8::try_from(symbol).map_err(|_| InflateRefusal::InvalidCodeLength)?;
                    position += 1;
                }
                16 => {
                    if position == 0 {
                        return Err(InflateRefusal::InvalidCodeLength);
                    }
                    let Some(extra) = self.reader.read_bits(2) else {
                        self.reader.restore(checkpoint);
                        return Ok(None);
                    };
                    let repeat = usize::from(extra) + 3;
                    if position + repeat > total {
                        return Err(InflateRefusal::InvalidCodeLength);
                    }
                    let previous = lengths[position - 1];
                    lengths[position..position + repeat].fill(previous);
                    position += repeat;
                }
                17 => {
                    let Some(extra) = self.reader.read_bits(3) else {
                        self.reader.restore(checkpoint);
                        return Ok(None);
                    };
                    let repeat = usize::from(extra) + 3;
                    if position + repeat > total {
                        return Err(InflateRefusal::InvalidCodeLength);
                    }
                    position += repeat;
                }
                18 => {
                    let Some(extra) = self.reader.read_bits(7) else {
                        self.reader.restore(checkpoint);
                        return Ok(None);
                    };
                    let repeat = usize::from(extra) + 11;
                    if position + repeat > total {
                        return Err(InflateRefusal::InvalidCodeLength);
                    }
                    position += repeat;
                }
                _ => return Err(InflateRefusal::InvalidCodeLength),
            }
        }
        if lengths[256] == 0 {
            return Err(InflateRefusal::InvalidCodeLength);
        }
        let literal_length = HuffmanTable::build(
            &lengths[..literal_count],
            self.limits,
            HuffmanSetPolicy::LiteralLengthMayBeIncomplete,
        )?;
        let distance = HuffmanTable::build(
            &lengths[literal_count..total],
            self.limits,
            HuffmanSetPolicy::DistanceMayUseSingleBitCode,
        )?;
        Ok(Some((literal_length, distance)))
    }

    fn copy_match(&mut self, distance: usize, length: usize) -> Result<(), InflateRefusal> {
        if distance == 0 || distance > self.window.len() {
            return Err(InflateRefusal::DistanceTooFar {
                distance,
                available: self.window.len(),
            });
        }
        self.ensure_output_growth(length)?;
        self.reserve_pending_output(length)?;
        for _ in 0..length {
            let index = self.window.len() - distance;
            let byte = self
                .window
                .get(index)
                .copied()
                .ok_or(InflateRefusal::DistanceTooFar {
                    distance,
                    available: self.window.len(),
                })?;
            self.emit_byte_unchecked(byte);
        }
        Ok(())
    }

    fn emit_byte_checked(&mut self, byte: u8) -> Result<(), InflateRefusal> {
        self.ensure_output_growth(1)?;
        self.reserve_pending_output(1)?;
        self.emit_byte_unchecked(byte);
        Ok(())
    }

    fn ensure_output_growth(&self, additional: usize) -> Result<(), InflateRefusal> {
        let projected = self.emitted_output_bytes.checked_add(additional).ok_or(
            InflateRefusal::ResourceLimit {
                resource: Resource::OutputBytes,
                limit: u64::try_from(self.limits.max_output_bytes).unwrap_or(u64::MAX),
                observed: u64::MAX,
            },
        )?;
        if projected > self.limits.max_output_bytes {
            return Err(InflateRefusal::ResourceLimit {
                resource: Resource::OutputBytes,
                limit: u64::try_from(self.limits.max_output_bytes).unwrap_or(u64::MAX),
                observed: u64::try_from(projected).unwrap_or(u64::MAX),
            });
        }
        if let Some(ratio) = self.limits.max_expansion_ratio {
            let compressed = self.reader.consumed_bytes().max(1);
            let compressed =
                u128::try_from(compressed).map_err(|_| InflateRefusal::ResourceLimit {
                    resource: Resource::ExpansionRatio,
                    limit: u64::MAX,
                    observed: u64::MAX,
                })?;
            let projected =
                u128::try_from(projected).map_err(|_| InflateRefusal::ResourceLimit {
                    resource: Resource::OutputBytes,
                    limit: u64::try_from(self.limits.max_output_bytes).unwrap_or(u64::MAX),
                    observed: u64::MAX,
                })?;
            let allowed = compressed.saturating_mul(u128::from(ratio));
            if projected > allowed {
                return Err(InflateRefusal::ResourceLimit {
                    resource: Resource::ExpansionRatio,
                    limit: u64::try_from(allowed).unwrap_or(u64::MAX),
                    observed: u64::try_from(projected).unwrap_or(u64::MAX),
                });
            }
        }
        Ok(())
    }

    fn reserve_pending_output(&mut self, additional: usize) -> Result<(), InflateRefusal> {
        self.pending_output
            .try_reserve(additional)
            .map_err(|_| InflateRefusal::ResourceLimit {
                resource: Resource::Allocation,
                limit: u64::try_from(self.limits.max_output_bytes).unwrap_or(u64::MAX),
                observed: u64::try_from(self.emitted_output_bytes.saturating_add(additional))
                    .unwrap_or(u64::MAX),
            })
    }

    fn emit_byte_unchecked(&mut self, byte: u8) {
        if self.window.len() == self.window_limit {
            let _ = self.window.pop_front();
        }
        self.window.push_back(byte);
        self.pending_output.push(byte);
        self.emitted_output_bytes += 1;
        self.adler32.update(byte);
    }

    fn charge_work(&mut self, control: &mut impl CancellationProbe) -> Result<(), InflateRefusal> {
        if control.is_cancelled() {
            return Err(InflateRefusal::Cancelled);
        }
        let observed = self.work_units.saturating_add(1);
        if observed > self.limits.max_work_units {
            return Err(InflateRefusal::ResourceLimit {
                resource: Resource::WorkUnits,
                limit: self.limits.max_work_units,
                observed,
            });
        }
        self.work_units = observed;
        Ok(())
    }
}

/// Inflates exactly one zlib member and returns only trailer-verified bytes.
pub fn inflate_zlib(input: &[u8], limits: InflateLimits) -> Result<Vec<u8>, InflateRefusal> {
    let mut inflater = Inflater::new(limits)?;
    let _ = inflater.push(input)?;
    inflater.finish()?;
    Ok(inflater.take_output())
}

#[derive(Clone, Copy, Debug)]
struct Adler32 {
    a: u32,
    b: u32,
}

impl Adler32 {
    const MODULUS: u32 = 65_521;

    const fn new() -> Self {
        Self { a: 1, b: 0 }
    }

    fn update(&mut self, byte: u8) {
        self.a = (self.a + u32::from(byte)) % Self::MODULUS;
        self.b = (self.b + self.a) % Self::MODULUS;
    }

    const fn value(self) -> u32 {
        (self.b << 16) | self.a
    }
}

#[cfg(test)]
mod tests {
    use super::{
        inflate_zlib, Adler32, CancellationProbe, InflateLimits, InflateRefusal, Inflater,
        Resource, StreamProgress,
    };
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const EMPTY_ZLIB: &[u8] = &[0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01];

    fn limits() -> InflateLimits {
        InflateLimits {
            max_input_bytes: 128 * 1024,
            max_pending_input_bytes: 128 * 1024,
            max_output_bytes: 128 * 1024,
            max_expansion_ratio: Some(512),
            max_window_bytes: 32_768,
            max_huffman_symbols: 320,
            max_collection_elements: 320,
            max_work_units: 1_000_000,
        }
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        let compact: Vec<u8> = hex
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        assert_eq!(compact.len() % 2, 0, "fixture must contain whole bytes");
        compact
            .chunks_exact(2)
            .map(|pair| {
                let high = hex_nibble(pair[0]);
                let low = hex_nibble(pair[1]);
                (high << 4) | low
            })
            .collect()
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("fixture contains a non-hex byte"),
        }
    }

    fn fixture(name: &str) -> Vec<u8> {
        match name {
            "stored" => decode_hex(include_str!("../fixtures/stored_hello.zlib.hex")),
            "fixed" => decode_hex(include_str!("../fixtures/fixed_repetition.zlib.hex")),
            "dynamic" => decode_hex(include_str!("../fixtures/dynamic_text.zlib.hex")),
            _ => panic!("unknown fixture"),
        }
    }

    fn adler32(bytes: &[u8]) -> u32 {
        let mut checksum = Adler32::new();
        for &byte in bytes {
            checksum.update(byte);
        }
        checksum.value()
    }

    fn zlib_member(deflate: Vec<u8>, plain: &[u8]) -> Vec<u8> {
        let mut member = vec![0x78, 0x01];
        member.extend(deflate);
        member.extend(adler32(plain).to_be_bytes());
        member
    }

    #[derive(Default)]
    struct BitPacker {
        bytes: Vec<u8>,
        used_bits: u8,
    }

    impl BitPacker {
        fn push_bits(&mut self, value: u16, count: u8) {
            for offset in 0..count {
                if self.used_bits == 0 {
                    self.bytes.push(0);
                }
                let bit = if ((value >> offset) & 1) == 0 { 0 } else { 1 };
                let final_index = self.bytes.len() - 1;
                self.bytes[final_index] |= bit << self.used_bits;
                self.used_bits = (self.used_bits + 1) % 8;
            }
        }

        fn align_to_byte(&mut self) {
            if self.used_bits != 0 {
                self.used_bits = 0;
            }
        }

        fn push_aligned_slice(&mut self, bytes: &[u8]) {
            assert_eq!(self.used_bits, 0, "stored bytes must be byte aligned");
            self.bytes.extend_from_slice(bytes);
        }

        fn finish(self) -> Vec<u8> {
            self.bytes
        }
    }

    fn fixed_literal_code(symbol: u16) -> (u16, u8) {
        let (canonical, bits) = match symbol {
            0..=143 => (0x30 + symbol, 8),
            144..=255 => (0x190 + (symbol - 144), 9),
            256..=279 => (symbol - 256, 7),
            280..=287 => (0xc0 + (symbol - 280), 8),
            _ => panic!("not a fixed literal/length symbol"),
        };
        (super::reverse_low_bits(canonical, bits), bits)
    }

    fn push_fixed_literal(packer: &mut BitPacker, symbol: u16) {
        let (bits, length) = fixed_literal_code(symbol);
        packer.push_bits(bits, length);
    }

    fn push_fixed_distance(packer: &mut BitPacker, symbol: u16) {
        packer.push_bits(super::reverse_low_bits(symbol, 5), 5);
    }

    fn begin_fixed_block(packer: &mut BitPacker, final_block: bool) {
        packer.push_bits(if final_block { 1 } else { 0 }, 1);
        packer.push_bits(1, 2);
    }

    fn distance_one_run_member() -> Vec<u8> {
        let mut deflate = BitPacker::default();
        begin_fixed_block(&mut deflate, true);
        push_fixed_literal(&mut deflate, u16::from(b'A'));
        push_fixed_literal(&mut deflate, 285);
        push_fixed_distance(&mut deflate, 0);
        push_fixed_literal(&mut deflate, 256);
        zlib_member(deflate.finish(), &vec![b'A'; 259])
    }

    fn maximum_distance_member() -> Vec<u8> {
        let prefix = vec![b'Z'; 32_768];
        let mut deflate = BitPacker::default();
        deflate.push_bits(0, 1);
        deflate.push_bits(0, 2);
        deflate.align_to_byte();
        deflate.push_aligned_slice(&32_768_u16.to_le_bytes());
        deflate.push_aligned_slice(&(!32_768_u16).to_le_bytes());
        deflate.push_aligned_slice(&prefix);
        begin_fixed_block(&mut deflate, true);
        push_fixed_literal(&mut deflate, 257);
        push_fixed_distance(&mut deflate, 29);
        deflate.push_bits(8_191, 13);
        push_fixed_literal(&mut deflate, 256);
        let mut plain = prefix;
        plain.extend_from_slice(b"ZZZ");
        zlib_member(deflate.finish(), &plain)
    }

    fn malformed_dynamic_member(code_length_lengths: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut deflate = BitPacker::default();
        deflate.push_bits(1, 1);
        deflate.push_bits(2, 2);
        deflate.push_bits(0, 5);
        deflate.push_bits(0, 5);
        deflate.push_bits(0, 4);
        for code_length in code_length_lengths {
            deflate.push_bits(u16::from(code_length), 3);
        }
        for &byte in body {
            deflate.push_bits(u16::from(byte), 8);
        }
        zlib_member(deflate.finish(), &[])
    }

    fn assert_resource(error: InflateRefusal, resource: Resource) {
        assert!(
            matches!(error, InflateRefusal::ResourceLimit { resource: found, .. } if found == resource)
        );
    }

    #[test]
    fn rfc1950_empty_reference_vector_decodes() {
        assert_eq!(inflate_zlib(EMPTY_ZLIB, limits()), Ok(Vec::new()));
    }

    #[test]
    fn offline_reference_vectors_decode_each_deflate_block_type() {
        let stored = fixture("stored");
        let fixed = fixture("fixed");
        let dynamic = fixture("dynamic");
        assert_eq!((stored[2] >> 1) & 0b11, 0);
        assert_eq!((fixed[2] >> 1) & 0b11, 1);
        assert_eq!((dynamic[2] >> 1) & 0b11, 2);
        assert_eq!(inflate_zlib(&stored, limits()), Ok(b"hello".to_vec()));
        assert_eq!(
            inflate_zlib(&fixed, limits()),
            Ok(b"fixed huffman reference vector: abracadabra abracadabra abracadabra".to_vec())
        );

        let mut expected = b"The quick brown fox jumps over the lazy dog. ".repeat(80);
        expected.extend(0_u8..128);
        expected.extend(b" dynamic huffman corpus ".repeat(50));
        assert_eq!(inflate_zlib(&dynamic, limits()), Ok(expected));
    }

    #[test]
    fn streaming_output_is_tentative_until_finish_verifies_adler32() {
        let encoded = fixture("dynamic");
        let mut inflater =
            Inflater::new(limits()).unwrap_or_else(|error| panic!("limits: {error}"));
        let mut output = Vec::new();
        for chunk in encoded.chunks(3) {
            assert!(matches!(
                inflater.push(chunk),
                Ok(StreamProgress::NeedInput | StreamProgress::Finished)
            ));
            output.extend(inflater.take_output());
        }
        assert!(inflater.finish().is_ok());
        assert!(inflater.is_finished());
        let mut expected = b"The quick brown fox jumps over the lazy dog. ".repeat(80);
        expected.extend(0_u8..128);
        expected.extend(b" dynamic huffman corpus ".repeat(50));
        assert_eq!(output, expected);
    }

    #[test]
    fn fixed_back_references_cover_distance_one_length_258_and_distance_32768() {
        let distance_one = distance_one_run_member();
        assert_eq!(inflate_zlib(&distance_one, limits()), Ok(vec![b'A'; 259]));

        let maximum_distance = maximum_distance_member();
        let decoded = inflate_zlib(&maximum_distance, limits());
        assert_eq!(decoded.as_ref().map(Vec::len), Ok(32_771));
        assert!(matches!(decoded, Ok(bytes) if bytes.iter().all(|byte| *byte == b'Z')));
    }

    #[test]
    fn stored_length_mismatch_is_refused_before_payload_acceptance() {
        let deflate = vec![0b0000_0001, 1, 0, 0, 0];
        assert!(matches!(
            inflate_zlib(&zlib_member(deflate, &[]), limits()),
            Err(InflateRefusal::StoredLengthMismatch {
                length: 1,
                complement: 0
            })
        ));
    }

    #[test]
    fn incomplete_and_oversubscribed_dynamic_code_sets_are_refused() {
        assert_eq!(
            inflate_zlib(&malformed_dynamic_member([2, 0, 0, 0], &[]), limits()),
            Err(InflateRefusal::IncompleteHuffmanSet)
        );
        assert_eq!(
            inflate_zlib(&malformed_dynamic_member([1, 1, 1, 0], &[]), limits()),
            Err(InflateRefusal::OversubscribedHuffmanSet)
        );
    }

    #[test]
    fn dynamic_code_length_repeats_past_the_declared_table_are_refused() {
        let body = [0b1111_1111, 0b1111_1111];
        assert_eq!(
            inflate_zlib(&malformed_dynamic_member([0, 0, 1, 1], &body), limits()),
            Err(InflateRefusal::InvalidCodeLength)
        );
    }

    #[test]
    fn distance_too_far_is_refused_and_nearby_distance_one_is_permitted() {
        let mut deflate = BitPacker::default();
        begin_fixed_block(&mut deflate, true);
        push_fixed_literal(&mut deflate, 257);
        push_fixed_distance(&mut deflate, 0);
        push_fixed_literal(&mut deflate, 256);
        assert_eq!(
            inflate_zlib(&zlib_member(deflate.finish(), &[]), limits()),
            Err(InflateRefusal::DistanceTooFar {
                distance: 1,
                available: 0
            })
        );
        assert_eq!(
            inflate_zlib(&distance_one_run_member(), limits()),
            Ok(vec![b'A'; 259])
        );
    }

    #[test]
    fn invalid_length_distance_and_reserved_block_types_are_refused() {
        let mut invalid_length = BitPacker::default();
        begin_fixed_block(&mut invalid_length, true);
        push_fixed_literal(&mut invalid_length, 286);
        assert_eq!(
            inflate_zlib(&zlib_member(invalid_length.finish(), &[]), limits()),
            Err(InflateRefusal::InvalidLengthOrDistanceCode)
        );

        let mut reserved = BitPacker::default();
        reserved.push_bits(1, 1);
        reserved.push_bits(3, 2);
        assert_eq!(
            inflate_zlib(&zlib_member(reserved.finish(), &[]), limits()),
            Err(InflateRefusal::ReservedBlockType)
        );
    }

    #[test]
    fn checksum_trailing_input_and_dictionary_requests_are_refused() {
        let mut checksum_bad = EMPTY_ZLIB.to_vec();
        let last = checksum_bad.len() - 1;
        checksum_bad[last] ^= 1;
        assert!(matches!(
            inflate_zlib(&checksum_bad, limits()),
            Err(InflateRefusal::Adler32Mismatch { .. })
        ));

        let mut trailing = EMPTY_ZLIB.to_vec();
        trailing.push(0);
        assert_eq!(
            inflate_zlib(&trailing, limits()),
            Err(InflateRefusal::TrailingGarbage)
        );
        assert_eq!(
            inflate_zlib(&[0x78, 0x20], limits()),
            Err(InflateRefusal::PresetDictionaryUnsupported)
        );
    }

    #[test]
    fn window_output_ratio_and_pending_input_limits_are_enforced() {
        let narrow_window = InflateLimits {
            max_window_bytes: 16_384,
            ..limits()
        };
        assert_resource(
            inflate_zlib(EMPTY_ZLIB, narrow_window)
                .err()
                .unwrap_or_else(|| panic!("32KiB zlib header must exceed narrow window")),
            Resource::WindowBytes,
        );

        let ratio_limited = InflateLimits {
            max_expansion_ratio: Some(4),
            ..limits()
        };
        assert_resource(
            inflate_zlib(&distance_one_run_member(), ratio_limited)
                .err()
                .unwrap_or_else(|| panic!("run must exceed ratio limit")),
            Resource::ExpansionRatio,
        );

        let output_limited = InflateLimits {
            max_output_bytes: 128,
            max_expansion_ratio: Some(512),
            ..limits()
        };
        assert_resource(
            inflate_zlib(&distance_one_run_member(), output_limited)
                .err()
                .unwrap_or_else(|| panic!("run must exceed output limit")),
            Resource::OutputBytes,
        );

        let pending_limited = InflateLimits {
            max_pending_input_bytes: 4,
            ..limits()
        };
        assert_resource(
            Inflater::new(pending_limited)
                .and_then(|mut inflater| inflater.push(EMPTY_ZLIB).map(|_| ()))
                .err()
                .unwrap_or_else(|| panic!("input must exceed pending-input limit")),
            Resource::PendingInputBytes,
        );

        let ratio_disabled = InflateLimits {
            max_expansion_ratio: None,
            ..limits()
        };
        assert_resource(
            Inflater::new(ratio_disabled)
                .err()
                .unwrap_or_else(|| panic!("ratio ceiling is mandatory")),
            Resource::Configuration,
        );
    }

    struct CancelImmediately;

    impl CancellationProbe for CancelImmediately {
        fn is_cancelled(&mut self) -> bool {
            true
        }
    }

    #[test]
    fn cancellation_is_a_typed_refusal_before_decode_progress() {
        let mut inflater =
            Inflater::new(limits()).unwrap_or_else(|error| panic!("limits: {error}"));
        let mut cancellation = CancelImmediately;
        assert_eq!(
            inflater.push_with_control(EMPTY_ZLIB, &mut cancellation),
            Err(InflateRefusal::Cancelled)
        );
    }

    #[test]
    fn seeded_random_input_never_panics_and_only_returns_typed_outcomes() {
        let mut seed = 0x59d5_3489_7a11_4c3d_u64;
        for case in 0..2_000_u32 {
            let length = usize::try_from(seed & 0x7f).unwrap_or(0);
            let mut input = Vec::with_capacity(length);
            for _ in 0..length {
                seed ^= seed << 7;
                seed ^= seed >> 9;
                seed ^= seed << 8;
                input.push(u8::try_from(seed & 0xff).unwrap_or(0));
            }
            let attempt = catch_unwind(AssertUnwindSafe(|| inflate_zlib(&input, limits())));
            assert!(
                attempt.is_ok(),
                "decoder panicked for seed {seed:016x}, case {case}"
            );
            let Ok(result) = attempt else {
                return;
            };
            match result {
                Ok(_) => {}
                Err(
                    InflateRefusal::ResourceLimit { .. }
                    | InflateRefusal::Cancelled
                    | InflateRefusal::InvalidZlibHeader
                    | InflateRefusal::PresetDictionaryUnsupported
                    | InflateRefusal::UnexpectedEnd
                    | InflateRefusal::TrailingGarbage
                    | InflateRefusal::Adler32Mismatch { .. }
                    | InflateRefusal::ReservedBlockType
                    | InflateRefusal::StoredLengthMismatch { .. }
                    | InflateRefusal::InvalidHuffmanCode
                    | InflateRefusal::IncompleteHuffmanSet
                    | InflateRefusal::OversubscribedHuffmanSet
                    | InflateRefusal::InvalidCodeLength
                    | InflateRefusal::InvalidLengthOrDistanceCode
                    | InflateRefusal::DistanceTooFar { .. },
                ) => {}
            }
        }
    }
}

#![forbid(unsafe_code)]
//! Bounded, streaming RFC 1950/RFC 1951 decompression for `FrankenGit`.
//!
//! The decoder owns no ambient I/O, clock, task, or cancellation authority.
//! Callers feed bytes through [`Inflater::push`], can drain tentative output
//! between chunks, and must call [`Inflater::finish`] before accepting those
//! bytes. A caller that needs deadline cancellation supplies a
//! [`CancellationProbe`] to [`Inflater::push_with_control`].

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

/// The RFC 1951 maximum backwards-copy distance.
pub const RFC1951_MAX_WINDOW_BYTES: usize = 32_768;
const MAX_HUFFMAN_BITS: u8 = 15;
const HUFFMAN_LENGTH_SLOTS: usize = 16;
const HUFFMAN_LOOKUP_MISSING: u16 = u16::MAX;
const HUFFMAN_LOOKUP_SYMBOL_BITS: u8 = 9;
const MATCH_HASH_ENTRIES: usize = 32_768;
const MATCH_INDEX_NONE: usize = usize::MAX;

/// Work units between cancellation polls in the streaming encoder.
///
/// One unit is one literal byte or one match-chain step, so this bounds the
/// pure-CPU compression performed between two cancellation checks to a
/// fraction of a millisecond — responsive for any session-length transport
/// deadline, while removing the per-byte clock reads that dominated a served
/// clone (frankengit-1n25). It does not affect the work-unit budget ceiling,
/// which is still charged on every unit.
const DEFLATE_CANCELLATION_PROBE_UNITS: u64 = 16_384;
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
        // One-shot callers legitimately supply an entire bounded object at
        // once.  Keep the pending ceiling equal to the member input ceiling;
        // streaming callers still compact consumed input after each push.
        max_pending_input_bytes: 64 * 1024 * 1024,
        max_output_bytes: 256 * 1024 * 1024,
        // Git permits highly compressible blobs.  The output, input, work,
        // window, and allocation ceilings remain independent hard bounds;
        // this ceiling admits ordinary multi-MiB repetition without making
        // output unbounded.
        max_expansion_ratio: Some(4_096),
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
    /// A dynamic block declared more literal/length or distance codes than
    /// the RFC 1951 alphabets contain.
    TooManyDeclaredCodes,
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
            Self::TooManyDeclaredCodes => {
                formatter.write_str("dynamic block declares too many length or distance symbols")
            }
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

/// Explicit resource ceilings for one deterministic zlib member encoder.
///
/// The encoder never buffers more than `max_pending_input_bytes`, and it
/// accounts for the RFC 1950 header, RFC 1951 blocks, and Adler-32 trailer in
/// `max_output_bytes` before allocating output space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeflateLimits {
    /// Maximum uncompressed bytes accepted over the whole member.
    pub max_input_bytes: usize,
    /// Maximum unencoded bytes retained between `push` calls.
    pub max_pending_input_bytes: usize,
    /// Maximum compressed zlib-member bytes emitted by one encoder.
    pub max_output_bytes: usize,
    /// Maximum RFC 1951 history window that an active profile may use.
    pub max_window_bytes: usize,
    /// Maximum symbols that a generated Huffman table may contain.
    pub max_huffman_symbols: usize,
    /// Maximum generated dynamic-code-length entries.
    pub max_collection_elements: usize,
    /// Deterministic encode work units. This is not a wall-clock budget;
    /// callers supply deadline cancellation through [`CancellationProbe`].
    pub max_work_units: u64,
}

impl DeflateLimits {
    /// Conservative deterministic-compression limits for Git object and pack
    /// emission. They constrain the encoder independently of a consumer's
    /// object-size admission policy.
    pub const GIT_OBJECT: Self = Self {
        max_input_bytes: 64 * 1024 * 1024,
        max_pending_input_bytes: 64 * 1024,
        max_output_bytes: 128 * 1024 * 1024,
        max_window_bytes: RFC1951_MAX_WINDOW_BYTES,
        max_huffman_symbols: 320,
        max_collection_elements: 320,
        max_work_units: 512 * 1024 * 1024,
    };

    fn validate(self, profile: DeflateProfile) -> Result<(), DeflateRefusal> {
        if self.max_input_bytes == 0
            || self.max_pending_input_bytes < profile.block_bytes
            || self.max_output_bytes < 6
            || self.max_window_bytes > RFC1951_MAX_WINDOW_BYTES
            || self.max_window_bytes < profile.window_bytes
            || self.max_huffman_symbols == 0
            || self.max_collection_elements == 0
            || self.max_work_units == 0
        {
            return Err(DeflateRefusal::ResourceLimit {
                resource: Resource::Configuration,
                limit: 1,
                observed: 0,
            });
        }
        if profile.block_bytes == 0
            || profile.block_bytes > usize::from(u16::MAX)
            || profile.window_bytes > RFC1951_MAX_WINDOW_BYTES
            || profile.max_match_chain > profile.window_bytes
            || profile.lazy_matching
        {
            return Err(DeflateRefusal::InvalidProfile);
        }
        match profile.block_kind {
            DeflateBlockKind::Stored | DeflateBlockKind::Dynamic
                if profile.window_bytes != 0 || profile.max_match_chain != 0 =>
            {
                return Err(DeflateRefusal::InvalidProfile);
            }
            DeflateBlockKind::Fixed | DeflateBlockKind::FixedOrStored
                if profile.window_bytes == 0 || profile.max_match_chain == 0 =>
            {
                return Err(DeflateRefusal::InvalidProfile);
            }
            DeflateBlockKind::Stored
            | DeflateBlockKind::Fixed
            | DeflateBlockKind::FixedOrStored
            | DeflateBlockKind::Dynamic => {}
        }
        Ok(())
    }
}

/// RFC 1951 block coding selected by a deterministic encoder profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeflateBlockKind {
    /// Stored (uncompressed) blocks, each with RFC 1951 length complement.
    Stored,
    /// Fixed RFC 1951 Huffman codes with deterministic bounded matching.
    Fixed,
    /// Dynamic RFC 1951 Huffman tables with deterministic literal emission.
    Dynamic,
    /// Per block, the fixed-Huffman encoding of [`Self::Fixed`] unless a stored
    /// block is strictly smaller in bits at the current bit offset
    /// (frankengit-uf91). Incompressible blocks are stored, neither expanded
    /// nor bit-encoded; every other block is byte-identical to `Fixed`.
    FixedOrStored,
}

/// A frozen deterministic compression policy.
///
/// `block_bytes` is the canonical split boundary: streaming calls accumulate
/// until that many bytes are present, then emit one non-final block. This
/// makes one-shot and differently chunked streaming input choose the same
/// blocks. `max_match_chain` is a direct backwards-search limit in this first
/// slice, and `lazy_matching` records whether the profile compares the next
/// position before accepting a match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeflateProfile {
    /// Stable receipt and evidence identifier for this exact policy.
    pub id: &'static str,
    /// RFC 1951 block coding chosen by the profile.
    pub block_kind: DeflateBlockKind,
    /// Canonical uncompressed block split size.
    pub block_bytes: usize,
    /// Maximum backwards history distance searched and retained.
    pub window_bytes: usize,
    /// Maximum candidate distances considered at each input position.
    pub max_match_chain: usize,
    /// Whether this profile performs one-byte lazy match comparison.
    pub lazy_matching: bool,
}

impl DeflateProfile {
    /// Fast, stored-heavy emission. It retains no match history and writes
    /// 32 KiB stored blocks, trading compressed size for minimal matcher work.
    pub const FAST_STORED: Self = Self {
        id: "fast-stored-v1",
        block_kind: DeflateBlockKind::Stored,
        block_bytes: RFC1951_MAX_WINDOW_BYTES,
        window_bytes: 0,
        max_match_chain: 0,
        lazy_matching: false,
    };

    /// Deterministic fixed-Huffman emission with a 32 KiB history and a
    /// nearest-first, 64-candidate greedy matcher. This is the default pack
    /// writer profile in this slice.
    pub const DEFAULT: Self = Self {
        id: "default-fixed-v1",
        block_kind: DeflateBlockKind::Fixed,
        block_bytes: RFC1951_MAX_WINDOW_BYTES,
        window_bytes: RFC1951_MAX_WINDOW_BYTES,
        max_match_chain: 64,
        lazy_matching: false,
    };

    /// Fixed-Huffman emission with the same policy as [`Self::DEFAULT`].
    pub const FIXED: Self = Self::DEFAULT;

    /// [`Self::DEFAULT`]'s matcher and fixed codes, except that a block whose
    /// fixed encoding would not beat a stored block is stored (frankengit-uf91).
    /// Random or already-compressed bytes then cost a copy instead of 8-9 bits
    /// per literal, and never expand by more than stored-block framing.
    pub const FIXED_OR_STORED: Self = Self {
        id: "fixed-or-stored-v1",
        block_kind: DeflateBlockKind::FixedOrStored,
        block_bytes: RFC1951_MAX_WINDOW_BYTES,
        window_bytes: RFC1951_MAX_WINDOW_BYTES,
        max_match_chain: 64,
        lazy_matching: false,
    };

    /// Deterministic dynamic-Huffman emission. Its first slice emits literals
    /// through a frozen dynamic codebook, so it intentionally retains no
    /// match history while still exercising RFC 1951 dynamic-block framing.
    pub const DYNAMIC: Self = Self {
        id: "dynamic-literals-v1",
        block_kind: DeflateBlockKind::Dynamic,
        block_bytes: RFC1951_MAX_WINDOW_BYTES,
        window_bytes: 0,
        max_match_chain: 0,
        lazy_matching: false,
    };
}

/// Deterministic encoder progress after accepting one input chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeflateStreamProgress {
    /// The encoder remains open for input or an explicit finalization.
    NeedInput,
    /// The zlib member has been finalized and its receipt is available.
    Finished,
}

/// Immutable evidence for one successfully finalized deterministic member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeflateReceipt {
    /// The full frozen policy that selected output bytes.
    pub profile: DeflateProfile,
    /// Total uncompressed bytes accepted before finalization.
    pub input_bytes: usize,
    /// Total RFC 1950 member bytes emitted, including header and trailer.
    pub output_bytes: usize,
    /// Number of RFC 1951 blocks emitted, including a final empty block.
    pub block_count: usize,
}

/// A precise non-success result from deterministic zlib/DEFLATE emission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeflateRefusal {
    /// A configured resource boundary or checked allocation was exceeded.
    ResourceLimit {
        /// The bounded resource that refused additional work or allocation.
        resource: Resource,
        /// The configured ceiling.
        limit: u64,
        /// The attempted amount.
        observed: u64,
    },
    /// Caller-owned control requested cancellation between bounded steps.
    Cancelled,
    /// Input was supplied after the zlib member had already finalized.
    AlreadyFinished,
    /// The encoder was previously cancelled or refused a resource request.
    RefusedAfterFailure,
    /// A caller-provided profile violates this crate's static RFC boundaries.
    InvalidProfile,
}

impl fmt::Display for DeflateRefusal {
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
            Self::Cancelled => formatter.write_str("deflate cancelled by caller control"),
            Self::AlreadyFinished => formatter.write_str("zlib member is already finalized"),
            Self::RefusedAfterFailure => {
                formatter.write_str("zlib member is unusable after an earlier refusal")
            }
            Self::InvalidProfile => formatter.write_str("invalid deterministic deflate profile"),
        }
    }
}

impl std::error::Error for DeflateRefusal {}

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
        let required = self.bytes.len().checked_add(input.len()).ok_or_else(|| {
            InflateRefusal::ResourceLimit {
                resource: Resource::PendingInputBytes,
                limit: u64::try_from(limit).unwrap_or(u64::MAX),
                observed: u64::MAX,
            }
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

    const fn available_bits(&self) -> usize {
        self.bytes
            .len()
            .saturating_mul(8)
            .saturating_sub(self.bit_position)
    }

    const fn checkpoint(&self) -> usize {
        self.bit_position
    }

    const fn restore(&mut self, checkpoint: usize) {
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

    const fn align_to_byte(&mut self) -> bool {
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

    const fn has_remaining_bytes(&self) -> bool {
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

/// One decoding table: `2^M` slots, `M` being the longest code length in the
/// set (one slot for an empty set). A code of length `L` fills every slot whose
/// low `L` bits are its bit-reversed code.
///
/// The decoder reads up to 15 bits and looks up `bits mod 2^M` through
/// [`Self::entry`]. No code is longer than `M`, so that is exactly the slot a
/// table of all `2^15` slots would hold at `bits`. Lookups, the bits consumed,
/// the work charged and every refusal are therefore unchanged, but a fixed
/// literal/length table is 512 slots and a fixed distance table 32, instead
/// of 32,768 each (frankengit-6kgs).
#[derive(Clone, Debug)]
struct HuffmanTable {
    lookup: Vec<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HuffmanSetPolicy {
    Complete,
    LiteralLengthMayUseSingleBitCode,
    DistanceMayUseSingleBitCode,
    DistanceMayBeEmpty,
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
        let mut longest = 0_u8;
        for &length in lengths {
            if length > MAX_HUFFMAN_BITS {
                return Err(InflateRefusal::InvalidCodeLength);
            }
            if length != 0 {
                counts[usize::from(length)] += 1;
                non_zero += 1;
                longest = longest.max(length);
            }
        }
        let entries = 1_usize << longest;
        let mut lookup = Vec::new();
        lookup
            .try_reserve_exact(entries)
            .map_err(|_| InflateRefusal::ResourceLimit {
                resource: Resource::Allocation,
                limit: u64::try_from(entries).unwrap_or(u64::MAX),
                observed: u64::try_from(entries).unwrap_or(u64::MAX),
            })?;
        lookup.resize(entries, HUFFMAN_LOOKUP_MISSING);
        if non_zero == 0 {
            return match policy {
                HuffmanSetPolicy::DistanceMayBeEmpty => Ok(Self { lookup }),
                HuffmanSetPolicy::Complete
                | HuffmanSetPolicy::LiteralLengthMayUseSingleBitCode
                | HuffmanSetPolicy::DistanceMayUseSingleBitCode => {
                    Err(InflateRefusal::IncompleteHuffmanSet)
                }
            };
        }

        let mut available = 1_i32;
        for &count in counts.iter().skip(1) {
            available = (available * 2) - i32::from(count);
            if available < 0 {
                return Err(InflateRefusal::OversubscribedHuffmanSet);
            }
        }
        if available != 0 {
            let single_one_bit_symbol = non_zero == 1 && counts[1] == 1;
            let is_permitted = match policy {
                // Both arms refuse, for distinct reasons: `Complete` never permits an
                // incomplete set at all, while `DistanceMayBeEmpty` only tolerates an
                // EMPTY distance set and this branch is reached when `available != 0`.
                HuffmanSetPolicy::Complete | HuffmanSetPolicy::DistanceMayBeEmpty => false,
                HuffmanSetPolicy::LiteralLengthMayUseSingleBitCode
                | HuffmanSetPolicy::DistanceMayUseSingleBitCode => single_one_bit_symbol,
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

        for (symbol, &bit_len) in lengths.iter().enumerate() {
            if bit_len == 0 {
                continue;
            }
            let index = usize::from(bit_len);
            let canonical = next[index];
            next[index] += 1;
            let reversed_bits = reverse_low_bits(canonical, bit_len);
            let packed = pack_huffman_lookup(
                u16::try_from(symbol).map_err(|_| InflateRefusal::InvalidCodeLength)?,
                bit_len,
            );
            let suffix_count = 1_usize << (longest - bit_len);
            for suffix in 0..suffix_count {
                let lookup_index = usize::from(reversed_bits) | (suffix << bit_len);
                let slot = lookup
                    .get_mut(lookup_index)
                    .ok_or(InflateRefusal::InvalidHuffmanCode)?;
                if *slot != HUFFMAN_LOOKUP_MISSING {
                    return Err(InflateRefusal::OversubscribedHuffmanSet);
                }
                *slot = packed;
            }
        }
        Ok(Self { lookup })
    }

    /// The slot a decoder that has read `bits` sees; see the type.
    fn entry(&self, bits: u16) -> Option<u16> {
        self.lookup
            .get(usize::from(bits) & (self.lookup.len() - 1))
            .copied()
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

const fn pack_huffman_lookup(symbol: u16, bit_len: u8) -> u16 {
    ((bit_len as u16) << HUFFMAN_LOOKUP_SYMBOL_BITS) | symbol
}

const fn unpack_huffman_length(value: u16) -> u8 {
    (value >> HUFFMAN_LOOKUP_SYMBOL_BITS) as u8
}

const fn unpack_huffman_symbol(value: u16) -> u16 {
    value & ((1_u16 << HUFFMAN_LOOKUP_SYMBOL_BITS) - 1)
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

/// `(bit-reversed code, length)` of every fixed literal/length symbol (RFC 1951
/// 3.2.6), computed once instead of on every emitted symbol (frankengit-uf91).
const FIXED_SYMBOL_CODES: [(u16, u8); 288] = fixed_symbol_codes();

const fn fixed_symbol_codes() -> [(u16, u8); 288] {
    let mut table = [(0_u16, 0_u8); 288];
    let mut symbol = 0_u16;
    while symbol < 288 {
        let (canonical, bit_len) = match symbol {
            0..=143 => (0x30 + symbol, 8),
            144..=255 => (0x190 + (symbol - 144), 9),
            256..=279 => (symbol - 256, 7),
            _ => (0xc0 + (symbol - 280), 8),
        };
        table[symbol as usize] = (reverse_low_bits(canonical, bit_len), bit_len);
        symbol += 1;
    }
    table
}

/// Index of the RFC 1951 length code covering `length`.
fn length_code(length: usize) -> Result<usize, DeflateRefusal> {
    LENGTH_BASE
        .iter()
        .enumerate()
        .rev()
        .find(|(index, base)| {
            length >= **base && length <= **base + ((1_usize << LENGTH_EXTRA[*index]) - 1)
        })
        .map(|(index, _)| index)
        .ok_or(DeflateRefusal::InvalidProfile)
}

/// Index of the RFC 1951 distance code covering `distance`.
fn distance_code(distance: usize) -> Result<usize, DeflateRefusal> {
    DISTANCE_BASE
        .iter()
        .enumerate()
        .rev()
        .find(|(index, base)| {
            distance >= **base && distance <= **base + ((1_usize << DISTANCE_EXTRA[*index]) - 1)
        })
        .map(|(index, _)| index)
        .ok_or(DeflateRefusal::InvalidProfile)
}

/// Exact bits `write_fixed_match` emits for one length/distance pair.
fn fixed_match_bits(length: usize, distance: usize) -> Result<u64, DeflateRefusal> {
    let length_index = length_code(length)?;
    let distance_index = distance_code(distance)?;
    Ok(u64::from(FIXED_SYMBOL_CODES[257 + length_index].1)
        + u64::from(LENGTH_EXTRA[length_index])
        + 5
        + u64::from(DISTANCE_EXTRA[distance_index]))
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
        literal_length: Arc<HuffmanTable>,
        distance: Arc<HuffmanTable>,
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
    allow_framing_suffix: bool,
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
            allow_framing_suffix: false,
        })
    }

    /// Creates a decoder for one zlib member embedded in outer framing.
    ///
    /// [`Self::new`] refuses bytes after the member because a loose object is
    /// exactly one member and a suffix is corruption. A pack stream instead
    /// carries members back to back, so the framing consumer must be allowed
    /// to overshoot: a member that finishes inside a pushed buffer reports
    /// [`StreamProgress::Finished`] and leaves the excess unconsumed, with
    /// [`Self::consumed_input_bytes`] naming the exact boundary. A push after
    /// the member has finished is still refused in both modes.
    pub fn new_framed(limits: InflateLimits) -> Result<Self, InflateRefusal> {
        let mut inflater = Self::new(limits)?;
        inflater.allow_framing_suffix = true;
        Ok(inflater)
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
        let received = self
            .received_input_bytes
            .checked_add(input.len())
            .ok_or_else(|| InflateRefusal::ResourceLimit {
                resource: Resource::InputBytes,
                limit: u64::try_from(self.limits.max_input_bytes).unwrap_or(u64::MAX),
                observed: u64::MAX,
            })?;
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

    /// Compressed input bytes the decoder has actually consumed.
    ///
    /// A zlib member is self-delimiting, so a caller that streams a larger
    /// buffer through [`Self::push`] cannot otherwise learn where the member
    /// ended. After [`StreamProgress::Finished`], the difference between the
    /// bytes it supplied and this count is exactly the suffix that belongs to
    /// whatever framing follows the member — the fact a pack-stream consumer
    /// needs to resume at the next entry header.
    #[must_use]
    pub fn consumed_input_bytes(&self) -> usize {
        self.reader.consumed_bytes()
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
                            literal_length: Arc::new(HuffmanTable::fixed_literal_length(
                                self.limits,
                            )?),
                            distance: Arc::new(HuffmanTable::fixed_distance(self.limits)?),
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
                                literal_length: Arc::new(literal_length),
                                distance: Arc::new(distance),
                                pending: PendingSymbol::Symbol,
                            }
                        }
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
                    if !self.allow_framing_suffix && self.reader.has_remaining_bytes() {
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
        literal_length: &Arc<HuffmanTable>,
        distance: &Arc<HuffmanTable>,
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
                            literal_length: Arc::clone(literal_length),
                            distance: Arc::clone(distance),
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
                            literal_length: Arc::clone(literal_length),
                            distance: Arc::clone(distance),
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
                let length = base.checked_add(usize::from(extra)).ok_or_else(|| {
                    InflateRefusal::ResourceLimit {
                        resource: Resource::OutputBytes,
                        limit: u64::try_from(self.limits.max_output_bytes).unwrap_or(u64::MAX),
                        observed: u64::MAX,
                    }
                })?;
                self.state = State::Compressed {
                    final_block,
                    literal_length: Arc::clone(literal_length),
                    distance: Arc::clone(distance),
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
                    literal_length: Arc::clone(literal_length),
                    distance: Arc::clone(distance),
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
                    literal_length: Arc::clone(literal_length),
                    distance: Arc::clone(distance),
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
            let entry = table
                .entry(bits)
                .ok_or(InflateRefusal::InvalidHuffmanCode)?;
            if entry != HUFFMAN_LOOKUP_MISSING && unpack_huffman_length(entry) <= bit_len {
                return Ok(Some(unpack_huffman_symbol(entry)));
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
        // RFC 1951 caps the declared code counts at the alphabets that exist
        // (286 literal/length codes, 30 distance codes). The five-bit fields
        // can encode two wider values each; reference decoders refuse those
        // outright ("too many length or distance symbols") instead of giving
        // Huffman codes to symbols that cannot occur, so this decoder does
        // the same before any table is built.
        if hlit > 29 || hdist > 29 {
            return Err(InflateRefusal::TooManyDeclaredCodes);
        }
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
        let literal_lengths = &lengths[..literal_count];
        let distance_lengths = &lengths[literal_count..total];
        let contains_length_symbol = literal_lengths
            .get(257..)
            .is_some_and(|values| values.iter().any(|length| *length != 0));
        let has_distance_code = distance_lengths.iter().any(|length| *length != 0);
        if contains_length_symbol && !has_distance_code {
            return Err(InflateRefusal::InvalidLengthOrDistanceCode);
        }
        let literal_length = HuffmanTable::build(
            literal_lengths,
            self.limits,
            HuffmanSetPolicy::LiteralLengthMayUseSingleBitCode,
        )?;
        let distance = HuffmanTable::build(
            distance_lengths,
            self.limits,
            if has_distance_code {
                HuffmanSetPolicy::DistanceMayUseSingleBitCode
            } else {
                HuffmanSetPolicy::DistanceMayBeEmpty
            },
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
        let projected = self
            .emitted_output_bytes
            .checked_add(additional)
            .ok_or_else(|| InflateRefusal::ResourceLimit {
                resource: Resource::OutputBytes,
                limit: u64::try_from(self.limits.max_output_bytes).unwrap_or(u64::MAX),
                observed: u64::MAX,
            })?;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeflateState {
    Active,
    Finished,
    Refused,
}

#[derive(Clone, Debug)]
struct BitWriter {
    complete_bytes: Vec<u8>,
    partial_byte: u8,
    used_bits: u8,
}

impl BitWriter {
    const fn new() -> Self {
        Self {
            complete_bytes: Vec::new(),
            partial_byte: 0,
            used_bits: 0,
        }
    }

    const fn is_aligned(&self) -> bool {
        self.used_bits == 0
    }

    fn additional_physical_bytes(&self, bit_count: u8) -> usize {
        if bit_count == 0 {
            return 0;
        }
        let existing = usize::from(self.used_bits != 0);
        let total_bits = usize::from(self.used_bits) + usize::from(bit_count);
        total_bits.div_ceil(8).saturating_sub(existing)
    }

    fn try_reserve(&mut self, additional: usize) -> Result<(), ()> {
        self.complete_bytes.try_reserve(additional).map_err(|_| ())
    }

    /// Append the low `bit_count` bits of `value`, least significant first.
    /// The bits are placed in bulk, in exactly the order a one-bit-at-a-time
    /// writer would place them (frankengit-uf91): at most 7 pending plus 16
    /// new bits fit one `u32`.
    fn write_bits_unchecked(&mut self, value: u16, bit_count: u8) {
        let mask = (1_u32 << bit_count) - 1;
        let mut pending =
            u32::from(self.partial_byte) | ((u32::from(value) & mask) << self.used_bits);
        let mut bits = self.used_bits + bit_count;
        while bits >= 8 {
            self.complete_bytes.push(pending.to_le_bytes()[0]);
            pending >>= 8;
            bits -= 8;
        }
        self.partial_byte = pending.to_le_bytes()[0];
        self.used_bits = bits;
    }

    fn align_zero_unchecked(&mut self) {
        if self.used_bits != 0 {
            self.complete_bytes.push(self.partial_byte);
            self.partial_byte = 0;
            self.used_bits = 0;
        }
    }

    fn write_aligned_unchecked(&mut self, bytes: &[u8]) {
        self.complete_bytes.extend_from_slice(bytes);
    }

    fn take_complete_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.complete_bytes)
    }

    fn discard(&mut self) {
        self.complete_bytes.clear();
        self.partial_byte = 0;
        self.used_bits = 0;
    }
}

#[derive(Clone, Copy, Debug)]
struct EncodeCode {
    symbol: u16,
    reversed_bits: u16,
    bit_len: u8,
}

#[derive(Clone, Debug)]
struct EncodeCodebook {
    codes: Vec<EncodeCode>,
}

impl EncodeCodebook {
    fn build(lengths: &[u8], limits: DeflateLimits) -> Result<Self, DeflateRefusal> {
        if lengths.len() > limits.max_huffman_symbols {
            return Err(deflate_resource_limit(
                Resource::HuffmanSymbols,
                limits.max_huffman_symbols,
                lengths.len(),
            ));
        }
        let mut counts = [0_u16; HUFFMAN_LENGTH_SLOTS];
        let mut non_zero = 0_usize;
        for &length in lengths {
            if length > MAX_HUFFMAN_BITS {
                return Err(DeflateRefusal::InvalidProfile);
            }
            if length != 0 {
                counts[usize::from(length)] += 1;
                non_zero += 1;
            }
        }
        if non_zero == 0 {
            return Err(DeflateRefusal::InvalidProfile);
        }

        let mut available = 1_i32;
        for &count in counts.iter().skip(1) {
            available = (available * 2) - i32::from(count);
            if available < 0 {
                return Err(DeflateRefusal::InvalidProfile);
            }
        }

        let mut next = [0_u16; HUFFMAN_LENGTH_SLOTS];
        let mut code = 0_u16;
        for bit_len in 1..=usize::from(MAX_HUFFMAN_BITS) {
            code = (code + counts[bit_len - 1]) << 1;
            next[bit_len] = code;
        }

        let mut codes = Vec::new();
        codes.try_reserve(non_zero).map_err(|_| {
            deflate_resource_limit(Resource::Allocation, limits.max_huffman_symbols, non_zero)
        })?;
        for (symbol, &bit_len) in lengths.iter().enumerate() {
            if bit_len == 0 {
                continue;
            }
            let index = usize::from(bit_len);
            let canonical = next[index];
            next[index] += 1;
            codes.push(EncodeCode {
                symbol: u16::try_from(symbol).map_err(|_| DeflateRefusal::InvalidProfile)?,
                reversed_bits: reverse_low_bits(canonical, bit_len),
                bit_len,
            });
        }
        Ok(Self { codes })
    }

    fn code_for(&self, symbol: u16) -> Result<EncodeCode, DeflateRefusal> {
        self.codes
            .iter()
            .copied()
            .find(|code| code.symbol == symbol)
            .ok_or(DeflateRefusal::InvalidProfile)
    }
}

/// Bounded candidate index for one fixed-Huffman block.
///
/// The index is encoder-local planning state, never storage.  Its chains are
/// keyed by the next three bytes and therefore let a finite candidate budget
/// search the whole retained 32 KiB window instead of accidentally treating
/// the candidate count as a distance ceiling.
#[derive(Clone, Debug)]
struct MatchIndex {
    heads: Vec<usize>,
    previous: Vec<usize>,
    history_len: usize,
}

impl MatchIndex {
    /// Indexes the history part of `bytes`, which is the retained history
    /// followed by the block: `history_len` bytes, then the block.
    fn new(bytes: &[u8], history_len: usize) -> Result<Self, DeflateRefusal> {
        if history_len > bytes.len() {
            return Err(DeflateRefusal::InvalidProfile);
        }
        let mut heads = Vec::new();
        heads.try_reserve_exact(MATCH_HASH_ENTRIES).map_err(|_| {
            deflate_resource_limit(Resource::Allocation, MATCH_HASH_ENTRIES, MATCH_HASH_ENTRIES)
        })?;
        heads.resize(MATCH_HASH_ENTRIES, MATCH_INDEX_NONE);
        let total = bytes.len();
        let mut previous = Vec::new();
        previous
            .try_reserve_exact(total)
            .map_err(|_| deflate_resource_limit(Resource::Allocation, total, total))?;
        previous.resize(total, MATCH_INDEX_NONE);
        let mut index = Self {
            heads,
            previous,
            history_len,
        };
        for position in 0..history_len {
            index.record(position, bytes)?;
        }
        Ok(index)
    }

    fn record_emitted(
        &mut self,
        block_position: usize,
        length: usize,
        bytes: &[u8],
    ) -> Result<(), DeflateRefusal> {
        let start = self
            .history_len
            .checked_add(block_position)
            .ok_or(DeflateRefusal::InvalidProfile)?;
        let end = start
            .checked_add(length)
            .ok_or(DeflateRefusal::InvalidProfile)?;
        if end > bytes.len() {
            return Err(DeflateRefusal::InvalidProfile);
        }
        for position in start..end {
            self.record(position, bytes)?;
        }
        Ok(())
    }

    fn candidate_for(&self, block_position: usize, bytes: &[u8]) -> usize {
        let Some(position) = self.history_len.checked_add(block_position) else {
            return MATCH_INDEX_NONE;
        };
        let Some(hash) = triple_hash(position, bytes) else {
            return MATCH_INDEX_NONE;
        };
        self.heads.get(hash).copied().unwrap_or(MATCH_INDEX_NONE)
    }

    fn previous_candidate(&self, position: usize) -> usize {
        self.previous
            .get(position)
            .copied()
            .unwrap_or(MATCH_INDEX_NONE)
    }

    fn record(&mut self, position: usize, bytes: &[u8]) -> Result<(), DeflateRefusal> {
        let Some(hash) = triple_hash(position, bytes) else {
            return Ok(());
        };
        let head = self
            .heads
            .get_mut(hash)
            .ok_or(DeflateRefusal::InvalidProfile)?;
        let previous = self
            .previous
            .get_mut(position)
            .ok_or(DeflateRefusal::InvalidProfile)?;
        *previous = *head;
        *head = position;
        Ok(())
    }
}

/// Hash of the three bytes at `position`, or `None` past the last triple.
fn triple_hash(position: usize, bytes: &[u8]) -> Option<usize> {
    let triple = bytes.get(position..position.checked_add(3)?)?;
    let hash = usize::from(triple[0])
        .wrapping_mul(251)
        .wrapping_add(usize::from(triple[1]))
        .wrapping_mul(251)
        .wrapping_add(usize::from(triple[2]));
    Some(hash & (MATCH_HASH_ENTRIES - 1))
}

/// Length of the common prefix of `left` and `right`, compared a word at a
/// time.
fn common_prefix_len(left: &[u8], right: &[u8]) -> usize {
    let limit = left.len().min(right.len());
    let (left, right) = (&left[..limit], &right[..limit]);
    let mut matched = 0_usize;
    for (left_word, right_word) in left.as_chunks::<8>().0.iter().zip(right.as_chunks::<8>().0) {
        let difference = u64::from_le_bytes(*left_word) ^ u64::from_le_bytes(*right_word);
        if difference != 0 {
            return matched + (difference.trailing_zeros() / 8) as usize;
        }
        matched += 8;
    }
    matched
        + left[matched..]
            .iter()
            .zip(&right[matched..])
            .take_while(|(left_byte, right_byte)| left_byte == right_byte)
            .count()
}

/// A bounded, deterministic streaming RFC 1950/RFC 1951 member encoder.
///
/// Output from [`Self::take_output`] before [`Self::finish`] is tentative.
/// A caller must discard it after any refusal and may promote bytes only after
/// `finish` succeeds. Input chunking does not select different blocks: full
/// non-final blocks are always the profile's `block_bytes`, with the final
/// remainder (or an empty final block) emitted by `finish`.
#[derive(Clone, Debug)]
pub struct Deflater {
    limits: DeflateLimits,
    profile: DeflateProfile,
    state: DeflateState,
    pending_input: Vec<u8>,
    /// The last `window_bytes` encoded bytes, oldest first.
    history: Vec<u8>,
    /// The retained history followed by the block being encoded, rebuilt for
    /// each block so matching reads one slice (frankengit-g4a9).
    match_bytes: Vec<u8>,
    accepted_input_bytes: usize,
    output_bytes: usize,
    work_units: u64,
    /// Work units remaining before the next cancellation poll.
    ///
    /// The dynamic-Huffman encoder charges one work unit per literal byte and
    /// per match-chain step, so a multi-megabyte object charges millions of
    /// units. Polling the caller's cancellation source on every one of those
    /// dominated a served clone: a profile of `fg serve` (frankengit-1n25)
    /// spent ~79% of all cycles reading two clocks per unit through the
    /// transport deadline and the Asupersync budget `Cx`. This counter batches
    /// the poll onto a bounded work stride. The budget counter below still
    /// advances every unit, so the ceiling keeps full precision; only the
    /// cancellation probe is amortized, and cancellation latency stays bounded
    /// to [`DEFLATE_CANCELLATION_PROBE_UNITS`] units of pure-CPU compression.
    probe_countdown: u64,
    block_count: usize,
    writer: BitWriter,
    adler32: Adler32,
    /// One block's matcher decisions, reused across blocks by FixedOrStored.
    fixed_tokens: Vec<FixedToken>,
}

/// One fixed-Huffman decision, recorded before choosing a block encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixedToken {
    Literal(u8),
    Match { length: u16, distance: u16 },
}

impl Deflater {
    /// Validates limits and creates a zlib member with its deterministic RFC
    /// 1950 header. The header remains tentative until [`Self::finish`].
    pub fn new(limits: DeflateLimits, profile: DeflateProfile) -> Result<Self, DeflateRefusal> {
        limits.validate(profile)?;
        let mut encoder = Self {
            limits,
            profile,
            state: DeflateState::Active,
            pending_input: Vec::new(),
            history: Vec::new(),
            match_bytes: Vec::new(),
            accepted_input_bytes: 0,
            output_bytes: 0,
            work_units: 0,
            probe_countdown: 0,
            block_count: 0,
            writer: BitWriter::new(),
            adler32: Adler32::new(),
            fixed_tokens: Vec::new(),
        };
        // CM=8, CINFO=7 (32 KiB), no dictionary, FCHECK valid.
        encoder.write_aligned(&[0x78, 0x01])?;
        Ok(encoder)
    }

    /// Supplies uncompressed input using a control that never cancels.
    pub fn push(&mut self, input: &[u8]) -> Result<DeflateStreamProgress, DeflateRefusal> {
        let mut control = NeverCancel;
        self.push_with_control(input, &mut control)
    }

    /// Supplies uncompressed input and checks caller-owned cancellation before
    /// bounded copy, matching, and block-emission steps.
    pub fn push_with_control(
        &mut self,
        input: &[u8],
        control: &mut impl CancellationProbe,
    ) -> Result<DeflateStreamProgress, DeflateRefusal> {
        match self.state {
            DeflateState::Finished => return Err(DeflateRefusal::AlreadyFinished),
            DeflateState::Refused => return Err(DeflateRefusal::RefusedAfterFailure),
            DeflateState::Active => {}
        }
        // Each public streaming call may carry a different control, so force a
        // cancellation poll at its start; the amortization then applies within
        // this call's own byte stream. Callers feed the encoder in bounded
        // chunks, so this is one guaranteed poll per chunk.
        self.probe_countdown = 0;
        let result = self.push_active(input, control);
        if result.is_err() {
            self.refuse();
        }
        result.map(|()| DeflateStreamProgress::NeedInput)
    }

    /// Finalizes the last RFC 1951 block and appends the RFC 1950 Adler-32
    /// trailer. A second finalization is idempotent.
    pub fn finish(&mut self) -> Result<(), DeflateRefusal> {
        let mut control = NeverCancel;
        self.finish_with_control(&mut control)
    }

    /// Finalizes with caller-owned cancellation checked during the final block
    /// and before Adler-32 trailer publication.
    pub fn finish_with_control(
        &mut self,
        control: &mut impl CancellationProbe,
    ) -> Result<(), DeflateRefusal> {
        match self.state {
            DeflateState::Finished => return Ok(()),
            DeflateState::Refused => return Err(DeflateRefusal::RefusedAfterFailure),
            DeflateState::Active => {}
        }
        // Finalization is a fresh control boundary: poll it at least once so a
        // caller that cancels only at finish is honoured regardless of how the
        // preceding push calls drained the probe stride.
        self.probe_countdown = 0;
        let result = self.finish_active(control);
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Drains complete output bytes. Bytes are never promoted by this method:
    /// they remain tentative until [`Self::finish`] has succeeded. A refused
    /// encoder returns no further bytes and discards its private remainder.
    #[must_use]
    pub fn take_output(&mut self) -> Vec<u8> {
        if matches!(self.state, DeflateState::Refused) {
            self.writer.discard();
            return Vec::new();
        }
        self.writer.take_complete_bytes()
    }

    /// Returns whether the RFC 1950 trailer has been emitted successfully.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(self.state, DeflateState::Finished)
    }

    /// Deterministic encoding work charged by this member so far.
    ///
    /// A multi-member owner can subtract this from one shared work allowance
    /// before constructing its next encoder. Starting a new zlib member must
    /// not replenish an operation's aggregate resource budget. The counter
    /// retains successful charges after refusal; a charge rejected by the work
    /// ceiling is not added to it.
    #[must_use]
    pub const fn work_units(&self) -> u64 {
        self.work_units
    }

    /// Returns immutable finalization evidence only after successful finish.
    #[must_use]
    pub const fn receipt(&self) -> Option<DeflateReceipt> {
        if !matches!(self.state, DeflateState::Finished) {
            return None;
        }
        Some(DeflateReceipt {
            profile: self.profile,
            input_bytes: self.accepted_input_bytes,
            output_bytes: self.output_bytes,
            block_count: self.block_count,
        })
    }

    fn push_active(
        &mut self,
        input: &[u8],
        control: &mut impl CancellationProbe,
    ) -> Result<(), DeflateRefusal> {
        let accepted = self
            .accepted_input_bytes
            .checked_add(input.len())
            .ok_or_else(|| {
                deflate_resource_limit(
                    Resource::InputBytes,
                    self.limits.max_input_bytes,
                    usize::MAX,
                )
            })?;
        if accepted > self.limits.max_input_bytes {
            return Err(deflate_resource_limit(
                Resource::InputBytes,
                self.limits.max_input_bytes,
                accepted,
            ));
        }

        let mut remaining = input;
        while !remaining.is_empty() {
            self.charge_work(control)?;
            if self.pending_input.len() == self.limits.max_pending_input_bytes {
                self.encode_pending_prefix(self.profile.block_bytes, false, control)?;
                continue;
            }
            let capacity = self
                .limits
                .max_pending_input_bytes
                .saturating_sub(self.pending_input.len());
            let take = remaining.len().min(capacity);
            let accepted_chunk = &remaining[..take];
            self.charge_work_units(control, take)?;
            self.reserve_pending_input(take)?;
            self.pending_input.extend_from_slice(accepted_chunk);
            self.adler32.update_slice(accepted_chunk);
            remaining = &remaining[take..];

            while self.pending_input.len() >= self.profile.block_bytes {
                self.encode_pending_prefix(self.profile.block_bytes, false, control)?;
            }
        }
        self.accepted_input_bytes = accepted;
        Ok(())
    }

    fn finish_active(
        &mut self,
        control: &mut impl CancellationProbe,
    ) -> Result<(), DeflateRefusal> {
        let final_length = self.pending_input.len();
        self.encode_pending_prefix(final_length, true, control)?;
        self.charge_work(control)?;
        self.align_zero();
        let trailer = self.adler32.value().to_be_bytes();
        self.write_aligned(&trailer)?;
        self.state = DeflateState::Finished;
        Ok(())
    }

    fn encode_pending_prefix(
        &mut self,
        length: usize,
        final_block: bool,
        control: &mut impl CancellationProbe,
    ) -> Result<(), DeflateRefusal> {
        if length > self.pending_input.len() || length > self.profile.block_bytes {
            return Err(DeflateRefusal::InvalidProfile);
        }
        let mut block = Vec::new();
        block.try_reserve(length).map_err(|_| {
            deflate_resource_limit(
                Resource::Allocation,
                self.limits.max_pending_input_bytes,
                length,
            )
        })?;
        block.extend_from_slice(&self.pending_input[..length]);
        self.encode_block(&block, final_block, control)?;
        self.append_history(&block)?;
        self.pending_input.drain(..length);
        self.block_count = self.block_count.saturating_add(1);
        Ok(())
    }

    fn encode_block(
        &mut self,
        block: &[u8],
        final_block: bool,
        control: &mut impl CancellationProbe,
    ) -> Result<(), DeflateRefusal> {
        self.charge_work(control)?;
        match self.profile.block_kind {
            DeflateBlockKind::Stored => self.encode_stored_block(block, final_block),
            DeflateBlockKind::Fixed => self.encode_fixed_block(block, final_block, control),
            DeflateBlockKind::Dynamic => self.encode_dynamic_block(block, final_block, control),
            DeflateBlockKind::FixedOrStored => {
                self.encode_fixed_or_stored_block(block, final_block, control)
            }
        }
    }

    /// The same matcher decisions as [`Self::encode_fixed_block`], recorded
    /// with their exact fixed-Huffman bit cost. The block is then emitted as
    /// those fixed codes, bit for bit what `Fixed` writes, unless a stored
    /// block (3 header bits, zero padding to a byte boundary from the current
    /// bit offset, LEN/NLEN, the bytes) is strictly smaller.
    fn encode_fixed_or_stored_block(
        &mut self,
        block: &[u8],
        final_block: bool,
        control: &mut impl CancellationProbe,
    ) -> Result<(), DeflateRefusal> {
        let mut tokens = std::mem::take(&mut self.fixed_tokens);
        tokens.clear();
        let reserved = tokens.try_reserve(block.len()).map_err(|_| {
            deflate_resource_limit(Resource::Allocation, self.profile.block_bytes, block.len())
        });
        let mut bytes = std::mem::take(&mut self.match_bytes);
        let result = reserved
            .and_then(|()| self.load_match_bytes(&mut bytes, block))
            .and_then(|history_len| {
                // Header and end-of-block code, then each decision.
                let mut fixed_bits = 3_u64 + u64::from(FIXED_SYMBOL_CODES[256].1);
                let mut matcher = MatchIndex::new(&bytes, history_len)?;
                let mut position = 0_usize;
                while position < block.len() {
                    if let Some((length, distance)) =
                        self.find_match(&bytes, history_len, position, &matcher, control)?
                    {
                        fixed_bits += fixed_match_bits(length, distance)?;
                        tokens.push(FixedToken::Match {
                            length: u16::try_from(length)
                                .map_err(|_| DeflateRefusal::InvalidProfile)?,
                            distance: u16::try_from(distance)
                                .map_err(|_| DeflateRefusal::InvalidProfile)?,
                        });
                        matcher.record_emitted(position, length, &bytes)?;
                        position += length;
                    } else {
                        fixed_bits += u64::from(FIXED_SYMBOL_CODES[usize::from(block[position])].1);
                        tokens.push(FixedToken::Literal(block[position]));
                        matcher.record_emitted(position, 1, &bytes)?;
                        position += 1;
                    }
                }
                let padding = (8 - (u64::from(self.writer.used_bits) + 3) % 8) % 8;
                let stored_bits = 3 + padding + 32 + 8 * block.len() as u64;
                if stored_bits < fixed_bits {
                    return self.encode_stored_block(block, final_block);
                }
                self.write_bits(u16::from(final_block), 1)?;
                self.write_bits(1, 2)?;
                for &token in &tokens {
                    match token {
                        FixedToken::Literal(byte) => self.write_fixed_symbol(u16::from(byte))?,
                        FixedToken::Match { length, distance } => {
                            self.write_fixed_match(usize::from(length), usize::from(distance))?;
                        }
                    }
                }
                self.write_fixed_symbol(256)
            });
        self.match_bytes = bytes;
        self.fixed_tokens = tokens;
        result
    }

    fn encode_stored_block(
        &mut self,
        block: &[u8],
        final_block: bool,
    ) -> Result<(), DeflateRefusal> {
        let length = u16::try_from(block.len()).map_err(|_| DeflateRefusal::InvalidProfile)?;
        self.write_bits(u16::from(final_block), 1)?;
        self.write_bits(0, 2)?;
        self.align_zero();
        self.write_aligned(&length.to_le_bytes())?;
        self.write_aligned(&(!length).to_le_bytes())?;
        self.write_aligned(block)
    }

    fn encode_fixed_block(
        &mut self,
        block: &[u8],
        final_block: bool,
        control: &mut impl CancellationProbe,
    ) -> Result<(), DeflateRefusal> {
        self.write_bits(u16::from(final_block), 1)?;
        self.write_bits(1, 2)?;
        let mut bytes = std::mem::take(&mut self.match_bytes);
        let result = self
            .load_match_bytes(&mut bytes, block)
            .and_then(|history_len| {
                let mut matcher = MatchIndex::new(&bytes, history_len)?;
                let mut position = 0_usize;
                while position < block.len() {
                    if let Some((length, distance)) =
                        self.find_match(&bytes, history_len, position, &matcher, control)?
                    {
                        self.write_fixed_match(length, distance)?;
                        matcher.record_emitted(position, length, &bytes)?;
                        position += length;
                    } else {
                        self.write_fixed_symbol(u16::from(block[position]))?;
                        matcher.record_emitted(position, 1, &bytes)?;
                        position += 1;
                    }
                }
                self.write_fixed_symbol(256)
            });
        self.match_bytes = bytes;
        result
    }

    /// Fills `bytes` with the retained history followed by `block` and returns
    /// the history length.
    fn load_match_bytes(&self, bytes: &mut Vec<u8>, block: &[u8]) -> Result<usize, DeflateRefusal> {
        let total = self
            .history
            .len()
            .checked_add(block.len())
            .ok_or(DeflateRefusal::InvalidProfile)?;
        bytes.clear();
        bytes
            .try_reserve(total)
            .map_err(|_| deflate_resource_limit(Resource::Allocation, total, total))?;
        bytes.extend_from_slice(&self.history);
        bytes.extend_from_slice(block);
        Ok(self.history.len())
    }

    fn encode_dynamic_block(
        &mut self,
        block: &[u8],
        final_block: bool,
        control: &mut impl CancellationProbe,
    ) -> Result<(), DeflateRefusal> {
        // A dynamic literal/length alphabet needs a Kraft-complete code set.
        // The former fixed-table prefix omitted symbols 286-287 while still
        // advertising 286 entries, leaving 254/256 of the code space and
        // producing members zlib correctly rejects.  This frozen table covers
        // every literal plus EOB in exactly 257 entries: 255 eight-bit codes
        // and two nine-bit codes fill the code space exactly.
        const LITERAL_COUNT: usize = 257;
        const DISTANCE_COUNT: usize = 1;
        // The code-length alphabet must also represent the one-bit distance
        // code.  Symbols 1, 8, and 9 are made complete with lengths 1, 2,
        // and 2 respectively.  Symbol 1 occurs late in RFC 1951's prescribed
        // transmission order, so HCLEN must include its eighteenth entry.
        const CODE_LENGTH_COUNT: usize = 18;
        let total_lengths = LITERAL_COUNT + DISTANCE_COUNT;
        if total_lengths > self.limits.max_collection_elements {
            return Err(deflate_resource_limit(
                Resource::CollectionElements,
                self.limits.max_collection_elements,
                total_lengths,
            ));
        }

        let mut literal_lengths = [0_u8; LITERAL_COUNT];
        literal_lengths[..255].fill(8);
        literal_lengths[255..].fill(9);
        let distance_lengths = [1_u8; DISTANCE_COUNT];
        let mut code_length_lengths = [0_u8; 19];
        code_length_lengths[1] = 1;
        code_length_lengths[8] = 2;
        code_length_lengths[9] = 2;

        let literal_codebook = EncodeCodebook::build(&literal_lengths, self.limits)?;
        let code_length_codebook = EncodeCodebook::build(&code_length_lengths, self.limits)?;

        self.write_bits(u16::from(final_block), 1)?;
        self.write_bits(2, 2)?;
        self.write_bits(0, 5)?;
        self.write_bits(0, 5)?;
        self.write_bits(
            u16::try_from(CODE_LENGTH_COUNT - 4).map_err(|_| DeflateRefusal::InvalidProfile)?,
            4,
        )?;
        for &index in CODE_LENGTH_ORDER.iter().take(CODE_LENGTH_COUNT) {
            self.write_bits(u16::from(code_length_lengths[index]), 3)?;
        }
        for &length in literal_lengths.iter().chain(distance_lengths.iter()) {
            self.write_codebook_symbol(&code_length_codebook, u16::from(length))?;
        }
        for &byte in block {
            self.charge_work(control)?;
            self.write_codebook_symbol(&literal_codebook, u16::from(byte))?;
        }
        self.write_codebook_symbol(&literal_codebook, 256)
    }

    /// The longest match at `position`, charging the decision's work: one
    /// unit for the decision, one per chain candidate, and one per byte the
    /// byte-by-byte extension compared after the first (each matching byte and
    /// the mismatch that stopped it). The units are summed and charged once,
    /// before every return, through the exact bulk charge, so the counter and
    /// any refusal are what single charges would produce (frankengit-g4a9).
    fn find_match(
        &mut self,
        bytes: &[u8],
        history_len: usize,
        position: usize,
        matcher: &MatchIndex,
        control: &mut impl CancellationProbe,
    ) -> Result<Option<(usize, usize)>, DeflateRefusal> {
        let mut units = 1_usize;
        let found = self.search_match(bytes, history_len, position, matcher, &mut units);
        self.charge_units_exactly(control, units)?;
        found
    }

    fn search_match(
        &self,
        bytes: &[u8],
        history_len: usize,
        position: usize,
        matcher: &MatchIndex,
        units: &mut usize,
    ) -> Result<Option<(usize, usize)>, DeflateRefusal> {
        let block_len = bytes
            .len()
            .checked_sub(history_len)
            .ok_or(DeflateRefusal::InvalidProfile)?;
        if self.profile.max_match_chain == 0 || position + 3 > block_len {
            return Ok(None);
        }
        let current = history_len.saturating_add(position);
        let max_length = (block_len - position).min(258);
        let mut best = None;
        let mut candidate = matcher.candidate_for(position, bytes);
        let mut candidates_seen = 0_usize;
        while candidate != MATCH_INDEX_NONE && candidates_seen < self.profile.max_match_chain {
            *units += 1;
            if candidate >= current {
                return Err(DeflateRefusal::InvalidProfile);
            }
            let distance = current - candidate;
            if distance > self.profile.window_bytes || bytes[candidate] != bytes[current] {
                candidate = matcher.previous_candidate(candidate);
                candidates_seen += 1;
                continue;
            }
            // The source may overlap the target, as an LZ77 copy does; both
            // are bytes already in the buffer.
            let length = 1 + common_prefix_len(
                &bytes[candidate + 1..],
                &bytes[current + 1..current + max_length],
            );
            *units += length - 1 + usize::from(length < max_length);
            if length >= 3 && best.is_none_or(|(best_length, _)| length > best_length) {
                best = Some((length, distance));
                if length == max_length {
                    return Ok(best);
                }
            }
            candidate = matcher.previous_candidate(candidate);
            candidates_seen += 1;
        }
        Ok(best)
    }

    fn write_fixed_match(&mut self, length: usize, distance: usize) -> Result<(), DeflateRefusal> {
        let length_index = length_code(length)?;
        let length_symbol = 257_u16
            .checked_add(u16::try_from(length_index).map_err(|_| DeflateRefusal::InvalidProfile)?)
            .ok_or(DeflateRefusal::InvalidProfile)?;
        self.write_fixed_symbol(length_symbol)?;
        self.write_bits(
            u16::try_from(length - LENGTH_BASE[length_index])
                .map_err(|_| DeflateRefusal::InvalidProfile)?,
            LENGTH_EXTRA[length_index],
        )?;

        let distance_index = distance_code(distance)?;
        self.write_bits(
            reverse_low_bits(
                u16::try_from(distance_index).map_err(|_| DeflateRefusal::InvalidProfile)?,
                5,
            ),
            5,
        )?;
        self.write_bits(
            u16::try_from(distance - DISTANCE_BASE[distance_index])
                .map_err(|_| DeflateRefusal::InvalidProfile)?,
            DISTANCE_EXTRA[distance_index],
        )
    }

    fn write_fixed_symbol(&mut self, symbol: u16) -> Result<(), DeflateRefusal> {
        let (code, bit_len) = *FIXED_SYMBOL_CODES
            .get(usize::from(symbol))
            .ok_or(DeflateRefusal::InvalidProfile)?;
        self.write_bits(code, bit_len)
    }

    fn write_codebook_symbol(
        &mut self,
        codebook: &EncodeCodebook,
        symbol: u16,
    ) -> Result<(), DeflateRefusal> {
        let code = codebook.code_for(symbol)?;
        self.write_bits(code.reversed_bits, code.bit_len)
    }

    fn append_history(&mut self, block: &[u8]) -> Result<(), DeflateRefusal> {
        if self.profile.window_bytes == 0 || block.is_empty() {
            return Ok(());
        }
        let remaining_capacity = self.profile.window_bytes.saturating_sub(self.history.len());
        self.history.try_reserve(remaining_capacity).map_err(|_| {
            deflate_resource_limit(
                Resource::Allocation,
                self.profile.window_bytes,
                self.profile.window_bytes,
            )
        })?;
        let window = self.profile.window_bytes;
        if block.len() >= window {
            self.history.clear();
            self.history
                .extend_from_slice(&block[block.len() - window..]);
        } else {
            let excess = (self.history.len() + block.len()).saturating_sub(window);
            self.history.drain(..excess);
            self.history.extend_from_slice(block);
        }
        Ok(())
    }

    fn reserve_pending_input(&mut self, additional: usize) -> Result<(), DeflateRefusal> {
        let required = self
            .pending_input
            .len()
            .checked_add(additional)
            .ok_or_else(|| {
                deflate_resource_limit(
                    Resource::PendingInputBytes,
                    self.limits.max_pending_input_bytes,
                    usize::MAX,
                )
            })?;
        if required > self.limits.max_pending_input_bytes {
            return Err(deflate_resource_limit(
                Resource::PendingInputBytes,
                self.limits.max_pending_input_bytes,
                required,
            ));
        }
        self.pending_input.try_reserve(additional).map_err(|_| {
            deflate_resource_limit(
                Resource::Allocation,
                self.limits.max_pending_input_bytes,
                required,
            )
        })
    }

    fn write_bits(&mut self, value: u16, bit_count: u8) -> Result<(), DeflateRefusal> {
        if bit_count > MAX_HUFFMAN_BITS {
            return Err(DeflateRefusal::InvalidProfile);
        }
        let additional = self.writer.additional_physical_bytes(bit_count);
        self.reserve_output(additional)?;
        self.writer.write_bits_unchecked(value, bit_count);
        self.output_bytes = self.output_bytes.saturating_add(additional);
        Ok(())
    }

    fn align_zero(&mut self) {
        if self.writer.is_aligned() {
            return;
        }
        self.writer.align_zero_unchecked();
    }

    fn write_aligned(&mut self, bytes: &[u8]) -> Result<(), DeflateRefusal> {
        if !self.writer.is_aligned() {
            return Err(DeflateRefusal::InvalidProfile);
        }
        self.reserve_output(bytes.len())?;
        self.writer.write_aligned_unchecked(bytes);
        self.output_bytes = self.output_bytes.saturating_add(bytes.len());
        Ok(())
    }

    fn reserve_output(&mut self, additional: usize) -> Result<(), DeflateRefusal> {
        let projected = self.output_bytes.checked_add(additional).ok_or_else(|| {
            deflate_resource_limit(
                Resource::OutputBytes,
                self.limits.max_output_bytes,
                usize::MAX,
            )
        })?;
        if projected > self.limits.max_output_bytes {
            return Err(deflate_resource_limit(
                Resource::OutputBytes,
                self.limits.max_output_bytes,
                projected,
            ));
        }
        self.writer.try_reserve(additional).map_err(|()| {
            deflate_resource_limit(
                Resource::Allocation,
                self.limits.max_output_bytes,
                projected,
            )
        })
    }

    fn charge_work(&mut self, control: &mut impl CancellationProbe) -> Result<(), DeflateRefusal> {
        self.charge_work_units(control, 1)
    }

    fn charge_work_units(
        &mut self,
        control: &mut impl CancellationProbe,
        units: usize,
    ) -> Result<(), DeflateRefusal> {
        let units = u64::try_from(units).unwrap_or(u64::MAX);
        // Poll cancellation on a bounded work stride rather than per unit: the
        // caller's probe can be expensive (two clock reads through the
        // transport deadline and the budget Cx), and this loop charges one
        // unit per byte. The budget ceiling below is unaffected — it advances
        // every unit — so only the cancellation latency is coarsened, and only
        // to a bounded amount of pure-CPU compression. See `probe_countdown`.
        if self.probe_countdown < units {
            if control.is_cancelled() {
                return Err(DeflateRefusal::Cancelled);
            }
            self.probe_countdown = DEFLATE_CANCELLATION_PROBE_UNITS;
        } else {
            self.probe_countdown -= units;
        }
        let observed = self.work_units.saturating_add(units);
        if observed > self.limits.max_work_units {
            return Err(DeflateRefusal::ResourceLimit {
                resource: Resource::WorkUnits,
                limit: self.limits.max_work_units,
                observed,
            });
        }
        self.work_units = observed;
        Ok(())
    }

    /// Charges `units` single units at once, refusing exactly where the first
    /// unit over the ceiling would have: `observed` is the ceiling plus one and
    /// the counter stops at the ceiling (frankengit-g4a9).
    fn charge_units_exactly(
        &mut self,
        control: &mut impl CancellationProbe,
        units: usize,
    ) -> Result<(), DeflateRefusal> {
        if units == 0 {
            return Ok(());
        }
        let units = u64::try_from(units).unwrap_or(u64::MAX);
        if self.probe_countdown < units {
            if control.is_cancelled() {
                return Err(DeflateRefusal::Cancelled);
            }
            self.probe_countdown = DEFLATE_CANCELLATION_PROBE_UNITS;
        } else {
            self.probe_countdown -= units;
        }
        let observed = self.work_units.saturating_add(units);
        if observed > self.limits.max_work_units {
            self.work_units = self.limits.max_work_units;
            return Err(DeflateRefusal::ResourceLimit {
                resource: Resource::WorkUnits,
                limit: self.limits.max_work_units,
                observed: self.limits.max_work_units.saturating_add(1),
            });
        }
        self.work_units = observed;
        Ok(())
    }

    fn refuse(&mut self) {
        self.state = DeflateState::Refused;
        self.pending_input.clear();
        self.history.clear();
        self.writer.discard();
    }
}

/// Encodes exactly one deterministic zlib member and returns bytes only after
/// its final RFC 1950 Adler-32 trailer has been emitted.
pub fn deflate_zlib(
    input: &[u8],
    limits: DeflateLimits,
    profile: DeflateProfile,
) -> Result<Vec<u8>, DeflateRefusal> {
    let mut deflater = Deflater::new(limits, profile)?;
    let _ = deflater.push(input)?;
    deflater.finish()?;
    Ok(deflater.take_output())
}

fn deflate_resource_limit(resource: Resource, limit: usize, observed: usize) -> DeflateRefusal {
    DeflateRefusal::ResourceLimit {
        resource,
        limit: u64::try_from(limit).unwrap_or(u64::MAX),
        observed: u64::try_from(observed).unwrap_or(u64::MAX),
    }
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

    /// Bytes [`Self::update_slice`] sums before reducing: zlib's NMAX, the
    /// largest n with 255n(n+1)/2 + (n+1)(65520) <= 2^32 - 1, so neither sum can
    /// overflow from reduced starting values.
    const NMAX: usize = 5_552;

    fn update(&mut self, byte: u8) {
        // Both sums start reduced and grow by less than the modulus, so one
        // conditional subtraction is the remainder (frankengit-g4a9).
        self.a += u32::from(byte);
        if self.a >= Self::MODULUS {
            self.a -= Self::MODULUS;
        }
        self.b += self.a;
        if self.b >= Self::MODULUS {
            self.b -= Self::MODULUS;
        }
    }

    /// [`Self::update`] for each byte, reducing once per run of at most
    /// [`Self::NMAX`] bytes.
    fn update_slice(&mut self, bytes: &[u8]) {
        for run in bytes.chunks(Self::NMAX) {
            let (mut a, mut b) = (self.a, self.b);
            for &byte in run {
                a += u32::from(byte);
                b += a;
            }
            self.a = a % Self::MODULUS;
            self.b = b % Self::MODULUS;
        }
    }

    const fn value(self) -> u32 {
        (self.b << 16) | self.a
    }
}

#[cfg(test)]
mod tests {
    /// The former one-bit-at-a-time writer, kept as the oracle for the bulk one.
    fn reference_bits(writes: &[(u16, u8)]) -> (Vec<u8>, u8, u8) {
        let (mut bytes, mut partial, mut used) = (Vec::new(), 0_u8, 0_u8);
        for &(value, bit_count) in writes {
            for offset in 0..bit_count {
                partial |= u8::from(((value >> offset) & 1) != 0) << used;
                used += 1;
                if used == 8 {
                    bytes.push(partial);
                    partial = 0;
                    used = 0;
                }
            }
        }
        (bytes, partial, used)
    }

    #[test]
    fn bulk_bit_writer_places_exactly_the_bits_of_the_one_bit_reference() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for round in 0..200 {
            let mut writes = Vec::new();
            for _ in 0..=(round % 37) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let bit_count = u8::try_from(state % 17).unwrap();
                // Includes bits above `bit_count`, which must be ignored.
                writes.push((u16::try_from(state >> 40 & 0xffff).unwrap(), bit_count));
            }
            let mut writer = super::BitWriter::new();
            for &(value, bit_count) in &writes {
                writer.write_bits_unchecked(value, bit_count);
            }
            let (bytes, partial, used) = reference_bits(&writes);
            assert_eq!(writer.complete_bytes, bytes, "round {round}");
            assert_eq!((writer.partial_byte, writer.used_bits), (partial, used));
        }
    }

    #[test]
    fn fixed_symbol_table_is_the_rfc1951_canonical_code_bit_reversed() {
        for symbol in 0_u16..288 {
            let (canonical, bit_len) = match symbol {
                0..=143 => (0x30 + symbol, 8),
                144..=255 => (0x190 + (symbol - 144), 9),
                256..=279 => (symbol - 256, 7),
                _ => (0xc0 + (symbol - 280), 8),
            };
            let mut reversed = 0_u16;
            for offset in 0..bit_len {
                reversed = (reversed << 1) | ((canonical >> offset) & 1);
            }
            assert_eq!(
                super::FIXED_SYMBOL_CODES[usize::from(symbol)],
                (reversed, bit_len),
                "symbol {symbol}"
            );
        }
    }

    use super::{
        Adler32, CancellationProbe, DeflateBlockKind, DeflateLimits, DeflateProfile,
        DeflateRefusal, DeflateStreamProgress, Deflater, FixedToken, InflateLimits, InflateRefusal,
        Inflater, MatchIndex, NeverCancel, RFC1951_MAX_WINDOW_BYTES, Resource, StreamProgress,
        deflate_zlib, inflate_zlib,
    };
    use std::panic::{AssertUnwindSafe, catch_unwind};

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
            .as_chunks::<2>()
            .0
            .iter()
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

    #[test]
    fn a_dynamic_block_declaring_more_codes_than_the_alphabet_is_refused() {
        // The refusal must fire at the header itself, before any code-length
        // bit is interpreted, exactly where reference decoders refuse.
        let build = |hlit: u16, hdist: u16| {
            let mut packer = BitPacker::default();
            packer.push_bits(1, 1); // bfinal
            packer.push_bits(0b10, 2); // dynamic block
            packer.push_bits(hlit, 5);
            packer.push_bits(hdist, 5);
            packer.push_bits(0, 4); // HCLEN; never consumed past the refusal
            packer.finish()
        };
        for (hlit, hdist) in [(30_u16, 0_u16), (31, 0), (0, 30), (0, 31)] {
            let member = zlib_member(build(hlit, hdist), &[]);
            assert!(
                matches!(
                    inflate_zlib(&member, limits()),
                    Err(InflateRefusal::TooManyDeclaredCodes)
                ),
                "HLIT {hlit} / HDIST {hdist} must be refused as over-wide"
            );
        }
    }

    #[test]
    fn a_maximal_dynamic_header_is_not_refused_for_its_declared_counts() {
        // 286 literal/length and 30 distance codes are the RFC maxima; a
        // header declaring them must pass the count gate and fail later on
        // its (here, empty) code-length alphabet instead.
        let mut packer = BitPacker::default();
        packer.push_bits(1, 1); // bfinal
        packer.push_bits(0b10, 2); // dynamic block
        packer.push_bits(29, 5); // HLIT: 286 literal/length codes
        packer.push_bits(29, 5); // HDIST: 30 distance codes
        packer.push_bits(0, 4); // HCLEN: four code-length codes
        for _ in 0..4 {
            packer.push_bits(0, 3); // every length zero: an incomplete set
        }
        let member = zlib_member(packer.finish(), &[]);
        assert!(matches!(
            inflate_zlib(&member, limits()),
            Err(InflateRefusal::IncompleteHuffmanSet)
        ));
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
                let bit = u8::from(((value >> offset) & 1) != 0);
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
        packer.push_bits(u16::from(final_block), 1);
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

    fn zero_distance_dynamic_member() -> Vec<u8> {
        let mut deflate = BitPacker::default();
        deflate.push_bits(1, 1);
        deflate.push_bits(2, 2);
        deflate.push_bits(0, 5);
        deflate.push_bits(0, 5);
        deflate.push_bits(14, 4);
        for &index in super::CODE_LENGTH_ORDER.iter().take(18) {
            let code_length = u16::from(index == 0 || index == 1);
            deflate.push_bits(code_length, 3);
        }
        for _ in 0..256 {
            deflate.push_bits(0, 1);
        }
        deflate.push_bits(1, 1);
        deflate.push_bits(0, 1);
        deflate.push_bits(0, 1);
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
    fn valid_dynamic_literal_only_block_may_omit_distance_codes() {
        assert_eq!(
            inflate_zlib(&zero_distance_dynamic_member(), limits()),
            Ok(Vec::new())
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

    #[test]
    fn git_object_profile_admits_large_repetition_and_large_one_shot_members() {
        let repeated = vec![0_u8; 1024 * 1024];
        let repeated_member = deflate_zlib(
            &repeated,
            DeflateLimits::GIT_OBJECT,
            DeflateProfile::DEFAULT,
        )
        .unwrap_or_else(|error| panic!("encode high-ratio Git blob: {error}"));
        assert_eq!(
            inflate_zlib(&repeated_member, InflateLimits::GIT_OBJECT),
            Ok(repeated)
        );

        let mut incompressible = Vec::with_capacity(1024 * 1024 + 1);
        let mut seed = 0xa059_2174_5bce_d013_u64;
        for _ in 0..=(1024 * 1024) {
            seed ^= seed << 7;
            seed ^= seed >> 9;
            seed ^= seed << 8;
            incompressible.push(u8::try_from(seed & 0xff).unwrap_or(0));
        }
        let large_member = deflate_zlib(
            &incompressible,
            DeflateLimits::GIT_OBJECT,
            DeflateProfile::FAST_STORED,
        )
        .unwrap_or_else(|error| panic!("encode large Git member: {error}"));
        assert!(large_member.len() > 1024 * 1024);
        assert_eq!(
            inflate_zlib(&large_member, InflateLimits::GIT_OBJECT),
            Ok(incompressible)
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
            assert!(
                matches!(
                    result,
                    Ok(_)
                        | Err(InflateRefusal::ResourceLimit { .. }
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
                            | InflateRefusal::DistanceTooFar { .. })
                ),
                "random decoder outcome was outside the public refusal vocabulary"
            );
        }
    }

    fn deflate_limits() -> DeflateLimits {
        DeflateLimits {
            max_input_bytes: 256 * 1024,
            max_pending_input_bytes: 32_768,
            max_output_bytes: 2 * 1024 * 1024,
            max_window_bytes: 32_768,
            max_huffman_symbols: 320,
            max_collection_elements: 320,
            max_work_units: 32 * 1024 * 1024,
        }
    }

    fn fnv1a64(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, &byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }

    fn encode_streamed(input: &[u8], profile: DeflateProfile, chunk_sizes: &[usize]) -> Vec<u8> {
        let mut encoder = Deflater::new(deflate_limits(), profile)
            .unwrap_or_else(|error| panic!("encoder configuration: {error}"));
        let mut output = encoder.take_output();
        let mut offset = 0_usize;
        for &requested in chunk_sizes {
            if offset == input.len() {
                break;
            }
            let end = offset.saturating_add(requested).min(input.len());
            assert_eq!(
                encoder.push(&input[offset..end]),
                Ok(DeflateStreamProgress::NeedInput)
            );
            output.extend(encoder.take_output());
            offset = end;
        }
        if offset != input.len() {
            assert_eq!(
                encoder.push(&input[offset..]),
                Ok(DeflateStreamProgress::NeedInput)
            );
            output.extend(encoder.take_output());
        }
        encoder
            .finish()
            .unwrap_or_else(|error| panic!("stream finalization: {error}"));
        output.extend(encoder.take_output());
        output
    }

    #[test]
    fn encoder_profiles_emit_their_declared_rfc1951_block_kinds() {
        let input = b"block-kind";
        for (profile, expected_header, expected_kind) in [
            (DeflateProfile::FAST_STORED, 1_u8, DeflateBlockKind::Stored),
            (DeflateProfile::DEFAULT, 3_u8, DeflateBlockKind::Fixed),
            (DeflateProfile::DYNAMIC, 5_u8, DeflateBlockKind::Dynamic),
            (
                DeflateProfile::FIXED_OR_STORED,
                3_u8,
                DeflateBlockKind::FixedOrStored,
            ),
        ] {
            let encoded = deflate_zlib(input, deflate_limits(), profile)
                .unwrap_or_else(|error| panic!("{}: {error}", profile.id));
            assert_eq!(encoded[2] & 0x07, expected_header, "{}", profile.id);
            assert_eq!(profile.block_kind, expected_kind);
            assert_eq!(
                inflate_zlib(&encoded, limits()),
                Ok(input.to_vec()),
                "{}",
                profile.id
            );
        }
    }

    #[test]
    fn encoder_golden_output_fingerprints_are_profile_stable() {
        // These non-cryptographic FNV-1a fingerprints are checked-in output
        // snapshots for this frozen encoder policy. They are regression
        // sentinels, not an external oracle or object commitments.
        let input = b"FrankenGit golden v1";
        for (profile, expected_len, expected_fingerprint) in [
            (
                DeflateProfile::FAST_STORED,
                31_usize,
                0x7e4f_9115_9375_0729_u64,
            ),
            (DeflateProfile::DEFAULT, 28_usize, 0xc93d_a395_cc04_32fd_u64),
            (
                DeflateProfile::DYNAMIC,
                101_usize,
                0xf25d_582e_0f0c_983d_u64,
            ),
        ] {
            let encoded = deflate_zlib(input, deflate_limits(), profile)
                .unwrap_or_else(|error| panic!("{}: {error}", profile.id));
            assert_eq!(
                encoded.len(),
                expected_len,
                "{}: actual fingerprint {:016x}",
                profile.id,
                fnv1a64(&encoded)
            );
            assert_eq!(
                fnv1a64(&encoded),
                expected_fingerprint,
                "{}: actual length {}",
                profile.id,
                encoded.len()
            );
        }
    }

    fn noise(seed: u64, length: usize) -> Vec<u8> {
        let mut state = seed | 1;
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.push(state.to_le_bytes()[3]);
        }
        bytes
    }

    fn text(length: usize) -> Vec<u8> {
        b"fn main() { println!(\"frankengit\"); }\n"
            .iter()
            .copied()
            .cycle()
            .take(length)
            .collect()
    }

    /// frankengit-uf91: where every block's fixed encoding wins, the profile
    /// is byte-identical to DEFAULT; where none does, it stores every block
    /// and is never larger than the input plus stored-block framing.
    #[test]
    fn fixed_or_stored_equals_default_on_compressible_input_and_stores_noise() {
        for length in [0, 1, 20, 32_767, 32_768, 32_769, 70_000] {
            let input = text(length);
            assert_eq!(
                deflate_zlib(&input, deflate_limits(), DeflateProfile::FIXED_OR_STORED),
                deflate_zlib(&input, deflate_limits(), DeflateProfile::DEFAULT),
                "text {length}"
            );
        }
        // One random byte is cheaper as a fixed literal than as a stored block.
        let single = noise(1, 1);
        assert_eq!(
            deflate_zlib(&single, deflate_limits(), DeflateProfile::FIXED_OR_STORED),
            deflate_zlib(&single, deflate_limits(), DeflateProfile::DEFAULT)
        );
        for length in [300, 32_767, 32_768, 32_769, 100_000] {
            let input = noise(u64::try_from(length).unwrap(), length);
            let stored =
                deflate_zlib(&input, deflate_limits(), DeflateProfile::FIXED_OR_STORED).unwrap();
            let fixed = deflate_zlib(&input, deflate_limits(), DeflateProfile::DEFAULT).unwrap();
            assert_eq!(inflate_zlib(&stored, limits()), Ok(input.clone()));
            // zlib header 2 + adler 4, and per block (every full block plus the
            // final, possibly empty one) at most a header byte, LEN and NLEN.
            let blocks = length / 32_768 + 1;
            assert!(
                stored.len() <= input.len() + 6 + 5 * blocks,
                "noise {length}"
            );
            assert!(stored.len() < fixed.len(), "noise {length}");
        }
    }

    /// Mixed blocks choose independently; the member still round-trips and is
    /// never larger than DEFAULT's.
    #[test]
    fn fixed_or_stored_chooses_per_block_on_mixed_input() {
        let mut input = Vec::new();
        for round in 0..3_u64 {
            input.extend(noise(round + 7, 32_768));
            input.extend(text(32_768));
        }
        let mixed =
            deflate_zlib(&input, deflate_limits(), DeflateProfile::FIXED_OR_STORED).unwrap();
        let fixed = deflate_zlib(&input, deflate_limits(), DeflateProfile::DEFAULT).unwrap();
        let wide = InflateLimits {
            max_input_bytes: 1 << 20,
            max_output_bytes: 1 << 20,
            ..limits()
        };
        assert_eq!(inflate_zlib(&mixed, wide), Ok(input.clone()));
        assert!(mixed.len() < fixed.len());
        assert_eq!(
            encode_streamed(
                &input,
                DeflateProfile::FIXED_OR_STORED,
                &[1, 17, 9_991, 31, 40_007]
            ),
            mixed
        );
    }

    #[test]
    fn encoder_streaming_chunking_is_byte_identical_to_one_shot() {
        let mut input = Vec::with_capacity(70_123);
        let mut state = 0x8437_1529_5a6c_d1e2_u64;
        for _ in 0..70_123 {
            state ^= state << 7;
            state ^= state >> 9;
            state ^= state << 8;
            input.push(u8::try_from(state & 0xff).unwrap_or(0));
        }
        for profile in [
            DeflateProfile::FAST_STORED,
            DeflateProfile::DEFAULT,
            DeflateProfile::DYNAMIC,
            DeflateProfile::FIXED_OR_STORED,
        ] {
            let one_shot = deflate_zlib(&input, deflate_limits(), profile)
                .unwrap_or_else(|error| panic!("{}: {error}", profile.id));
            let streamed = encode_streamed(&input, profile, &[1, 17, 9_991, 31, 40_007]);
            assert_eq!(streamed, one_shot, "{}", profile.id);
        }
    }

    /// The fixed-block matcher exactly as it was before frankengit-g4a9: a
    /// ring-buffer history read byte by byte, one work unit per compared byte.
    /// The former table builder, kept verbatim as the oracle for the sized
    /// tables (frankengit-6kgs): every table had all `2^15` slots and the
    /// decoder indexed it with `bits` directly.
    mod reference_huffman {
        use super::super::{
            HUFFMAN_LENGTH_SLOTS, HUFFMAN_LOOKUP_MISSING, HuffmanSetPolicy, InflateLimits,
            InflateRefusal, MAX_HUFFMAN_BITS, Resource, pack_huffman_lookup, reverse_low_bits,
        };

        const HUFFMAN_LOOKUP_ENTRIES: usize = 1_usize << MAX_HUFFMAN_BITS;

        pub fn build(
            lengths: &[u8],
            limits: InflateLimits,
            policy: HuffmanSetPolicy,
        ) -> Result<Vec<u16>, InflateRefusal> {
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
            let mut lookup = vec![HUFFMAN_LOOKUP_MISSING; HUFFMAN_LOOKUP_ENTRIES];
            if non_zero == 0 {
                return match policy {
                    HuffmanSetPolicy::DistanceMayBeEmpty => Ok(lookup),
                    HuffmanSetPolicy::Complete
                    | HuffmanSetPolicy::LiteralLengthMayUseSingleBitCode
                    | HuffmanSetPolicy::DistanceMayUseSingleBitCode => {
                        Err(InflateRefusal::IncompleteHuffmanSet)
                    }
                };
            }
            let mut available = 1_i32;
            for &count in counts.iter().skip(1) {
                available = (available * 2) - i32::from(count);
                if available < 0 {
                    return Err(InflateRefusal::OversubscribedHuffmanSet);
                }
            }
            if available != 0 {
                let single_one_bit_symbol = non_zero == 1 && counts[1] == 1;
                let is_permitted = match policy {
                    HuffmanSetPolicy::Complete | HuffmanSetPolicy::DistanceMayBeEmpty => false,
                    HuffmanSetPolicy::LiteralLengthMayUseSingleBitCode
                    | HuffmanSetPolicy::DistanceMayUseSingleBitCode => single_one_bit_symbol,
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
            for (symbol, &bit_len) in lengths.iter().enumerate() {
                if bit_len == 0 {
                    continue;
                }
                let index = usize::from(bit_len);
                let canonical = next[index];
                next[index] += 1;
                let reversed_bits = reverse_low_bits(canonical, bit_len);
                let packed = pack_huffman_lookup(
                    u16::try_from(symbol).map_err(|_| InflateRefusal::InvalidCodeLength)?,
                    bit_len,
                );
                for suffix in 0..1_usize << (MAX_HUFFMAN_BITS - bit_len) {
                    let slot = lookup
                        .get_mut(usize::from(reversed_bits) | (suffix << bit_len))
                        .ok_or(InflateRefusal::InvalidHuffmanCode)?;
                    if *slot != HUFFMAN_LOOKUP_MISSING {
                        return Err(InflateRefusal::OversubscribedHuffmanSet);
                    }
                    *slot = packed;
                }
            }
            Ok(lookup)
        }
    }

    /// Every code-length set, valid or not, builds to the same result as the
    /// former 2^15-slot builder, and every one of the 2^15 lookups the decoder
    /// can make answers the same slot (frankengit-6kgs). Sets: the fixed
    /// tables, edge cases, random complete codes, and perturbations of them
    /// that are oversubscribed, incomplete or over-long; each under all four
    /// policies and under a symbol limit that refuses the larger alphabets.
    #[test]
    fn sized_huffman_tables_answer_every_lookup_exactly_as_the_full_tables() {
        use super::{HuffmanSetPolicy, HuffmanTable, MAX_HUFFMAN_BITS};

        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = |bound: usize| -> usize {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % bound as u64) as usize
        };
        let mut fixed_literal = vec![8_u8; 288];
        fixed_literal[144..256].fill(9);
        fixed_literal[256..280].fill(7);
        let mut cases: Vec<Vec<u8>> = vec![
            fixed_literal,
            vec![5; 32],
            Vec::new(),
            vec![0; 19],
            vec![1],
            vec![0, 1],
            vec![1, 1],
            vec![1, 1, 1],
            vec![2, 2, 2],
            vec![15, 15],
            vec![16],
            vec![1, 16],
        ];
        for _ in 0..240 {
            let symbols = 2 + next(310);
            let leaves = 2 + next(symbols - 1);
            let mut depths = vec![0_u8];
            while depths.len() < leaves {
                let open: Vec<usize> = (0..depths.len())
                    .filter(|&at| depths[at] < MAX_HUFFMAN_BITS)
                    .collect();
                if open.is_empty() {
                    break;
                }
                let depth = depths.swap_remove(open[next(open.len())]) + 1;
                depths.extend([depth, depth]);
            }
            let mut positions: Vec<usize> = (0..symbols).collect();
            for at in (1..symbols).rev() {
                positions.swap(at, next(at + 1));
            }
            let mut lengths = vec![0_u8; symbols];
            for (&depth, &position) in depths.iter().zip(&positions) {
                lengths[position] = depth;
            }
            let used: Vec<usize> = (0..symbols).filter(|&at| lengths[at] != 0).collect();
            let pick = used[next(used.len())];
            let mut shorter = lengths.clone();
            shorter[pick] -= 1;
            let mut longer = lengths.clone();
            longer[pick] += 1;
            let mut dropped = lengths.clone();
            dropped[pick] = 0;
            cases.extend([lengths, shorter, longer, dropped]);
            cases.push((0..symbols).map(|_| next(17) as u8).collect());
        }

        let policies = [
            HuffmanSetPolicy::Complete,
            HuffmanSetPolicy::LiteralLengthMayUseSingleBitCode,
            HuffmanSetPolicy::DistanceMayUseSingleBitCode,
            HuffmanSetPolicy::DistanceMayBeEmpty,
        ];
        let narrow = InflateLimits {
            max_huffman_symbols: 30,
            ..limits()
        };
        let (mut built, mut refused) = (0_usize, 0_usize);
        for lengths in &cases {
            for policy in policies {
                for limit in [limits(), narrow] {
                    match (
                        reference_huffman::build(lengths, limit, policy),
                        HuffmanTable::build(lengths, limit, policy),
                    ) {
                        (Ok(full), Ok(table)) => {
                            built += 1;
                            assert!(table.lookup.len().is_power_of_two());
                            for bits in 0..1_u16 << MAX_HUFFMAN_BITS {
                                assert_eq!(
                                    table.entry(bits),
                                    Some(full[usize::from(bits)]),
                                    "lengths {lengths:?} policy {policy:?} bits {bits}"
                                );
                            }
                        }
                        (Err(expected), Err(observed)) => {
                            refused += 1;
                            assert_eq!(observed, expected, "lengths {lengths:?} policy {policy:?}");
                        }
                        (expected, observed) => panic!(
                            "lengths {lengths:?} policy {policy:?}: reference {:?}, sized {:?}",
                            expected.map(|_| "table"),
                            observed.map(|_| "table")
                        ),
                    }
                }
            }
        }
        assert!(
            built > 500 && refused > 1_000,
            "built {built}, refused {refused}"
        );
        assert_eq!(
            HuffmanTable::fixed_literal_length(limits()).map(|table| table.lookup.len()),
            Ok(512)
        );
        assert_eq!(
            HuffmanTable::fixed_distance(limits()).map(|table| table.lookup.len()),
            Ok(32)
        );
    }

    /// The literal/length table of `zero_distance_dynamic_member` holds one
    /// one-bit code (end of block, `0`), so the code `1` is unused. As with the
    /// former 2^15-slot table, the decoder reads up to fifteen bits before it
    /// refuses that code, and a stream that ends sooner asks for more input
    /// (frankengit-6kgs).
    #[test]
    fn an_unused_code_reads_fifteen_bits_before_it_is_refused() {
        let header = |deflate: &mut BitPacker| {
            deflate.push_bits(1, 1);
            deflate.push_bits(2, 2);
            deflate.push_bits(0, 5);
            deflate.push_bits(0, 5);
            deflate.push_bits(14, 4);
            for &index in super::CODE_LENGTH_ORDER.iter().take(18) {
                deflate.push_bits(u16::from(index == 0 || index == 1), 3);
            }
            for _ in 0..256 {
                deflate.push_bits(0, 1);
            }
            deflate.push_bits(1, 1);
            deflate.push_bits(0, 1);
        };
        for extra_bits in 0..=20_u8 {
            let mut deflate = BitPacker::default();
            header(&mut deflate);
            deflate.push_bits(1, 1);
            for _ in 0..extra_bits {
                deflate.push_bits(1, 1);
            }
            let mut member = vec![0x78, 0x01];
            let body = deflate.finish();
            // The bits after the unused code that the stream really carries,
            // counting the zero padding of its last byte.
            let available = body.len() * 8 - 329 - 1;
            member.extend(body);
            let Ok(mut inflater) = Inflater::new(limits()) else {
                panic!("test limits are valid");
            };
            let pushed = inflater.push(&member);
            if available >= 14 {
                assert_eq!(
                    pushed,
                    Err(InflateRefusal::InvalidHuffmanCode),
                    "{extra_bits}"
                );
            } else {
                assert_eq!(pushed, Ok(StreamProgress::NeedInput), "{extra_bits}");
                assert_eq!(inflater.finish(), Err(InflateRefusal::UnexpectedEnd));
            }
        }
    }

    mod reference_matcher {
        use std::collections::VecDeque;

        use super::super::{FixedToken, MATCH_HASH_ENTRIES, MATCH_INDEX_NONE};

        struct MatchIndex {
            heads: Vec<usize>,
            previous: Vec<usize>,
            history_len: usize,
        }

        impl MatchIndex {
            fn new(history: &VecDeque<u8>, block: &[u8]) -> Self {
                let mut index = Self {
                    heads: vec![MATCH_INDEX_NONE; MATCH_HASH_ENTRIES],
                    previous: vec![MATCH_INDEX_NONE; history.len() + block.len()],
                    history_len: history.len(),
                };
                for position in 0..history.len() {
                    index.record(position, history, block);
                }
                index
            }

            fn record_emitted(
                &mut self,
                block_position: usize,
                length: usize,
                history: &VecDeque<u8>,
                block: &[u8],
            ) {
                for position in block_position..block_position + length {
                    self.record(self.history_len + position, history, block);
                }
            }

            fn candidate_for(
                &self,
                block_position: usize,
                history: &VecDeque<u8>,
                block: &[u8],
            ) -> usize {
                triple_hash(self.history_len + block_position, history, block)
                    .map_or(MATCH_INDEX_NONE, |hash| self.heads[hash])
            }

            fn record(&mut self, position: usize, history: &VecDeque<u8>, block: &[u8]) {
                let Some(hash) = triple_hash(position, history, block) else {
                    return;
                };
                self.previous[position] = self.heads[hash];
                self.heads[hash] = position;
            }
        }

        fn triple_hash(position: usize, history: &VecDeque<u8>, block: &[u8]) -> Option<usize> {
            let first = virtual_byte(position, history, block)?;
            let second = virtual_byte(position.checked_add(1)?, history, block)?;
            let third = virtual_byte(position.checked_add(2)?, history, block)?;
            let hash = usize::from(first)
                .wrapping_mul(251)
                .wrapping_add(usize::from(second))
                .wrapping_mul(251)
                .wrapping_add(usize::from(third));
            Some(hash & (MATCH_HASH_ENTRIES - 1))
        }

        fn virtual_byte(position: usize, history: &VecDeque<u8>, block: &[u8]) -> Option<u8> {
            if position < history.len() {
                history.get(position).copied()
            } else {
                block.get(position.checked_sub(history.len())?).copied()
            }
        }

        fn source_byte(
            history: &VecDeque<u8>,
            block: &[u8],
            position: usize,
            distance: usize,
            offset: usize,
        ) -> Option<u8> {
            let source = (history.len() + position + offset).checked_sub(distance)?;
            if source < history.len() {
                history.get(source).copied()
            } else {
                block.get(source - history.len()).copied()
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn find_match(
            history: &VecDeque<u8>,
            block: &[u8],
            position: usize,
            matcher: &MatchIndex,
            window_bytes: usize,
            max_match_chain: usize,
            units: &mut u64,
        ) -> Option<(usize, usize)> {
            if max_match_chain == 0 || position + 3 > block.len() {
                return None;
            }
            let current = history.len() + position;
            let max_length = (block.len() - position).min(258);
            let mut best = None;
            let mut candidate = matcher.candidate_for(position, history, block);
            let mut candidates_seen = 0_usize;
            while candidate != MATCH_INDEX_NONE && candidates_seen < max_match_chain {
                *units += 1;
                let distance = current - candidate;
                if distance > window_bytes {
                    candidate = matcher.previous[candidate];
                    candidates_seen += 1;
                    continue;
                }
                if source_byte(history, block, position, distance, 0) != Some(block[position]) {
                    candidate = matcher.previous[candidate];
                    candidates_seen += 1;
                    continue;
                }
                let mut length = 1_usize;
                while length < max_length {
                    *units += 1;
                    if source_byte(history, block, position, distance, length)
                        != Some(block[position + length])
                    {
                        break;
                    }
                    length += 1;
                }
                if length >= 3 && best.is_none_or(|(best_length, _)| length > best_length) {
                    best = Some((length, distance));
                    if length == max_length {
                        return best;
                    }
                }
                candidate = matcher.previous[candidate];
                candidates_seen += 1;
            }
            best
        }

        /// One block's tokens and the work units the old encoder charged for
        /// it: one for the block, one per decision, and the matcher's.
        pub(super) fn block_tokens(
            history: &VecDeque<u8>,
            block: &[u8],
            window_bytes: usize,
            max_match_chain: usize,
        ) -> (Vec<FixedToken>, u64) {
            let mut units = 1_u64;
            let mut matcher = MatchIndex::new(history, block);
            let mut tokens = Vec::new();
            let mut position = 0_usize;
            while position < block.len() {
                units += 1;
                if let Some((length, distance)) = find_match(
                    history,
                    block,
                    position,
                    &matcher,
                    window_bytes,
                    max_match_chain,
                    &mut units,
                ) {
                    tokens.push(FixedToken::Match {
                        length: u16::try_from(length).unwrap(),
                        distance: u16::try_from(distance).unwrap(),
                    });
                    matcher.record_emitted(position, length, history, block);
                    position += length;
                } else {
                    tokens.push(FixedToken::Literal(block[position]));
                    matcher.record_emitted(position, 1, history, block);
                    position += 1;
                }
            }
            (tokens, units)
        }
    }

    /// frankengit-g4a9: the contiguous matcher makes the old matcher's
    /// decisions and charges its work, block for block, over random,
    /// repetitive, text, shifted and pathological inputs whose blocks carry
    /// every history length from empty to the full window.
    #[test]
    fn the_contiguous_matcher_decides_and_charges_exactly_as_the_ring_buffer_matcher() {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut random = |length: usize| -> Vec<u8> {
            (0..length)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    (seed >> 24) as u8
                })
                .collect()
        };
        let text: Vec<u8> = (0..20_000_u32)
            .flat_map(|line| format!("line {line} of a slowly shifting text\n").into_bytes())
            .collect();
        let mut inputs = vec![
            vec![0_u8; 70_000],
            random(90_000),
            text.clone(),
            [&text[7..30_000], &random(5_000)[..], &text[..40_000]].concat(),
            (0..100_000_u32).map(|at| (at % 251) as u8).collect(),
            (0..80_000_u32).map(|at| u8::from(at % 7 == 0)).collect(),
            random(3),
            Vec::new(),
        ];
        let mut mixed = Vec::new();
        for round in 0..12 {
            mixed.extend_from_slice(&random(700 + round * 13));
            mixed.extend_from_slice(&text[round * 211..round * 211 + 3_000]);
        }
        inputs.push(mixed);
        let (mut blocks, mut matches) = (0, 0);
        for input in inputs {
            for block_bytes in [RFC1951_MAX_WINDOW_BYTES, 4_096, 1_000] {
                let profile = DeflateProfile {
                    block_bytes,
                    ..DeflateProfile::FIXED_OR_STORED
                };
                let mut encoder = Deflater::new(deflate_limits(), profile)
                    .unwrap_or_else(|error| panic!("encoder: {error}"));
                let mut control = NeverCancel;
                let chunks: Vec<&[u8]> = input.chunks(block_bytes).collect();
                for (index, chunk) in chunks.iter().enumerate() {
                    let history: std::collections::VecDeque<u8> =
                        encoder.history.iter().copied().collect();
                    let (expected, expected_units) = reference_matcher::block_tokens(
                        &history,
                        chunk,
                        profile.window_bytes,
                        profile.max_match_chain,
                    );
                    encoder.pending_input.extend_from_slice(chunk);
                    let before = encoder.work_units;
                    encoder
                        .encode_pending_prefix(chunk.len(), index + 1 == chunks.len(), &mut control)
                        .unwrap_or_else(|error| panic!("block {index}: {error}"));
                    assert_eq!(encoder.fixed_tokens, expected, "block {index}");
                    assert_eq!(encoder.work_units - before, expected_units, "block {index}");
                    blocks += 1;
                    matches += expected
                        .iter()
                        .filter(|token| matches!(token, FixedToken::Match { .. }))
                        .count();
                }
            }
        }
        assert!(
            blocks > 100 && matches > 1_000,
            "{blocks} blocks, {matches} matches"
        );
    }

    /// A bulk charge of `n` compared bytes ends exactly as `n` single charges
    /// do: the same refusal with the ceiling plus one observed, and the same
    /// counter, from every starting count around the ceiling.
    #[test]
    fn a_bulk_compare_charge_ends_exactly_as_single_charges() {
        let mut control = NeverCancel;
        // A zero ceiling is a configuration refusal, not a budget.
        for ceiling in [1_u64, 2, 7, 300] {
            for start in [0_u64, 1, 5, 7, 299, 300] {
                if start > ceiling {
                    continue;
                }
                for units in [0_usize, 1, 2, 3, 8, 257, 258] {
                    let limits = DeflateLimits {
                        max_work_units: ceiling,
                        ..deflate_limits()
                    };
                    let fresh = || {
                        let mut encoder = Deflater::new(limits, DeflateProfile::FIXED_OR_STORED)
                            .unwrap_or_else(|error| panic!("encoder: {error}"));
                        encoder.work_units = start;
                        encoder
                    };
                    let mut bulk = fresh();
                    let bulk_outcome = bulk.charge_units_exactly(&mut control, units);
                    let mut single = fresh();
                    let single_outcome =
                        (0..units).try_for_each(|_| single.charge_work(&mut control));
                    assert_eq!(bulk_outcome, single_outcome, "{ceiling} {start} {units}");
                    assert_eq!(
                        bulk.work_units, single.work_units,
                        "{ceiling} {start} {units}"
                    );
                }
            }
        }
    }

    /// Whole members refuse on the work ceiling exactly below their cost.
    #[test]
    fn a_member_refuses_on_the_work_ceiling_exactly_below_its_cost() {
        let input: Vec<u8> = (0..5_000_u32)
            .flat_map(|line| format!("{line} repeated words repeated words\n").into_bytes())
            .collect();
        let encode = |ceiling: u64| {
            let limits = DeflateLimits {
                max_work_units: ceiling,
                ..deflate_limits()
            };
            Deflater::new(limits, DeflateProfile::FIXED_OR_STORED).and_then(|mut encoder| {
                let _ = encoder.push(&input)?;
                encoder.finish()?;
                Ok(encoder.work_units())
            })
        };
        let exact = encode(deflate_limits().max_work_units)
            .unwrap_or_else(|error| panic!("unbounded: {error}"));
        assert_eq!(encode(exact), Ok(exact));
        for ceiling in [
            1,
            2,
            exact / 3,
            exact / 2,
            exact - 258,
            exact - 2,
            exact - 1,
        ] {
            assert!(
                matches!(
                    encode(ceiling),
                    Err(DeflateRefusal::ResourceLimit {
                        resource: Resource::WorkUnits,
                        limit,
                        ..
                    }) if limit == ceiling
                ),
                "ceiling {ceiling}"
            );
        }
    }

    /// Single and bulk Adler-32 updates equal the per-byte modular definition
    /// across run boundaries and on all-0xff input, the overflow worst case.
    #[test]
    fn adler32_single_and_bulk_updates_equal_the_modular_definition() {
        let reference = |bytes: &[u8]| {
            let (mut a, mut b) = (1_u32, 0_u32);
            for &byte in bytes {
                a = (a + u32::from(byte)) % 65_521;
                b = (b + a) % 65_521;
            }
            (b << 16) | a
        };
        let mut seed = 0x51ed_270b_c6d1_a4e3_u64;
        let mut inputs = vec![
            vec![0xff_u8; 3 * Adler32::NMAX + 7],
            Vec::new(),
            vec![0_u8; 1],
        ];
        for length in [
            1,
            2,
            Adler32::NMAX - 1,
            Adler32::NMAX,
            Adler32::NMAX + 1,
            40_000,
        ] {
            inputs.push(
                (0..length)
                    .map(|_| {
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        (seed >> 24) as u8
                    })
                    .collect(),
            );
        }
        for input in inputs {
            let expected = reference(&input);
            let mut single = Adler32::new();
            for &byte in &input {
                single.update(byte);
            }
            assert_eq!(single.value(), expected);
            for split in [0, 1, Adler32::NMAX, input.len() / 2, input.len()] {
                let split = split.min(input.len());
                let mut bulk = Adler32::new();
                bulk.update_slice(&input[..split]);
                bulk.update_slice(&input[split..]);
                assert_eq!(bulk.value(), expected, "split {split} of {}", input.len());
            }
        }
    }

    #[test]
    fn fixed_matcher_reaches_rfc_maximum_length_for_all_zero_input() {
        let input = vec![0_u8; 259];
        let mut encoder = Deflater::new(deflate_limits(), DeflateProfile::DEFAULT)
            .unwrap_or_else(|error| panic!("encoder configuration: {error}"));
        let mut control = NeverCancel;
        let mut matcher = MatchIndex::new(&input, 0)
            .unwrap_or_else(|error| panic!("matcher construction: {error}"));
        matcher
            .record_emitted(0, 1, &input)
            .unwrap_or_else(|error| panic!("record first byte: {error}"));
        assert_eq!(
            encoder.find_match(&input, 0, 1, &matcher, &mut control),
            Ok(Some((258, 1)))
        );

        let member = deflate_zlib(&input, deflate_limits(), DeflateProfile::DEFAULT)
            .unwrap_or_else(|error| panic!("all-zero input: {error}"));
        assert!(member.len() < input.len(), "maximum match must compress");
        assert_eq!(inflate_zlib(&member, limits()), Ok(input));
    }

    #[test]
    fn fixed_matcher_searches_the_retained_window_not_only_nearby_distances() {
        let history = (0_u8..128).collect::<Vec<_>>();
        let block = history.clone();
        let mut encoder = Deflater::new(deflate_limits(), DeflateProfile::DEFAULT)
            .unwrap_or_else(|error| panic!("encoder configuration: {error}"));
        encoder
            .append_history(&history)
            .unwrap_or_else(|error| panic!("seed history: {error}"));
        let bytes = [encoder.history.as_slice(), &block].concat();
        let matcher = MatchIndex::new(&bytes, encoder.history.len())
            .unwrap_or_else(|error| panic!("matcher construction: {error}"));
        let mut control = NeverCancel;
        assert_eq!(
            encoder.find_match(&bytes, encoder.history.len(), 0, &matcher, &mut control),
            Ok(Some((128, 128)))
        );
    }

    #[test]
    fn encoder_round_trips_seeded_random_and_pathological_inputs() {
        let mut cases = vec![Vec::new(), vec![0_u8; 8_192], vec![0_u8; 259]];
        let mut seed = 0x72ba_1e09_45cd_318f_u64;
        for case in 0..96_u32 {
            let length = usize::try_from((seed & 0x7ff) + 1).unwrap_or(1);
            let mut input = Vec::with_capacity(length);
            for _ in 0..length {
                seed ^= seed << 7;
                seed ^= seed >> 9;
                seed ^= seed << 8;
                input.push(u8::try_from(seed & 0xff).unwrap_or(0));
            }
            cases.push(input);
            assert_ne!(
                seed, 0,
                "random seed unexpectedly reached zero at case {case}"
            );
        }
        for (case, input) in cases.iter().enumerate() {
            for profile in [
                DeflateProfile::FAST_STORED,
                DeflateProfile::DEFAULT,
                DeflateProfile::DYNAMIC,
            ] {
                let encoded =
                    deflate_zlib(input, deflate_limits(), profile).unwrap_or_else(|error| {
                        panic!(
                            "encode seed {seed:016x}, case {case}, profile {}: {error}",
                            profile.id
                        )
                    });
                let decoded = inflate_zlib(&encoded, limits()).unwrap_or_else(|error| {
                    panic!(
                        "decode seed {seed:016x}, case {case}, profile {}: {error}",
                        profile.id
                    )
                });
                assert_eq!(
                    decoded.as_slice(),
                    input.as_slice(),
                    "seed {seed:016x}, case {case}, {}",
                    profile.id
                );
            }
        }
    }

    #[test]
    fn encoder_budget_refusal_discards_unpromoted_output() {
        let input = b"budget refusal must not promote a member";
        let refusal_limits = DeflateLimits {
            max_output_bytes: 16,
            ..deflate_limits()
        };
        let mut encoder = Deflater::new(refusal_limits, DeflateProfile::FAST_STORED)
            .unwrap_or_else(|error| panic!("encoder configuration: {error}"));
        let tentative_header = encoder.take_output();
        assert_eq!(tentative_header, vec![0x78, 0x01]);
        assert_eq!(encoder.push(input), Ok(DeflateStreamProgress::NeedInput));
        let refusal = encoder
            .finish()
            .err()
            .unwrap_or_else(|| panic!("small output budget must refuse"));
        assert!(matches!(
            refusal,
            DeflateRefusal::ResourceLimit {
                resource: Resource::OutputBytes,
                ..
            }
        ));
        assert!(!encoder.is_finished());
        assert_eq!(encoder.receipt(), None);
        assert_eq!(encoder.take_output(), Vec::new());
        assert_eq!(encoder.finish(), Err(DeflateRefusal::RefusedAfterFailure));

        let permitted = deflate_zlib(input, deflate_limits(), DeflateProfile::FAST_STORED)
            .unwrap_or_else(|error| panic!("near-identical permitted member: {error}"));
        assert_eq!(inflate_zlib(&permitted, limits()), Ok(input.to_vec()));
    }

    #[test]
    fn encoder_refuses_invalid_profiles_and_resource_limits_before_promotion() {
        let invalid_profile = DeflateProfile {
            lazy_matching: true,
            ..DeflateProfile::DEFAULT
        };
        assert!(matches!(
            Deflater::new(deflate_limits(), invalid_profile),
            Err(DeflateRefusal::InvalidProfile)
        ));
        let invalid_limits = DeflateLimits {
            max_output_bytes: 5,
            ..deflate_limits()
        };
        assert!(matches!(
            Deflater::new(invalid_limits, DeflateProfile::FAST_STORED),
            Err(DeflateRefusal::ResourceLimit {
                resource: Resource::Configuration,
                ..
            })
        ));

        let input_limited = DeflateLimits {
            max_input_bytes: 3,
            ..deflate_limits()
        };
        let mut encoder = Deflater::new(input_limited, DeflateProfile::FAST_STORED)
            .unwrap_or_else(|error| panic!("encoder configuration: {error}"));
        assert!(matches!(
            encoder.push(b"four"),
            Err(DeflateRefusal::ResourceLimit {
                resource: Resource::InputBytes,
                ..
            })
        ));
        assert_eq!(encoder.take_output(), Vec::new());

        let work_limited = DeflateLimits {
            max_work_units: 1,
            ..deflate_limits()
        };
        let mut work_encoder = Deflater::new(work_limited, DeflateProfile::FAST_STORED)
            .unwrap_or_else(|error| panic!("encoder configuration: {error}"));
        assert!(matches!(
            work_encoder.push(b"work"),
            Err(DeflateRefusal::ResourceLimit {
                resource: Resource::WorkUnits,
                ..
            })
        ));
        assert_eq!(work_encoder.take_output(), Vec::new());

        let permitted = deflate_zlib(b"three", deflate_limits(), DeflateProfile::FAST_STORED)
            .unwrap_or_else(|error| panic!("near-identical permitted member: {error}"));
        assert_eq!(inflate_zlib(&permitted, limits()), Ok(b"three".to_vec()));
    }

    struct CancelEncoderImmediately;

    impl CancellationProbe for CancelEncoderImmediately {
        fn is_cancelled(&mut self) -> bool {
            true
        }
    }

    #[test]
    fn encoder_finish_cancellation_is_a_typed_refusal() {
        let mut encoder = Deflater::new(deflate_limits(), DeflateProfile::DEFAULT)
            .unwrap_or_else(|error| panic!("encoder configuration: {error}"));
        assert_eq!(
            encoder.push(b"cancellation must be caller controlled"),
            Ok(DeflateStreamProgress::NeedInput)
        );
        let mut cancellation = CancelEncoderImmediately;
        assert_eq!(
            encoder.finish_with_control(&mut cancellation),
            Err(DeflateRefusal::Cancelled)
        );
        assert_eq!(encoder.receipt(), None);
        assert_eq!(encoder.take_output(), Vec::new());
    }

    #[test]
    fn finalized_encoder_receipt_records_the_frozen_profile() {
        let mut encoder = Deflater::new(deflate_limits(), DeflateProfile::DYNAMIC)
            .unwrap_or_else(|error| panic!("encoder configuration: {error}"));
        let mut output = encoder.take_output();
        assert_eq!(
            encoder.push(b"receipt"),
            Ok(DeflateStreamProgress::NeedInput)
        );
        output.extend(encoder.take_output());
        encoder
            .finish()
            .unwrap_or_else(|error| panic!("encoder finalization: {error}"));
        output.extend(encoder.take_output());
        let receipt = encoder
            .receipt()
            .unwrap_or_else(|| panic!("finished encoder must retain receipt"));
        assert_eq!(receipt.profile, DeflateProfile::DYNAMIC);
        assert_eq!(receipt.input_bytes, 7);
        assert_eq!(receipt.output_bytes, output.len());
        assert_eq!(receipt.block_count, 1);
        assert_eq!(inflate_zlib(&output, limits()), Ok(b"receipt".to_vec()));
    }
}

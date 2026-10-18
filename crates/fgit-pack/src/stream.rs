//! Bounded native pack intake without retaining the pack or all inflated bodies.
//!
//! A sink owns each inflated entry in turn. Every callback is tentative: only
//! the final receipt authenticates the native trailer and exact EOF. Native
//! object identities, delta resolution and complete graph admission remain the
//! caller's quarantine responsibility. A failed stream never yields a receipt.

use std::fmt;
use std::io::{self, BufRead};

use fgit_crypto::{DigestHasher, Sha1Hasher, Sha256Hasher};
use fgit_deflate::{CancellationProbe, Inflater, StreamProgress};

use crate::{
    Deadline, EntryKind, ObjectFormat, ObjectId, PackError, PackHeader, PackLimits,
    QuarantinedEntry, checkpoint, decode_entry_header, object_id_from_bytes, parse_delta_base,
    parse_pack_header,
};

const INPUT_CHUNK: usize = 32 * 1024;
const PENDING_INPUT: usize = 64 * 1024;

/// One fully inflated, still tentative entry with its exact encoded range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamPackEntry {
    pub entry: QuarantinedEntry,
    /// Exclusive encoded end, measured from the pack's first `P` byte.
    pub end_offset: u64,
    /// IEEE CRC-32 over the complete encoded entry, including delta headers.
    pub crc32: u32,
}

/// Whole-pack framing and native trailer verification, issued only at exact EOF.
/// This is not native object or repository-closure admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamPackReceipt {
    header: PackHeader,
    format: ObjectFormat,
    trailer: ObjectId,
    pack_bytes: u64,
    pack_sha256: [u8; 32],
    pub(crate) framing_sha256: [u8; 32],
}

impl StreamPackReceipt {
    #[must_use]
    pub const fn header(&self) -> PackHeader {
        self.header
    }
    #[must_use]
    pub const fn format(&self) -> ObjectFormat {
        self.format
    }
    #[must_use]
    pub const fn trailer(&self) -> ObjectId {
        self.trailer
    }
    #[must_use]
    pub const fn pack_bytes(&self) -> u64 {
        self.pack_bytes
    }
    /// SHA-256 of every exact pack byte, including its native trailer.
    #[must_use]
    pub const fn pack_sha256(&self) -> [u8; 32] {
        self.pack_sha256
    }
}

/// Preserve the source of failure; callbacks may use a typed quarantine error.
#[derive(Debug)]
pub enum StreamPackError<E> {
    Io(io::Error),
    Pack(PackError),
    Sink(E),
}

impl<E: fmt::Display> fmt::Display for StreamPackError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "streamed pack input: {error}"),
            Self::Pack(error) => write!(f, "streamed pack refused: {error}"),
            Self::Sink(error) => write!(f, "streamed pack quarantine: {error}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for StreamPackError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Pack(error) => Some(error),
            Self::Sink(error) => Some(error),
        }
    }
}

impl<E> From<PackError> for StreamPackError<E> {
    fn from(value: PackError) -> Self {
        Self::Pack(value)
    }
}
impl<E> From<io::Error> for StreamPackError<E> {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Read exactly one bounded pack, transferring one tentative inflated entry at
/// a time to `sink`. No seek or whole-pack allocation is required.
///
/// The existing entry/base parsers and framed DEFLATE decoder define semantics.
/// Input, object count, each object/program, aggregate inflation, inflate work,
/// expansion ratio and caller checkpoints are enforced before further work.
/// The sink must retain one operation budget for any later delta reconstruction.
///
/// The caller controls the blocking reader's I/O timeout. Cooperative checkpoints
/// cannot interrupt an in-progress `BufRead::fill_buf` call. Sink side effects
/// must stay in quarantine until this returns a receipt and native validation
/// succeeds; a trailer, EOF, I/O or cancellation failure can follow any callback.
pub fn read_streamed_pack<R, F, E>(
    reader: &mut R,
    format: ObjectFormat,
    limits: &PackLimits,
    deadline: &mut impl Deadline,
    mut sink: F,
) -> Result<StreamPackReceipt, StreamPackError<E>>
where
    R: BufRead + ?Sized,
    F: FnMut(StreamPackEntry) -> Result<(), E>,
{
    checkpoint(deadline)?;
    let mut input = Input::new(reader, format, limits);
    let mut fixed = [0_u8; 12];
    input.exact(&mut fixed, "pack header", true, deadline)?;
    let header = parse_pack_header(&fixed, limits)?;
    let mut total_inflated = 0_usize;
    let mut framing = framing_hasher();
    for _ in 0..header.object_count {
        checkpoint(deadline)?;
        let offset = input.position();
        input.crc = Some(u32::MAX);
        let mut encoded = [0_u8; 11];
        let mut size = 0;
        let entry_header = loop {
            if size == encoded.len() {
                return Err(PackError::InvalidVarint {
                    context: "pack entry size",
                }
                .into());
            }
            input.exact(
                &mut encoded[size..size + 1],
                "pack entry header",
                true,
                deadline,
            )?;
            size += 1;
            match decode_entry_header(&encoded[..size], limits, deadline) {
                Ok((parsed, _)) => break parsed,
                Err(PackError::Truncated { .. }) => {}
                Err(error) => return Err(error.into()),
            }
        };
        let delta_base = match entry_header.kind {
            EntryKind::RefDelta => {
                let mut bytes = [0_u8; 32];
                let width = format.digest_len();
                input.exact(&mut bytes[..width], "REF_DELTA base", true, deadline)?;
                Some(parse_delta_base(
                    entry_header.kind,
                    offset,
                    &bytes[..width],
                    format,
                    deadline,
                )?)
            }
            EntryKind::OfsDelta => {
                let mut bytes = [0_u8; 11];
                let mut size = 0;
                loop {
                    if size == bytes.len() {
                        return Err(PackError::InvalidOfsDelta.into());
                    }
                    input.exact(&mut bytes[size..size + 1], "OFS_DELTA base", true, deadline)?;
                    size += 1;
                    match parse_delta_base(
                        entry_header.kind,
                        offset,
                        &bytes[..size],
                        format,
                        deadline,
                    ) {
                        Ok(parsed) => break Some(parsed),
                        Err(PackError::Truncated { .. }) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            _ => None,
        };
        total_inflated = total_inflated
            .checked_add(entry_header.declared_size)
            .ok_or(PackError::IntegerOverflow {
                context: "pack total inflated bytes",
            })?;
        if total_inflated > limits.max_total_expanded_bytes {
            return Err(PackError::TotalExpandedLimit {
                actual: total_inflated,
                limit: limits.max_total_expanded_bytes,
            }
            .into());
        }
        let inflated = inflate_entry(&mut input, entry_header.declared_size, limits, deadline)?;
        let end_offset = input.position();
        let crc32 = !input.crc.take().ok_or(PackError::InvalidIndexOrdering)?;
        framing_row(&mut framing, offset, end_offset, crc32);
        checkpoint(deadline)?;
        sink(StreamPackEntry {
            entry: QuarantinedEntry {
                offset,
                header: entry_header,
                delta_base,
                inflated,
            },
            end_offset,
            crc32,
        })
        .map_err(StreamPackError::Sink)?;
    }
    checkpoint(deadline)?;
    let expected = input.native.clone().finish();
    let mut trailer = [0_u8; 32];
    let width = format.digest_len();
    input.exact(&mut trailer[..width], "pack trailer", false, deadline)?;
    if expected.as_bytes() != &trailer[..width] {
        return Err(PackError::TrailerChecksumMismatch.into());
    }
    checkpoint(deadline)?;
    if !input.reader.fill_buf()?.is_empty() {
        return Err(PackError::TrailingPackData.into());
    }
    checkpoint(deadline)?;
    Ok(StreamPackReceipt {
        header,
        format,
        trailer: object_id_from_bytes(format, &trailer[..width])?,
        pack_bytes: input.position(),
        pack_sha256: input.sha256.finish(),
        framing_sha256: framing.finish(),
    })
}

fn inflate_entry<R: BufRead + ?Sized, E>(
    input: &mut Input<'_, R>,
    declared: usize,
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<Vec<u8>, StreamPackError<E>> {
    let mut inflate_limits = crate::reader::inflate_limits(limits, declared);
    // The caller may admit GiB input, but only a decode fragment plus an RFC
    // header can remain pending. Never retain a pack-sized inflater input buffer.
    inflate_limits.max_pending_input_bytes = limits.max_input_bytes.min(PENDING_INPUT);
    let mut inflater = Inflater::new_framed(inflate_limits).map_err(PackError::Inflate)?;
    let mut output = Vec::new();
    let mut fed = 0_usize;
    loop {
        checkpoint(deadline)?;
        let remaining = limits.max_input_bytes.saturating_sub(input.bytes);
        let buffer = input.reader.fill_buf()?;
        if buffer.is_empty() {
            return Err(PackError::Inflate(fgit_deflate::InflateRefusal::UnexpectedEnd).into());
        }
        if remaining == 0 {
            return Err(PackError::InputLimit {
                actual: input.bytes.saturating_add(1),
                limit: limits.max_input_bytes,
            }
            .into());
        }
        let supplied = buffer.len().min(INPUT_CHUNK).min(remaining);
        let progress = inflater
            .push_with_control(&buffer[..supplied], &mut Probe(deadline))
            .map_err(PackError::Inflate)?;
        let consumed = if progress == StreamProgress::Finished {
            inflater
                .consumed_input_bytes()
                .checked_sub(fed)
                .filter(|count| *count <= supplied)
                .ok_or(PackError::IntegerOverflow {
                    context: "streamed zlib member boundary",
                })?
        } else {
            supplied
        };
        input.consume(consumed, true)?;
        fed = fed
            .checked_add(consumed)
            .ok_or(PackError::IntegerOverflow {
                context: "streamed zlib member bytes",
            })?;
        append_output(&mut output, inflater.take_output(), declared)?;
        if progress == StreamProgress::Finished {
            checkpoint(deadline)?;
            inflater.finish().map_err(PackError::Inflate)?;
            append_output(&mut output, inflater.take_output(), declared)?;
            if output.len() != declared {
                return Err(PackError::InflatedEntrySizeMismatch {
                    declared,
                    actual: output.len(),
                }
                .into());
            }
            return Ok(output);
        }
    }
}

fn append_output(
    output: &mut Vec<u8>,
    mut fresh: Vec<u8>,
    declared: usize,
) -> Result<(), PackError> {
    let total = output
        .len()
        .checked_add(fresh.len())
        .ok_or(PackError::IntegerOverflow {
            context: "streamed inflated entry bytes",
        })?;
    if total > declared {
        return Err(PackError::InflatedEntrySizeMismatch {
            declared,
            actual: total,
        });
    }
    if output.is_empty() {
        *output = fresh;
    } else {
        if total > output.capacity() {
            // Byte-sized readers must not force one reallocating copy per
            // emitted byte. Grow geometrically within this entry's already
            // checked declaration; never reserve a pack-sized output buffer.
            let target = total.max(output.capacity().saturating_mul(2).min(declared));
            output
                .try_reserve_exact(target.saturating_sub(output.len()))
                .map_err(|_| PackError::AllocationFailed { requested: target })?;
        }
        output.append(&mut fresh);
    }
    Ok(())
}

struct Probe<'a, D>(&'a mut D);
impl<D: Deadline> CancellationProbe for Probe<'_, D> {
    fn is_cancelled(&mut self) -> bool {
        !self.0.checkpoint()
    }
}

#[derive(Clone)]
enum NativeHasher {
    Sha1(Sha1Hasher),
    Sha256(Sha256Hasher),
}
impl NativeHasher {
    fn new(format: ObjectFormat) -> Self {
        match format {
            ObjectFormat::Sha1 => Self::Sha1(Sha1Hasher::new()),
            ObjectFormat::Sha256 => Self::Sha256(Sha256Hasher::new()),
        }
    }
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(h) => h.update(bytes),
            Self::Sha256(h) => h.update(bytes),
        }
    }
    fn finish(self) -> ObjectId {
        match self {
            Self::Sha1(h) => fgit_types::native::GitOidSha1::from_bytes(h.finish()).into(),
            Self::Sha256(h) => fgit_types::native::GitOidSha256::from_bytes(h.finish()).into(),
        }
    }
}

struct Input<'a, R: ?Sized> {
    reader: &'a mut R,
    native: NativeHasher,
    sha256: Sha256Hasher,
    bytes: usize,
    maximum: usize,
    crc: Option<u32>,
}
impl<'a, R: BufRead + ?Sized> Input<'a, R> {
    fn new(reader: &'a mut R, format: ObjectFormat, limits: &PackLimits) -> Self {
        Self {
            reader,
            native: NativeHasher::new(format),
            sha256: Sha256Hasher::new(),
            bytes: 0,
            maximum: limits.max_input_bytes,
            crc: None,
        }
    }
    fn position(&self) -> u64 {
        self.bytes as u64
    }
    fn exact<E>(
        &mut self,
        into: &mut [u8],
        context: &'static str,
        body: bool,
        deadline: &mut impl Deadline,
    ) -> Result<(), StreamPackError<E>> {
        let mut offset = 0;
        while offset < into.len() {
            checkpoint(deadline)?;
            let source = self.reader.fill_buf()?;
            if source.is_empty() {
                return Err(PackError::Truncated { context }.into());
            }
            let count = source.len().min(into.len() - offset);
            into[offset..offset + count].copy_from_slice(&source[..count]);
            self.consume(count, body)?;
            offset += count;
        }
        Ok(())
    }
    fn consume<E>(&mut self, count: usize, body: bool) -> Result<(), StreamPackError<E>> {
        let total = self
            .bytes
            .checked_add(count)
            .ok_or(PackError::IntegerOverflow {
                context: "streamed pack bytes",
            })?;
        if total > self.maximum {
            return Err(PackError::InputLimit {
                actual: total,
                limit: self.maximum,
            }
            .into());
        }
        let source = self.reader.fill_buf()?;
        let bytes = source.get(..count).ok_or(PackError::Truncated {
            context: "stream buffer",
        })?;
        if body {
            self.native.update(bytes);
        }
        self.sha256.update(bytes);
        if let Some(crc) = &mut self.crc {
            for &byte in bytes {
                *crc = CRC_TABLE[((*crc ^ u32::from(byte)) & 255) as usize] ^ (*crc >> 8);
            }
        }
        self.reader.consume(count);
        self.bytes = total;
        Ok(())
    }
}

pub(crate) fn framing_hasher() -> Sha256Hasher {
    let mut hash = Sha256Hasher::new();
    hash.update(b"frankengit/stream-pack-index-rows/v1\0");
    hash
}
pub(crate) fn framing_row(hash: &mut Sha256Hasher, offset: u64, end: u64, crc: u32) {
    hash.update(&offset.to_be_bytes());
    hash.update(&end.to_be_bytes());
    hash.update(&crc.to_be_bytes());
}

pub(crate) const CRC_TABLE: [u32; 256] = crc_table();
const fn crc_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut i = 0;
    while i < table.len() {
        let mut value = i as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 == 0 {
                value >> 1
            } else {
                (value >> 1) ^ 0xedb8_8320
            };
            bit += 1;
        }
        table[i] = value;
        i += 1;
    }
    table
}

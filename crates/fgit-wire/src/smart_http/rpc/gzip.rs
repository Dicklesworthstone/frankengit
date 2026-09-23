//! Single-member gzip content decoding for upload-pack HTTP requests.
//!
//! Reuse the native, bounded RFC 1951 decoder through its RFC 1950 interface:
//! prepend a fixed zlib header, retain the last eight HTTP payload bytes, and
//! supply the computed Adler-32 only at the exact HTTP boundary. The ORIGINAL
//! gzip CRC-32 and ISIZE must independently verify before success. The strict
//! zlib decoder must consume exactly the raw DEFLATE bytes plus six framing
//! bytes, without emitting any additional output during finalization. This
//! also rejects truncated blocks, concatenated members and hidden suffixes.
//!
//! No body-sized compressed buffer, new compression engine, or ambient I/O is
//! introduced. Output is tentative until finish; the owning UploadRpc withholds
//! all replies and pack requests, and poisons itself after any refusal.

use fgit_pack::{CancellationProbe, InflateLimits, InflateRefusal, Inflater, StreamProgress};

use super::{HttpError, HttpLimits, ReceiveCancellation, RpcError, checkpoint};

pub(super) const INPUT_CHUNK_BYTES: usize = 1024;
const TRAILER_BYTES: usize = 8;
const HEADER_BYTES: usize = 10;
const ADLER_MODULUS: u32 = 65_521;

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Active,
    Finished,
    Failed,
}

pub(super) struct GzipDecoder {
    inflater: Inflater,
    state: State,
    header: [u8; HEADER_BYTES],
    header_len: usize,
    tail: [u8; TRAILER_BYTES],
    tail_len: usize,
    input_bytes: u64,
    input_limit: u64,
    raw_bytes: usize,
    output_bytes: u64,
    crc: u32,
    adler_a: u32,
    adler_b: u32,
}

struct Probe<'a, C>(&'a mut C);
impl<C: ReceiveCancellation> CancellationProbe for Probe<'_, C> {
    fn is_cancelled(&mut self) -> bool {
        !self.0.checkpoint()
    }
}

fn inflate_error(error: InflateRefusal) -> RpcError {
    match error {
        InflateRefusal::Cancelled => RpcError::Cancelled,
        InflateRefusal::ResourceLimit { .. } => HttpError::BodyTooLarge.into(),
        InflateRefusal::UnexpectedEnd => HttpError::TruncatedBody.into(),
        _ => HttpError::InvalidCompressedBody.into(),
    }
}

impl GzipDecoder {
    pub(super) fn new(limits: HttpLimits) -> Result<Self, RpcError> {
        limits.validate()?;
        let ceiling = usize::try_from(limits.max_body_bytes)
            .map_err(|_| HttpError::InvalidLimits)?;
        if ceiling == 0 {
            return Err(HttpError::InvalidLimits.into());
        }
        let inflate_limits = InflateLimits {
            max_input_bytes: ceiling.checked_add(6).ok_or(HttpError::InvalidLimits)?,
            max_pending_input_bytes: 4 * INPUT_CHUNK_BYTES,
            max_output_bytes: ceiling,
            // Keep native ratio, window, table and deterministic work ceilings.
            ..InflateLimits::GIT_OBJECT
        };
        let mut inflater = Inflater::new(inflate_limits).map_err(inflate_error)?;
        // CM=8, 32 KiB window, no dictionary, valid FCHECK. This fixed envelope
        // is implementation framing; it does NOT replace the gzip commitment.
        inflater.push(&[0x78, 0x01]).map_err(inflate_error)?;
        Ok(Self {
            inflater,
            state: State::Active,
            header: [0; HEADER_BYTES],
            header_len: 0,
            tail: [0; TRAILER_BYTES],
            tail_len: 0,
            input_bytes: 0,
            input_limit: limits.max_body_bytes,
            raw_bytes: 0,
            output_bytes: 0,
            crc: u32::MAX,
            adler_a: 1,
            adler_b: 0,
        })
    }

    pub(super) const fn decoded_bytes(&self) -> u64 {
        self.output_bytes
    }

    pub(super) fn push<C: ReceiveCancellation>(
        &mut self,
        input: &[u8],
        cancellation: &mut C,
    ) -> Result<Vec<u8>, RpcError> {
        let result = self.push_inner(input, cancellation);
        if result.is_err() {
            self.state = State::Failed;
        }
        result
    }

    fn push_inner<C: ReceiveCancellation>(
        &mut self,
        mut input: &[u8],
        cancellation: &mut C,
    ) -> Result<Vec<u8>, RpcError> {
        if self.state != State::Active {
            return Err(RpcError::FailedRequest);
        }
        checkpoint(cancellation)?;
        if input.len() > INPUT_CHUNK_BYTES {
            return Err(HttpError::InvalidLimits.into());
        }
        self.input_bytes = self.input_bytes.checked_add(input.len() as u64)
            .ok_or(HttpError::BodyTooLarge)?;
        if self.input_bytes > self.input_limit {
            return Err(HttpError::BodyTooLarge.into());
        }
        if self.header_len < HEADER_BYTES {
            let count = input.len().min(HEADER_BYTES - self.header_len);
            self.header[self.header_len..self.header_len + count].copy_from_slice(&input[..count]);
            self.header_len += count;
            input = &input[count..];
            if self.header_len < HEADER_BYTES {
                return Ok(Vec::new());
            }
            if self.header[..3] != [0x1f, 0x8b, 8] {
                return Err(HttpError::InvalidCompressedBody.into());
            }
            // Git's HTTP compressor emits this fixed header. FTEXT is advisory;
            // optional metadata is an explicit non-claim of this first profile.
            if self.header[3] & !1 != 0 {
                return Err(HttpError::UnsupportedContentEncoding.into());
            }
        }
        let mut pending = [0_u8; INPUT_CHUNK_BYTES + TRAILER_BYTES];
        let total = self.tail_len + input.len();
        pending[..self.tail_len].copy_from_slice(&self.tail[..self.tail_len]);
        pending[self.tail_len..total].copy_from_slice(input);
        let raw_count = total.saturating_sub(TRAILER_BYTES);
        self.tail_len = total - raw_count;
        self.tail[..self.tail_len].copy_from_slice(&pending[raw_count..total]);
        if raw_count == 0 {
            return Ok(Vec::new());
        }
        self.raw_bytes = self.raw_bytes.checked_add(raw_count).ok_or(HttpError::BodyTooLarge)?;
        let progress = self.inflater
            .push_with_control(&pending[..raw_count], &mut Probe(cancellation))
            .map_err(inflate_error)?;
        // The internally supplied Adler trailer has not been sent yet. A
        // completed zlib member here would hide bytes inside the gzip body.
        if progress == StreamProgress::Finished {
            return Err(HttpError::InvalidCompressedBody.into());
        }
        let output = self.inflater.take_output();
        self.output_bytes = self.output_bytes.checked_add(output.len() as u64)
            .ok_or(HttpError::BodyTooLarge)?;
        for fragment in output.chunks(4096) {
            checkpoint(cancellation)?;
            for &byte in fragment {
                self.crc = crc_byte(self.crc, byte);
                self.adler_a = (self.adler_a + u32::from(byte)) % ADLER_MODULUS;
                self.adler_b = (self.adler_b + self.adler_a) % ADLER_MODULUS;
            }
        }
        Ok(output)
    }

    pub(super) fn finish<C: ReceiveCancellation>(
        &mut self,
        cancellation: &mut C,
    ) -> Result<(), RpcError> {
        let result = self.finish_inner(cancellation);
        if result.is_err() {
            self.state = State::Failed;
        }
        result
    }

    fn finish_inner<C: ReceiveCancellation>(
        &mut self,
        cancellation: &mut C,
    ) -> Result<(), RpcError> {
        checkpoint(cancellation)?;
        match self.state {
            State::Finished => return Ok(()),
            State::Failed => return Err(RpcError::FailedRequest),
            State::Active => {}
        }
        if self.header_len != HEADER_BYTES || self.tail_len != TRAILER_BYTES {
            return Err(HttpError::TruncatedBody.into());
        }
        let expected_crc = u32::from_le_bytes([self.tail[0], self.tail[1], self.tail[2], self.tail[3]]);
        let expected_size = u32::from_le_bytes([self.tail[4], self.tail[5], self.tail[6], self.tail[7]]);
        // RFC 1952 ISIZE is modulo 2^32, not a trusted allocation size.
        let size = u32::try_from(self.output_bytes % (u64::from(u32::MAX) + 1))
            .map_err(|_| HttpError::InvalidCompressedBody)?;
        if expected_crc != !self.crc || expected_size != size {
            return Err(HttpError::InvalidCompressedBody.into());
        }
        let adler = ((self.adler_b << 16) | self.adler_a).to_be_bytes();
        let progress = self.inflater.push_with_control(&adler, &mut Probe(cancellation))
            .map_err(inflate_error)?;
        if progress != StreamProgress::Finished {
            return Err(HttpError::TruncatedBody.into());
        }
        if !self.inflater.take_output().is_empty()
            || Some(self.inflater.consumed_input_bytes()) != self.raw_bytes.checked_add(6)
        {
            return Err(HttpError::InvalidCompressedBody.into());
        }
        checkpoint(cancellation)?;
        self.state = State::Finished;
        Ok(())
    }
}

const fn crc_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = (value >> 1) ^ if value & 1 == 0 { 0 } else { 0xedb8_8320 };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}
const CRC_TABLE: [u32; 256] = crc_table();
fn crc_byte(crc: u32, byte: u8) -> u32 {
    CRC_TABLE[usize::from((crc ^ u32::from(byte)).to_le_bytes()[0])] ^ (crc >> 8)
}

#[cfg(test)]
mod tests;

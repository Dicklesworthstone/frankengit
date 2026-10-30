//! Caller-owned quarantine I/O. Exact span digests detect changed scratch bytes;
//! no scratch pathname, object-store placement, or publication is interpreted.

use super::super::{BundleVerifyError, BundleVerifyLimits, checkpoint};
use fgit_crypto::{DigestHasher, Sha256Hasher, sha256_digest};
use fgit_pack::{PackLimits, ResolutionBudget, STREAM_DELTA_CHUNK_BYTES};
use std::io::{self, Read, Seek, SeekFrom, Write};

pub(super) const CHUNK_BYTES: usize = 64 * 1024;

pub(super) fn io_error(operation: &'static str, error: io::Error) -> BundleVerifyError {
    BundleVerifyError::Io {
        operation,
        kind: error.kind(),
    }
}

pub(super) fn seek(
    file: &mut impl Seek,
    position: SeekFrom,
    operation: &'static str,
    live: &mut impl FnMut() -> bool,
) -> Result<u64, BundleVerifyError> {
    checkpoint(live)?;
    let result = file.seek(position);
    checkpoint(live)?;
    let observed = result.map_err(|error| io_error(operation, error))?;
    if let SeekFrom::Start(expected) = position {
        if observed != expected {
            return Err(BundleVerifyError::SourceChanged);
        }
    }
    Ok(observed)
}

pub(super) struct HashingReader<R> {
    reader: R,
    hash: Sha256Hasher,
    bytes: u64,
}
impl<R> HashingReader<R> {
    pub(super) const fn new(reader: R) -> Self {
        Self {
            reader,
            hash: Sha256Hasher::new(),
            bytes: 0,
        }
    }
    pub(super) fn finish(self) -> ([u8; 32], u64) {
        (self.hash.finish(), self.bytes)
    }
}
impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let offered = output.len().min(CHUNK_BYTES);
        let count = self.reader.read(&mut output[..offered])?;
        if count > offered {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid source read count",
            ));
        }
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source count overflow"))?;
        self.hash.update(&output[..count]);
        Ok(count)
    }
}

pub(super) fn read_source_hash(
    input: &mut (impl Read + Seek),
    expected_length: u64,
    live: &mut impl FnMut() -> bool,
) -> Result<[u8; 32], BundleVerifyError> {
    seek(
        input,
        SeekFrom::Start(0),
        "rewind bundle for checksum",
        live,
    )?;
    let mut reader = HashingReader::new(input);
    let mut buffer = [0_u8; CHUNK_BYTES];
    loop {
        checkpoint(live)?;
        let result = reader.read(&mut buffer);
        checkpoint(live)?;
        match result {
            Ok(0) => break,
            Ok(_) if reader.bytes > expected_length => {
                return Err(BundleVerifyError::SourceChanged);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error("hash bundle input", error)),
        }
    }
    let (digest, bytes) = reader.finish();
    if bytes != expected_length {
        return Err(BundleVerifyError::SourceChanged);
    }
    checkpoint(live)?;
    Ok(digest)
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Span {
    offset: u64,
    length: usize,
    sha256: [u8; 32],
}
impl Span {
    pub(super) const fn length(self) -> usize {
        self.length
    }
}

/// One bounded append, still private and uncommitted until its exact length
/// has arrived. A failed append cannot mint a reusable span.
pub(super) struct Append {
    offset: u64,
    length: usize,
    written: usize,
    hash: Sha256Hasher,
}

/// A bounded index derived from one fully verified span. Its hashes are only
/// usable after the complete span commitment and caller's native identity
/// check succeed. Every random read authenticates a whole indexed block before
/// returning any requested bytes; the one retained block is an owned copy.
pub(super) struct IndexedSpan {
    span: Span,
    hashes: Vec<[u8; 32]>,
    cached: Option<usize>,
    cache: [u8; STREAM_DELTA_CHUNK_BYTES],
}

/// Exact range custody. The digest is rechecked on the actual descriptor's
/// bytes; EOF is returned only after the complete retained span verifies.
pub(super) struct SpanReader<'a, W> {
    file: &'a mut W,
    remaining: usize,
    expected: [u8; 32],
    hash: Sha256Hasher,
    verified: bool,
}
impl<W: Read> SpanReader<'_, W> {
    pub(super) const fn is_verified(&self) -> bool {
        self.verified
    }

    pub(super) fn read(
        &mut self,
        output: &mut [u8],
        live: &mut impl FnMut() -> bool,
    ) -> Result<usize, BundleVerifyError> {
        checkpoint(live)?;
        if self.remaining == 0 {
            if !self.verified && self.hash.clone().finish() != self.expected {
                return Err(BundleVerifyError::ScratchChanged);
            }
            self.verified = true;
            return Ok(0);
        }
        let offered = output.len().min(CHUNK_BYTES).min(self.remaining);
        if offered == 0 {
            return Err(BundleVerifyError::ScratchChanged);
        }
        loop {
            checkpoint(live)?;
            let result = self.file.read(&mut output[..offered]);
            checkpoint(live)?;
            match result {
                Ok(0) => return Err(BundleVerifyError::ScratchChanged),
                Ok(count) if count <= offered => {
                    self.hash.update(&output[..count]);
                    self.remaining -= count;
                    return Ok(count);
                }
                Ok(_) => return Err(BundleVerifyError::ScratchChanged),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_error("read scratch", error)),
            }
        }
    }
}

pub(super) struct Scratch<'a, W> {
    file: &'a mut W,
    end: u64,
    maximum: u64,
}
impl<'a, W: Read + Write + Seek> Scratch<'a, W> {
    /// Reborrow scratch whose length and per-span commitments were retained
    /// by a completed verifier. This is not a constructor for caller offsets.
    pub(super) fn reopen(
        file: &'a mut W,
        end: u64,
        limits: &BundleVerifyLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Self, BundleVerifyError> {
        let maximum = (limits.pack.max_total_expanded_bytes as u64)
            .checked_add(limits.graph.max_payload_bytes)
            .ok_or(BundleVerifyError::ScratchChanged)?;
        if end > maximum || seek(file, SeekFrom::End(0), "recheck scratch length", live)? != end {
            return Err(BundleVerifyError::ScratchChanged);
        }
        Ok(Self { file, end, maximum })
    }

    pub(super) fn new(
        file: &'a mut W,
        limits: &BundleVerifyLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Self, BundleVerifyError> {
        let position = seek(file, SeekFrom::Current(0), "inspect scratch position", live)?;
        let end = seek(file, SeekFrom::End(0), "inspect scratch length", live)?;
        if position != 0 || end != 0 {
            return Err(BundleVerifyError::ScratchNotEmpty);
        }
        let maximum = (limits.pack.max_total_expanded_bytes as u64)
            .checked_add(limits.graph.max_payload_bytes)
            .ok_or(BundleVerifyError::Graph(super::super::GraphRefusal::Limit(
                "scratch bytes",
            )))?;
        Ok(Self {
            file,
            end: 0,
            maximum,
        })
    }
    pub(super) const fn bytes(&self) -> u64 {
        self.end
    }

    pub(super) fn begin_append(
        &mut self,
        length: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Append, BundleVerifyError> {
        checkpoint(live)?;
        self.end
            .checked_add(length as u64)
            .filter(|end| *end <= self.maximum)
            .ok_or(BundleVerifyError::Graph(super::super::GraphRefusal::Limit(
                "scratch bytes",
            )))?;
        seek(
            self.file,
            SeekFrom::Start(self.end),
            "seek scratch output",
            live,
        )?;
        Ok(Append {
            offset: self.end,
            length,
            written: 0,
            hash: Sha256Hasher::new(),
        })
    }

    pub(super) fn append_chunk(
        &mut self,
        append: &mut Append,
        bytes: &[u8],
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), BundleVerifyError> {
        checkpoint(live)?;
        if append.offset != self.end
            || append
                .written
                .checked_add(bytes.len())
                .is_none_or(|written| written > append.length)
        {
            return Err(BundleVerifyError::ScratchChanged);
        }
        let mut pending = bytes;
        while !pending.is_empty() {
            checkpoint(live)?;
            let offered = pending.len().min(CHUNK_BYTES);
            let result = self.file.write(&pending[..offered]);
            checkpoint(live)?;
            match result {
                Ok(0) => return Err(io_error("write scratch", io::ErrorKind::WriteZero.into())),
                Ok(count) if count <= offered => {
                    append.hash.update(&pending[..count]);
                    append.written += count;
                    pending = &pending[count..];
                }
                Ok(_) => return Err(BundleVerifyError::ScratchChanged),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_error("write scratch", error)),
            }
        }
        checkpoint(live)
    }

    /// Delta execution alternates reads of an older span and writes to this
    /// uncommitted result. Restore the result cursor explicitly before writing.
    pub(super) fn resume_append(
        &mut self,
        append: &Append,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), BundleVerifyError> {
        if append.offset != self.end || append.written > append.length {
            return Err(BundleVerifyError::ScratchChanged);
        }
        let offset = append
            .offset
            .checked_add(append.written as u64)
            .ok_or(BundleVerifyError::ScratchChanged)?;
        seek(
            self.file,
            SeekFrom::Start(offset),
            "resume scratch output",
            live,
        )?;
        Ok(())
    }

    pub(super) fn finish_append(
        &mut self,
        append: Append,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Span, BundleVerifyError> {
        checkpoint(live)?;
        if append.offset != self.end || append.written != append.length {
            return Err(BundleVerifyError::ScratchChanged);
        }
        self.end = self
            .end
            .checked_add(append.length as u64)
            .filter(|end| *end <= self.maximum)
            .ok_or(BundleVerifyError::ScratchChanged)?;
        let span = Span {
            offset: append.offset,
            length: append.length,
            sha256: append.hash.finish(),
        };
        checkpoint(live)?;
        Ok(span)
    }

    pub(super) fn append(
        &mut self,
        body: &[u8],
        live: &mut impl FnMut() -> bool,
    ) -> Result<Span, BundleVerifyError> {
        let mut append = self.begin_append(body.len(), live)?;
        self.append_chunk(&mut append, body, live)?;
        self.finish_append(append, live)
    }

    pub(super) fn reader(
        &mut self,
        span: Span,
        maximum: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<SpanReader<'_, W>, BundleVerifyError> {
        checkpoint(live)?;
        if span.length > maximum
            || span
                .offset
                .checked_add(span.length as u64)
                .is_none_or(|end| end > self.end)
        {
            return Err(BundleVerifyError::ScratchChanged);
        }
        self.flush(live)?;
        seek(
            self.file,
            SeekFrom::Start(span.offset),
            "seek scratch input",
            live,
        )?;
        Ok(SpanReader {
            file: self.file,
            remaining: span.length,
            expected: span.sha256,
            hash: Sha256Hasher::new(),
            verified: false,
        })
    }

    /// Transfer a temporary scratch borrow into an exact-span reader. The
    /// returned reader borrows the original descriptor, not this wrapper.
    pub(super) fn into_reader(
        mut self,
        span: Span,
        maximum: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<SpanReader<'a, W>, BundleVerifyError> {
        self.flush(live)?;
        open_span_reader(self.file, self.end, span, maximum, live)
    }

    pub(super) fn read(
        &mut self,
        span: Span,
        maximum: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Vec<u8>, BundleVerifyError> {
        checkpoint(live)?;
        if span.length > maximum
            || span
                .offset
                .checked_add(span.length as u64)
                .is_none_or(|end| end > self.end)
        {
            return Err(BundleVerifyError::ScratchChanged);
        }
        self.flush(live)?;
        seek(
            self.file,
            SeekFrom::Start(span.offset),
            "seek scratch input",
            live,
        )?;
        let mut body = Vec::new();
        body.try_reserve_exact(span.length)
            .map_err(|_| BundleVerifyError::Allocation)?;
        body.resize(span.length, 0);
        let mut hash = Sha256Hasher::new();
        let mut offset = 0;
        while offset < body.len() {
            checkpoint(live)?;
            let end = body.len().min(offset + CHUNK_BYTES);
            let result = self.file.read(&mut body[offset..end]);
            checkpoint(live)?;
            match result {
                Ok(0) => return Err(BundleVerifyError::ScratchChanged),
                Ok(count) if count <= end - offset => {
                    hash.update(&body[offset..offset + count]);
                    offset += count;
                }
                Ok(_) => return Err(BundleVerifyError::ScratchChanged),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_error("read scratch", error)),
            }
        }
        if hash.finish() != span.sha256 {
            return Err(BundleVerifyError::ScratchChanged);
        }
        checkpoint(live)?;
        Ok(body)
    }

    /// Verify a complete base once and derive one SHA-256 per 16 KiB block.
    /// The caller prepaid this sequential pass in the shared delta work budget
    /// and verifies the native identity through `observe`. The index has at
    /// most ceil(maximum / 16 KiB) entries and lives for one reconstruction.
    pub(super) fn index_span(
        &mut self,
        span: Span,
        maximum: usize,
        observe: &mut impl FnMut(&[u8]) -> Result<(), BundleVerifyError>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<IndexedSpan, BundleVerifyError> {
        checkpoint(live)?;
        if span.length > maximum {
            return Err(BundleVerifyError::ScratchChanged);
        }
        let count = span.length.div_ceil(STREAM_DELTA_CHUNK_BYTES);
        let mut hashes = Vec::new();
        hashes
            .try_reserve_exact(count)
            .map_err(|_| BundleVerifyError::Allocation)?;
        let mut reader = self.reader(span, maximum, live)?;
        let mut buffer = [0_u8; STREAM_DELTA_CHUNK_BYTES];
        let mut remaining = span.length;
        while remaining != 0 {
            checkpoint(live)?;
            let length = remaining.min(buffer.len());
            let mut filled = 0;
            while filled < length {
                let read = reader.read(&mut buffer[filled..length], live)?;
                if read == 0 {
                    return Err(BundleVerifyError::ScratchChanged);
                }
                filled += read;
            }
            observe(&buffer[..length])?;
            hashes.push(sha256_digest(&buffer[..length]));
            remaining -= length;
        }
        // The span reader authenticates its original full SHA-256 only at EOF,
        // including an empty base. Never return the tentative block hashes early.
        if reader.read(&mut buffer[..1], live)? != 0 {
            return Err(BundleVerifyError::ScratchChanged);
        }
        checkpoint(live)?;
        Ok(IndexedSpan {
            span,
            hashes,
            cached: None,
            cache: [0_u8; STREAM_DELTA_CHUNK_BYTES],
        })
    }

    /// Authenticate the actual random-read bytes before a delta can copy them.
    /// A one-byte request can require a complete block read; charge that whole
    /// physical read before I/O, so alternating tiny copies cannot hide work.
    pub(super) fn read_indexed(
        &mut self,
        index: &mut IndexedSpan,
        offset: usize,
        output: &mut [u8],
        budget: &mut ResolutionBudget,
        limits: &PackLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<usize, BundleVerifyError> {
        checkpoint(live)?;
        if output.is_empty() || offset >= index.span.length {
            return Err(BundleVerifyError::ScratchChanged);
        }
        let block = offset / STREAM_DELTA_CHUNK_BYTES;
        let start = block * STREAM_DELTA_CHUNK_BYTES;
        let length = (index.span.length - start).min(STREAM_DELTA_CHUNK_BYTES);
        if index.cached != Some(block) {
            budget
                .charge_work(length, limits)
                .map_err(BundleVerifyError::Pack)?;
            let position = index
                .span
                .offset
                .checked_add(start as u64)
                .ok_or(BundleVerifyError::ScratchChanged)?;
            self.flush(live)?;
            seek(
                self.file,
                SeekFrom::Start(position),
                "seek indexed scratch base",
                live,
            )?;
            index.cached = None;
            let mut filled = 0;
            while filled < length {
                checkpoint(live)?;
                let read = self.file.read(&mut index.cache[filled..length]);
                checkpoint(live)?;
                match read {
                    Ok(0) => return Err(BundleVerifyError::ScratchChanged),
                    Ok(count) if count <= length - filled => filled += count,
                    Ok(_) => return Err(BundleVerifyError::ScratchChanged),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(io_error("read indexed scratch base", error)),
                }
            }
            if index.hashes.get(block) != Some(&sha256_digest(&index.cache[..length])) {
                return Err(BundleVerifyError::ScratchChanged);
            }
            index.cached = Some(block);
        }
        let within = offset - start;
        let count = output.len().min(length - within);
        output[..count].copy_from_slice(&index.cache[within..within + count]);
        checkpoint(live)?;
        Ok(count)
    }

    fn flush(&mut self, live: &mut impl FnMut() -> bool) -> Result<(), BundleVerifyError> {
        checkpoint(live)?;
        let result = self.file.flush();
        checkpoint(live)?;
        result.map_err(|error| io_error("flush scratch", error))
    }

    pub(super) fn finish(
        &mut self,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), BundleVerifyError> {
        self.flush(live)?;
        if seek(self.file, SeekFrom::End(0), "verify scratch length", live)? != self.end {
            return Err(BundleVerifyError::ScratchChanged);
        }
        checkpoint(live)
    }
}

fn open_span_reader<'a, W: Read + Seek>(
    file: &'a mut W,
    end: u64,
    span: Span,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<SpanReader<'a, W>, BundleVerifyError> {
    checkpoint(live)?;
    if span.length > maximum
        || span
            .offset
            .checked_add(span.length as u64)
            .is_none_or(|limit| limit > end)
    {
        return Err(BundleVerifyError::ScratchChanged);
    }
    seek(
        file,
        SeekFrom::Start(span.offset),
        "seek scratch input",
        live,
    )?;
    Ok(SpanReader {
        file,
        remaining: span.length,
        expected: span.sha256,
        hash: Sha256Hasher::new(),
        verified: false,
    })
}

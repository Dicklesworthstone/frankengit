//! Caller-owned quarantine I/O. Exact span digests detect changed scratch bytes;
//! no scratch pathname, object-store placement, or publication is interpreted.

use super::super::{BundleVerifyError, BundleVerifyLimits, checkpoint};
use fgit_crypto::{DigestHasher, Sha256Hasher};
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
    pub(super) fn new(reader: R) -> Self {
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
pub(super) struct Scratch<'a, W> {
    file: &'a mut W,
    end: u64,
    maximum: u64,
}
impl<'a, W: Read + Write + Seek> Scratch<'a, W> {
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

    pub(super) fn append(
        &mut self,
        body: &[u8],
        live: &mut impl FnMut() -> bool,
    ) -> Result<Span, BundleVerifyError> {
        checkpoint(live)?;
        let end = self
            .end
            .checked_add(body.len() as u64)
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
        let mut hash = Sha256Hasher::new();
        let mut pending = body;
        while !pending.is_empty() {
            checkpoint(live)?;
            let offered = pending.len().min(CHUNK_BYTES);
            let result = self.file.write(&pending[..offered]);
            checkpoint(live)?;
            match result {
                Ok(0) => return Err(io_error("write scratch", io::ErrorKind::WriteZero.into())),
                Ok(count) if count <= offered => {
                    hash.update(&pending[..count]);
                    pending = &pending[count..];
                }
                Ok(_) => return Err(BundleVerifyError::ScratchChanged),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_error("write scratch", error)),
            }
        }
        let span = Span {
            offset: self.end,
            length: body.len(),
            sha256: hash.finish(),
        };
        self.end = end;
        checkpoint(live)?;
        Ok(span)
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

//! Hold one opened archive across all passes. Path replacement never switches
//! the input, and in-place changes are detected by rechecking the trusted pin.
//! Only bounded metadata survives a pass; records borrow one reusable buffer.
use super::super::regular;
use super::archive::{
    Record,
    stream::{Seal, StreamDecoder, StreamHeader, TransferLimits},
};
use super::profile::Deadline;
use fgit_crypto::{DigestHasher, Sha256Hasher};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

pub(super) struct PinnedArchive<R = File> {
    input: R,
    header: StreamHeader,
    seal: Seal,
    limits: TransferLimits,
}
impl PinnedArchive<File> {
    pub fn open(
        path: &Path,
        expected: [u8; 32],
        limits: TransferLimits,
        deadline: Deadline,
    ) -> Result<Self, String> {
        limits.validate()?;
        deadline.check()?;
        if regular(path)? > limits.max_archive_bytes {
            return Err("repository backup archive-byte limit exceeded".into());
        }
        let file = File::open(path).map_err(|e| e.to_string())?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limits.max_archive_bytes {
            return Err("repository backup input changed or exceeds its archive-byte limit".into());
        }
        Self::new(file, expected, limits, deadline)
    }
}
impl<R: Read + Seek> PinnedArchive<R> {
    fn new(
        mut input: R,
        expected: [u8; 32],
        limits: TransferLimits,
        deadline: Deadline,
    ) -> Result<Self, String> {
        limits.validate()?;
        input.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        // Preserve checksum-before-decoding precedence and avoid feeding an
        // untrusted, wrong-pin authority bundle to the canonical parser.
        let initial = check_checksum(&mut input, expected, limits, deadline)?;
        input.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut live = || deadline.check();
        let mut decoded = StreamDecoder::new(&mut input, limits, &mut live)?;
        while decoded.record(&mut live)?.is_some() {}
        let (header, seal) = decoded.finish(expected, &mut live)?;
        if seal != initial {
            return Err("repository backup changed between checksum and validation".into());
        }
        Ok(Self {
            input,
            header,
            seal,
            limits,
        })
    }
    pub const fn header(&self) -> &StreamHeader {
        &self.header
    }
    pub const fn seal(&self) -> Seal {
        self.seal
    }
    /// The visitor may compute or stage, never publish: this pass is tentative
    /// until EOF and the whole-file pin validate, even after an earlier pass.
    pub fn scan(
        &mut self,
        deadline: Deadline,
        mut visit: impl for<'a> FnMut(Record<'a>) -> Result<(), String>,
    ) -> Result<(), String> {
        deadline.check()?;
        self.input
            .seek(SeekFrom::Start(0))
            .map_err(|e| format!("backup input seek failed: {e}"))?;
        let mut live = || deadline.check();
        let mut decoded = StreamDecoder::new(&mut self.input, self.limits, &mut live)?;
        if decoded.header() != &self.header {
            return Err("repository backup metadata changed between passes".into());
        }
        while let Some(record) = decoded.record(&mut live)? {
            visit(record)?;
        }
        let (_, seal) = decoded.finish(self.seal.digest, &mut live)?;
        if seal != self.seal {
            return Err("repository backup length changed between passes".into());
        }
        Ok(())
    }
}
fn check_checksum(
    input: &mut impl Read,
    expected: [u8; 32],
    limits: TransferLimits,
    deadline: Deadline,
) -> Result<Seal, String> {
    let mut buffer = [0; 64 * 1024];
    let mut hash = Sha256Hasher::new();
    let mut bytes = 0_u64;
    loop {
        deadline.check()?;
        // At capacity, probe one byte to distinguish exact EOF from oversize.
        let maximum = (limits.max_archive_bytes - bytes + 1).min(buffer.len() as u64) as usize;
        let count = match input.read(&mut buffer[..maximum]) {
            Ok(0) => break,
            Ok(count) if count <= maximum => count,
            Ok(_) => return Err("invalid backup checksum reader byte count".into()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("backup checksum read failed: {error}")),
        };
        bytes = bytes
            .checked_add(count as u64)
            .filter(|n| *n <= limits.max_archive_bytes)
            .ok_or("repository backup archive-byte limit exceeded")?;
        hash.update(&buffer[..count]);
    }
    deadline.check()?;
    let seal = Seal {
        digest: hash.finish(),
        bytes,
    };
    if seal.digest != expected {
        return Err("repository backup checksum mismatch; no destination created".into());
    }
    Ok(seal)
}

#[cfg(test)]
#[path = "input_tests.rs"]
mod tests;

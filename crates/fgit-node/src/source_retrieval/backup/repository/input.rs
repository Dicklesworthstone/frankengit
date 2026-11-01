//! Hold one opened archive across all passes. Path replacement never switches
//! the input, and in-place changes are detected by rechecking the trusted pin.
//! Only bounded metadata and retained-checkpoint evidence survive a pass;
//! source Git blob bodies pass through bounded readers.
use super::super::regular;
#[cfg(test)]
use super::archive::Record;
use super::archive::stream::{RecordHeader, Seal, StreamDecoder, StreamHeader, TransferLimits};
use super::profile::Deadline;
use fgit_crypto::{DigestHasher, Sha256Hasher};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// Only disagreement with the independently approved whole-file seal permits
/// trying another copy. A matching seal selects one immutable input; later
/// codec, resource, storage or liveness failures cannot be blamed on a replica.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DamageKind {
    LengthMismatch,
    ChecksumMismatch,
}

#[cfg(unix)]
impl DamageKind {
    pub(super) const fn code(self) -> &'static str {
        match self {
            Self::LengthMismatch => "archive_length_mismatch",
            Self::ChecksumMismatch => "archive_checksum_mismatch",
        }
    }
}

#[cfg(unix)]
#[derive(Debug)]
pub(super) enum ReplicaInputFailure {
    Damaged(DamageKind),
    Fatal(String),
}

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
    /// Verify one already-owned reader without reopening its pathname. Native
    /// composition can wrap the reader in its original operation's I/O ledger.
    #[cfg(unix)]
    pub(super) fn from_reader(
        input: R,
        expected: [u8; 32],
        limits: TransferLimits,
        deadline: Deadline,
    ) -> Result<Self, String> {
        Self::new(input, expected, limits, deadline)
    }

    /// Acquire one explicitly named replica under its original approved size
    /// and digest. The same owned reader performs exactly the ordinary two
    /// admission passes and remains pinned for every subsequent native pass.
    #[cfg(unix)]
    pub(super) fn from_replica_reader(
        mut input: R,
        expected: Seal,
        limits: TransferLimits,
        deadline: Deadline,
    ) -> Result<Self, ReplicaInputFailure> {
        use ReplicaInputFailure::{Damaged, Fatal};

        limits.validate().map_err(Fatal)?;
        deadline.check().map_err(Fatal)?;
        if expected.bytes == 0 || expected.bytes > limits.max_archive_bytes {
            return Err(Fatal(
                "approved replica length is outside the selected archive-byte allowance".into(),
            ));
        }
        input
            .seek(SeekFrom::Start(0))
            .map_err(|error| Fatal(error.to_string()))?;
        let initial = match checksum_pass(&mut input, expected.bytes, deadline) {
            Ok(seal) => seal,
            Err(ChecksumFailure::LimitExceeded) => {
                deadline.check().map_err(Fatal)?;
                return Err(Damaged(DamageKind::LengthMismatch));
            }
            Err(ChecksumFailure::Fatal(error)) => return Err(Fatal(error)),
        };
        if initial.bytes != expected.bytes {
            return Err(Damaged(DamageKind::LengthMismatch));
        }
        if initial.digest != expected.digest {
            return Err(Damaged(DamageKind::ChecksumMismatch));
        }
        // Once original whole-file commitments agree, every further refusal is
        // fatal. Do not retry identical bytes for a codec/resource failure.
        Self::after_checksum(input, initial, limits, deadline).map_err(Fatal)
    }

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
        Self::after_checksum(input, initial, limits, deadline)
    }

    fn after_checksum(
        mut input: R,
        initial: Seal,
        limits: TransferLimits,
        deadline: Deadline,
    ) -> Result<Self, String> {
        input.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut live = || deadline.check();
        let mut decoded = StreamDecoder::new(&mut input, limits, &mut live)?;
        while decoded.visit_record(&mut live, |header, body| {
            let buffer_bytes = (header.length.min(64 * 1024) as usize).max(1);
            let mut buffer = Vec::new();
            buffer
                .try_reserve_exact(buffer_bytes)
                .map_err(|_| "repository backup validation buffer allocation failed")?;
            buffer.resize(buffer_bytes, 0);
            loop {
                deadline.check()?;
                if body.read(&mut buffer).map_err(|e| e.to_string())? == 0 {
                    break;
                }
            }
            deadline.check()
        })? {}
        let (header, seal) = decoded.finish(initial.digest, &mut live)?;
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
    /// Record readers authenticate their native and strong commitments at EOF;
    /// callers must consume them completely before this pass can succeed.
    pub fn scan_stream(
        &mut self,
        deadline: Deadline,
        mut visit: impl FnMut(RecordHeader, &mut dyn Read) -> Result<(), String>,
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
        while decoded.visit_record(&mut live, |header, body| visit(header, body))? {}
        let (_, seal) = decoded.finish(self.seal.digest, &mut live)?;
        if seal != self.seal {
            return Err("repository backup length changed between passes".into());
        }
        Ok(())
    }
    /// Bounded compatibility oracle used by the original buffered tests.
    #[cfg(test)]
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
    let seal =
        checksum_pass(input, limits.max_archive_bytes, deadline).map_err(
            |failure| match failure {
                ChecksumFailure::LimitExceeded => {
                    "repository backup archive-byte limit exceeded".into()
                }
                ChecksumFailure::Fatal(error) => error,
            },
        )?;
    if seal.digest != expected {
        return Err("repository backup checksum mismatch".into());
    }
    Ok(seal)
}

enum ChecksumFailure {
    LimitExceeded,
    Fatal(String),
}

/// One bounded whole-file checksum pass. Ordinary intake interprets excess as
/// its resource refusal; replica intake compares the authenticated exact length.
fn checksum_pass(
    input: &mut impl Read,
    maximum_bytes: u64,
    deadline: Deadline,
) -> Result<Seal, ChecksumFailure> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(64 * 1024).map_err(|_| {
        ChecksumFailure::Fatal("repository backup checksum buffer allocation failed".into())
    })?;
    buffer.resize(64 * 1024, 0);
    let mut hash = Sha256Hasher::new();
    let mut bytes = 0_u64;
    loop {
        deadline.check().map_err(ChecksumFailure::Fatal)?;
        // At capacity, probe one byte to distinguish exact EOF from oversize.
        let maximum = (maximum_bytes - bytes + 1).min(buffer.len() as u64) as usize;
        let count = match input.read(&mut buffer[..maximum]) {
            Ok(0) => break,
            Ok(count) if count <= maximum => count,
            Ok(_) => {
                return Err(ChecksumFailure::Fatal(
                    "invalid backup checksum reader byte count".into(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(ChecksumFailure::Fatal(format!(
                    "backup checksum read failed: {error}"
                )));
            }
        };
        bytes = bytes
            .checked_add(count as u64)
            .filter(|n| *n <= maximum_bytes)
            .ok_or(ChecksumFailure::LimitExceeded)?;
        hash.update(&buffer[..count]);
    }
    deadline.check().map_err(ChecksumFailure::Fatal)?;
    let seal = Seal {
        digest: hash.finish(),
        bytes,
    };
    Ok(seal)
}

#[cfg(test)]
#[path = "input_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "input_stream_tests.rs"]
mod stream_tests;

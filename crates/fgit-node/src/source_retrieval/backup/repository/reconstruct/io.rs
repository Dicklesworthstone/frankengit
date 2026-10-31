//! One actual-byte ledger and stable NOFOLLOW source descriptors. A recoverable
//! unavailable replica is distinct from a fatal deadline, read budget or I/O
//! failure; only the former may cause another explicitly selected copy to run.

use std::cell::{Cell, RefCell};
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::super::approval::VerifiedApproval;
use super::super::profile::Deadline;

pub(super) const BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Checkpoint {
    PayloadRead { bytes: usize, total: u64 },
    ChunkAccepted { chunk: usize, replica: usize },
    BeforeVerification,
    AfterVerification,
    BeforePublication,
}

#[derive(Debug)]
pub(super) enum ReadFailure {
    Io(io::Error),
    Gate(String),
}

impl ReadFailure {
    pub(super) fn message(self) -> String {
        match self {
            Self::Io(error) => format!("backup payload read failed: {error}"),
            Self::Gate(error) => error,
        }
    }
}

/// A zero remaining budget does not manufacture EOF. A real one-byte probe
/// may return zero; any byte it returns is charged and makes failure sticky.
struct ReadBudget {
    maximum: u64,
    bytes: Cell<u64>,
    calls: Cell<u64>,
    exceeded: Cell<bool>,
}

impl ReadBudget {
    fn new(maximum: u64) -> Self {
        Self {
            maximum,
            bytes: Cell::new(0),
            calls: Cell::new(0),
            exceeded: Cell::new(false),
        }
    }

    fn remaining(&self) -> u64 {
        self.maximum.saturating_sub(self.bytes.get())
    }

    fn read(&self, input: &mut impl Read, buffer: &mut [u8]) -> Result<usize, ReadFailure> {
        if self.exceeded.get() {
            return Err(ReadFailure::Gate(
                "backup aggregate payload-read budget exceeded".into(),
            ));
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        let maximum = buffer
            .len()
            .min(BUFFER_BYTES)
            .min(self.remaining().max(1).min(BUFFER_BYTES as u64) as usize);
        self.calls.set(self.calls.get() + 1);
        let count = input
            .read(&mut buffer[..maximum])
            .map_err(ReadFailure::Io)?;
        if count > maximum {
            self.exceeded.set(true);
            return Err(ReadFailure::Gate(
                "invalid backup payload reader byte count".into(),
            ));
        }
        // The finite ceiling is 67 TiB, so even the final refused probe cannot
        // overflow u64. Record actual consumption before refusing excess.
        self.bytes.set(self.bytes.get() + count as u64);
        if self.bytes.get() > self.maximum {
            self.exceeded.set(true);
            return Err(ReadFailure::Gate(
                "backup aggregate payload-read budget exceeded".into(),
            ));
        }
        Ok(count)
    }
}

pub(super) struct Control<'a> {
    approval: &'a VerifiedApproval,
    deadline: Deadline,
    budget: ReadBudget,
    checkpoint: RefCell<&'a mut dyn FnMut(Checkpoint) -> Result<(), String>>,
    stopped: RefCell<Option<String>>,
}

impl<'a> Control<'a> {
    pub(super) fn new(
        approval: &'a VerifiedApproval,
        deadline: Deadline,
        maximum: u64,
        checkpoint: &'a mut dyn FnMut(Checkpoint) -> Result<(), String>,
    ) -> Self {
        Self {
            approval,
            deadline,
            budget: ReadBudget::new(maximum),
            checkpoint: RefCell::new(checkpoint),
            stopped: RefCell::new(None),
        }
    }

    fn stop(&self, error: String) -> String {
        let mut stopped = self.stopped.borrow_mut();
        stopped.get_or_insert(error).clone()
    }

    pub(super) fn check(&self) -> Result<(), String> {
        if let Some(error) = self.stopped.borrow().as_ref() {
            return Err(error.clone());
        }
        self.deadline
            .check()
            .and_then(|()| self.approval.check_current())
            .map_err(|error| self.stop(error))
    }

    pub(super) fn checkpoint(&self, event: Checkpoint) -> Result<(), String> {
        self.check()?;
        (self.checkpoint.borrow_mut())(event).map_err(|error| self.stop(error))?;
        self.check()
    }

    pub(super) fn reserve(&self, bytes: u64) -> Result<(), String> {
        self.check()?;
        if bytes > self.budget.remaining() {
            return Err(self.stop("backup aggregate payload-read allowance cannot cover this candidate and required native verification".into()));
        }
        Ok(())
    }

    pub(super) fn bytes_read(&self) -> u64 {
        self.budget.bytes.get()
    }
    pub(super) fn read_calls(&self) -> u64 {
        self.budget.calls.get()
    }

    pub(super) fn read(
        &self,
        input: &mut impl Read,
        buffer: &mut [u8],
    ) -> Result<usize, ReadFailure> {
        self.check().map_err(ReadFailure::Gate)?;
        let count = match self.budget.read(input, buffer) {
            Err(ReadFailure::Gate(error)) => return Err(ReadFailure::Gate(self.stop(error))),
            result => result?,
        };
        if count != 0 {
            self.checkpoint(Checkpoint::PayloadRead {
                bytes: count,
                total: self.bytes_read(),
            })
            .map_err(ReadFailure::Gate)?;
        }
        self.check().map_err(ReadFailure::Gate)?;
        Ok(count)
    }

    pub(super) fn metadata_read(
        &self,
        input: &mut impl Read,
        buffer: &mut [u8],
    ) -> Result<usize, String> {
        loop {
            self.check()?;
            let maximum = buffer.len().min(BUFFER_BYTES);
            match input.read(&mut buffer[..maximum]) {
                Ok(count) if count <= maximum => {
                    self.check()?;
                    return Ok(count);
                }
                Ok(_) => return Err("invalid backup catalog reader byte count".into()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(format!("backup catalog read failed: {error}")),
            }
        }
    }

    pub(super) fn write_all(
        &self,
        output: &mut impl Write,
        mut bytes: &[u8],
    ) -> Result<(), String> {
        while !bytes.is_empty() {
            self.check()?;
            let maximum = bytes.len().min(BUFFER_BYTES);
            match output.write(&bytes[..maximum]) {
                Ok(0) => return Err("backup staging write made no progress".into()),
                Ok(count) if count <= maximum => bytes = &bytes[count..],
                Ok(_) => return Err("invalid backup staging writer byte count".into()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(format!("backup staging write failed: {error}")),
            }
        }
        self.check()
    }
}

pub(super) struct Metered<'a, 'b, R> {
    pub(super) input: R,
    pub(super) control: &'a Control<'b>,
}

impl<R: Read> Read for Metered<'_, '_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.control
            .read(&mut self.input, buffer)
            .map_err(|failure| match failure {
                ReadFailure::Io(error) => error,
                ReadFailure::Gate(error) => io::Error::other(error),
            })
    }
}

impl<R: Seek> Seek for Metered<'_, '_, R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.control.check().map_err(io::Error::other)?;
        let position = self.input.seek(position)?;
        self.control.check().map_err(io::Error::other)?;
        Ok(position)
    }
}

#[derive(Debug)]
pub(super) enum SourceFailure {
    Unavailable(String),
    Fatal(String),
}

impl SourceFailure {
    pub(super) fn from_io(error: io::Error) -> Self {
        if matches!(
            error.kind(),
            io::ErrorKind::NotFound
                | io::ErrorKind::NotADirectory
                | io::ErrorKind::PermissionDenied
        ) || error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())
        {
            Self::Unavailable(format!("source unavailable: {error}"))
        } else {
            Self::Fatal(format!("backup source I/O failed: {error}"))
        }
    }

    pub(super) fn message(self) -> String {
        match self {
            Self::Unavailable(error) | Self::Fatal(error) => error,
        }
    }
}

pub(super) struct Source {
    path: PathBuf,
    pub(super) file: File,
    identity: Metadata,
}

impl Source {
    pub(super) fn open(path: &Path, maximum: u64) -> Result<Self, SourceFailure> {
        let file = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| SourceFailure::from_io(error.into()))?;
        let identity = file.metadata().map_err(SourceFailure::from_io)?;
        if !identity.is_file() || identity.len() == 0 || identity.len() > maximum {
            return Err(SourceFailure::Unavailable(
                "source is not a bounded nonempty regular file".into(),
            ));
        }
        let source = Self {
            path: path.to_path_buf(),
            file,
            identity,
        };
        source.check()?;
        Ok(source)
    }

    pub(super) fn length(&self) -> u64 {
        self.identity.len()
    }
    pub(super) fn identity(&self) -> (u64, u64) {
        (self.identity.dev(), self.identity.ino())
    }

    pub(super) fn check(&self) -> Result<(), SourceFailure> {
        let opened = self.file.metadata().map_err(SourceFailure::from_io)?;
        let named = fs::symlink_metadata(&self.path).map_err(SourceFailure::from_io)?;
        if !same_file(&self.identity, &opened) || !same_file(&self.identity, &named) {
            return Err(SourceFailure::Unavailable(
                "source identity or content metadata changed".into(),
            ));
        }
        Ok(())
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
        && left.len() == right.len()
        && left.nlink() == right.nlink()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn exact_budget_performs_real_eof_and_counts_refused_extra_byte() {
        let budget = ReadBudget::new(3);
        let mut input = Cursor::new(b"abc");
        let mut buffer = [0; 9];
        assert_eq!(budget.read(&mut input, &mut buffer).unwrap(), 3);
        assert_eq!(budget.read(&mut input, &mut buffer).unwrap(), 0);
        assert_eq!(budget.bytes.get(), 3);
        assert_eq!(budget.calls.get(), 2);
        let mut trailing = Cursor::new(b"x");
        assert!(matches!(
            budget.read(&mut trailing, &mut buffer),
            Err(ReadFailure::Gate(_))
        ));
        assert_eq!(budget.bytes.get(), 4);
        let calls = budget.calls.get();
        assert!(budget.read(&mut input, &mut buffer).is_err());
        assert_eq!(budget.calls.get(), calls, "excess is sticky");
    }

    #[test]
    fn failed_candidates_and_late_io_share_actual_bytes_without_synthetic_eof() {
        struct LateError {
            first: bool,
        }
        impl Read for LateError {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if !self.first {
                    return Err(io::Error::other("late storage failure"));
                }
                self.first = false;
                output[0] = 42;
                Ok(1)
            }
        }
        let budget = ReadBudget::new(4);
        let mut buffer = [0; 8];
        assert_eq!(
            budget.read(&mut Cursor::new(b"bad"), &mut buffer).unwrap(),
            3
        );
        let mut late = LateError { first: true };
        assert_eq!(budget.read(&mut late, &mut buffer).unwrap(), 1);
        assert!(matches!(
            budget.read(&mut late, &mut buffer),
            Err(ReadFailure::Io(_))
        ));
        assert_eq!(budget.bytes.get(), 4);
        assert_eq!(budget.calls.get(), 3);
        assert!(matches!(
            SourceFailure::from_io(io::Error::other("late storage failure")),
            SourceFailure::Fatal(_)
        ));
        assert!(matches!(
            SourceFailure::from_io(io::Error::from(io::ErrorKind::Interrupted)),
            SourceFailure::Fatal(_)
        ));
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::NotADirectory,
            io::ErrorKind::PermissionDenied,
        ] {
            assert!(matches!(
                SourceFailure::from_io(io::Error::from(kind)),
                SourceFailure::Unavailable(_)
            ));
        }
    }
}

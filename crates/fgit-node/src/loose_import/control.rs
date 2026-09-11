//! One caller-owned cancellation boundary across blocking import preparation.
//!
//! The control is borrowed, stack-scoped and sticky. Adapters share it instead
//! of manufacturing a fresh deadline for I/O, decoding, graph walks or staging.
//! An in-progress OS call cannot be preempted; its result is checked before use.
use std::cell::{Cell, RefCell};
use std::io::{self, Read};

use fgit_git_object::{CancellationProbe, InflateLimits, LooseObject, ParseLimits, ZlibLooseObjectDecoder};
use fgit_pack::Deadline;
use fgit_types::RefusalCode;

use super::LooseGitImportRefusal;
use crate::{NodeRequestContext, PackContextCheckpoint, checkpoint_pack_context};

pub(super) const IO_CHUNK_BYTES: usize = 32 * 1024;
// Decoder callbacks can occur once per byte. They are not scheduler polls:
// amortize the runtime checkpoint without changing parser/delta work budgets.
const CPU_PROBE_INTERVAL: u16 = 1024;

pub(super) struct ImportControl<'a> {
    deadline: RefCell<&'a mut dyn Deadline>,
    stopped: Cell<Option<RefusalCode>>,
}

impl<'a> ImportControl<'a> {
    pub(super) fn new(deadline: &'a mut impl Deadline) -> Self {
        Self { deadline: RefCell::new(deadline), stopped: Cell::new(None) }
    }

    pub(super) fn checkpoint(&self) -> Result<(), LooseGitImportRefusal> {
        if let Some(code) = self.stopped.get() { return Err(interrupted(code)); }
        let live = self.deadline.try_borrow_mut()
            .map(|mut deadline| deadline.checkpoint());
        let code = match live {
            Ok(true) => return Ok(()),
            Ok(false) => RefusalCode::CancellationInProgress,
            Err(_) => RefusalCode::InternalInvariantBreach,
        };
        self.stopped.set(Some(code));
        Err(interrupted(code))
    }

    pub(super) fn is_live(&self) -> bool { self.checkpoint().is_ok() }

    pub(super) fn run<T>(&self, operation: impl FnOnce() -> T) -> Result<T, LooseGitImportRefusal> {
        self.checkpoint()?;
        let result = operation();
        self.checkpoint()?;
        Ok(result)
    }

    pub(super) fn cpu_probe(&self) -> CpuProbe<'_, 'a> {
        CpuProbe { control: self, remaining: 0 }
    }

    /// Observe a stop after a bounded operation BEFORE interpreting its result.
    /// This is used only for reads and preparation, never a canonical CAS result.
    pub(super) fn after<T, E>(&self, result: Result<T, E>, map: impl FnOnce(E) -> LooseGitImportRefusal)
        -> Result<T, LooseGitImportRefusal>
    {
        self.checkpoint()?;
        result.map_err(map)
    }
}

pub(super) fn interrupted(code: RefusalCode) -> LooseGitImportRefusal {
    LooseGitImportRefusal::Interrupted { code, exhaustion: None }
}

/// Check the ORIGINAL request context; there is no budget extension or child
/// context here. Exhaustion retains the runtime's exact failed dimension.
pub(crate) fn checkpoint_request(request: &NodeRequestContext) -> Result<(), LooseGitImportRefusal> {
    match checkpoint_pack_context(request.authority()) {
        PackContextCheckpoint::Live => Ok(()),
        PackContextCheckpoint::Stopped { budget_exhaustion } => Err(LooseGitImportRefusal::Interrupted {
            code: if budget_exhaustion.is_some() { RefusalCode::ResourceBudgetExceeded }
                else { RefusalCode::CancellationInProgress },
            exhaustion: budget_exhaustion,
        }),
    }
}

#[derive(Debug)]
pub(super) enum ReadFailure {
    Io(io::Error),
    Interrupted(LooseGitImportRefusal),
}

/// Read at most `limit + 1` bytes in bounded chunks. EOF is not a way to
/// suppress cancellation, and interrupted OS reads do not reset the deadline.
pub(super) fn read_bytes(
    mut reader: impl Read, limit: u64, control: &ImportControl<'_>,
) -> Result<Vec<u8>, ReadFailure> {
    let mut remaining = limit.saturating_add(1);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; IO_CHUNK_BYTES];
    loop {
        control.checkpoint().map_err(ReadFailure::Interrupted)?;
        if remaining == 0 { return Ok(bytes); }
        let size = usize::try_from(remaining).unwrap_or(usize::MAX).min(buffer.len());
        let read = reader.read(&mut buffer[..size]);
        control.checkpoint().map_err(ReadFailure::Interrupted)?;
        let count = match read {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(ReadFailure::Io(error)),
        };
        if count == 0 { return Ok(bytes); }
        if count > size {
            return Err(ReadFailure::Io(io::Error::new(io::ErrorKind::InvalidData,
                "reader returned more bytes than requested")));
        }
        bytes.try_reserve(count).map_err(|_| ReadFailure::Interrupted(
            interrupted(RefusalCode::ResourceBudgetExceeded)))?;
        bytes.extend_from_slice(&buffer[..count]);
        remaining -= u64::try_from(count).map_err(|_| ReadFailure::Interrupted(
            interrupted(RefusalCode::ResourceBudgetExceeded)))?;
    }
}

/// The existing zlib/native decoder retains framing and checksum authority.
/// Its own inflation checkpoints consult the SAME control used by file I/O.
pub(super) fn decode_loose(
    bytes: &[u8], inflate_limits: InflateLimits, parse_limits: ParseLimits,
    control: &ImportControl<'_>,
) -> Result<LooseObject, LooseGitImportRefusal> {
    control.checkpoint()?;
    let decode_error = |error| LooseGitImportRefusal::LooseObject(Box::new(error));
    let mut decoder = ZlibLooseObjectDecoder::new(inflate_limits, parse_limits).map_err(decode_error)?;
    let mut probe = control.cpu_probe();
    for chunk in bytes.chunks(IO_CHUNK_BYTES) {
        control.checkpoint()?;
        let progress = decoder.push_with_control(chunk, &mut probe);
        control.after(progress, decode_error)?;
    }
    control.checkpoint()?;
    let decoded = decoder.finish();
    control.after(decoded, decode_error)
}

/// Only pure-CPU parser/resolver loops use this adapter. I/O and staging keep
/// unconditional entry/exit checkpoints. The parser's own byte/work limits
/// remain charged at their original granularity.
pub(super) struct CpuProbe<'a, 'b> {
    control: &'a ImportControl<'b>,
    remaining: u16,
}
impl CpuProbe<'_, '_> {
    fn poll(&mut self) -> bool {
        if self.control.stopped.get().is_some() { return false; }
        if self.remaining == 0 {
            self.remaining = CPU_PROBE_INTERVAL - 1;
            self.control.is_live()
        } else {
            self.remaining -= 1;
            true
        }
    }
}
impl Deadline for CpuProbe<'_, '_> {
    fn checkpoint(&mut self) -> bool { self.poll() }
}
impl CancellationProbe for CpuProbe<'_, '_> {
    fn is_cancelled(&mut self) -> bool { !self.poll() }
}

#[cfg(test)]
mod tests;

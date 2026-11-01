#![forbid(unsafe_code)]
//! Shared actual-byte accounting for native recovery payload reads. The caller
//! supplies its already validated finite allowance. A depleted allowance still
//! probes the real reader for EOF; a returned byte is charged and then refused.

use std::cell::Cell;
use std::io::{self, Read};

pub(crate) const BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) enum ReadFailure {
    Io(io::Error),
    Gate(String),
}

impl ReadFailure {
    pub(crate) fn message(self) -> String {
        match self {
            Self::Io(error) => format!("backup payload read failed: {error}"),
            Self::Gate(error) => error,
        }
    }
}

pub(crate) struct ReadBudget {
    maximum: u64,
    bytes: Cell<u64>,
    calls: Cell<u64>,
    stopped: Cell<Option<&'static str>>,
}

impl ReadBudget {
    pub(crate) fn new(maximum: u64) -> Self {
        Self {
            maximum,
            bytes: Cell::new(0),
            calls: Cell::new(0),
            stopped: Cell::new(None),
        }
    }

    pub(crate) fn remaining(&self) -> u64 {
        self.maximum.saturating_sub(self.bytes.get())
    }

    pub(crate) fn bytes_read(&self) -> u64 {
        self.bytes.get()
    }

    pub(crate) fn read_calls(&self) -> u64 {
        self.calls.get()
    }

    fn stop(&self, message: &'static str) -> ReadFailure {
        let first = self.stopped.get().unwrap_or(message);
        self.stopped.set(Some(first));
        ReadFailure::Gate(first.into())
    }

    pub(crate) fn read(
        &self,
        input: &mut impl Read,
        buffer: &mut [u8],
    ) -> Result<usize, ReadFailure> {
        if let Some(error) = self.stopped.get() {
            return Err(ReadFailure::Gate(error.into()));
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        let maximum = buffer
            .len()
            .min(BUFFER_BYTES)
            .min(self.remaining().max(1).min(BUFFER_BYTES as u64) as usize);
        let calls = self
            .calls
            .get()
            .checked_add(1)
            .ok_or_else(|| self.stop("backup payload-read call count overflow"))?;
        self.calls.set(calls);
        let count = input
            .read(&mut buffer[..maximum])
            .map_err(ReadFailure::Io)?;
        if count > maximum {
            return Err(self.stop("invalid backup payload reader byte count"));
        }
        let bytes = self
            .bytes
            .get()
            .checked_add(count as u64)
            .ok_or_else(|| self.stop("backup payload-read byte count overflow"))?;
        // Actual consumption is recorded before the final refused extra byte.
        self.bytes.set(bytes);
        if bytes > self.maximum {
            return Err(self.stop("backup aggregate payload-read budget exceeded"));
        }
        Ok(count)
    }
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
        assert_eq!(budget.bytes_read(), 3);
        assert_eq!(budget.read_calls(), 2);
        let mut trailing = Cursor::new(b"x");
        let error = budget
            .read(&mut trailing, &mut buffer)
            .unwrap_err()
            .message();
        assert_eq!(error, "backup aggregate payload-read budget exceeded");
        assert_eq!(budget.bytes_read(), 4);
        let calls = budget.read_calls();
        assert_eq!(
            budget.read(&mut input, &mut buffer).unwrap_err().message(),
            error
        );
        assert_eq!(budget.read_calls(), calls, "excess is sticky");
    }

    #[test]
    fn failed_candidates_and_late_io_keep_actual_bytes_without_synthetic_eof() {
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
        assert_eq!(budget.bytes_read(), 4);
        assert_eq!(budget.read_calls(), 3);
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn offered_slices_follow_chunk_and_remaining_limits_then_probe_real_eof() {
        struct Observed {
            input: Cursor<Vec<u8>>,
            offered: Vec<usize>,
        }
        impl Read for Observed {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                self.offered.push(output.len());
                self.input.read(output)
            }
        }
        let size = BUFFER_BYTES * 2 + 7;
        let budget = ReadBudget::new(size as u64);
        let mut input = Observed {
            input: Cursor::new(vec![42; size]),
            offered: Vec::new(),
        };
        let mut buffer = vec![0; BUFFER_BYTES * 3];
        assert_eq!(budget.read(&mut input, &mut buffer).unwrap(), BUFFER_BYTES);
        assert_eq!(budget.read(&mut input, &mut buffer).unwrap(), BUFFER_BYTES);
        assert_eq!(budget.read(&mut input, &mut buffer).unwrap(), 7);
        assert_eq!(budget.read(&mut input, &mut buffer).unwrap(), 0);
        assert_eq!(input.offered, [BUFFER_BYTES, BUFFER_BYTES, 7, 1]);
        assert_eq!(budget.bytes_read(), size as u64);
        assert_eq!(budget.read_calls(), 4);
    }

    #[test]
    fn invalid_reader_counts_preserve_the_first_refusal_without_more_io() {
        struct Invalid;
        impl Read for Invalid {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                Ok(output.len() + 1)
            }
        }
        let budget = ReadBudget::new(4);
        let mut buffer = [0; 8];
        let error = budget
            .read(&mut Invalid, &mut buffer)
            .unwrap_err()
            .message();
        assert_eq!(error, "invalid backup payload reader byte count");
        assert_eq!(budget.bytes_read(), 0);
        assert_eq!(budget.read_calls(), 1);
        let mut permitted = Cursor::new(b"abcd");
        assert_eq!(
            budget
                .read(&mut permitted, &mut buffer)
                .unwrap_err()
                .message(),
            error
        );
        assert_eq!(permitted.position(), 0);
        assert_eq!(budget.read_calls(), 1);
        let allowed = ReadBudget::new(4);
        assert_eq!(allowed.read(&mut permitted, &mut buffer).unwrap(), 4);
        assert_eq!(allowed.read(&mut permitted, &mut buffer).unwrap(), 0);
    }

    #[test]
    fn interrupted_reads_count_calls_but_no_bytes_and_empty_requests_do_no_io() {
        struct InterruptedOnce {
            first: bool,
            input: Cursor<&'static [u8]>,
        }
        impl Read for InterruptedOnce {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if self.first {
                    self.first = false;
                    Err(io::Error::from(io::ErrorKind::Interrupted))
                } else {
                    self.input.read(output)
                }
            }
        }
        let budget = ReadBudget::new(3);
        let mut input = InterruptedOnce {
            first: true,
            input: Cursor::new(b"abc"),
        };
        assert_eq!(budget.read(&mut input, &mut []).unwrap(), 0);
        assert_eq!(budget.read_calls(), 0);
        let mut buffer = [0; 9];
        assert!(
            matches!(budget.read(&mut input, &mut buffer), Err(ReadFailure::Io(error)) if error.kind() == io::ErrorKind::Interrupted)
        );
        assert_eq!(budget.bytes_read(), 0);
        assert_eq!(budget.read_calls(), 1);
        assert_eq!(budget.read(&mut input, &mut buffer).unwrap(), 3);
        assert_eq!(budget.read(&mut input, &mut buffer).unwrap(), 0);
        assert_eq!(budget.bytes_read(), 3);
        assert_eq!(budget.read_calls(), 3);
    }

    #[test]
    fn accounting_overflow_refuses_without_wrapping_or_permitting_more_io() {
        let budget = ReadBudget::new(u64::MAX);
        budget.bytes.set(u64::MAX - 1);
        let mut input = Cursor::new(b"ab");
        let mut buffer = [0; 2];
        assert_eq!(budget.read(&mut input, &mut buffer).unwrap(), 1);
        assert_eq!(budget.bytes_read(), u64::MAX);
        let error = budget.read(&mut input, &mut buffer).unwrap_err().message();
        assert_eq!(error, "backup payload-read byte count overflow");
        assert_eq!(budget.bytes_read(), u64::MAX);
        assert_eq!(budget.read_calls(), 2);
        assert_eq!(
            budget.read(&mut input, &mut buffer).unwrap_err().message(),
            error
        );
        let calls = ReadBudget::new(3);
        calls.calls.set(u64::MAX);
        let mut pristine = Cursor::new(b"a");
        assert_eq!(
            calls
                .read(&mut pristine, &mut buffer)
                .unwrap_err()
                .message(),
            "backup payload-read call count overflow"
        );
        assert_eq!(pristine.position(), 0);
    }
}

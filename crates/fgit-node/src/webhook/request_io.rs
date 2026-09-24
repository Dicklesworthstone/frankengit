//! Bounded socket lifetime for the explicit blocking HTTP adapter.
//!
//! One monotonic deadline covers preparation and all socket operations; a
//! partial read/write does not renew it. Socket waits poll cancellation with
//! short idle timeouts. Blocking OS DNS and local filesystem persistence are
//! not preemptible here: their elapsed time is charged before further socket
//! work, but this is not an asynchronous resolver or filesystem implementation.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use fgit_types::RefusalCode;

const IO_QUANTUM: Duration = Duration::from_millis(100);
const WRITE_CHUNK_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// A failure before any attempted write is distinct from an unknown delivery.
#[derive(Debug)]
pub(super) enum Failure {
    Refused(RefusalCode),
    Unsent(io::Error),
    Ambiguous(String),
}

impl Failure {
    fn stopped(code: RefusalCode, attempted_write: bool) -> Self {
        if attempted_write {
            Self::Ambiguous(format!("HTTP delivery outcome unknown: {code:?}"))
        } else {
            Self::Refused(code)
        }
    }

    fn io(error: io::Error, attempted_write: bool) -> Self {
        if attempted_write {
            Self::Ambiguous(format!("HTTP delivery outcome unknown: {error}"))
        } else {
            Self::Unsent(error)
        }
    }
}

pub(super) struct Attempt<'a, C: ?Sized> {
    deadline: Instant,
    checkpoint: &'a C,
}

impl<'a, C: Fn() -> Result<(), RefusalCode> + ?Sized> Attempt<'a, C> {
    pub(super) fn new(timeout: Duration, checkpoint: &'a C) -> Result<Self, RefusalCode> {
        checkpoint()?;
        if timeout.is_zero() {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(RefusalCode::ResourceBudgetExceeded)?;
        Ok(Self {
            deadline,
            checkpoint,
        })
    }

    pub(super) fn check(&self) -> Result<Duration, RefusalCode> {
        (self.checkpoint)()?;
        self.remaining_at(Instant::now())
    }

    fn remaining_at(&self, now: Instant) -> Result<Duration, RefusalCode> {
        self.deadline
            .checked_duration_since(now)
            .filter(|remaining| !remaining.is_zero())
            .ok_or(RefusalCode::ResourceBudgetExceeded)
    }

    /// Borrow the body rather than constructing a second payload-sized request.
    /// The owner drops the stream before recording a result or returning.
    pub(super) fn exchange(
        &self,
        stream: &mut TcpStream,
        header: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, Failure> {
        let mut response = Vec::new();
        response
            .try_reserve_exact(MAX_RESPONSE_BYTES)
            .map_err(|_| Failure::Refused(RefusalCode::ResourceBudgetExceeded))?;
        let timeout = self.check().map_err(Failure::Refused)?.min(IO_QUANTUM);
        // Install both directions before sending, so unsupported timeout
        // configuration can still be reported as a known pre-send failure.
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .map_err(Failure::Unsent)?;
        let mut attempted_write = false;
        for mut bytes in [header, payload] {
            while !bytes.is_empty() {
                let timeout = self
                    .check()
                    .map_err(|code| Failure::stopped(code, attempted_write))?
                    .min(IO_QUANTUM);
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|error| Failure::io(error, attempted_write))?;
                let count = bytes.len().min(WRITE_CHUNK_BYTES);
                // A failed write can still have transferred bytes. From here
                // onwards neither cancellation nor timeout proves rejection.
                attempted_write = true;
                match stream.write(&bytes[..count]) {
                    Ok(0) => {
                        return Err(Failure::io(
                            io::Error::new(io::ErrorKind::WriteZero, "webhook write returned zero"),
                            attempted_write,
                        ));
                    }
                    Ok(written) => bytes = &bytes[written..],
                    Err(error) if retryable_wait(&error) => {}
                    Err(error) => return Err(Failure::io(error, attempted_write)),
                }
            }
        }
        // TcpStream is unbuffered: there is no userspace flush that can extend
        // the attempt or duplicate the body. A final header is sufficient ACK.
        let mut buffer = [0_u8; 4096];
        loop {
            // Preserve a complete acknowledgement already received, even if
            // cancellation arrives before another I/O would be attempted.
            if super::parse_http_status(&response).is_some() {
                return Ok(response);
            }
            if response.len() == MAX_RESPONSE_BYTES {
                return Err(Failure::Ambiguous(
                    "HTTP response headers exceed the 64 KiB limit".into(),
                ));
            }
            let timeout = self
                .check()
                .map_err(|code| Failure::stopped(code, attempted_write))?
                .min(IO_QUANTUM);
            stream
                .set_read_timeout(Some(timeout))
                .map_err(|error| Failure::io(error, attempted_write))?;
            let count = buffer.len().min(MAX_RESPONSE_BYTES - response.len());
            match stream.read(&mut buffer[..count]) {
                // The caller classifies an incomplete/empty head as ambiguous,
                // not a rejection inferred from EOF.
                Ok(0) => return Ok(response),
                Ok(read) => response.extend_from_slice(&buffer[..read]),
                Err(error) if retryable_wait(&error) => {}
                Err(error) => return Err(Failure::io(error, attempted_write)),
            }
        }
    }
}

fn retryable_wait(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests;

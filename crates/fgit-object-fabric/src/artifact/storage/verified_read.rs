//! Read-only access to a complete verified copy, independent of later changes
//! to the original custody file. No path or writable descriptor escapes.

use super::{ArtifactIdentity, ArtifactOperation, ArtifactStorageError, CHUNK_BYTES, File};
use std::io::{self, Read};

/// A fully verified payload in temporary, private, unlinked local custody.
///
/// Only the existing store can construct this reader. It exposes at most 64 KiB
/// per read and retains the original operation's deadline and cancellation.
/// A failed read poisons the reader: a caller cannot restart it under a
/// fresh budget or treat its remaining prefix as a complete payload.
pub struct VerifiedArtifactReader<'operation, 'live> {
    identity: ArtifactIdentity,
    file: File,
    operation: &'operation ArtifactOperation<'live>,
    remaining: u64,
    complete: bool,
    failed: bool,
}

impl<'operation, 'live> VerifiedArtifactReader<'operation, 'live> {
    pub(super) fn new(
        identity: ArtifactIdentity,
        file: File,
        operation: &'operation ArtifactOperation<'live>,
    ) -> Self {
        let remaining = identity.payload_len();
        Self {
            identity,
            file,
            operation,
            remaining,
            complete: false,
            failed: false,
        }
    }

    /// The complete original identity verified before this reader was created.
    #[must_use]
    pub const fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }

    /// Payload bytes still unread, excluding all artifact framing.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.remaining
    }

    fn read_inner(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.operation.checkpoint().map_err(stopped)?;
        if self.complete {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut extra = [0_u8; 1];
            if self.read_file(&mut extra)? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "verified artifact spool has trailing bytes",
                ));
            }
            self.operation.checkpoint().map_err(stopped)?;
            self.complete = true;
            return Ok(0);
        }
        let maximum = output
            .len()
            .min(CHUNK_BYTES)
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let count = self.read_file(&mut output[..maximum])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "verified artifact spool ended early",
            ));
        }
        self.operation.checkpoint().map_err(stopped)?;
        self.remaining -= count as u64;
        Ok(count)
    }

    fn read_file(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            self.operation.checkpoint().map_err(stopped)?;
            match self.file.read(output) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }
}

impl std::fmt::Debug for VerifiedArtifactReader<'_, '_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedArtifactReader")
            .field("identity", &self.identity)
            .field("remaining", &self.remaining)
            .field("complete", &self.complete)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl Read for VerifiedArtifactReader<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verified artifact reader already failed",
            ));
        }
        match self.read_inner(output) {
            Ok(count) => Ok(count),
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
}

fn stopped(error: ArtifactStorageError) -> io::Error {
    // Interrupted would invite Read helpers to retry forever after permanent
    // cancellation. Both operation stop conditions end this bounded stream.
    io::Error::new(io::ErrorKind::TimedOut, error)
}

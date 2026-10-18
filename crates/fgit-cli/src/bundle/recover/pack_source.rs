//! Replay the exact pack range selected by native file-backed verification.
//! Each EOF is a fresh SHA-256 and stable-descriptor check, so an earlier
//! verification never grants permission to publish changed source bytes.

use std::io::{self, Read, Seek, SeekFrom};

use fgit_crypto::{DigestHasher, Sha256Hasher};

use super::filesystem::VerifiedPackSource;
use crate::bundle::verify::local_files::StableInput;

pub(super) struct FilePack<'a> {
    input: &'a mut StableInput,
    offset: u64,
    length: u64,
    expected: [u8; 32],
    hasher: Sha256Hasher,
    position: u64,
    started: bool,
    checked: bool,
}

impl<'a> FilePack<'a> {
    pub(super) fn new(
        input: &'a mut StableInput,
        offset: u64,
        length: u64,
        expected: [u8; 32],
    ) -> io::Result<Self> {
        if length == 0 || offset.checked_add(length) != Some(input.len()) {
            return Err(changed("verified pack range does not end at the input EOF"));
        }
        Ok(Self {
            input,
            offset,
            length,
            expected,
            hasher: Sha256Hasher::new(),
            position: 0,
            started: false,
            checked: false,
        })
    }
}

fn changed(detail: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail.into())
}

impl VerifiedPackSource for FilePack<'_> {
    fn len(&self) -> u64 {
        self.length
    }

    fn rewind(&mut self) -> io::Result<()> {
        self.started = false;
        self.checked = false;
        // The filesystem writer checks its sticky cancellation before and
        // after source operations. This recheck performs bounded metadata I/O.
        self.input.recheck(&mut || true).map_err(changed)?;
        let position = self.input.file_mut().seek(SeekFrom::Start(self.offset))?;
        if position != self.offset {
            return Err(changed("verified pack seek returned the wrong position"));
        }
        self.hasher = Sha256Hasher::new();
        self.position = 0;
        self.started = true;
        Ok(())
    }

    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if !self.started {
            return Err(changed("verified pack replay was not started"));
        }
        if self.position < self.length {
            let count = (self.length - self.position).min(output.len() as u64) as usize;
            let read = self.input.file_mut().read(&mut output[..count])?;
            if read == 0 {
                return Err(changed("verified pack source ended early"));
            }
            self.hasher.update(&output[..read]);
            self.position += read as u64;
            return Ok(read);
        }
        if !self.checked {
            let mut extra = [0_u8; 1];
            if self.input.file_mut().read(&mut extra)? != 0 {
                return Err(changed("verified pack source has trailing bytes"));
            }
            if self.hasher.clone().finish() != self.expected {
                return Err(changed("verified pack SHA-256 binding changed"));
            }
            self.input.recheck(&mut || true).map_err(changed)?;
            self.checked = true;
        }
        Ok(0)
    }
}

#[cfg(test)]
#[path = "pack_source_tests.rs"]
mod tests;

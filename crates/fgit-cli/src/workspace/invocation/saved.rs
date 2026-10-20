//! Creation-only result custody after all execution owners have settled.
use super::{Fields, Invocation, MAX_REQUEST, frame};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub(super) const TERMINAL_MAGIC: &[u8; 8] = b"FGWIT001";
pub(super) const MAX_BUNDLE: usize = 128 * 1024 * 1024 + 4096;
pub(super) const MAX_RECEIPT: usize = 16 * 1024 * 1024;
pub(super) const MAX_FAILURE: usize = 16 * 1024;

impl Invocation {
    pub(in crate::workspace) fn complete(
        self,
        header: &[u8],
        pack: &[u8],
        receipt: &[u8],
    ) -> Result<[u8; 32], String> {
        if receipt.len() > MAX_RECEIPT
            || header
                .len()
                .checked_add(pack.len())
                .is_none_or(|n| n > MAX_BUNDLE)
        {
            return Err("workspace saved result exceeds its finite bound".into());
        }
        let (length, digest) = write_body(
            &self.directory.join("candidate.bundle"),
            &[header, pack],
            MAX_BUNDLE,
        )?;
        let (receipt_length, receipt_digest) = write_body(
            &self.directory.join("receipt.json"),
            &[receipt],
            MAX_RECEIPT,
        )?;
        let mut fields = Fields::default();
        for value in [
            b"ready".as_slice(),
            &self.request_id,
            &length.to_be_bytes(),
            &digest,
            &receipt_length.to_be_bytes(),
            &receipt_digest,
        ] {
            fields.push(value).map_err(|e| e.to_string())?;
        }
        self.terminal(&fields.0)
    }
    pub(in crate::workspace) fn fail(self, error: &str) -> Result<(), String> {
        let mut end = error.len().min(MAX_FAILURE);
        while !error.is_char_boundary(end) {
            end -= 1;
        }
        let mut fields = Fields::default();
        for value in [
            b"failed".as_slice(),
            &self.request_id,
            error[..end].as_bytes(),
        ] {
            fields.push(value).map_err(|e| e.to_string())?;
        }
        self.terminal(&fields.0).map(|_| ())
    }
    fn terminal(&self, payload: &[u8]) -> Result<[u8; 32], String> {
        let bytes = frame(TERMINAL_MAGIC, payload);
        let (_, digest) = write_body(
            &self.directory.join("terminal"),
            &[&bytes],
            MAX_REQUEST + 48,
        )?;
        File::open(&self.directory)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(digest)
    }
}
fn write_body(path: &Path, chunks: &[&[u8]], maximum: usize) -> Result<(u64, [u8; 32]), String> {
    let length = chunks
        .iter()
        .try_fold(0usize, |n, bytes| n.checked_add(bytes.len()))
        .filter(|n| *n <= maximum)
        .ok_or("workspace saved result exceeds its finite bound")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    let mut hasher = Sha256Hasher::new();
    for chunk in chunks {
        file.write_all(chunk).map_err(|e| e.to_string())?;
        hasher.update(chunk);
    }
    file.sync_all().map_err(|e| e.to_string())?;
    Ok((length as u64, hasher.finish()))
}

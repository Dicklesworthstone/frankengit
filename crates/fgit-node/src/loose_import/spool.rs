//! Private, bounded byte custody between whole-graph validation and placement.
//! The source is read once. Handles retain only offsets, lengths and native
//! kinds, never every body in RAM. Spool bytes are re-identified before use.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fgit_git_object::{LooseObject, ObjectType};
use fgit_types::{GitOid, RefusalCode};

use super::control::{IO_CHUNK_BYTES, ImportControl, interrupted};
use super::{LooseGitImportRefusal, io_refusal};

#[derive(Clone, Copy, Debug)]
pub(super) struct Entry {
    offset: u64,
    length: usize,
    kind: ObjectType,
}

/// One synchronous import owns one file, not one file per object. On Unix it
/// is unlinked immediately: cancellation, panic and process death cannot leave
/// named scratch payloads. Other hosts remove the exclusive name on close.
pub(super) struct Spool {
    file: Option<File>,
    path: PathBuf,
    linked: bool,
    bytes: u64,
    maximum: u64,
}

impl Spool {
    pub(super) fn create(
        root: &Path,
        maximum: u64,
        control: &ImportControl<'_>,
    ) -> Result<Self, LooseGitImportRefusal> {
        control.checkpoint()?;
        for _ in 0..8 {
            let path = root.join(format!(
                ".fg-import-quarantine-{:032x}",
                std::random::random::<u128>(..)
            ));
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = match options.open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(io_refusal("create private import spool", path, error)),
            };
            let mut spool = Self {
                file: Some(file),
                path,
                linked: true,
                bytes: 0,
                maximum,
            };
            #[cfg(unix)]
            {
                fs::remove_file(&spool.path).map_err(|error| {
                    io_refusal("unlink private import spool", spool.path.clone(), error)
                })?;
                spool.linked = false;
            }
            control.checkpoint()?;
            return Ok(spool);
        }
        Err(interrupted(RefusalCode::ResourceBudgetExceeded))
    }

    pub(super) fn retain(
        &mut self,
        _identity: GitOid,
        object: LooseObject,
        control: &ImportControl<'_>,
    ) -> Result<Entry, LooseGitImportRefusal> {
        control.checkpoint()?;
        let next = self
            .bytes
            .checked_add(object.body.len() as u64)
            .ok_or_else(|| interrupted(RefusalCode::ResourceBudgetExceeded))?;
        if next > self.maximum {
            return Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
                limit: self.maximum,
                observed: next,
            });
        }
        // The only caller has already authenticated the object and graph edge
        // kind. Keep identity out of the filename and preserve exact bytes.
        let entry = Entry {
            offset: self.bytes,
            length: object.body.len(),
            kind: object.object_type,
        };
        let path = self.path.clone();
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| interrupted(RefusalCode::InternalInvariantBreach))?;
        file.seek(SeekFrom::Start(self.bytes))
            .map_err(|error| io_refusal("seek import spool append", path.clone(), error))?;
        for chunk in object.body.chunks(IO_CHUNK_BYTES) {
            control.checkpoint()?;
            file.write_all(chunk)
                .map_err(|error| io_refusal("write private import spool", path.clone(), error))?;
        }
        control.checkpoint()?;
        self.bytes = next;
        Ok(entry)
    }

    pub(super) fn read(
        &mut self,
        identity: GitOid,
        entry: Entry,
        control: &ImportControl<'_>,
    ) -> Result<LooseObject, LooseGitImportRefusal> {
        control.checkpoint()?;
        if entry
            .offset
            .checked_add(entry.length as u64)
            .is_none_or(|end| end > self.bytes)
        {
            return Err(interrupted(RefusalCode::InternalInvariantBreach));
        }
        let mut body = Vec::new();
        body.try_reserve_exact(entry.length)
            .map_err(|_| interrupted(RefusalCode::ResourceBudgetExceeded))?;
        body.resize(entry.length, 0);
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| interrupted(RefusalCode::InternalInvariantBreach))?;
        file.seek(SeekFrom::Start(entry.offset))
            .map_err(|error| io_refusal("seek private import spool", self.path.clone(), error))?;
        for chunk in body.chunks_mut(IO_CHUNK_BYTES) {
            control.checkpoint()?;
            file.read_exact(chunk).map_err(|error| {
                io_refusal("read private import spool", self.path.clone(), error)
            })?;
        }
        control.checkpoint()?;
        let observed = fgit_crypto::git_object_id(identity.algorithm(), entry.kind, &body);
        control.checkpoint()?;
        if observed != identity {
            return Err(LooseGitImportRefusal::ObjectIdentityMismatch {
                expected: identity,
                observed,
            });
        }
        Ok(LooseObject {
            object_type: entry.kind,
            declared_size: body.len(),
            body,
        })
    }

    /// No fsync claim is attached to scratch custody. Durable placement and
    /// authority publication retain their original independent protocols.
    pub(super) fn finish(mut self) -> Result<(), LooseGitImportRefusal> {
        drop(self.file.take());
        if self.linked {
            fs::remove_file(&self.path).map_err(|error| {
                io_refusal("remove private import spool", self.path.clone(), error)
            })?;
            self.linked = false;
        }
        Ok(())
    }
}
impl Drop for Spool {
    fn drop(&mut self) {
        drop(self.file.take());
        if self.linked {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests;

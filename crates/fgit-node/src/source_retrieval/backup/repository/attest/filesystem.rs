//! Private key input and create-only detached approval publication on Unix.
//! Stable, trusted parent paths are required; this is not a hostile-UID sandbox.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::approval::issuer;
use super::super::profile::Deadline;
use fgit_crypto::DsseEd25519SigningKey;

static NEXT: AtomicU64 = AtomicU64::new(1);
const MAX_KEY: usize = 8192;
const MAX_ENVELOPE: usize = 16 * 1024;

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn same(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    same(left, right)
        && left.is_file()
        && right.is_file()
        && left.len() == right.len()
        && left.nlink() == right.nlink()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

pub(super) fn destination_preflight(path: &Path) -> Result<(), String> {
    if path.file_name().is_none() {
        return Err("attestation requires a named new approval file".into());
    }
    super::super::super::require_absent(path)?;
    let metadata =
        fs::symlink_metadata(parent(path)).map_err(|error| format!("approval parent: {error}"))?;
    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err("approval output requires an existing owner-private directory".into());
    }
    Ok(())
}

pub(in super::super) struct Stage {
    destination: PathBuf,
    temporary: PathBuf,
    parent: File,
    parent_identity: Metadata,
    file: File,
    identity: Metadata,
    state: &'static str,
}

impl Stage {
    pub(in super::super) fn reserve(path: &Path, deadline: Deadline) -> Result<Self, String> {
        deadline.check()?;
        destination_preflight(path)?;
        let parent_identity =
            fs::symlink_metadata(parent(path)).map_err(|error| error.to_string())?;
        let directory = File::open(parent(path)).map_err(|error| error.to_string())?;
        if !same(
            &parent_identity,
            &directory.metadata().map_err(|error| error.to_string())?,
        ) {
            return Err("approval parent changed while opening".into());
        }
        for _ in 0..16 {
            deadline.check()?;
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let temporary = parent(path).join(format!(
                ".fg-backup-approval-{}-{sequence}.tmp",
                std::process::id()
            ));
            let opened = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary);
            let file = match opened {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("cannot stage backup approval: {error}")),
            };
            let identity = file.metadata().map_err(|error| error.to_string())?;
            let mut stage = Self {
                destination: path.to_path_buf(),
                temporary,
                parent: directory,
                parent_identity,
                file,
                identity,
                state: "staged",
            };
            if let Err(error) = stage.check_parent().and_then(|()| stage.check_stage(1)) {
                return Err(stage.failure(error));
            }
            return Ok(stage);
        }
        Err("no unused backup approval staging name".into())
    }

    pub(super) fn owner(&self) -> u32 {
        self.identity.uid()
    }

    /// Native composition may stream into this same owned descriptor. The
    /// caller must verify its artifact before publication.
    pub(in super::super) fn file(&mut self) -> &mut File {
        &mut self.file
    }

    /// Synchronize and freeze this exact content's metadata. This is a byte
    /// custody fence, not semantic verification. A native verifier can read the
    /// same descriptor afterward; publication rejects changed metadata rather
    /// than accepting a newly frozen, different file after verification.
    pub(in super::super) fn synchronize_content(
        &mut self,
        expected_len: u64,
        deadline: Deadline,
    ) -> Result<(), String> {
        deadline.check()?;
        self.check_parent()?;
        self.check_stage(1)?;
        let before = self.file.metadata().map_err(|error| error.to_string())?;
        if before.len() != expected_len || expected_len == 0 {
            return Err("verified backup staging length changed".into());
        }
        self.file
            .sync_all()
            .map_err(|error| format!("verified backup staging sync: {error}"))?;
        let after = self.file.metadata().map_err(|error| error.to_string())?;
        if !same_file(&before, &after) {
            return Err("verified backup staging changed during synchronization".into());
        }
        self.identity = after;
        self.check_stage(1)?;
        deadline.check()
    }

    fn check_parent(&self) -> Result<(), String> {
        let opened = self.parent.metadata().map_err(|error| error.to_string())?;
        let named =
            fs::symlink_metadata(parent(&self.destination)).map_err(|error| error.to_string())?;
        if !same(&opened, &self.parent_identity)
            || !same(&opened, &named)
            || !opened.is_dir()
            || opened.mode() & 0o077 != 0
            || opened.uid() != self.owner()
        {
            return Err("approval parent must remain private and owned by this invocation's filesystem user".into());
        }
        Ok(())
    }

    fn check_stage(&self, links: u64) -> Result<(), String> {
        let opened = self.file.metadata().map_err(|error| error.to_string())?;
        let named = fs::symlink_metadata(&self.temporary).map_err(|error| error.to_string())?;
        if !same(&opened, &self.identity)
            || !same_file(&opened, &named)
            || !opened.is_file()
            || opened.mode() & 0o077 != 0
            || opened.nlink() != links
        {
            return Err("backup approval stage identity or ownership changed".into());
        }
        Ok(())
    }

    pub(super) fn write_verified(
        &mut self,
        bytes: &[u8],
        deadline: Deadline,
    ) -> Result<(), String> {
        deadline.check()?;
        if bytes.is_empty()
            || bytes.len() > MAX_ENVELOPE
            || self
                .file
                .metadata()
                .map_err(|error| error.to_string())?
                .len()
                != 0
        {
            return Err("backup approval output exceeds its bounded fresh-file profile".into());
        }
        self.check_parent()?;
        self.check_stage(1)?;
        let mut remaining = bytes;
        while !remaining.is_empty() {
            deadline.check()?;
            match self.file().write(remaining) {
                Ok(0) => return Err("backup approval write made no progress".into()),
                Ok(count) => remaining = &remaining[count..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(format!("backup approval write: {error}")),
            }
        }
        self.file
            .sync_all()
            .map_err(|error| format!("backup approval staging sync: {error}"))?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|error| error.to_string())?;
        let before = self.file.metadata().map_err(|error| error.to_string())?;
        let mut offset = 0;
        let mut buffer = [0; 1024];
        loop {
            deadline.check()?;
            let count = match self.file.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(format!("backup approval readback: {error}")),
            };
            if count == 0 {
                break;
            }
            let expected = bytes
                .get(offset..offset + count)
                .ok_or("backup approval readback length changed")?;
            if expected != &buffer[..count] {
                return Err("backup approval readback changed".into());
            }
            offset += count;
        }
        if offset != bytes.len()
            || !same_file(
                &before,
                &self.file.metadata().map_err(|error| error.to_string())?,
            )
        {
            return Err("backup approval readback length or identity changed".into());
        }
        self.identity = before;
        self.synchronize_content(bytes.len() as u64, deadline)
    }

    pub(in super::super) fn publish(
        &mut self,
        mut live: impl FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        live()?;
        self.check_parent()?;
        self.check_stage(1)?;
        if !same_file(
            &self.identity,
            &self.file.metadata().map_err(|error| error.to_string())?,
        ) {
            return Err("backup approval changed after readback".into());
        }
        super::super::super::require_absent(&self.destination)?;
        live()?;
        self.state = "publication_uncertain";
        if let Err(error) = fs::hard_link(&self.temporary, &self.destination) {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                self.state = "staged";
            }
            return Err(format!("backup approval publication: {error}"));
        }
        self.state = "published";
        let published =
            fs::symlink_metadata(&self.destination).map_err(|error| error.to_string())?;
        if !same(&self.identity, &published) || !published.is_file() || published.nlink() != 2 {
            return Err("published approval identity changed; preserve output and stage".into());
        }
        self.check_parent()?;
        self.check_stage(2)?;
        fs::remove_file(&self.temporary)
            .map_err(|error| format!("backup approval stage cleanup: {error}"))?;
        self.parent
            .sync_all()
            .map_err(|error| format!("backup approval parent synchronization: {error}"))?;
        self.state = "durable";
        Ok(())
    }

    pub(in super::super) fn failure(&mut self, error: String) -> String {
        if self.state != "staged" {
            return format!(
                "{error}; approval publication_state={}; preserve the approval output and inspect it before retrying",
                self.state
            );
        }
        let cleanup = self
            .check_parent()
            .and_then(|()| self.check_stage(1))
            .and_then(|()| fs::remove_file(&self.temporary).map_err(|error| error.to_string()));
        match cleanup {
            Ok(()) => format!("{error}; approval publication_state=not_created"),
            Err(cleanup) => format!(
                "{error}; approval publication_state=not_created; owned staging cleanup refused at {}: {cleanup}",
                self.temporary.display()
            ),
        }
    }
}

pub(super) fn read_private_key(
    path: &Path,
    owner: u32,
    deadline: Deadline,
) -> Result<DsseEd25519SigningKey, String> {
    use rustix::fs::{Mode, OFlags};
    deadline.check()?;
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("backup private key inspection: {error}"))?;
    let valid = |metadata: &Metadata| {
        metadata.is_file()
            && metadata.uid() == owner
            && metadata.mode() & 0o077 == 0
            && metadata.nlink() == 1
            && metadata.len() > 0
            && metadata.len() <= MAX_KEY as u64
    };
    if !valid(&before) {
        return Err(
            "backup private key must be an owner-private single-link bounded regular file".into(),
        );
    }
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| format!("backup private key open: {error}"))?;
    let mut file = File::from(descriptor);
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if !valid(&opened) || !same_file(&before, &opened) {
        return Err("backup private key changed while opening".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize + 1);
    let result = (|| {
        let mut buffer = [0; 256];
        loop {
            deadline.check()?;
            let count = match file.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(format!("backup private key read: {error}")),
            };
            if count == 0 {
                break;
            }
            if bytes.len() + count > MAX_KEY {
                return Err("backup private key byte limit".into());
            }
            bytes.extend_from_slice(&buffer[..count]);
            buffer.fill(0);
        }
        deadline.check()?;
        let after = file.metadata().map_err(|error| error.to_string())?;
        let named = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if !valid(&after)
            || bytes.len() != opened.len() as usize
            || !same_file(&opened, &after)
            || !same_file(&after, &named)
        {
            return Err("backup private key changed while reading".into());
        }
        issuer::signing_key(&bytes)
    })();
    bytes.fill(0);
    result
}

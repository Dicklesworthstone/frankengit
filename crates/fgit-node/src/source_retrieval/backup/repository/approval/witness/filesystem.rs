//! Private, pinned files and a create-only durable witness lease. All mutation
//! stays beneath stable trusted parents; no same-UID sandbox is claimed.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::Deadline;
use super::state::MAX_STATE_BYTES;

pub(super) const STATE: &str = "witness.json";
pub(super) const LOCK: &str = ".witness-lock";
static NEXT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Checkpoint {
    BeforeStage,
    StageSynced,
    BeforeRename,
    Renamed,
    DirectorySynced,
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

fn private(metadata: &Metadata) -> bool {
    metadata.mode() & 0o077 == 0
}

pub(super) fn physical_directory(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .ok_or("backup witness requires a named directory")?;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(fs::canonicalize(parent)
        .map_err(|error| format!("backup witness parent: {error}"))?
        .join(name))
}

struct Directory {
    path: PathBuf,
    file: File,
    identity: Metadata,
}

impl Directory {
    fn open(path: &Path) -> Result<Self, String> {
        let file = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| format!("backup witness directory open: {error}"))?;
        let identity = file.metadata().map_err(|error| error.to_string())?;
        if !identity.is_dir() || !private(&identity) {
            return Err("backup witness requires owner-private directories".into());
        }
        let directory = Self {
            path: path.to_path_buf(),
            file,
            identity,
        };
        directory.check()?;
        Ok(directory)
    }

    fn check(&self) -> Result<(), String> {
        let opened = self.file.metadata().map_err(|error| error.to_string())?;
        let named = fs::symlink_metadata(&self.path).map_err(|error| error.to_string())?;
        if !same(&self.identity, &opened)
            || !same(&opened, &named)
            || !named.is_dir()
            || !private(&named)
        {
            return Err("backup witness directory identity or private ownership changed".into());
        }
        Ok(())
    }

    fn sync(&self) -> Result<(), String> {
        self.file
            .sync_all()
            .map_err(|error| format!("backup witness directory synchronization: {error}"))
    }
}

pub(super) struct StateFile {
    file: File,
    identity: Metadata,
    pub(super) bytes: Vec<u8>,
}

fn read_state(path: &Path, owner: u32, deadline: Deadline) -> Result<StateFile, String> {
    deadline.check()?;
    let mut file = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| format!("backup witness state open: {error}"))?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file()
        || !private(&before)
        || before.uid() != owner
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_STATE_BYTES as u64
    {
        return Err(
            "backup witness state must be a bounded single-link owner-private regular file".into(),
        );
    }
    let expected = before.len() as usize;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected + 1)
        .map_err(|_| "backup witness state allocation refused")?;
    bytes.resize(expected + 1, 0);
    let mut at = 0;
    while at < bytes.len() {
        deadline.check()?;
        match file.read(&mut bytes[at..]) {
            Ok(0) => break,
            Ok(count) if count <= bytes.len() - at => at += count,
            Ok(_) => return Err("invalid backup witness reader byte count".into()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("backup witness read failed: {error}")),
        }
    }
    deadline.check()?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    let named = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if at != expected || !same_file(&before, &after) || !same_file(&after, &named) {
        return Err("backup witness state changed while reading".into());
    }
    bytes.truncate(expected);
    Ok(StateFile {
        file,
        identity: after,
        bytes,
    })
}

fn write_all(file: &mut File, mut bytes: &[u8], deadline: Deadline) -> Result<(), String> {
    while !bytes.is_empty() {
        deadline.check()?;
        match file.write(bytes) {
            Ok(0) => return Err("backup witness write made no progress".into()),
            Ok(count) if count <= bytes.len() => bytes = &bytes[count..],
            Ok(_) => return Err("invalid backup witness writer byte count".into()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("backup witness write failed: {error}")),
        }
    }
    deadline.check()
}

pub(super) fn initialize(path: &Path, bytes: &[u8], deadline: Deadline) -> Result<PathBuf, String> {
    deadline.check()?;
    let path = physical_directory(path)?;
    let parent = Directory::open(path.parent().ok_or("backup witness parent missing")?)?;
    let mut created = false;
    let result = (|| {
        parent.check()?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| format!("backup witness create-only initialization: {error}"))?;
        created = true;
        let root = Directory::open(&path)?;
        if root.identity.uid() != parent.identity.uid() {
            return Err(
                "backup witness parent must belong to this invocation's filesystem user".into(),
            );
        }
        let state_path = path.join(STATE);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&state_path)
            .map_err(|error| error.to_string())?;
        let owner = file.metadata().map_err(|error| error.to_string())?.uid();
        if owner != root.identity.uid() {
            return Err(
                "backup witness root must belong to this invocation's filesystem user".into(),
            );
        }
        write_all(&mut file, bytes, deadline)?;
        file.sync_all()
            .map_err(|error| format!("backup witness initial state sync: {error}"))?;
        let readback = read_state(&state_path, owner, deadline)?;
        if readback.bytes != bytes
            || !same_file(
                &readback.identity,
                &file.metadata().map_err(|error| error.to_string())?,
            )
        {
            return Err("backup witness initial state readback changed".into());
        }
        root.sync()?;
        parent.sync()?;
        root.check()?;
        parent.check()?;
        deadline.check()?;
        Ok(path.clone())
    })();
    result.map_err(|error: String| {
        if created { format!("{error}; backup witness initialization may be visible at {}; preserve this directory; never implicitly reset it", path.display()) }
        else { error }
    })
}

/// An unfinished owner always leaves the create-only lease in place. Only an
/// explicit release after settled work unlinks it; dropping never guesses.
pub(super) struct Lease {
    root: Directory,
    lock: File,
    identity: Metadata,
}

impl Lease {
    pub(super) fn acquire(path: &Path, deadline: Deadline) -> Result<Self, String> {
        deadline.check()?;
        let path = physical_directory(path)?;
        let root = Directory::open(&path)?;
        let lock_path = path.join(LOCK);
        let mut lock = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)
            .open(&lock_path).map_err(|error| format!("backup witness exclusive lease unavailable at {}: {error}; no automatic lock stealing", lock_path.display()))?;
        let initialized = (|| {
            let initial = lock.metadata().map_err(|error| error.to_string())?;
            if !initial.is_file()
                || !private(&initial)
                || initial.nlink() != 1
                || initial.uid() != root.identity.uid()
            {
                return Err("backup witness lease/root must be private and owned by this invocation's filesystem user".into());
            }
            let token = NEXT.fetch_add(1, Ordering::Relaxed);
            let bytes = format!(
                "{{\"type\":\"repository_backup_witness_lock_v1\",\"pid\":{},\"token\":\"{:016x}{token:016x}\"}}\n",
                std::process::id(),
                u64::from(std::process::id())
            );
            write_all(&mut lock, bytes.as_bytes(), deadline)?;
            lock.sync_all()
                .map_err(|error| format!("backup witness lease synchronization: {error}"))?;
            root.sync()?;
            root.check()?;
            deadline.check()?;
            lock.metadata().map_err(|error| error.to_string())
        })();
        let identity = initialized.map_err(|error: String| {
            format!(
                "{error}; witness_lock_retained=true at {}",
                lock_path.display()
            )
        })?;
        let lease = Self {
            root,
            lock,
            identity,
        };
        lease.check().map_err(|error| {
            format!(
                "{error}; witness_lock_retained=true at {}",
                lease.path().display()
            )
        })?;
        Ok(lease)
    }

    pub(super) fn path(&self) -> &Path {
        &self.root.path
    }

    pub(super) fn check(&self) -> Result<(), String> {
        self.root.check()?;
        let opened = self.lock.metadata().map_err(|error| error.to_string())?;
        let named =
            fs::symlink_metadata(self.root.path.join(LOCK)).map_err(|error| error.to_string())?;
        if !same_file(&self.identity, &opened)
            || !same_file(&opened, &named)
            || opened.nlink() != 1
            || !private(&opened)
            || opened.uid() != self.root.identity.uid()
        {
            return Err("backup witness lease identity, bytes or ownership changed".into());
        }
        Ok(())
    }

    pub(super) fn state(&self, deadline: Deadline) -> Result<StateFile, String> {
        self.check()?;
        read_state(&self.root.path.join(STATE), self.identity.uid(), deadline)
    }

    pub(super) fn check_custody(&self, state: &StateFile) -> Result<(), String> {
        self.check()?;
        let opened = state.file.metadata().map_err(|error| error.to_string())?;
        let named =
            fs::symlink_metadata(self.root.path.join(STATE)).map_err(|error| error.to_string())?;
        if !same_file(&state.identity, &opened) || !same_file(&opened, &named) {
            return Err("backup witness state identity or content metadata changed".into());
        }
        Ok(())
    }

    pub(super) fn check_state(&self, state: &StateFile, deadline: Deadline) -> Result<(), String> {
        self.check_custody(state)?;
        let current = self.state(deadline)?;
        if !same_file(&current.identity, &state.identity) || current.bytes != state.bytes {
            return Err("backup witness original state changed".into());
        }
        Ok(())
    }

    pub(super) fn replace(
        &self,
        state: &StateFile,
        bytes: &[u8],
        deadline: Deadline,
        mut checkpoint: impl FnMut(Checkpoint) -> Result<(), String>,
    ) -> Result<StateFile, String> {
        let mut publication = "not_published";
        let mut staged: Option<(PathBuf, File, Metadata)> = None;
        let result: Result<StateFile, String> = (|| {
            deadline.check()?;
            checkpoint(Checkpoint::BeforeStage)?;
            self.check_state(state, deadline)?;
            if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
                return Err("backup witness update exceeds its state-byte limit".into());
            }
            for _ in 0..16 {
                deadline.check()?;
                let name = self.root.path.join(format!(
                    ".witness-{}-{}.tmp",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&name)
                {
                    Ok(file) => {
                        let identity = file.metadata().map_err(|error| error.to_string())?;
                        staged = Some((name, file, identity));
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(format!("backup witness staging open: {error}")),
                }
            }
            let (path, file, identity) = staged
                .as_mut()
                .ok_or("backup witness has no unused staging name")?;
            if identity.uid() != self.identity.uid()
                || !identity.is_file()
                || !private(identity)
                || identity.nlink() != 1
            {
                return Err("backup witness stage is not an owned private regular file".into());
            }
            write_all(file, bytes, deadline)?;
            file.sync_all()
                .map_err(|error| format!("backup witness staging synchronization: {error}"))?;
            checkpoint(Checkpoint::StageSynced)?;
            let readback = read_state(path, self.identity.uid(), deadline)?;
            if readback.bytes != bytes
                || !same_file(
                    &readback.identity,
                    &file.metadata().map_err(|error| error.to_string())?,
                )
            {
                return Err("backup witness stage readback changed".into());
            }
            self.check_state(state, deadline)?;
            checkpoint(Checkpoint::BeforeRename)?;
            self.check_state(state, deadline)?;
            let current_stage = fs::symlink_metadata(&*path).map_err(|error| error.to_string())?;
            if !same_file(&readback.identity, &current_stage)
                || !same_file(
                    &current_stage,
                    &file.metadata().map_err(|error| error.to_string())?,
                )
            {
                return Err("backup witness stage changed after readback".into());
            }
            deadline.check()?;
            publication = "publication_unknown";
            fs::rename(&*path, self.root.path.join(STATE))
                .map_err(|error| format!("backup witness state replacement: {error}"))?;
            publication = "visible_completion_incomplete";
            checkpoint(Checkpoint::Renamed)?;
            // Synchronization settles the now-visible replacement even if the
            // caller's lifetime expires. Never restore the previous state.
            self.root.sync()?;
            self.root.check()?;
            checkpoint(Checkpoint::DirectorySynced)?;
            let current = self.state(deadline)?;
            if current.bytes != bytes
                || !same_file(
                    &current.identity,
                    &file.metadata().map_err(|error| error.to_string())?,
                )
            {
                return Err("backup witness published state readback changed".into());
            }
            publication = "durable";
            Ok(current)
        })();
        match result {
            Ok(state) => Ok(state),
            Err(error) => {
                let cleanup = if publication == "not_published" {
                    staged
                        .as_ref()
                        .map(|(path, file, identity)| self.retire_stage(path, file, identity))
                        .transpose()
                } else {
                    Ok(None)
                };
                let suffix = cleanup.err().map_or_else(String::new, |error| {
                    format!("; owned stage cleanup refused: {error}")
                });
                Err(format!(
                    "{error}; witness_publication_state={publication}; witness_lock_retained=true{suffix}"
                ))
            }
        }
    }

    fn retire_stage(&self, path: &Path, file: &File, identity: &Metadata) -> Result<(), String> {
        self.check()?;
        let opened = file.metadata().map_err(|error| error.to_string())?;
        let named = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if !same(identity, &opened) || !same_file(&opened, &named) || opened.nlink() != 1 {
            return Err("backup witness refuses cleanup of a changed staging file".into());
        }
        fs::remove_file(path).map_err(|error| error.to_string())?;
        self.root.sync()
    }

    /// Cleanup carries no fresh deadline and does not invalidate completed
    /// native publication. Its own failure remains explicit and preserves state.
    pub(super) fn release(self) -> Result<(), String> {
        self.check()
            .map_err(|error| format!("{error}; witness_lock_retained=true"))?;
        fs::remove_file(self.root.path.join(LOCK)).map_err(|error| {
            format!("backup witness lease removal: {error}; witness_lock_retained=true")
        })?;
        self.root
            .sync()
            .map_err(|error| format!("{error}; witness_lock_release_uncertain=true"))?;
        Ok(())
    }
}
